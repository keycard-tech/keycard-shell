#include <string.h>

#include "crypto/ecdsa.h"
#include "crypto/rand.h"
#include "crypto/bip39.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/keycard.h"
#include "keycard/pairing.h"
#include "keycard/scv2_whitelist.h"
#include "keycard/secure_channel_v1.h"
#include "sc_card.h"
#include "sc_host.h"
#include "sc_v1_card.h"
#include "unity.h"
#include "ui_host.h"

/*
 * keycard_activate is the card's state machine: SELECT, read the application info, pair if the card
 * is not paired yet, open a secure channel, read the card's name, verify the PIN. Everything it
 * decides it announces on the screen, so the seam records which notices appeared and in what order,
 * and the wire records what the card was asked.
 *
 * The card here is scripted rather than emulated: each test queues the answers one exchange needs.
 * Its send-sequence is a counter in this file, because N(S) toggles with every I-block across the
 * whole activation, not per command.
 */

/* The applet's secure-element key, whose public half the application info carries. */
static const uint8_t SC_PRIV[32] = {0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91,
                                    0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12,
                                    0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92,
                                    0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13};

static const uint8_t INSTANCE_UID[APP_INFO_INSTANCE_UID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                                                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                                                0xdd, 0xee, 0xff, 0x00};

#define RNG_SEED 0x5eedULL

#define SELECT_APDU "00A4040009A0000008040001010100"

static keycard_t kc;

/* Once the pairing is agreed the card is a v1 channel, so the same model answers it here. */
static v1_card_t model;
static uint8_t sc_pub[65];
static unsigned card_seq;

void setUp(void) {
  host_ui_reset();
  hal_host_sc_reset();
  /* The pairing store is read on the way to a channel, and the key that encrypts it comes from the
   * one the host flash model boots with. */
  hal_host_flash_reset();
  hal_host_aes_reset();
  memset(&kc, 0, sizeof(kc));
  smartcard_init(&kc.sc);
  card_seq = 0;

  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, SC_PRIV, sc_pub));

}

void tearDown(void) {}

/* The card's next I-block, with its send-sequence taken care of. */
static void card_says(const uint8_t* info, size_t len) { sc_card_answer(info, len, card_seq++); }

static void card_says_status(uint16_t sw) { sc_card_status(sw, card_seq++); }

/* The application info a v3 applet answers SELECT with: its UID, the secure element's key, the
 * version, a free pairing slot, the key UID and the capabilities. The key UID's length is what says
 * whether the card has keys, so a shorter one reports a card that does not. */
static size_t app_info_v3(uint8_t* out, size_t max, uint16_t version, uint8_t key_uid_len) {
  uint8_t inner[160];
  size_t n = 0;

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(inner),
                                         (unsigned)(16 + 67 + 4 + 3 + key_uid_len + 3), "inner tlv");

  inner[n++] = 0x8f;
  inner[n++] = APP_INFO_INSTANCE_UID_LEN;
  memcpy(&inner[n], INSTANCE_UID, APP_INFO_INSTANCE_UID_LEN);
  n += APP_INFO_INSTANCE_UID_LEN;

  inner[n++] = 0x80;
  inner[n++] = 65;
  memcpy(&inner[n], sc_pub, 65);
  n += 65;

  inner[n++] = 0x02;
  inner[n++] = 2;
  inner[n++] = (uint8_t)(version >> 8);
  inner[n++] = (uint8_t)version;

  inner[n++] = 0x02;
  inner[n++] = 1;
  inner[n++] = 3; /* free pairing slots */

  inner[n++] = 0x8e;
  inner[n++] = key_uid_len;
  memset(&inner[n], 0x5a, key_uid_len);
  n += key_uid_len;

  inner[n++] = 0x8d;
  inner[n++] = 1;
  inner[n++] = 0x00;

  /* A template this long needs the two-octet form of the length, which is what a real applet
   * sends and what the reader accepts. */
  const size_t hdr = (n >= 0x80) ? 3 : 2;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)max, (unsigned)(n + hdr), "out");

  out[0] = 0xa4;
  if (hdr == 3) {
    out[1] = 0x81;
    out[2] = (uint8_t)n;
  } else {
    out[1] = (uint8_t)n;
  }
  memcpy(&out[hdr], inner, n);

  return n + hdr;
}

/* A card in the reader, answering the negotiation. keycard_activate switches it on itself, so the
 * test only queues what the activation reads rather than performing it. */
static void card_present(void) {
  hal_host_sc_reply_hex(SC_CARD_ATR);
  hal_host_sc_reply_hex(SC_CARD_IFS_ANSWER);
}

/* The prefix every test past this point needs: a card selected, paired for the first time, and a
 * channel opened against it. The model is left holding the session keys and the chain, and card_seq
 * has walked the six blocks the handshake costs. The key uid's length is what tells the shell whether
 * the card carries a key, so 0 asks for a card that needs one loaded. */
/* What a v4 applet answers SELECT with: its version, an initialised status, a key, the
 * capabilities and the device certificate. The certificate is what the shell tries to verify against
 * the embedded CA, and its first bytes are the device's own public key. */
static size_t app_info_v4(uint8_t* out, size_t max, uint16_t version, const uint8_t* cert) {
  uint8_t inner[192];
  size_t n = 0;

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(inner),
                                         (unsigned)(4 + 3 + 2 + APP_INFO_KEY_UID_LEN + 3 + 2 +
                                                    APP_INFO_CERT_SIZE),
                                         "inner tlv");

  inner[n++] = 0x02;
  inner[n++] = 2;
  inner[n++] = (uint8_t)(version >> 8);
  inner[n++] = (uint8_t)version;

  inner[n++] = 0x8c;
  inner[n++] = 1;
  inner[n++] = APP_STATUS_INITIALIZED;

  inner[n++] = 0x8e;
  inner[n++] = APP_INFO_KEY_UID_LEN;
  memset(&inner[n], 0x5a, APP_INFO_KEY_UID_LEN);
  n += APP_INFO_KEY_UID_LEN;

  inner[n++] = 0x8d;
  inner[n++] = 1;
  inner[n++] = 0x00;

  inner[n++] = 0x8a;
  inner[n++] = APP_INFO_CERT_SIZE;
  memcpy(&inner[n], cert, APP_INFO_CERT_SIZE);
  n += APP_INFO_CERT_SIZE;

  const size_t hdr = (n >= 0x80) ? 3 : 2;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)max, (unsigned)(n + hdr + 2), "out");

  size_t o = 0;
  out[o++] = 0xa4;
  if (hdr == 3) {
    out[o++] = 0x81;
  }
  out[o++] = (uint8_t)n;
  memcpy(&out[o], inner, n);
  o += n;

  out[o++] = 0x90;
  out[o++] = 0x00;
  return o;
}

static void card_paired_and_open(uint8_t key_uid_len) {
  card_present();

  /* Three draws go by before the channel is up: the identify challenge, the pairing challenge and
   * the ephemeral key of the handshake. One stream, taken in the order the module takes them. */
  hal_host_rng_seed(RNG_SEED);
  uint8_t scratch[SHA256_DIGEST_LENGTH];
  random_buffer(scratch, sizeof(scratch));

  uint8_t pairing_challenge[SHA256_DIGEST_LENGTH];
  random_buffer(pairing_challenge, sizeof(pairing_challenge));

  /* The card answers the pairing with a slot and a salt, and what both sides keep is SHA-256 over
   * the pairing secret and that salt. */
  uint8_t salt[SHA256_DIGEST_LENGTH];
  memset(salt, 0xab, sizeof(salt));
  uint8_t pairing_key[SHA256_DIGEST_LENGTH];
  v1_sha256_cat(KEYCARD_DEFAULT_PSK, SHA256_DIGEST_LENGTH, salt, sizeof(salt), pairing_key);

  v1_card_draws(&model, sc_pub, pairing_key);

  uint8_t info[180];
  const size_t info_len = app_info_v3(info, sizeof(info), 0x0302, key_uid_len);
  uint8_t select_answer[182];
  memcpy(select_answer, info, info_len);
  select_answer[info_len] = 0x90;
  select_answer[info_len + 1] = 0x00;
  card_says(select_answer, info_len + 2);

  /* IDENTIFY answered with something that is not a signed certificate, and the user, shown that the
   * card cannot prove itself, says to go on. */
  const uint8_t not_a_cert[] = {0xde, 0xad, 0xbe, 0xef, 0x90, 0x00};
  card_says(not_a_cert, sizeof(not_a_cert));
  host_ui_answer_call("ui_keycard_not_genuine", CORE_EVT_UI_OK);

  uint8_t pair_reply[2 * SHA256_DIGEST_LENGTH + 2];
  v1_sha256_cat(KEYCARD_DEFAULT_PSK, SHA256_DIGEST_LENGTH, pairing_challenge,
                sizeof(pairing_challenge), pair_reply);
  memset(&pair_reply[SHA256_DIGEST_LENGTH], 0xcd, SHA256_DIGEST_LENGTH);
  pair_reply[sizeof(pair_reply) - 2] = 0x90;
  pair_reply[sizeof(pair_reply) - 1] = 0x00;
  card_says(pair_reply, sizeof(pair_reply));

  uint8_t idx_reply[1 + SHA256_DIGEST_LENGTH + 2];
  idx_reply[0] = 3;
  memcpy(&idx_reply[1], salt, sizeof(salt));
  idx_reply[sizeof(idx_reply) - 2] = 0x90;
  idx_reply[sizeof(idx_reply) - 1] = 0x00;
  card_says(idx_reply, sizeof(idx_reply));

  const unsigned open_seq = card_seq;
  v1_card_queue_open(&model, open_seq);
  card_seq += 2;
}

static uint8_t sealed_want[256];
static size_t sealed_want_len;

/* One sealed command, answered the way a card holding the same chain answers it: the model predicts
 * the block the shell will send and encrypts the reply under that command's own MAC, which moves the
 * chain on both sides. want and want_len are where the model wrote its prediction of the request,
 * for a test that asserts the wire. */
static void card_answer_sealed(uint8_t ins, uint8_t p1, const uint8_t* cmd, size_t cmd_len,
                               const uint8_t* reply_plain, size_t reply_plain_len) {
  uint8_t reply_iv[AES_BLOCK_SIZE];
  v1_card_expect_command(&model, ins, p1, 0, cmd, cmd_len, sealed_want, &sealed_want_len, reply_iv);

  uint8_t reply[256];
  const size_t len = v1_card_reply(&model, reply_iv, reply_plain, reply_plain_len, reply);
  card_says(reply, len);
}

/* A command the card accepts with nothing to say. */
/* A command the card accepts with nothing to say. Every command the activation sends takes P2 0, and
 * P1 where the command says so -- it is inside the MAC, so it has to be predicted. */
static void card_says_ok(uint8_t ins, uint8_t p1, const uint8_t* cmd, size_t cmd_len) {
  const uint8_t accepted[2] = {0x90, 0x00};
  card_answer_sealed(ins, p1, cmd, cmd_len, accepted, sizeof(accepted));
}

/* The card's name, which is the first thing read once the channel is open. */
static void card_says_name(void) {
  static const char name[] = "card";
  uint8_t plain[32];
  plain[0] = (uint8_t)(0x20 | (sizeof(name) - 1));
  memcpy(&plain[1], name, sizeof(name) - 1);
  plain[sizeof(name)] = 0x90;
  plain[sizeof(name) + 1] = 0x00;

  card_answer_sealed(0xca, 0, NULL, 0, plain, sizeof(name) + 2);
}

/* The application status: how many PIN and PUK retries the card has left, and a key present. */
static void card_says_retries(uint8_t pin_retries, uint8_t puk_retries) {
  uint8_t plain[32];
  plain[0] = 0xa3;
  plain[1] = 0x09;
  plain[2] = 0x02;
  plain[3] = 0x01;
  plain[4] = pin_retries;
  plain[5] = 0x02;
  plain[6] = 0x01;
  plain[7] = puk_retries;
  plain[8] = 0x01;
  plain[9] = 0x01;
  plain[10] = 0x01;
  plain[11] = 0x90;
  plain[12] = 0x00;

  card_answer_sealed(0xf2, 0, NULL, 0, plain, 13);
}

/* Not every card on the contacts is a Keycard, and the answer to that is a screen and no more
 * exchanges -- the shell does not go on pairing with whatever answered. */
void test_a_card_that_is_not_keycard_is_said_so(void) {
  card_present();
  card_says_status(0x6a82);

  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_wrong_card"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_keycard_ready"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));

  /* One block, the SELECT, and the reader switched off afterwards. */
  uint8_t want[32];
  const size_t want_len = test_unhex(SELECT_APDU, want, sizeof(want));

  uint8_t apdu[64];
  TEST_ASSERT_EQUAL_UINT((unsigned)want_len, sc_card_apdu(0, apdu, sizeof(apdu)));
  TEST_ASSERT_EQUAL_MEMORY(want, apdu, want_len);
  TEST_ASSERT_NOT_EQUAL(SC_READY, kc.sc.state);
}

/* An application info that does not parse is the same refusal: the card is not the one the shell
 * expected, whatever it said. */
void test_an_application_info_that_cannot_be_read_is_said_so(void) {
  card_present();

  const uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef, 0x90, 0x00};
  card_says(garbage, sizeof(garbage));

  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_wrong_card"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));
  sc_card_assert_no_apdu(1);
}

/* A card older than the shell's minimum is refused on the version, before any pairing is written:
 * an old applet would be given a channel it cannot speak. */
void test_a_card_older_than_the_shell_is_said_so(void) {
  card_present();

  uint8_t info[160];
  const size_t len = app_info_v3(info, sizeof(info), 0x0300, APP_INFO_KEY_UID_LEN);
  uint8_t answer[180];
  memcpy(answer, info, len);
  answer[len] = 0x90;
  answer[len + 1] = 0x00;
  card_says(answer, len + 2);

  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_ready"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_old_card"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_keycard_already_paired"));
  sc_card_assert_no_apdu(1);

  /* The pairing store is untouched, which is what makes this refusal cheap. */
  pairing_t pairing;
  memset(&pairing, 0, sizeof(pairing));
  memcpy(pairing.instance_uid, INSTANCE_UID, APP_INFO_INSTANCE_UID_LEN);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, pairing_read(&pairing));
}

/* The pairing this activation just agreed to, refused by the card that agreed to it: another pass
 * means pairing from scratch and offering the same agreement again, which is not a thing that can
 * mend a refusal. The card is told so, and the pass is not repeated -- while a *stale* pairing still
 * gets its re-pair, which is how a card reset or paired elsewhere comes back. */
void test_a_channel_refused_on_a_fresh_pairing_is_not_asked_again(void) {
  card_present();

  /* The two draws the pass makes before the channel: the identify challenge and the pairing
   * challenge, both of which the card's answers have to be computed over. */
  hal_host_rng_seed(RNG_SEED);
  uint8_t identify_challenge[SHA256_DIGEST_LENGTH];
  random_buffer(identify_challenge, sizeof(identify_challenge));
  (void)identify_challenge;

  uint8_t pairing_challenge[SHA256_DIGEST_LENGTH];
  random_buffer(pairing_challenge, sizeof(pairing_challenge));

  uint8_t info[180];
  const size_t info_len = app_info_v3(info, sizeof(info), 0x0302, APP_INFO_KEY_UID_LEN);
  uint8_t select_answer[182];
  memcpy(select_answer, info, info_len);
  select_answer[info_len] = 0x90;
  select_answer[info_len + 1] = 0x00;
  card_says(select_answer, info_len + 2);

  /* IDENTIFY answered with something that is not a signed certificate, and the user, shown that the
   * card cannot prove itself, says to go on. */
  const uint8_t not_a_cert[] = {0xde, 0xad, 0xbe, 0xef, 0x90, 0x00};
  card_says(not_a_cert, sizeof(not_a_cert));
  host_ui_answer_call("ui_keycard_not_genuine", CORE_EVT_UI_OK);

  /* The pairing handshake, completed by a card that holds the default pairing secret. */
  uint8_t card_challenge[SHA256_DIGEST_LENGTH];
  memset(card_challenge, 0xcd, sizeof(card_challenge));
  uint8_t pair_reply[2 * SHA256_DIGEST_LENGTH + 2];
  v1_sha256_cat(KEYCARD_DEFAULT_PSK, SHA256_DIGEST_LENGTH, pairing_challenge,
             sizeof(pairing_challenge), pair_reply);
  memcpy(&pair_reply[SHA256_DIGEST_LENGTH], card_challenge, sizeof(card_challenge));
  pair_reply[sizeof(pair_reply) - 2] = 0x90;
  pair_reply[sizeof(pair_reply) - 1] = 0x00;
  card_says(pair_reply, sizeof(pair_reply));

  uint8_t salt[SHA256_DIGEST_LENGTH];
  memset(salt, 0xab, sizeof(salt));
  uint8_t idx_reply[1 + SHA256_DIGEST_LENGTH + 2];
  idx_reply[0] = 3;
  memcpy(&idx_reply[1], salt, sizeof(salt));
  idx_reply[sizeof(idx_reply) - 2] = 0x90;
  idx_reply[sizeof(idx_reply) - 1] = 0x00;
  card_says(idx_reply, sizeof(idx_reply));

  /* The channel: the card answers the key exchange, then cannot MAC its own reply. */
  uint8_t open_answer[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memset(open_answer, 0xc0, sizeof(open_answer) - 2);
  open_answer[sizeof(open_answer) - 2] = 0x90;
  open_answer[sizeof(open_answer) - 1] = 0x00;
  card_says(open_answer, sizeof(open_answer));
  card_says_status(0x9000); /* no MAC in it, so the shell will not open it */

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_paired"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_secure_channel_failed"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));

  /* Six commands -- SELECT, IDENTIFY, PAIR twice, the key exchange and its mutual half -- and no
   * second pass: the seventh is what a retry would have put on the wire. */
  sc_card_assert_no_apdu(6);

  /* The pairing that was refused is not left in the store for the next activation to trip over. */
  pairing_t leftover;
  memset(&leftover, 0, sizeof(leftover));
  memcpy(leftover.instance_uid, INSTANCE_UID, APP_INFO_INSTANCE_UID_LEN);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, pairing_read(&leftover));
}

/* A pairing from an earlier life of the card -- it was reset, or paired by another reader -- is worth
 * replacing, so this one does get its second pass. It is the pairing agreed to in the pass itself
 * that is not, and the test above is that one. */
void test_a_stale_pairing_is_erased_and_the_card_asked_again(void) {
  card_present();

  /* A pairing in the store, for this card. */
  pairing_t stored;
  memset(&stored, 0, sizeof(stored));
  memcpy(stored.instance_uid, INSTANCE_UID, APP_INFO_INSTANCE_UID_LEN);
  stored.idx = 3;
  memset(stored.key, 0x11, sizeof(stored.key));
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&stored));

  uint8_t info[180];
  const size_t info_len = app_info_v3(info, sizeof(info), 0x0302, APP_INFO_KEY_UID_LEN);
  uint8_t select_answer[182];
  memcpy(select_answer, info, info_len);
  select_answer[info_len] = 0x90;
  select_answer[info_len + 1] = 0x00;
  card_says(select_answer, info_len + 2);

  /* The channel the stored pairing opens is refused. Nothing here depends on what the shell drew,
   * since the mutual half is answered with a block that carries no MAC. */
  uint8_t open_answer[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memset(open_answer, 0xc0, sizeof(open_answer) - 2);
  open_answer[sizeof(open_answer) - 2] = 0x90;
  open_answer[sizeof(open_answer) - 1] = 0x00;
  card_says(open_answer, sizeof(open_answer));
  card_says_status(0x9000);

  /* The second pass, which is what the stale pairing bought. Answered with a card that is not a
   * Keycard, so the pass ends there rather than needing a pairing dialogue scripted out. */
  const uint8_t wrong_card[] = {0x6a, 0x82};
  card_says(wrong_card, sizeof(wrong_card));

  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_already_paired"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_secure_channel_failed"));

  /* The screen a card that is not a Keycard gets, which is the proof that a second pass ran -- and
   * that the loop stopped on its own, since this failure is not one that asks to be retried. */
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_wrong_card"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));

  /* SELECT, the key exchange and its mutual half, then the SELECT of the pass the stale pairing
   * bought -- four blocks, and no fifth. */
  sc_card_assert_no_apdu(4);

  /* And the pairing that was refused is gone from the store, which is what makes the second pass a
   * re-pair rather than the same attempt again. */
  pairing_t leftover;
  memset(&leftover, 0, sizeof(leftover));
  memcpy(leftover.instance_uid, INSTANCE_UID, APP_INFO_INSTANCE_UID_LEN);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, pairing_read(&leftover));
}

/* The path a card actually takes: paired for the first time, its channel opened, its name read, its
 * PIN verified. Everything past the handshake is sealed, so this is the end-to-end agreement between
 * the shell and a card holding the key the pairing just produced -- and that a card which works is
 * left open, with no failure on the screen. */
void test_a_card_is_paired_opened_and_unlocked(void) {
  card_paired_and_open(APP_INFO_KEY_UID_LEN);

  card_says_name();
  card_says_retries(3, 16);

  static const uint8_t PIN[KEYCARD_PIN_LEN] = {'1', '2', '3', '4', '5', '6'};
  host_ui_script_pin(PIN);
  host_ui_answer_call("ui_read_pin", CORE_EVT_UI_OK);

  card_says_ok(0x20, 0, PIN, sizeof(PIN));

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_paired"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_secure_channel_ok"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_pin_ok"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_keycard_wrong_pin"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_card_transport_error"));

  /* The channel is left open and the card is what the shell read it to be, which is only true if
   * every sealed reply opened under the keys the model holds. */
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);
  TEST_ASSERT_EQUAL_STRING("card", kc.name);
  TEST_ASSERT_EQUAL_UINT(0x0302, (unsigned)kc.app_version);

  /* Nine blocks and no tenth: SELECT, IDENTIFY, PAIR twice, the key exchange and its mutual half,
   * GET DATA, GET STATUS and VERIFY. */
  sc_card_assert_no_apdu(9);

  /* The PIN went out sealed: the model's prediction is what left, with no PIN anywhere in it. */
  uint8_t apdu[256];
  const size_t len = sc_card_apdu(8, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5u + sealed_want_len + 1u, (unsigned)len);
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0x20, apdu[1]);
  TEST_ASSERT_EQUAL_MEMORY(sealed_want, apdu + 5, sealed_want_len);
  TEST_ASSERT_NULL(memmem(apdu, len, PIN, sizeof(PIN)));
}

/* A wrong PIN is an answer, not a broken session. The card seals its 63cx back, the retry count the
 * card chose is the one shown, and the next PIN goes out under the same chain -- which is what has to
 * be true for the ordinary way of getting it wrong, three attempts, to work at all. */
void test_a_wrong_pin_leaves_the_channel_open_for_the_next_one(void) {
  card_paired_and_open(APP_INFO_KEY_UID_LEN);

  card_says_name();
  card_says_retries(3, 16);

  static const uint8_t PIN[KEYCARD_PIN_LEN] = {'1', '2', '3', '4', '5', '6'};
  host_ui_script_pin(PIN);
  host_ui_answer_call("ui_read_pin", CORE_EVT_UI_OK);

  const uint8_t two_left[2] = {0x63, 0xc2};
  card_answer_sealed(0x20, 0, PIN, sizeof(PIN), two_left, sizeof(two_left));

  uint8_t first[256];
  const size_t first_len = sealed_want_len;
  memcpy(first, sealed_want, first_len);

  card_says_ok(0x20, 0, PIN, sizeof(PIN));

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_wrong_pin"));
  TEST_ASSERT_EQUAL_UINT8(2, host_ui_wrong_pin_retries());
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_pin_ok"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_card_transport_error"));

  /* The session outlived the refusal, and the pass ended with the PIN accepted. */
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);
  sc_card_assert_no_apdu(10);

  /* Two VERIFY commands with the same PIN, sharing nothing but the header -- because the chain moved
   * -- and neither showing the PIN. */
  uint8_t apdu[256];
  const size_t len1 = sc_card_apdu(8, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_MEMORY(first, apdu + 5, first_len);
  TEST_ASSERT_NULL(memmem(apdu, len1, PIN, sizeof(PIN)));

  const size_t len2 = sc_card_apdu(9, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_MEMORY(sealed_want, apdu + 5, sealed_want_len);
  TEST_ASSERT_NULL(memmem(apdu, len2, PIN, sizeof(PIN)));

  TEST_ASSERT_TRUE_MESSAGE(
      memcmp(apdu + 5 + AES_BLOCK_SIZE, first + AES_BLOCK_SIZE, first_len - AES_BLOCK_SIZE) != 0,
      "two VERIFY commands sealed identically");
}

/* A PIN with no retries left is unblocked with the PUK and a new PIN, both typed. One command
 * carries them, in that order, sealed; the card's 9000 ends the pass with the channel open. */
void test_the_puk_unblocks_a_pin_with_no_retries_left(void) {
  card_paired_and_open(APP_INFO_KEY_UID_LEN);

  card_says_name();
  card_says_retries(0, 3);

  static const uint8_t PIN[KEYCARD_PIN_LEN] = {'7', '7', '7', '7', '7', '7'};
  static const uint8_t PUK[KEYCARD_PUK_LEN] = {'9', '8', '7', '6', '5', '4',
                                               '3', '2', '1', '0', '1', '2'};
  host_ui_script_pin(PIN);
  host_ui_script_puk(PUK);
  host_ui_answer_call("ui_prompt_try_puk", CORE_EVT_UI_OK);
  host_ui_answer_call("ui_read_pin", CORE_EVT_UI_OK);
  host_ui_answer_call("ui_read_puk", CORE_EVT_UI_OK);

  uint8_t both[KEYCARD_PUK_LEN + KEYCARD_PIN_LEN];
  memcpy(both, PUK, sizeof(PUK));
  memcpy(&both[sizeof(PUK)], PIN, sizeof(PIN));
  card_says_ok(0x22, 0, both, sizeof(both));

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_prompt_try_puk"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_read_puk"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_puk_ok"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_keycard_wrong_pin"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_card_transport_error"));
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);
  sc_card_assert_no_apdu(9);

  /* The unblock is the eighth block, and it carries neither secret in the clear -- which is the whole
   * point of it being a sealed command rather than a bare one. */
  uint8_t apdu[256];
  const size_t len = sc_card_apdu(8, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0x22, apdu[1]);
  TEST_ASSERT_EQUAL_MEMORY(sealed_want, apdu + 5, sealed_want_len);
  TEST_ASSERT_NULL(memmem(apdu, len, PIN, sizeof(PIN)));
  TEST_ASSERT_NULL(memmem(apdu, len, PUK, sizeof(PUK)));
}

/* Declining the PUK leaves a factory reset as the only way back, and the card is then asked to be set
 * up again from the top. The reset goes out unsealed, with no session to protect it, which is why the
 * block is asserted as bytes rather than through the model. */
void test_declining_the_puk_resets_the_card_and_starts_over(void) {
  card_paired_and_open(APP_INFO_KEY_UID_LEN);

  card_says_name();
  card_says_retries(0, 3);

  host_ui_answer_call("ui_prompt_try_puk", CORE_EVT_UI_CANCELLED);
  host_ui_answer_call("ui_confirm_factory_reset", CORE_EVT_UI_OK);

  card_says_status(0x9000); /* the factory reset, in the clear */

  /* The second pass the reset bought, ended by a card that is not a Keycard -- answering it
   * properly would mean scripting a whole setup again, and the point here is only that the pass
   * started. */
  const uint8_t wrong_card[] = {0x6a, 0x82};
  card_says(wrong_card, sizeof(wrong_card));

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  /* The channel was open and the PUK was offered first, so the reset that follows is the refusal's
   * and not some earlier failure's. */
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_secure_channel_ok"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_prompt_try_puk"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_read_puk"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_confirm_factory_reset"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_wrong_card"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));

  /* The eighth block is the reset -- 80 fd aa 55, unsealed -- the ninth is the second SELECT, and
   * nothing comes after it. */
  uint8_t apdu[256];
  sc_card_apdu(8, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0xfd, apdu[1]);
  TEST_ASSERT_EQUAL_UINT8(0xaa, apdu[2]);
  TEST_ASSERT_EQUAL_UINT8(0x55, apdu[3]);

  sc_card_apdu(9, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT8(0xa4, apdu[1]);
  sc_card_assert_no_apdu(10);
}

/* A card that is initialised but carries no key is given one: the user chooses a generated mnemonic,
 * the card produces the entropy, and the seed derived from it goes back sealed -- the same seed the
 * test derives from the entropy the card handed out, which is what makes the assertion worth making. */
void test_a_card_with_no_keys_is_given_one(void) {
  card_paired_and_open(0);

  host_ui_script_mnemonic(MENU_MNEMO_GENERATE, 12, false);
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  host_ui_answer_call("ui_backup_mnemonic", CORE_EVT_UI_OK);

  card_says_name();
  card_says_retries(3, 16);

  static const uint8_t PIN[KEYCARD_PIN_LEN] = {'1', '2', '3', '4', '5', '6'};
  host_ui_script_pin(PIN);
  host_ui_answer_call("ui_read_pin", CORE_EVT_UI_OK);
  card_says_ok(0x20, 0, PIN, sizeof(PIN));

  /* Two bytes per word, big endian, and each index inside the wordlist -- the shell reads the
   * entropy straight into its index array. */
  uint8_t entropy[24];
  for (size_t i = 0; i < 12; i++) {
    entropy[2 * i] = (uint8_t)(i % 8);
    entropy[2 * i + 1] = (uint8_t)(i * 7);
  }
  uint8_t generated[2 + sizeof(entropy)];
  memcpy(generated, entropy, sizeof(entropy));
  generated[sizeof(generated) - 2] = 0x90;
  generated[sizeof(generated) - 1] = 0x00;
  card_answer_sealed(0xd2, 4, NULL, 0, generated, sizeof(generated));

  /* The seed follows: PBKDF2 over the twelve words those indexes spell, with no passphrase. */
  uint16_t indexes[BIP39_MAX_MNEMONIC_LEN];
  for (size_t i = 0; i < 12; i++) {
    indexes[i] = (uint16_t)((entropy[2 * i] << 8) | entropy[2 * i + 1]);
  }
  uint8_t seed[64];
  mnemonic_indexes_to_seed(indexes, 12, "", seed);
  card_says_ok(0xd0, 3, seed, sizeof(seed));

  hal_host_rng_seed(RNG_SEED);
  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_no_keys"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_seed_loaded"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_card_transport_error"));
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);

  /* SELECT, IDENTIFY, PAIR twice, the handshake, GET DATA, GET STATUS, VERIFY, GENERATE MNEMONIC and
   * LOAD SEED -- eleven blocks, and the last of them the one that matters. */
  sc_card_assert_no_apdu(11);

  uint8_t apdu[256];
  const size_t len = sc_card_apdu(10, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0xd0, apdu[1]);
  TEST_ASSERT_EQUAL_UINT8(3, apdu[2]); /* P1 3 is a seed; P1 2 would be a generated key template */
  TEST_ASSERT_EQUAL_UINT(5u + sealed_want_len + 1u, (unsigned)len);
  TEST_ASSERT_EQUAL_MEMORY(sealed_want, apdu + 5, sealed_want_len);

  /* The seed itself is nowhere in the block: 64 bytes padded and encrypted under the session key. */
  TEST_ASSERT_EQUAL_UINT8(96, apdu[4]);
  TEST_ASSERT_NULL(memmem(apdu, len, seed, sizeof(seed)));
  TEST_ASSERT_NULL(memmem(apdu, len, entropy, sizeof(entropy)));
}

/* A v4 card whose certificate the shell cannot check against the embedded CA is refused unless the
 * user says to trust it -- and trusting it is durable: the device public key goes on the whitelist,
 * so the same card is not asked about again. The channel it opens is another matter, and this card
 * gets no further than the refusal. */
void test_a_v4_card_accepted_despite_its_certificate_is_whitelisted(void) {
  card_present();

  /* Not a certificate the embedded CA signed, and not a public key either -- the point is only that
   * verification fails and the user is asked. */
  uint8_t cert[APP_INFO_CERT_SIZE];
  memset(cert, 0xa1, sizeof(cert));

  uint8_t answer[192];
  const size_t len = app_info_v4(answer, sizeof(answer), 0x0400, cert);
  card_says(answer, len);

  host_ui_answer_call("ui_keycard_not_genuine", CORE_EVT_UI_OK);

  /* The v2 channel open, which this card does not answer properly. */
  card_says_status(0x6a81);

  keycard_activate(&kc);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_keycard_not_genuine"));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_card_transport_error"));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  TEST_ASSERT_EQUAL_UINT(0x0400, (unsigned)kc.app_version);

  /* Two blocks: the SELECT and the open the card refused. Nothing is retried on a v4 card, since
   * there is no pairing to redo. */
  sc_card_assert_no_apdu(2);

  /* The durable part: from now on the shell believes this device key, so the next activation of the
   * same card will not ask. */
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(cert));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_card_that_is_not_keycard_is_said_so);
  RUN_TEST(test_an_application_info_that_cannot_be_read_is_said_so);
  RUN_TEST(test_a_card_older_than_the_shell_is_said_so);
  RUN_TEST(test_a_channel_refused_on_a_fresh_pairing_is_not_asked_again);
  RUN_TEST(test_a_stale_pairing_is_erased_and_the_card_asked_again);
  RUN_TEST(test_a_card_is_paired_opened_and_unlocked);
  RUN_TEST(test_a_wrong_pin_leaves_the_channel_open_for_the_next_one);
  RUN_TEST(test_the_puk_unblocks_a_pin_with_no_retries_left);
  RUN_TEST(test_declining_the_puk_resets_the_card_and_starts_over);
  RUN_TEST(test_a_card_with_no_keys_is_given_one);
  RUN_TEST(test_a_v4_card_accepted_despite_its_certificate_is_whitelisted);

  return UNITY_END();
}
