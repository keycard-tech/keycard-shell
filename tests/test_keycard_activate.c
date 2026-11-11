#include <string.h>

#include "crypto/ecdsa.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/keycard.h"
#include "keycard/pairing.h"
#include "keycard/secure_channel_v1.h"
#include "sc_card.h"
#include "sc_host.h"
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

/* SHA256 over two buffers run together, which is what the card's pairing cryptograms are. */
static void sha256_cat(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen, uint8_t out[32]) {
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  sha256_Update(&ctx, a, alen);
  sha256_Update(&ctx, b, blen);
  sha256_Final(&ctx, out);
}
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
  sha256_cat(KEYCARD_DEFAULT_PSK, SHA256_DIGEST_LENGTH, pairing_challenge,
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

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_card_that_is_not_keycard_is_said_so);
  RUN_TEST(test_an_application_info_that_cannot_be_read_is_said_so);
  RUN_TEST(test_a_card_older_than_the_shell_is_said_so);
  RUN_TEST(test_a_channel_refused_on_a_fresh_pairing_is_not_asked_again);
  RUN_TEST(test_a_stale_pairing_is_erased_and_the_card_asked_again);

  return UNITY_END();
}
