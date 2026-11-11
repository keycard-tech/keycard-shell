#include <stdint.h>
#include <string.h>

#include "crypto/aes.h"
#include "crypto/ecdsa.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/keycard.h"
#include "keycard/pairing.h"
#include "keycard/secure_channel.h"
#include "keycard/secure_channel_v1.h"
#include "sc_card.h"
#include "sc_host.h"
#include "sc_v1_card.h"
#include "unity.h"

/*
 * secure_channel_v1.c is the pairing-key channel: ECDH with the applet's secure-element key, a
 * SHA-512 over that secret, the stored pairing key and a card nonce, and then every command sealed
 * with AES-256-CBC under a MAC chain that both sides carry forward. It is asserted against a second
 * implementation of the same schedule written here, so what is checked is that the bytes the shell
 * puts on the wire are the bytes a paired card can produce and verify -- and that a card which
 * cannot MAC a reply gets nothing further.
 *
 * The handshake is reproducible because the shell's ephemeral key and its mutual-authenticate
 * challenge come from the seeded RNG: drawn once here to build the card's answers, then drawn again
 * by the module from the same seed.
 */

#define RNG_SEED 0x5eedULL

/* The applet's secure-element key, whose public half is what open() is handed. */
static const uint8_t SC_PRIV[32] = {0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91,
                                    0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12,
                                    0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92,
                                    0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13};

static const uint8_t PAIRING_KEY[SHA256_DIGEST_LENGTH] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                                          0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                                                          0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                                                          0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};

#define PAIRING_IDX 7

static keycard_t kc;
static uint8_t sc_pub[65];

/* The card, as a second implementation of the schedule computes it. */
static v1_card_t model;
static v1_card_t* const s = &model;

/* The handshake's two draws, taken from the seed the module is then re-seeded with. */
static void handshake_draws(v1_card_t* c) {
  hal_host_rng_seed(RNG_SEED);
  v1_card_draws(c, sc_pub, PAIRING_KEY);
}

void setUp(void) {
  hal_host_sc_reset();
  memset(&kc, 0, sizeof(kc));
  smartcard_init(&kc.sc);
  kc.ch.open = 0;
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, SC_PRIV, sc_pub));
}

void tearDown(void) {}

static app_err_t open_channel(v1_card_t* s) {
  pairing_t pairing;
  memset(&pairing, 0, sizeof(pairing));
  memcpy(pairing.key, PAIRING_KEY, sizeof(PAIRING_KEY));
  pairing.idx = PAIRING_IDX;

  sc_v1_open_t ctx = {.pairing = &pairing, .sc_pub = sc_pub};

  hal_host_rng_seed(RNG_SEED);
  return securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V1, &ctx);
}

/* Open both halves: the shell sends its public key under the pairing index, then its challenge
 * sealed and MACed; the card proves it holds the pairing key by MACing its reply. */
void test_open_seals_the_challenge_under_the_derived_session(void) {
  handshake_draws(s);

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0);

  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);

  uint8_t apdu[128];

  /* MUTUAL AUTHENTICATE's predecessor: 80 10 <idx> 00, the 65-byte key, Le. */
  size_t len = sc_card_apdu(0, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5 + 65 + 1, len);
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0x10, apdu[1]);
  TEST_ASSERT_EQUAL_UINT8(PAIRING_IDX, apdu[2]);
  TEST_ASSERT_EQUAL_UINT8(65, apdu[4]);
  TEST_ASSERT_EQUAL_MEMORY(s->client_pub, &apdu[5], 65);

  /* Then the challenge: Lc 64, the command MAC, and the ciphertext -- byte for byte what a card
   * holding the same keys computes. */
  len = sc_card_apdu(1, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5 + 64 + 1, len);
  TEST_ASSERT_EQUAL_UINT8(0x11, apdu[1]);
  TEST_ASSERT_EQUAL_UINT8(0, apdu[2]);
  TEST_ASSERT_EQUAL_UINT8(64, apdu[4]);
  TEST_ASSERT_EQUAL_MEMORY(s->cmd_mac, &apdu[5], AES_BLOCK_SIZE);
  TEST_ASSERT_EQUAL_MEMORY(s->cmd_ct, &apdu[5 + AES_BLOCK_SIZE], sizeof(s->cmd_ct));
}

/* A card that cannot MAC its reply is not opened: the session stays closed and the next command
 * never reaches the wire. */
void test_a_card_that_cannot_mac_its_reply_is_not_opened(void) {
  handshake_draws(s);

  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memcpy(first, s->card_nonce, sizeof(s->card_nonce));
  memcpy(&first[sizeof(s->card_nonce)], s->card_iv, sizeof(s->card_iv));
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;

  uint8_t plain[34];
  memset(plain, 0x5a, sizeof(plain) - 2);
  plain[32] = 0x90;
  plain[33] = 0x00;

  uint8_t second[64 + 2];
  const size_t len = v1_card_reply(s, s->cmd_mac, plain, sizeof(plain), second);
  second[3] ^= 0x01; /* the MAC the shell recomputes will not match */

  sc_card_activate(&kc.sc);
  sc_card_answer(first, sizeof(first), 0);
  sc_card_answer(second, len, 1);

  const app_err_t res = open_channel(s);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, res);
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);

  /* The keys were derived before the card proved the pairing key, so a refused handshake has to
   * take them with it. */
  const uint8_t zero[sizeof(kc.ch.v1)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, &kc.ch.v1, sizeof(kc.ch.v1));
}

/* Nothing is sealed, and nothing is sent, on a channel that was never opened: the wrapper is what
 * refuses, both versions alike. What a caller holds after a refused handshake is an APDU buffer and
 * zeroed keys, so the applet never sees a command under keys an unfinished exchange agreed. */
void test_a_command_on_a_channel_that_was_never_opened_never_reaches_the_wire(void) {
  handshake_draws(s);

  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memcpy(first, s->card_nonce, sizeof(s->card_nonce));
  memcpy(&first[sizeof(s->card_nonce)], s->card_iv, sizeof(s->card_iv));
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;

  sc_card_activate(&kc.sc);
  sc_card_answer(first, sizeof(first), 0);

  /* The card answers the key exchange and then says nothing more, so it cannot finish. */
  TEST_ASSERT_NOT_EQUAL(ERR_OK, open_channel(s));

  const size_t sent = hal_host_sc_sent_len();
  TEST_ASSERT_TRUE_MESSAGE(sent > 0, "the handshake never reached the card");

  SC_BUF(pin, 6);
  memset(pin, '1', 6);

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_send_apdu(&kc.sc, &kc.ch, &kc.apdu, pin, 6));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(sent, hal_host_sc_sent_len(), "a sealed command reached the wire");
}

/* The reply must be the 34 bytes a Keycard sends -- a cryptogram and its status word. A shorter or
 * longer plaintext means a card that is not answering this command, and the shell says so rather
 * than carrying on with a half-built session. */
void test_the_mutual_authenticate_answer_has_one_length(void) {
  handshake_draws(s);

  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memcpy(first, s->card_nonce, sizeof(s->card_nonce));
  memcpy(&first[sizeof(s->card_nonce)], s->card_iv, sizeof(s->card_iv));
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;

  /* A cryptogram short by two bytes but ending in a status word, so the inner check passes and the
   * length is what fails: the shell expects 32 bytes of cryptogram plus that status word. */
  uint8_t plain[30];
  memset(plain, 0x5a, sizeof(plain) - 2);
  plain[sizeof(plain) - 2] = 0x90;
  plain[sizeof(plain) - 1] = 0x00;

  uint8_t second[64 + 2];
  const size_t len = v1_card_reply(s, s->cmd_mac, plain, sizeof(plain), second);

  sc_card_activate(&kc.sc);
  sc_card_answer(first, sizeof(first), 0);
  sc_card_answer(second, len, 1);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, open_channel(s));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
}

/* Less than a nonce and an iv in the first answer is refused before any key is derived. */
void test_a_short_card_nonce_refuses_the_session(void) {
  sc_card_activate(&kc.sc);

  uint8_t short_answer[SHA256_DIGEST_LENGTH + 2];
  memset(short_answer, 0xc0, sizeof(short_answer) - 2);
  short_answer[sizeof(short_answer) - 2] = 0x90;
  short_answer[sizeof(short_answer) - 1] = 0x00;
  sc_card_answer(short_answer, sizeof(short_answer), 0);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, open_channel(s));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(5u + 65u + 1u + 4u, (unsigned)hal_host_sc_sent_len(),
                                 "one block, nothing after");
}

/* The applet's public key comes out of the card's own answer to SELECT, so it is attacker-writable
 * in a way the pairing key is not: a point that is not on the curve must not produce a secret. */
void test_an_off_curve_secure_element_key_is_refused(void) {
  handshake_draws(s);

  uint8_t bogus[65];
  memset(bogus, 0, sizeof(bogus));
  bogus[0] = 0x04;
  memset(&bogus[1], 0xff, 64);

  memcpy(sc_pub, bogus, sizeof(bogus));

  sc_card_activate(&kc.sc);
  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memset(first, 0xc0, sizeof(first) - 2);
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;
  sc_card_answer(first, sizeof(first), 0);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, open_channel(s));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  TEST_ASSERT_EQUAL_UINT(5u + 65u + 1u + 4u, (unsigned)hal_host_sc_sent_len());
}

/* 6982 is the applet refusing on security grounds; the channel does not continue to decrypt. */
void test_the_card_refusing_the_security_condition_ends_open(void) {
  handshake_draws(s);

  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memcpy(first, s->card_nonce, sizeof(s->card_nonce));
  memcpy(&first[sizeof(s->card_nonce)], s->card_iv, sizeof(s->card_iv));
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;

  sc_card_activate(&kc.sc);
  sc_card_answer(first, sizeof(first), 0);
  sc_card_status(0x6982, 1);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, open_channel(s));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
}

/* Every command moves the chain: the iv of the next one is the MAC of the reply that came back, so
 * two identical commands cannot look alike -- and both are still predicted exactly by the card. */
void test_the_chain_moves_with_every_command(void) {
  handshake_draws(s);
  /* SC_BUF, not pin[6], and the length passed is 6 rather than sizeof(pin): protect_apdu pads the
   * caller's buffer in place, which is what the macro's extra SC_PAD bytes are for. */

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0); /* leaves the shell chained to the MAC of the card's reply */
  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));

  SC_BUF(pin, 6);
  memset(pin, '1', 6);

  uint8_t reply_plain[30];
  memset(reply_plain, 0x03, sizeof(reply_plain) - 2);
  reply_plain[sizeof(reply_plain) - 2] = 0x90;
  reply_plain[sizeof(reply_plain) - 1] = 0x00;

  uint8_t want[64];
  size_t want_len = 0;
  uint8_t next_iv[16];
  uint8_t reply[66];
  uint8_t apdu[128];

  v1_card_expect_command(s, 0x20, 0, 0, pin, 6, want, &want_len, next_iv);
  const size_t reply_len = v1_card_reply(s, next_iv, reply_plain, sizeof(reply_plain), reply);

  hal_host_sc_sent_clear();
  sc_card_answer(reply, reply_len, 0); /* the card's third I-block: N(S) is back to 0 */

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_send_apdu(&kc.sc, &kc.ch, &kc.apdu, pin, 6));

  const size_t len1 = sc_card_apdu(0, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5u + want_len + 1u, len1);
  TEST_ASSERT_EQUAL_UINT8(0x20, apdu[4]);
  TEST_ASSERT_EQUAL_MEMORY(want, apdu + 5, want_len);

  uint8_t first_ct[64];
  memcpy(first_ct, apdu + 5 + AES_BLOCK_SIZE, want_len - AES_BLOCK_SIZE);

  /* The same PIN again. The shell's own iv has moved, so what leaves is different -- and the card
   * knows why, because it moved the same way. */
  v1_card_expect_command(s, 0x20, 0, 0, pin, 6, want, &want_len, next_iv);
  const size_t reply2_len = v1_card_reply(s, next_iv, reply_plain, sizeof(reply_plain), reply);

  hal_host_sc_sent_clear();
  sc_card_answer(reply, reply2_len, 1);

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_v1_send_apdu(&kc.sc, &kc.ch.v1, &kc.apdu, pin, 6));

  const size_t len2 = sc_card_apdu(0, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5u + want_len + 1u, len2);
  TEST_ASSERT_EQUAL_MEMORY(want, apdu + 5, want_len);

  TEST_ASSERT_TRUE_MESSAGE(
      memcmp(first_ct, apdu + 5 + AES_BLOCK_SIZE, want_len - AES_BLOCK_SIZE) != 0,
      "two VERIFY commands of one PIN sealed identically");
}

/* A reply whose MAC the shell cannot reproduce is the end of the session, not a hiccup: v1 keeps no
 * nonce a later command could re-synchronise with, so the chain, the keys and the open flag go
 * together. */
void test_a_reply_that_does_not_mac_ends_the_session(void) {
  handshake_draws(s);

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));

  uint8_t reply[64 + 2];
  uint8_t plain[30];
  memset(plain, 0x03, sizeof(plain) - 2);
  plain[sizeof(plain) - 2] = 0x90;
  plain[sizeof(plain) - 1] = 0x00;
  const size_t reply_len = v1_card_reply(s, s->iv, plain, sizeof(plain), reply);
  reply[3] ^= 0x01; /* the MAC, not the ciphertext */

  hal_host_sc_sent_clear();
  sc_card_answer(reply, reply_len, 0);

  SC_BUF(pin, 6);
  memset(pin, '1', 6);

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_send_apdu(&kc.sc, &kc.ch, &kc.apdu, pin, 6));

  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  const uint8_t zero[sizeof(kc.ch.v1)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, &kc.ch.v1, sizeof(kc.ch.v1));

  const size_t sent = hal_host_sc_sent_len();
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_send_apdu(&kc.sc, &kc.ch, &kc.apdu, pin, 6));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(sent, hal_host_sc_sent_len(), "a command went out on a dead session");
}


/* A reply that MACs honestly but carries no ISO-9797-1 marker in its plaintext leaves the shell with a
 * plaintext length of nothing -- a card needs no forgery to arrange that, only a payload with no 0x80
 * in it. A status word lives inside every seal, so nothing is not a reply, and reading one reads
 * before the response buffer. */
void test_a_reply_with_no_padding_marker_is_refused_not_read(void) {
  handshake_draws(s);

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));

  uint8_t blank[16] = {0};
  uint8_t reply[sizeof(blank) + AES_BLOCK_SIZE + 2];
  const size_t reply_len = v1_card_reply_unpadded(s, s->iv, blank, sizeof(blank), reply);

  hal_host_sc_sent_clear();
  sc_card_answer(reply, reply_len, 0);

  SC_BUF(pin, 6);
  memset(pin, '1', 6);

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_send_apdu(&kc.sc, &kc.ch, &kc.apdu, pin, 6));

  /* Ended the way any failed seal ends it: the chain was never the problem, but the session is. */
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  const uint8_t zero[sizeof(kc.ch.v1)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, &kc.ch.v1, sizeof(kc.ch.v1));
}

/* What protect_apdu does to the caller's buffer: the plaintext is wiped as part of sealing it, so a
 * PIN does not survive in the caller's stack frame. */
void test_the_plaintext_is_wiped_as_it_is_sealed(void) {
  handshake_draws(s);

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));

  SC_BUF(pin, 6);
  memset(pin, '1', 6);

  uint8_t reply[64 + 2];
  uint8_t plain[30];
  memset(plain, 0x03, sizeof(plain));
  plain[sizeof(plain) - 2] = 0x90;
  plain[sizeof(plain) - 1] = 0x00;
  const size_t reply_len = v1_card_reply(s, s->iv, plain, sizeof(plain), reply);
  sc_card_answer(reply, reply_len, 0);

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_v1_send_apdu(&kc.sc, &kc.ch.v1, &kc.apdu, pin, 6));

  const uint8_t zero[6] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, pin, sizeof(zero));
}

/* The pairing command (0xFE) is what a setup sends: the card's PIN, PUK and pairing secret, wrapped
 * under a fresh ECDH secret with the shell's new public key and an iv in front of them. A tap of
 * the contacts must not show those bytes, and the applet must be able to unwrap them, so the exact
 * shape is pinned here against the same schedule. */
void test_pairing_wraps_the_card_secrets_under_a_fresh_ecdh_secret(void) {
  sc_card_activate(&kc.sc);

  /* Follows init's own order -- key, secret, public key, iv -- so that the draws land where the
   * module's land whatever the key agreement does to the generator in between. */
  hal_host_rng_seed(RNG_SEED);
  uint8_t priv[32];
  random_buffer(priv, sizeof(priv));

  uint8_t point[65];
  TEST_ASSERT_EQUAL_INT(0, ecdh_multiply(&secp256k1, priv, sc_pub, point));

  uint8_t pub[65];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, priv, pub));

  uint8_t iv[AES_IV_SIZE];
  random_buffer(iv, sizeof(iv));

  /* PIN, PUK, pairing secret -- whatever the setup hands over. init seals the caller's own buffer,
   * padding it in place, so it is declared with the slack for that. */
  SC_BUF(payload, 32);
  uint8_t secrets[32];
  for (size_t i = 0; i < 32; i++) {
    payload[i] = secrets[i] = (uint8_t)i;
  }
  uint8_t plain[48];
  const size_t padded_len = v1_pad1(secrets, 32, plain);

  uint8_t ct[48];
  TEST_ASSERT_TRUE(aes_encrypt_cbc(&point[1], iv, plain, padded_len, ct));

  sc_card_answer((const uint8_t[]){0x90, 0x00}, 2, 0);

  hal_host_rng_seed(RNG_SEED); /* the module draws the same key and iv again */
  TEST_ASSERT_EQUAL_INT(ERR_OK,
                        securechannel_init(&kc.sc, &kc.ch, &kc.apdu, SC_V1, sc_pub, payload, 32));

  uint8_t apdu[256];
  const size_t len = sc_card_apdu(0, apdu, sizeof(apdu));
  TEST_ASSERT_EQUAL_UINT(5u + 1u + 65u + AES_IV_SIZE + padded_len + 1u, len);
  TEST_ASSERT_EQUAL_UINT8(0x80, apdu[0]);
  TEST_ASSERT_EQUAL_UINT8(0xfe, apdu[1]);
  TEST_ASSERT_EQUAL_UINT8(0, apdu[2]);
  TEST_ASSERT_EQUAL_UINT8(1u + 65u + AES_IV_SIZE + padded_len, apdu[4]);

  /* The 0x41 length byte, the public key the applet will store the pairing against, the iv, and
   * then the wrapped secrets. */
  TEST_ASSERT_EQUAL_UINT8(65, apdu[5]);
  TEST_ASSERT_EQUAL_MEMORY(pub, &apdu[6], 65);
  TEST_ASSERT_EQUAL_MEMORY(iv, &apdu[6 + 65], AES_IV_SIZE);
  TEST_ASSERT_EQUAL_MEMORY(ct, &apdu[6 + 65 + AES_IV_SIZE], padded_len);

  /* And the secrets themselves are not anywhere in what left. */
  TEST_ASSERT_NULL(memmem(apdu, len, secrets, 24));
}

/* Closing takes the session out of the struct. */
void test_closing_zeroes_the_session(void) {
  handshake_draws(s);

  sc_card_activate(&kc.sc);
  v1_card_queue_open(s, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, open_channel(s));

  TEST_ASSERT_EQUAL_MEMORY(s->enc_key, kc.ch.v1.enc_key, sizeof(s->enc_key));

  securechannel_close(&kc.ch);

  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  const uint8_t zero[sizeof(kc.ch.v1)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, &kc.ch.v1, sizeof(kc.ch.v1));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_open_seals_the_challenge_under_the_derived_session);
  RUN_TEST(test_a_card_that_cannot_mac_its_reply_is_not_opened);
  RUN_TEST(test_the_mutual_authenticate_answer_has_one_length);
  RUN_TEST(test_a_short_card_nonce_refuses_the_session);
  RUN_TEST(test_an_off_curve_secure_element_key_is_refused);
  RUN_TEST(test_the_card_refusing_the_security_condition_ends_open);
  RUN_TEST(test_a_command_on_a_channel_that_was_never_opened_never_reaches_the_wire);
  RUN_TEST(test_the_chain_moves_with_every_command);
  RUN_TEST(test_a_reply_that_does_not_mac_ends_the_session);
  RUN_TEST(test_a_reply_with_no_padding_marker_is_refused_not_read);
  RUN_TEST(test_the_plaintext_is_wiped_as_it_is_sealed);
  RUN_TEST(test_pairing_wraps_the_card_secrets_under_a_fresh_ecdh_secret);
  RUN_TEST(test_closing_zeroes_the_session);

  return UNITY_END();
}
