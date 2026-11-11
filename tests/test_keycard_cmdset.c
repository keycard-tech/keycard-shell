#include <stdint.h>
#include <string.h>

#include "crypto/rand.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/keycard.h"
#include "keycard/keycard_cmdset.h"
#include "keycard/secure_channel.h"
#include "sc_card.h"
#include "sc_v1_card.h"
#include "sc_host.h"
#include "unity.h"

/*
 * keycard_cmdset.c turns a call into the APDU a Keycard applet expects and the card's status word
 * back into an app_err_t; secure_channel.c decides whether the bytes go out at all. Both are
 * asserted here rather than on the device, because what a wrong P1 or a swallowed 6a84 costs is a
 * card silently left unpaired, or a PIN prompt that reports a transport failure.
 *
 * The card is scripted one exchange deep, which is all these files need: no command asserted here
 * depends on card state. keycard_init is not called -- it lives in keycard.c, which needs the ui --
 * and what it does is the two statements in setUp.
 */

#define RNG_SEED 0x5eedULL

static keycard_t kc;

void setUp(void) {
  hal_host_sc_reset();
  memset(&kc, 0, sizeof(kc));
  smartcard_init(&kc.sc);
  kc.ch.open = 0;
}

void tearDown(void) {}

static void assert_second_apdu(const uint8_t* want, size_t len) {
  uint8_t got[128];

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(got), (unsigned)len, "want");
  const size_t sent = hal_host_sc_apdu_at(1, got, sizeof(got));
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)len, (unsigned)sent, "apdu length");
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, got, (unsigned)((len < sent) ? len : sent), "apdu");
}

static void assert_apdu(const char* hex) {
  uint8_t want[128];
  sc_card_assert_apdu(want, test_unhex(hex, want, sizeof(want)));
}

/* SELECT by file identifier, the first command of every activation. The 04 in P1 is what makes it a
 * selection of the Keycard AID rather than of a DF under it. */
void test_select_sends_the_aid_by_file_identifier(void) {
  static const uint8_t aid[9] = {0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01};

  sc_card_activate(&kc.sc);
  hal_host_sc_reply_apdu("9000");

  TEST_ASSERT_EQUAL_INT(ERR_OK, keycard_cmd_select(&kc, aid, sizeof(aid)));
  assert_apdu("00A4040009A0000008040001010100");
  TEST_ASSERT_EQUAL_UINT16(SW_OK, APDU_SW(&kc.apdu));
}

/* A refusal is the card's answer, not a failure of the exchange: the caller reads SW and decides, so
 * the command returns ERR_OK with 6a82 left in place. */
void test_select_leaves_a_refusal_to_the_caller(void) {
  static const uint8_t aid[9] = {0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01};

  sc_card_activate(&kc.sc);
  hal_host_sc_reply_apdu("6a82");

  TEST_ASSERT_EQUAL_INT(ERR_OK, keycard_cmd_select(&kc, aid, sizeof(aid)));
  TEST_ASSERT_EQUAL_UINT16(0x6a82, APDU_SW(&kc.apdu));
}

/* PAIR carries the step in P1 and a 32-byte payload; the same INS serves both halves of the
 * handshake, so P1 is the only thing that tells the applet which half it is being handed. */
void test_pair_carries_the_step_and_the_challenge(void) {
  uint8_t challenge[SHA256_DIGEST_LENGTH];
  memset(challenge, 0xa1, sizeof(challenge));

  sc_card_activate(&kc.sc);
  hal_host_sc_reply_apdu("9000");

  TEST_ASSERT_EQUAL_INT(ERR_OK, keycard_cmd_pair(&kc, 0, challenge));
  assert_apdu("8012000020"
              "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"
              "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"
              "00");
}

/* The pairing handshake proves the card before it is given anything: the applet answers the shell's
 * challenge with SHA256(PSK || challenge) and the shell answers the card's in return. The challenge
 * is the seeded RNG's -- drawn once here to derive what the card must send, then drawn again by the
 * module from the same seed. */
void test_autopair_completes_against_a_card_that_proves_itself(void) {
  static const uint8_t psk[SHA256_DIGEST_LENGTH] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
  uint8_t challenge[SHA256_DIGEST_LENGTH];
  uint8_t card_challenge[SHA256_DIGEST_LENGTH];
  uint8_t salt[SHA256_DIGEST_LENGTH];
  uint8_t reply[2 * SHA256_DIGEST_LENGTH + 2];
  uint8_t our_cryptogram[SHA256_DIGEST_LENGTH];
  uint8_t want_apdu[5 + SHA256_DIGEST_LENGTH + 1];
  uint8_t expected_key[SHA256_DIGEST_LENGTH];
  pairing_t pairing;

  hal_host_rng_seed(RNG_SEED);
  random_buffer(challenge, sizeof(challenge));

  memset(card_challenge, 0xcd, sizeof(card_challenge));
  memset(salt, 0xab, sizeof(salt));
  v1_sha256_cat(psk, sizeof(psk), challenge, sizeof(challenge), reply);
  memcpy(&reply[SHA256_DIGEST_LENGTH], card_challenge, SHA256_DIGEST_LENGTH);
  reply[2 * SHA256_DIGEST_LENGTH] = 0x90;
  reply[2 * SHA256_DIGEST_LENGTH + 1] = 0x00;

  sc_card_activate(&kc.sc);
  sc_card_answer(reply, sizeof(reply), 0);

  uint8_t second[1 + SHA256_DIGEST_LENGTH + 2];
  second[0] = 3;
  memcpy(&second[1], salt, sizeof(salt));
  second[sizeof(second) - 2] = 0x90;
  second[sizeof(second) - 1] = 0x00;
  sc_card_answer(second, sizeof(second), 1);

  hal_host_rng_seed(RNG_SEED);
  const app_err_t res = keycard_cmd_autopair(&kc, psk, &pairing);
  TEST_ASSERT_EQUAL_INT(ERR_OK, res);

  v1_sha256_cat(psk, sizeof(psk), card_challenge, sizeof(card_challenge), our_cryptogram);
  want_apdu[0] = 0x80;
  want_apdu[1] = 0x12;
  want_apdu[2] = 1;
  want_apdu[3] = 0;
  want_apdu[4] = SHA256_DIGEST_LENGTH;
  memcpy(&want_apdu[5], our_cryptogram, SHA256_DIGEST_LENGTH);
  want_apdu[5 + SHA256_DIGEST_LENGTH] = 0;

  /* Two blocks in the record, and the second is the one that carries the shell's own cryptogram. */
  TEST_ASSERT_EQUAL_UINT((unsigned)(2 * (sizeof(want_apdu) + 4)), (unsigned)hal_host_sc_sent_len());
  assert_second_apdu(want_apdu, sizeof(want_apdu));

  TEST_ASSERT_EQUAL_UINT8(3, pairing.idx);
  v1_sha256_cat(psk, sizeof(psk), salt, sizeof(salt), expected_key);
  TEST_ASSERT_EQUAL_MEMORY(expected_key, pairing.key, SHA256_DIGEST_LENGTH);
}

/* The second half is not sent to a card that failed the first: one block leaves, so a reader that
 * has just failed to authenticate itself does not hand over a cryptogram it made with the PSK. */
void test_a_card_that_cannot_prove_itself_is_not_answered(void) {
  static const uint8_t psk[SHA256_DIGEST_LENGTH] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
  uint8_t reply[2 * SHA256_DIGEST_LENGTH + 2];
  pairing_t pairing;

  memset(reply, 0xee, sizeof(reply) - 2); /* a well-formed answer with the wrong cryptogram in it */
  reply[sizeof(reply) - 2] = 0x90;
  reply[sizeof(reply) - 1] = 0x00;

  sc_card_activate(&kc.sc);
  sc_card_answer(reply, sizeof(reply), 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_autopair(&kc, psk, &pairing));
  /* One PAIR block: header, the 32-byte challenge, Le, and 11.4.4's header and epilogue. */
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)(5 + SHA256_DIGEST_LENGTH + 1 + 4),
      (unsigned)hal_host_sc_sent_len(), "the shell's cryptogram never left");
}

/* The applet holds a bounded number of pairing slots. 6a84 means it is full and the user has to be
 * told that: as a retry it would spin, as a crypto error it would blame the card. */
void test_a_full_pairing_slot_is_not_a_retry(void) {
  static const uint8_t psk[SHA256_DIGEST_LENGTH] = {0x77};
  pairing_t pairing;

  sc_card_activate(&kc.sc);
  hal_host_sc_reply_apdu("6a84");

  TEST_ASSERT_EQUAL_INT(ERR_FULL, keycard_cmd_autopair(&kc, psk, &pairing));
}

/* 9000 with less than a cryptogram and a challenge is not a Keycard. Reading on would take the
 * pairing material out of whatever the previous exchange left in the buffer. */
void test_a_short_pairing_answer_is_a_card_failure(void) {
  static const uint8_t psk[SHA256_DIGEST_LENGTH] = {0x77};
  pairing_t pairing;

  sc_card_activate(&kc.sc);
  hal_host_sc_reply_apdu("001122339000");

  TEST_ASSERT_EQUAL_INT(ERR_HW, keycard_cmd_autopair(&kc, psk, &pairing));
}

/* Every credential command goes through the secure channel, and a channel that is not open refuses
 * before the card is touched: a PIN in the clear, or a command framed with a keystream no card
 * holds, is worse than an error. */
void test_a_closed_channel_sends_nothing(void) {
  uint8_t pin[KEYCARD_PIN_LEN];
  uint8_t path[16];

  memset(pin, '1', sizeof(pin));
  memset(path, 0x80, sizeof(path));

  sc_card_activate(&kc.sc);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_verify_pin(&kc, pin));
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_get_status(&kc));
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_unpair(&kc, 0));
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_export_key(&kc, 1, path, sizeof(path)));

  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_sent_len(), "nothing on the wire");
}

/* The PUK is wiped by the command that consumes it, and that has to hold on the path where the send
 * never happens -- which is the one nobody would think to check. */
void test_the_puk_is_wiped_even_when_the_send_refuses(void) {
  uint8_t pin[KEYCARD_PIN_LEN];
  uint8_t puk[KEYCARD_PUK_LEN];

  memset(pin, '1', sizeof(pin));
  memset(puk, '9', sizeof(puk));

  sc_card_activate(&kc.sc);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, keycard_cmd_unblock_pin(&kc, pin, puk));

  for (size_t i = 0; i < sizeof(puk); i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, puk[i], "puk");
  }
}

/* securechannel_open dispatches on the version and owes an answer for a value that is neither. */
void test_an_unknown_channel_version_opens_nothing(void) {
  sc_card_activate(&kc.sc);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, (sc_version_t)0x77, NULL));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_sent_len());
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_select_sends_the_aid_by_file_identifier);
  RUN_TEST(test_select_leaves_a_refusal_to_the_caller);
  RUN_TEST(test_pair_carries_the_step_and_the_challenge);
  RUN_TEST(test_autopair_completes_against_a_card_that_proves_itself);
  RUN_TEST(test_a_card_that_cannot_prove_itself_is_not_answered);
  RUN_TEST(test_a_full_pairing_slot_is_not_a_retry);
  RUN_TEST(test_a_short_pairing_answer_is_a_card_failure);
  RUN_TEST(test_a_closed_channel_sends_nothing);
  RUN_TEST(test_the_puk_is_wiped_even_when_the_send_refuses);
  RUN_TEST(test_an_unknown_channel_version_opens_nothing);

  return UNITY_END();
}
