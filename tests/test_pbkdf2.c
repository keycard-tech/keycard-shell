#include <string.h>

#include "crypto/pbkdf2.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_pbkdf2.h"

/*
 * PBKDF2-HMAC-SHA256 turns the two secrets a user types into keys: the pairing password that seals a
 * session with the card (keycard.c:722), and the passphrase that stretches a SLIP-39 master secret
 * during recovery. Both are comparisons against another implementation, so the derived bytes have to
 * match exactly -- a single bit off is a card that refuses to pair or a seed that will not decrypt,
 * and in the second case the user has the shares and no way back.
 */

#define MAX_IO 256
#define GUARD 0xa5

void setUp(void) {}

void tearDown(void) {}

static const pbkdf2_kat_t* vector_named(const char* name) {
  for (size_t i = 0; i < PBKDF2_KAT_COUNT; i++) {
    if (strcmp(PBKDF2_KAT[i].name, name) == 0) {
      return &PBKDF2_KAT[i];
    }
  }
  return NULL;
}

static void derive(const pbkdf2_kat_t* v, uint8_t* out, size_t room) {
  uint8_t pass[MAX_IO], salt[MAX_IO];
  const size_t pass_len = test_unhex(v->pass_hex, pass, sizeof(pass));
  const size_t salt_len = test_unhex(v->salt_hex, salt, sizeof(salt));
  const size_t dk_len = strlen(v->dk_hex) / 2;

  TEST_ASSERT_LESS_OR_EQUAL_INT((int)room, (int)dk_len);
  memset(out, GUARD, room);

  pbkdf2_hmac_sha256(pass, (int)pass_len, salt, (int)salt_len, v->iterations, out, (int)dk_len);

  TEST_ASSERT_HEX(out, dk_len, v->dk_hex);
}

static void test_known_answers(void) {
  for (size_t i = 0; i < PBKDF2_KAT_COUNT; i++) {
    const pbkdf2_kat_t* v = &PBKDF2_KAT[i];
    uint8_t out[MAX_IO];

    derive(v, out, sizeof(out));

    /* A derived key that is not a whole number of digests gets a short copy of the last block, which
     * is where a caller's buffer ends: nothing past the requested length may move. */
    const size_t dk_len = strlen(v->dk_hex) / 2;
    for (size_t n = dk_len; n < sizeof(out); n++) {
      TEST_ASSERT_EQUAL_UINT_MESSAGE(GUARD, out[n], v->name);
    }
  }
}

static void test_the_salt_length_excludes_the_terminator(void) {
  /* keycard.c:722 hands the salt as a string literal with an explicit length of 29. Passing the
   * terminator too -- sizeof() rather than 29 -- is the obvious way to get this call wrong, and it
   * derives a different key from the same password, which the card then rejects. */
  static const char salt[] = "Keycard Pairing Password Salt";
  static const char password[] = "1234";
  uint8_t as_called[SHA256_DIGEST_LENGTH], with_terminator[SHA256_DIGEST_LENGTH];

  const pbkdf2_kat_t* v = vector_named("pairing password, 4B");
  TEST_ASSERT_NOT_NULL(v);

  pbkdf2_hmac_sha256((const uint8_t*)password, 4, (const uint8_t*)salt, 29, 50000, as_called, sizeof(as_called));
  pbkdf2_hmac_sha256((const uint8_t*)password, 4, (const uint8_t*)salt, sizeof(salt), 50000, with_terminator,
                     sizeof(with_terminator));

  TEST_ASSERT_HEX(as_called, sizeof(as_called), v->dk_hex);
  TEST_ASSERT_TRUE(memcmp(as_called, with_terminator, sizeof(as_called)) != 0);
}

static void test_a_request_for_nothing_derives_nothing(void) {
  uint8_t out[16];
  memset(out, GUARD, sizeof(out));

  pbkdf2_hmac_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1000, out, 0);

  for (size_t n = 0; n < sizeof(out); n++) {
    TEST_ASSERT_EQUAL_UINT(GUARD, out[n]);
  }
}

static void test_the_streaming_api_answers_what_the_one_shot_does(void) {
  /* The one-shot is what the two callers use; the streaming form is what bip39.c drives the SHA-512
   * sibling with, and the two share the iteration loop and the byte order fixup. */
  const pbkdf2_kat_t* v = &PBKDF2_KAT[PBKDF2_KAT_COUNT - 1];
  uint8_t pass[MAX_IO], salt[MAX_IO], streamed[SHA256_DIGEST_LENGTH], one_shot[SHA256_DIGEST_LENGTH];
  const size_t pass_len = test_unhex(v->pass_hex, pass, sizeof(pass));
  const size_t salt_len = test_unhex(v->salt_hex, salt, sizeof(salt));

  PBKDF2_HMAC_SHA256_CTX ctx = {0};
  pbkdf2_hmac_sha256_Init(&ctx, pass, (int)pass_len, salt, (int)salt_len, 1);
  pbkdf2_hmac_sha256_Update(&ctx, v->iterations);
  pbkdf2_hmac_sha256_Final(&ctx, streamed);

  pbkdf2_hmac_sha256(pass, (int)pass_len, salt, (int)salt_len, v->iterations, one_shot, sizeof(one_shot));

  TEST_ASSERT_EQUAL_MEMORY(streamed, one_shot, sizeof(one_shot));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_known_answers);
  RUN_TEST(test_the_salt_length_excludes_the_terminator);
  RUN_TEST(test_a_request_for_nothing_derives_nothing);
  RUN_TEST(test_the_streaming_api_answers_what_the_one_shot_does);
  return UNITY_END();
}
