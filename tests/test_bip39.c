#include <stdlib.h>
#include <string.h>
#include "crypto/bip39.h"
#include "crypto/memzero.h"
#include "crypto/sha2.h"
#include "framework/test_util.h"
#include "vectors/vectors_bip39.h"
#include "unity.h"

#define MAX_MNEMONIC_CHARS 512

/* Number of space separated words in a vector mnemonic. */
#define BIP39_WORD_COUNT_FOR(text) (1 + strchr_count((text), ' '))

static size_t strchr_count(const char* text, char c) {
  size_t count = 0;
  for (const char* p = strchr(text, c); p != NULL; p = strchr(p + 1, c)) {
    count++;
  }
  return count;
}

static uint16_t indexes[BIP39_MAX_MNEMONIC_LEN];
static uint32_t indexes_len;
static char mnemonic[MAX_MNEMONIC_CHARS];
static uint8_t entropy[64];
static size_t entropy_len;
static uint8_t seed[64];

void setUp(void) {
  mnemonic_indexes_reset(indexes, BIP39_MAX_MNEMONIC_LEN);
  indexes_len = 0;
  entropy_len = 0;
  memset(mnemonic, 0, sizeof(mnemonic));
  memset(seed, 0, sizeof(seed));
}

void tearDown(void) {
  memzero(seed, sizeof(seed));
}

static void test_wordlist_matches_spec(void) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  for (size_t i = 0; i < BIP39_WORDLIST_COUNT; i++) {
    sha256_Update(&ctx, (const uint8_t*)BIP39_WORDLIST_ENGLISH[i], strlen(BIP39_WORDLIST_ENGLISH[i]));
    sha256_Update(&ctx, (const uint8_t*)"\n", 1);
  }

  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, digest);
  TEST_ASSERT_EQUAL_INT(BIP39_WORD_COUNT, BIP39_WORDLIST_COUNT);
  TEST_ASSERT_HEX(digest, sizeof(digest), BIP39_WORDLIST_SHA256);
}

static void test_entropy_to_mnemonic(void) {
  for (size_t i = 0; i < BIP39_VECTOR_COUNT; i++) {
    entropy_len = test_unhex(BIP39_VECTORS[i].entropy, entropy, sizeof(entropy));
    TEST_ASSERT_TRUE(entropy_len < sizeof(entropy));

    if (!BIP39_VECTORS[i].supported) {
      /* 15, 18 and 21 word mnemonics are in the official vectors but out of scope here. */
      TEST_ASSERT_FALSE_MESSAGE(mnemonic_from_data(indexes, &indexes_len, entropy, entropy_len),
                                BIP39_VECTORS[i].entropy);
      continue;
    }

    TEST_ASSERT_TRUE_MESSAGE(mnemonic_from_data(indexes, &indexes_len, entropy, entropy_len),
                             BIP39_VECTORS[i].entropy);
    mnemonic_from_indexes(mnemonic, indexes, indexes_len);
    TEST_ASSERT_EQUAL_STRING(BIP39_VECTORS[i].mnemonic, mnemonic);
  }
}

static void test_mnemonic_to_indexes_and_back(void) {
  for (size_t i = 0; i < BIP39_VECTOR_COUNT; i++) {
    if (!BIP39_VECTORS[i].supported) {
      TEST_ASSERT_FALSE(mnemonic_from_string(indexes, &indexes_len, BIP39_VECTORS[i].mnemonic));
      continue;
    }

    TEST_ASSERT_TRUE(mnemonic_from_string(indexes, &indexes_len, BIP39_VECTORS[i].mnemonic));
    TEST_ASSERT_EQUAL_UINT(BIP39_WORD_COUNT_FOR(BIP39_VECTORS[i].mnemonic), indexes_len);

    mnemonic[0] = '\0';
    mnemonic_from_indexes(mnemonic, indexes, indexes_len);
    TEST_ASSERT_EQUAL_STRING(BIP39_VECTORS[i].mnemonic, mnemonic);
  }
}

static void test_checksum(void) {
  for (size_t i = 0; i < BIP39_VECTOR_COUNT; i++) {
    if (!BIP39_VECTORS[i].supported) {
      continue;
    }

    TEST_ASSERT_TRUE(mnemonic_from_string(indexes, &indexes_len, BIP39_VECTORS[i].mnemonic));
    TEST_ASSERT_EQUAL_INT(1, mnemonic_check(indexes, indexes_len));

    /* The substituted word is a real list entry, so only the checksum can reject it. */
    TEST_ASSERT_TRUE(mnemonic_from_string(indexes, &indexes_len, BIP39_VECTORS[i].corrupt_mnemonic));
    TEST_ASSERT_EQUAL_INT(0, mnemonic_check(indexes, indexes_len));
  }
}

static void test_seed(void) {
  for (size_t i = 0; i < BIP39_VECTOR_COUNT; i++) {
    mnemonic_to_seed(BIP39_VECTORS[i].mnemonic, "TREZOR", seed);
    TEST_ASSERT_HEX(seed, sizeof(seed), BIP39_VECTORS[i].seed);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_wordlist_matches_spec);
  RUN_TEST(test_entropy_to_mnemonic);
  RUN_TEST(test_mnemonic_to_indexes_and_back);
  RUN_TEST(test_checksum);
  RUN_TEST(test_seed);
  return UNITY_END();
}
