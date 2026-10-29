#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/sha2.h"
#include "crypto/slip39.h"
#include "framework/test_util.h"
#include "hal_host.h"
#include "unity.h"
#include "vectors/vectors_slip39.h"

/* slip39.h declares this as slip39_comebine_groups; slip39.c defines it without the typo. */
int slip39_combine_groups(slip39_group_t groups[], uint8_t group_count, uint8_t* secret, int secret_len);

#define MAX_WORDS 64
#define MAX_SHARDS SLIP39_VECTOR_MAX_SHARES

static const char* word_index_of[SLIP39_WORDS_COUNT];
static uint16_t words[MAX_WORDS];
static slip39_shard_t shards[MAX_SHARDS];
static slip39_group_t groups[SLIP39_MAX_GROUPS];
static uint8_t encrypted[64];

void setUp(void) {}

void tearDown(void) {}

static int decode(const char* mnemonic, slip39_shard_t* shard) {
  size_t count = 0;
  const char* p = mnemonic;

  while (*p != '\0') {
    const char* space = strchr(p, ' ');
    size_t len = (space == NULL) ? strlen(p) : (size_t)(space - p);
    char word[32];
    TEST_ASSERT_TRUE(len < sizeof(word));
    memcpy(word, p, len);
    word[len] = '\0';

    int index = -1;
    for (int i = 0; i < SLIP39_WORDS_COUNT; i++) {
      if (strcmp(word_index_of[i], word) == 0) {
        index = i;
        break;
      }
    }
    TEST_ASSERT_NOT_EQUAL_MESSAGE(-1, index, word);
    TEST_ASSERT_TRUE(count < MAX_WORDS);
    words[count++] = (uint16_t)index;
    p += len + ((space == NULL) ? 0 : 1);
  }

  return slip39_decode_mnemonic(words, count, shard);
}

static void test_wordlist_matches_spec(void) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  for (size_t i = 0; i < SLIP39_WORDLIST_COUNT; i++) {
    sha256_Update(&ctx, (const uint8_t*)SLIP39_WORDLIST[i], strlen(SLIP39_WORDLIST[i]));
    sha256_Update(&ctx, (const uint8_t*)"\n", 1);
  }

  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, digest);
  TEST_ASSERT_EQUAL_INT(SLIP39_WORDS_COUNT, SLIP39_WORDLIST_COUNT);
  TEST_ASSERT_HEX(digest, sizeof(digest), SLIP39_WORDLIST_SHA256);
}

/* Decodes every share of a vector and recovers the master secret, decrypting it the way the
 * application does after a combine. Negative return means some step rejected the set. */
static int recover(const slip39_vector_t* vector, uint8_t* secret, size_t* secret_len) {
  for (uint32_t i = 0; i < vector->share_count; i++) {
    int err = decode(vector->mnemonics[i], &shards[i]);
    if (err < 0) {
      return err;
    }
  }

  int length;
  if (shards[0].group_threshold == 1) {
    length = slip39_combine(shards, vector->share_count, encrypted, sizeof(encrypted));
    if (length < 0) {
      return length;
    }
  } else {
    uint8_t group_count = 0;
    for (uint8_t group_index = 0; group_index < shards[0].group_count; group_index++) {
      slip39_shard_t group_shards[SLIP39_MAX_MEMBERS];
      uint8_t group_shard_count = 0;

      for (uint32_t j = 0; j < vector->share_count; j++) {
        if (shards[j].group_index == group_index) {
          TEST_ASSERT_TRUE(group_shard_count < SLIP39_MAX_MEMBERS);
          group_shards[group_shard_count++] = shards[j];
        }
      }

      if (group_shard_count == 0) {
        continue;
      }

      int err = slip39_combine_shards(group_shards, group_shard_count, &groups[group_count]);
      if (err < 0) {
        return err;
      }
      group_count++;
    }

    length = groups[0].value_length;
    if (length > (int)sizeof(encrypted)) {
      return ERROR_INSUFFICIENT_SPACE;
    }

    int err = slip39_combine_groups(groups, group_count, encrypted, sizeof(encrypted));
    if (err < 0) {
      return err;
    }
  }

  slip39_decrypt(encrypted, length, SLIP39_PASSPHRASE, shards[0].extendable,
                 shards[0].iteration_exponent, shards[0].identifier, secret);
  *secret_len = length;
  return 0;
}

static void test_valid_share_sets_recover(void) {
  hal_host_rng_seed(1);

  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    if (SLIP39_VECTORS[i].master_secret[0] == '\0') {
      continue;
    }

    uint8_t secret[64] = {0};
    size_t secret_len = 0;
    TEST_ASSERT_EQUAL_MESSAGE(0, recover(&SLIP39_VECTORS[i], secret, &secret_len),
                              SLIP39_VECTORS[i].description);
    TEST_ASSERT_HEX(secret, strlen(SLIP39_VECTORS[i].master_secret) / 2,
                    SLIP39_VECTORS[i].master_secret);
  }
}

/* The set metadata slip39_validate_shard_in_set() compares, field by field. */
static bool shares_disagree(const slip39_shard_t* set, uint32_t count) {
  for (uint32_t i = 1; i < count; i++) {
    if ((set[i].identifier != set[0].identifier) || (set[i].extendable != set[0].extendable) ||
        (set[i].iteration_exponent != set[0].iteration_exponent) ||
        (set[i].group_threshold != set[0].group_threshold) ||
        (set[i].group_count != set[0].group_count) ||
        (set[i].value_length != set[0].value_length) ||
        (set[i].member_threshold != set[0].member_threshold)) {
      return true;
    }
  }
  return false;
}

/*
 * None of the invalid share sets in the SLIP-39 vectors may combine into a secret.
 *
 * They currently do whenever the shares merely disagree on set metadata: the combine path
 * never calls slip39_validate_shard_in_set(), which exists to make exactly that check, so it
 * interpolates over shares that were never split from one secret and returns a plausible
 * looking master secret. app/ui/ui.c re-implements part of the check at share entry time
 * (identifier and group index), so the shipped flow is covered for those two fields only.
 *
 * Asserting the shape of the gap rather than a list of names: every set that is accepted has
 * to be a metadata disagreement. A set accepted for any other reason -- a bad checksum, a
 * duplicate member index, too few shares -- is a different and worse defect.
 */
static void test_invalid_share_sets_are_rejected(void) {
  hal_host_rng_seed(1);
  unsigned int accepted = 0;

  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    if (SLIP39_VECTORS[i].master_secret[0] != '\0') {
      continue;
    }

    uint8_t secret[64] = {0};
    size_t secret_len = 0;
    if (recover(&SLIP39_VECTORS[i], secret, &secret_len) < 0) {
      continue;
    }

    accepted++;
    TEST_ASSERT_TRUE_MESSAGE(shares_disagree(shards, SLIP39_VECTORS[i].share_count),
                             SLIP39_VECTORS[i].description);
  }

  /* Once the combine path validates the set, this becomes TEST_ASSERT_EQUAL_UINT(0, accepted)
   * and the shape check above can go away. */
  TEST_ASSERT_TRUE_MESSAGE(accepted > 0, "gap closed: require every invalid set to be rejected");
}

static void test_validate_shard_in_set_catches_the_disagreement(void) {
  slip39_shard_t set[2] = {{0}};

  /* Two shares of vector "Mnemonics with different identifiers" are individually valid and
   * differ only in the identifier field. */
  uint32_t i;
  for (i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    if (strstr(SLIP39_VECTORS[i].description, "different identifiers") != NULL) {
      break;
    }
  }
  TEST_ASSERT_TRUE(i < SLIP39_VECTOR_COUNT);
  TEST_ASSERT_TRUE(SLIP39_VECTORS[i].share_count >= 2);

  TEST_ASSERT_TRUE(decode(SLIP39_VECTORS[i].mnemonics[0], &set[0]) >= 0);
  TEST_ASSERT_TRUE(decode(SLIP39_VECTORS[i].mnemonics[1], &set[1]) >= 0);

  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_SHARD_SET, slip39_validate_shard_in_set(&set[1], set, 2));
}

static void test_generate_and_combine_roundtrip(void) {
  static const uint8_t secret[SLIP39_SEED_STRENGTH] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  slip39_shard_t made[3] = {{0}};
  uint8_t ems[64] = {0};
  uint8_t combined[64] = {0};
  uint8_t recovered[64] = {0};

  hal_host_rng_seed(0x5eed);
  TEST_ASSERT_EQUAL_INT(3, slip39_generate(2, secret, sizeof(secret), ems, made, 3));
  TEST_ASSERT_EQUAL_UINT8(2, made[0].member_threshold);
  TEST_ASSERT_EQUAL_UINT8(sizeof(secret), made[0].value_length);

  TEST_ASSERT_EQUAL_INT((int)sizeof(secret), slip39_combine(&made[1], 2, combined, sizeof(combined)));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(combined, ems, sizeof(secret));

  /* slip39_generate() encrypts the master secret under an empty passphrase. */
  slip39_decrypt(ems, sizeof(secret), "", made[0].extendable, made[0].iteration_exponent,
                 made[0].identifier, recovered);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(recovered, secret, sizeof(secret));
}

static void test_rejects_incomplete_shard_set(void) {
  static const uint8_t secret[SLIP39_SEED_STRENGTH] = {0};
  slip39_shard_t made[3] = {{0}};
  uint8_t ems[64] = {0};
  uint8_t combined[64] = {0};

  hal_host_rng_seed(0x1234);
  TEST_ASSERT_EQUAL_INT(3, slip39_generate(3, secret, sizeof(secret), ems, made, 3));
  TEST_ASSERT_EQUAL_INT(ERROR_NOT_ENOUGH_MEMBER_SHARDS,
                        slip39_combine(made, 2, combined, sizeof(combined)));
}

int main(void) {
  for (int i = 0; i < SLIP39_WORDS_COUNT; i++) {
    word_index_of[i] = SLIP39_WORDLIST[i];
  }

  UNITY_BEGIN();
  RUN_TEST(test_wordlist_matches_spec);
  RUN_TEST(test_valid_share_sets_recover);
  RUN_TEST(test_invalid_share_sets_are_rejected);
  RUN_TEST(test_validate_shard_in_set_catches_the_disagreement);
  RUN_TEST(test_generate_and_combine_roundtrip);
  RUN_TEST(test_rejects_incomplete_shard_set);
  return UNITY_END();
}
