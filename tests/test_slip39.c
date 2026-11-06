#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/sha2.h"
#include "crypto/slip39.h"
#include "framework/test_util.h"
#include "hal_host.h"
#include "unity.h"
#include "vectors/vectors_slip39.h"

#define MAX_WORDS 64
#define MAX_SHARDS SLIP39_VECTOR_MAX_SHARES

static const char* word_index_of[SLIP39_WORDS_COUNT];
static uint16_t words[MAX_WORDS];
static slip39_shard_t shards[MAX_SHARDS];
static slip39_group_t groups[SLIP39_MAX_GROUPS];
static uint8_t encrypted[64];

void setUp(void) {}

void tearDown(void) {}

/* A published share is a sentence of the wordlist; this turns it into the ten-bit values the module
 * takes, and is the only place the published strings are read as anything but text. */
static uint32_t parse(const char* mnemonic, uint16_t* out, uint32_t cap) {
  uint32_t count = 0;
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
    TEST_ASSERT_TRUE(count < cap);
    out[count++] = (uint16_t)index;
    p += len + ((space == NULL) ? 0 : 1);
  }

  return count;
}

static int decode(const char* mnemonic, slip39_shard_t* shard) {
  return slip39_decode_mnemonic(words, parse(mnemonic, words, MAX_WORDS), shard);
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

/* Decodes every share of a vector and combines to the encrypted master secret, which is left in
 * `encrypted` with the set's metadata in `shards[]`. Negative return means some step rejected the set. */
static int combine(const slip39_vector_t* vector) {
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
    /* The contract of slip39_combine_groups(): a group descriptor keeps no identifier or
     * iteration exponent, so the caller validates the set across groups. */
    for (uint32_t i = 1; i < vector->share_count; i++) {
      int err = slip39_validate_shard_in_set(&shards[i], shards, i);
      if (err < 0) {
        return err;
      }
    }

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

  return length;
}

/* The way the application finishes: combine, then decrypt with the passphrase the set was made with. */
static int recover(const slip39_vector_t* vector, uint8_t* secret, size_t* secret_len) {
  int length = combine(vector);
  if (length < 0) {
    return length;
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

static void test_invalid_share_sets_are_rejected(void) {
  hal_host_rng_seed(1);

  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    if (SLIP39_VECTORS[i].master_secret[0] != '\0') {
      continue;
    }

    uint8_t secret[64] = {0};
    size_t secret_len = 0;
    TEST_ASSERT_TRUE_MESSAGE(recover(&SLIP39_VECTORS[i], secret, &secret_len) < 0,
                             SLIP39_VECTORS[i].description);
  }
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

/* The RS1024 checksum is generated in one place and verified in another: slip39_decode_mnemonic()
 * polynomials the words to zero and never calls rs1024_create_checksum(), so a generator that produced
 * some other checksum would have been caught by the module's own decode and by nothing else. Here the
 * input is a published share decoded into a struct and the expectation is the published string it came
 * from, words and checksum included. */
static void test_encode_reproduces_the_published_words(void) {
  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    const slip39_vector_t* vector = &SLIP39_VECTORS[i];
    if (vector->master_secret[0] == '\0') {
      continue; /* a refused set does not decode, so there is nothing to re-encode */
    }

    for (uint32_t j = 0; j < vector->share_count; j++) {
      slip39_shard_t shard;
      TEST_ASSERT_TRUE_MESSAGE(decode(vector->mnemonics[j], &shard) >= 0, vector->description);

      uint16_t published[MAX_WORDS];
      uint32_t count = parse(vector->mnemonics[j], published, MAX_WORDS);

      uint16_t encoded[MAX_WORDS];
      int written = slip39_encode_mnemonic(&shard, encoded, MAX_WORDS);
      TEST_ASSERT_EQUAL_INT_MESSAGE((int)count, written, vector->description);
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(published, encoded, (size_t)count * sizeof(uint16_t),
                                       vector->description);
    }
  }
}

/* The bound slip39_words_for_data() enforces is the caller's length minus the metadata, so a buffer
 * below that subtracts into a large one and the value words land past the end. Swept with a canary
 * because the failure is a write, and because the one production caller passes SLIP39_MNEMO_LEN --
 * exactly the width a 128 bit share needs, with nothing tying the two constants together. */
static void test_encode_refuses_a_short_destination(void) {
  static const uint8_t master[SLIP39_SEED_STRENGTH] = {7};
  slip39_shard_t made[1];
  uint8_t ems[64];

  hal_host_rng_seed(0x51f);
  TEST_ASSERT_EQUAL_INT(1, slip39_generate(1, master, sizeof(master), ems, made, 1));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(SLIP39_MNEMO_LEN, slip39_mnemonic_length(sizeof(master)),
                                 "the device's own buffer is wide enough for its own strength");

  for (uint32_t cap = 0; cap < SLIP39_MNEMO_LEN; cap++) {
    uint16_t buffer[SLIP39_MNEMO_LEN];
    memset(buffer, 0xA5, sizeof(buffer));
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERROR_INSUFFICIENT_SPACE,
                                  slip39_encode_mnemonic(made, buffer, cap), "one word short");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0xA5A5, buffer[SLIP39_MNEMO_LEN - 1],
                                     "nothing written to the last word");
  }

  uint16_t exact[SLIP39_MNEMO_LEN];
  TEST_ASSERT_EQUAL_INT(SLIP39_MNEMO_LEN, slip39_encode_mnemonic(made, exact, SLIP39_MNEMO_LEN));
}

/* The Feistel network, the PBKDF2 round function and the salt drawn from the identifier, against
 * Trezor. The encrypted master secret is not published, but it is recoverable: combining the published
 * share values gives it. Encrypting the published master secret has to give the same bytes, which is
 * the only statement here about the direction the Trezor corpus cannot exercise -- its passphrase is
 * "TREZOR", while the device makes backups under an empty one. */
static void test_encrypt_reproduces_the_encrypted_master_secret(void) {
  uint8_t master[64];
  uint8_t again[64];

  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    const slip39_vector_t* vector = &SLIP39_VECTORS[i];
    if (vector->master_secret[0] == '\0') {
      continue;
    }

    int length = combine(vector);
    TEST_ASSERT_TRUE_MESSAGE(length >= 0, vector->description);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)strlen(vector->master_secret) / 2, length,
                                  vector->description);

    size_t master_len = test_unhex(vector->master_secret, master, sizeof(master));
    slip39_encrypt(master, master_len, SLIP39_PASSPHRASE, shards[0].extendable,
                   shards[0].iteration_exponent, shards[0].identifier, again);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(encrypted, again, master_len, vector->description);
  }
}

/* What SLIP-39 says about a generated set, and what the device relies on: one 15 bit identifier for
 * all of it, one group whose members are indexed 0..count-1 at the asked-for threshold, and words that
 * decode back to the shard they were made from. The share values themselves are random, so nothing can
 * pin them; the RNG is seeded only so a failure repeats. */
static void test_generate_sets_are_well_formed(void) {
  static const uint8_t shapes[][2] = { {1, 1}, {2, 2}, {2, 3}, {3, 5}, {5, 5}, {8, 8} };
  uint8_t ems[64];
  uint16_t written[MAX_WORDS];

  hal_host_rng_seed(0xa11ce);

  for (size_t s = 0; s < sizeof(shapes) / sizeof(*shapes); s++) {
    for (uint8_t strength = SLIP39_SEED_STRENGTH; strength <= 32; strength += 8) {
      uint8_t threshold = shapes[s][0];
      uint8_t count = shapes[s][1];
      char label[64];
      snprintf(label, sizeof(label), "%d of %d, %d bytes", threshold, count, strength);

      uint8_t master[32];
      for (uint8_t j = 0; j < strength; j++) {
        master[j] = (uint8_t)(0x10u + j + strength);
      }
      slip39_shard_t made[MAX_SHARDS];

      TEST_ASSERT_EQUAL_INT_MESSAGE(count, slip39_generate(threshold, master, strength, ems, made, count),
                                    label);

      for (uint8_t i = 0; i < count; i++) {
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(made[0].identifier, made[i].identifier, label);
        TEST_ASSERT_TRUE_MESSAGE(made[0].identifier < (1u << 15), label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(SLIP39_EXT, made[i].extendable, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(SLIP39_ITERATION_DEF, made[i].iteration_exponent, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, made[i].group_threshold, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, made[i].group_count, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, made[i].group_index, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(i, made[i].member_index, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(threshold, made[i].member_threshold, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(strength, made[i].value_length, label);

        int words = slip39_encode_mnemonic(&made[i], written, MAX_WORDS);
        TEST_ASSERT_EQUAL_INT_MESSAGE((int)slip39_mnemonic_length(strength), words, label);

        slip39_shard_t back;
        TEST_ASSERT_TRUE_MESSAGE(slip39_decode_mnemonic(written, (uint32_t)words, &back) >= 0, label);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(made[i].identifier, back.identifier, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].extendable, back.extendable, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].iteration_exponent, back.iteration_exponent, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].group_index, back.group_index, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].group_threshold, back.group_threshold, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].group_count, back.group_count, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].member_index, back.member_index, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].member_threshold, back.member_threshold, label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(made[i].value_length, back.value_length, label);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(made[i].value, back.value, strength, label);

        if (i > 0) {
          TEST_ASSERT_TRUE_MESSAGE(slip39_validate_shard_in_set(&made[i], made, i) >= 0, label);
        }
      }
    }
  }
}

/* The counts slip39_generate() will not make shares for, each one a UI state the backup flow has to
 * refuse rather than emit a set that cannot be recovered. */
static void test_generate_refuses_impossible_share_counts(void) {
  static const uint8_t master[SLIP39_SEED_STRENGTH] = {1};
  slip39_shard_t made[3];
  uint8_t ems[64];

  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_SHARD_SET,
                        slip39_generate(1, master, sizeof(master), ems, made, 0));
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_MEMBER_THRESHOLD,
                        slip39_generate(1, master, sizeof(master), ems, made, 3));
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_MEMBER_THRESHOLD,
                        slip39_generate(4, master, sizeof(master), ems, made, 3));
  TEST_ASSERT_EQUAL_INT(ERROR_SECRET_TOO_SHORT,
                        slip39_generate(2, master, SLIP39_SEED_STRENGTH - 1, ems, made, 3));
}

/* The backup UI offers only the words that can close a mnemonic, and slip39_last_word_mask() is what
 * tells it -- live at ui/input.c:934 and untested until now. RS1024 leaves one word to choose, so
 * exactly one of the 1024 is valid, and the valid one is the word Trezor published. */
static void test_last_word_mask_offers_the_published_word(void) {
  uint8_t mask[SLIP39_WORDS_COUNT / 8];
  uint16_t indexes[MAX_WORDS];

  for (size_t i = 0; i < SLIP39_VECTOR_COUNT; i++) {
    const slip39_vector_t* vector = &SLIP39_VECTORS[i];
    if (vector->master_secret[0] == '\0') {
      continue;
    }

    for (uint32_t j = 0; j < vector->share_count; j++) {
      uint32_t len = parse(vector->mnemonics[j], indexes, MAX_WORDS);

      TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, slip39_last_word_mask(indexes, len, mask),
                                       vector->description);

      uint32_t bits = 0;
      uint32_t marked = 0;
      for (size_t b = 0; b < sizeof(mask); b++) {
        for (uint8_t k = 0; k < 8; k++) {
          if (mask[b] & (1u << k)) {
            bits++;
            marked = (uint32_t)b * 8 + k;
          }
        }
      }
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, bits, vector->description);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(indexes[len - 1], marked, vector->description);

      /* The choice is a function of everything but the last word, so a prefix that does not belong to
       * any mnemonic has no candidate at all rather than a permissive answer. */
      uint16_t first = indexes[0];
      bool refused = false;
      for (uint32_t w = 0; w < SLIP39_WORDS_COUNT; w++) {
        indexes[0] = (uint16_t)w;
        if (slip39_last_word_mask(indexes, len, mask) == 0) {
          refused = true;
          break;
        }
      }
      indexes[0] = first;
      TEST_ASSERT_TRUE_MESSAGE(refused, vector->description);
    }
  }

  uint16_t short_words[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
  TEST_ASSERT_EQUAL_UINT32(0, slip39_last_word_mask(short_words,
                                                    sizeof(short_words) / sizeof(*short_words), mask));
}

/* Edges a combine has to refuse, and slip39_count_shards(), which nothing in app/ calls: pinned the
 * way slip39_validate_shard_in_set() is, so that a revived caller inherits the rules rather than
 * rewriting them. The 25 byte case is the one no mnemonic makes -- an odd number of bytes cannot be
 * encoded -- so it is built by editing a generated shard rather than by finding a file. */
static void test_refuses_misshapen_sets_and_counts(void) {
  static const uint8_t master[SLIP39_SEED_STRENGTH] = {3};
  static const uint16_t short_words[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
  slip39_shard_t made[SLIP39_VECTOR_MAX_SHARES];
  uint8_t ems[64];
  uint8_t out[64];
  uint16_t words_written[MAX_WORDS];

  hal_host_rng_seed(0x9be);
  TEST_ASSERT_EQUAL_INT(3, slip39_generate(2, master, sizeof(master), ems, made, 3));

  /* A 25 byte value is an odd number of bytes, which no mnemonic encodes: it arrives from a caller
   * that filled the struct by hand, and the decoder refuses it. 25 rather than 17 because a value word
   * count that is a multiple of four leaves no padding for the decoder to argue about, and the first
   * byte non-zero so its leading-zero rule cannot fire. */
  slip39_shard_t odd = made[0];
  memset(odd.value, 0x11, sizeof(odd.value)); /* no run of zero bits, which is what the decoder's
                                                 leading-zero rule reads */
  odd.value_length = 25;
  int written = slip39_encode_mnemonic(&odd, words_written, MAX_WORDS);
  TEST_ASSERT_EQUAL_INT(27, written);

  slip39_shard_t back;
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_SECRET_LENGTH,
                        slip39_decode_mnemonic(words_written, (uint32_t)written, &back));
  TEST_ASSERT_EQUAL_INT(ERROR_NOT_ENOUGH_MNEMONIC_WORDS,
                        slip39_decode_mnemonic(short_words, sizeof(short_words) / sizeof(*short_words),
                                               &back));

  TEST_ASSERT_EQUAL_INT(0, slip39_validate_shard_in_set(&made[0], made, 0));

  slip39_group_t group;
  TEST_ASSERT_EQUAL_INT((int)sizeof(master), slip39_combine_shards(made, 2, &group));
  TEST_ASSERT_EQUAL_INT(ERROR_INSUFFICIENT_SPACE,
                        slip39_combine_groups(&group, 1, out, group.value_length - 1));

  TEST_ASSERT_EQUAL_INT(ERROR_INSUFFICIENT_SPACE,
                        slip39_combine(made, 2, out, (int)sizeof(master) - 1));

  slip39_shard_t two_groups = made[0];
  two_groups.member_threshold = 1;
  two_groups.group_threshold = 2;
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_GROUP_THRESHOLD,
                        slip39_combine(&two_groups, 1, out, sizeof(out)));

  static const slip39_group_desc_t good[] = {{.threshold = 3, .count = 3},
                                             {.threshold = 2, .count = 5}};
  TEST_ASSERT_EQUAL_INT(8, slip39_count_shards(2, good, 2));

  static const slip39_group_desc_t too_many_groups[] = {{.threshold = 3, .count = 3}};
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_GROUP_THRESHOLD,
                        slip39_count_shards(2, too_many_groups, 1));

  static const slip39_group_desc_t over[] = {{.threshold = 4, .count = 3}};
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_MEMBER_THRESHOLD, slip39_count_shards(1, over, 1));

  static const slip39_group_desc_t singleton[] = {{.threshold = 1, .count = 3}};
  TEST_ASSERT_EQUAL_INT(ERROR_INVALID_SINGLETON_MEMBER, slip39_count_shards(1, singleton, 1));
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
  RUN_TEST(test_encode_reproduces_the_published_words);
  RUN_TEST(test_encode_refuses_a_short_destination);
  RUN_TEST(test_encrypt_reproduces_the_encrypted_master_secret);
  RUN_TEST(test_generate_sets_are_well_formed);
  RUN_TEST(test_generate_refuses_impossible_share_counts);
  RUN_TEST(test_last_word_mask_offers_the_published_word);
  RUN_TEST(test_refuses_misshapen_sets_and_counts);
  return UNITY_END();
}
