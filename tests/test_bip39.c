#include <ctype.h>
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

/* A standard SeedQR is the word indexes as four decimal digits each, with no separator and no
 * checksum. The rows that carry a seed are the Trezor mnemonics above spelled that way, so the chain
 * scanned digits -> indexes -> seed is checked against published data at both ends: the indexes are
 * the published words' indexes and the seed is the published one.
 *
 * The digits are copied to the heap and handed over with their length, because a scanned QR is not
 * NUL-terminated: an implementation that read past the end would be a sanitiser report here rather
 * than a coincidence about what followed the literal. */
static void test_seedqr_standard(void) {
  for (size_t i = 0; i < SEEDQR_ROW_COUNT; i++) {
    const seedqr_row_t* row = &SEEDQR_ROWS[i];
    char* digits = malloc(row->len + 1);
    TEST_ASSERT_NOT_NULL(digits);
    memcpy(digits, row->digits, row->len);
    digits[row->len] = '@'; /* past the end the function is told about */

    mnemonic_indexes_reset(indexes, BIP39_MAX_MNEMONIC_LEN);
    indexes_len = 0xDEAD;
    const bool ok = mnemonic_from_seedqr_standard(indexes, &indexes_len, digits, (int)row->len);

    if (row->indexes < 0) {
      TEST_ASSERT_FALSE_MESSAGE(ok, row->digits);
      /* *out_len is written once the length is accepted and before any digit is looked at, so a
       * refusal part way through still reports a word count. A length refusal reports nothing. */
      const uint32_t expected =
          ((row->len == 48) || (row->len == 96)) ? (row->len / 4) : 0xDEADu;
      TEST_ASSERT_EQUAL_UINT_MESSAGE(expected, indexes_len, row->digits);
      free(digits);
      continue;
    }

    const uint32_t words = row->len / 4;
    TEST_ASSERT_TRUE_MESSAGE(ok, row->digits);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(words, indexes_len, row->digits);
    TEST_ASSERT_EQUAL_UINT16_ARRAY_MESSAGE(SEEDQR_INDEXES[row->indexes], indexes, words,
                                           row->digits);
    /* Nothing beyond the words it reported. */
    for (uint32_t w = words; w < BIP39_MAX_MNEMONIC_LEN; w++) {
      TEST_ASSERT_EQUAL_UINT16_MESSAGE(0xFFFF, indexes[w], row->digits);
    }

    if (row->seed[0] != '\0') {
      mnemonic_indexes_to_seed(indexes, indexes_len, "TREZOR", seed);
      TEST_ASSERT_HEX_MESSAGE(seed, sizeof(seed), row->seed, row->digits);
    }
    free(digits);
  }
}

/* Which last words complete the checksum, for the words already known. The bitmap is checked three
 * ways: against a digest of the one the vectors' model built, by popcount against the closed form
 * 2^(11 - len/3), and against mnemonic_check() word by word -- a bit set exactly when that word makes
 * the whole mnemonic valid. The third is the one that matters: two independent implementations of the
 * same checksum rule, and the published mnemonic's own last word has to be in the set. */
static void test_last_word_mask(void) {
  uint8_t mask[256];
  uint16_t candidate[BIP39_MAX_MNEMONIC_LEN];

  for (size_t i = 0; i < LAST_WORD_ROW_COUNT; i++) {
    const last_word_row_t* row = &LAST_WORD_ROWS[i];
    memset(mask, 0xAA, sizeof(mask));
    memcpy(candidate, LAST_WORD_INDEXES[i], sizeof(uint16_t) * (row->words - 1));

    TEST_ASSERT_EQUAL_UINT_MESSAGE(row->count,
                                   mnemonic_last_word_mask(candidate, (int)row->words, mask),
                                   BIP39_VECTORS[i].mnemonic);

    /* The vectors carry a digest rather than 256 bytes per row, for the same reason every other
     * wordlist here does: the whole bitmap as hex would dwarf the rest of the file. */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(mask, sizeof(mask), digest);
    TEST_ASSERT_HEX_MESSAGE(digest, sizeof(digest), row->mask_sha256, BIP39_VECTORS[i].mnemonic);

    uint32_t bits = 0;
    for (size_t byte = 0; byte < sizeof(mask); byte++) {
      bits += (uint32_t)__builtin_popcount(mask[byte]);
    }
    TEST_ASSERT_EQUAL_UINT_MESSAGE(row->count, bits, BIP39_VECTORS[i].mnemonic);
    TEST_ASSERT_TRUE(mask[row->last / 8] & (1 << (row->last % 8)));

    for (uint32_t index = 0; index < 2048; index++) {
      const bool listed = mask[index / 8] & (1 << (index % 8));
      candidate[row->words - 1] = (uint16_t)index;
      TEST_ASSERT_EQUAL_INT_MESSAGE(listed, mnemonic_check(candidate, (int)row->words),
                                    BIP39_VECTORS[i].mnemonic);
    }
  }

  /* Refused lengths leave the mask alone; nothing is computed to be thrown away. */
  memset(mask, 0x5C, sizeof(mask));
  TEST_ASSERT_EQUAL_INT(0, mnemonic_last_word_mask(LAST_WORD_INDEXES[0], 11, mask));
  TEST_ASSERT_EQUAL_INT(0, mnemonic_last_word_mask(LAST_WORD_INDEXES[0], 25, mask));
  TEST_ASSERT_EQUAL_INT(0, mnemonic_last_word_mask(LAST_WORD_INDEXES[0], 13, mask));
  TEST_ASSERT_EQUAL_INT(0, mnemonic_last_word_mask(LAST_WORD_INDEXES[0], 0, mask));
  for (size_t byte = 0; byte < sizeof(mask); byte++) {
    TEST_ASSERT_EQUAL_UINT8(0x5C, mask[byte]);
  }
}

/* The first word of a phrase, replaced by something the caller typed. */
static void set_first_word(char* text, const char* word) {
  char* space = strchr(text, ' ');
  TEST_ASSERT_NOT_NULL(space);
  memmove(text + strlen(word), space, strlen(space) + 1);
  memcpy(text, word, strlen(word));
}

static size_t words_to_indexes(const char* text, uint16_t* out, size_t cap) {
  size_t n = 0;
  const char* p = text;
  while (*p != '\0') {
    const char* end = strchr(p, ' ');
    size_t len = (end == NULL) ? strlen(p) : (size_t)(end - p);
    bool found = false;
    for (size_t i = 0; i < BIP39_WORDLIST_COUNT && !found; i++) {
      if (strlen(BIP39_WORDLIST_ENGLISH[i]) == len && !strncmp(BIP39_WORDLIST_ENGLISH[i], p, len)) {
        TEST_ASSERT_TRUE(n < cap);
        out[n++] = (uint16_t)i;
        found = true;
      }
    }
    TEST_ASSERT_TRUE_MESSAGE(found, text);
    if (end == NULL) {
      break;
    }
    p = end + 1;
  }
  return n;
}

/* mnemonic_check takes 12, 18 and 24 words. mnemonic_from_string takes 12 and 24 only, which is why
 * the 18-word rows of the suite are marked unsupported and their checksum -- the 6-bit comparison,
 * which is between the other two -- has to be reached without the string parser. */
static void test_eighteen_word_checksum(void) {
  size_t rows = 0;
  for (size_t i = 0; i < BIP39_VECTOR_COUNT; i++) {
    if (BIP39_VECTORS[i].supported) {
      continue;
    }
    rows++;

    size_t n = words_to_indexes(BIP39_VECTORS[i].mnemonic, indexes, BIP39_MAX_MNEMONIC_LEN);
    TEST_ASSERT_EQUAL_INT(18, n);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, mnemonic_check(indexes, (int)n), BIP39_VECTORS[i].mnemonic);
    TEST_ASSERT_EQUAL_INT(18 * 11, mnemonic_to_bits(indexes, (int)n, entropy));

    n = words_to_indexes(BIP39_VECTORS[i].corrupt_mnemonic, indexes, BIP39_MAX_MNEMONIC_LEN);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, mnemonic_check(indexes, (int)n),
                                  BIP39_VECTORS[i].corrupt_mnemonic);
  }
  /* The loop above is the only thing that reaches that branch, so it must not be empty. */
  TEST_ASSERT_TRUE(rows > 0);
}

/* A word count is not a mnemonic: eleven through twenty-four only means something at 12, 18 and 24. */
static void test_word_count_bounds(void) {
  size_t n = words_to_indexes(BIP39_VECTORS[0].mnemonic, indexes, BIP39_MAX_MNEMONIC_LEN);
  TEST_ASSERT_EQUAL_INT(12, n);
  TEST_ASSERT_EQUAL_INT(1, mnemonic_check(indexes, (int)n));

  for (int words = 1; words <= 26; words++) {
    /* A word count is legal here in BIP-39's arithmetic -- a multiple of three between 12 and 24 --
     * which is wider than the counts that can carry a checksum at all. */
    const int bits_ok = (words >= 12) && (words <= 24) && (words % 3 == 0);
    TEST_ASSERT_EQUAL_INT_MESSAGE(bits_ok ? words * 11 : 0,
                                  mnemonic_to_bits(indexes, words, entropy),
                                  BIP39_VECTORS[0].mnemonic);
    /* 15 and 21 words are where that difference shows: the bits convert, and then there is no
     * checksum width defined for them, so the phrase is refused. */
    if (words != 12) {
      TEST_ASSERT_EQUAL_INT(0, mnemonic_check(indexes, words));
    }
  }
}

/* What the caller is left holding when the phrase is refused. The count is taken from the spaces
 * before anything else happens, so a count refusal leaves the caller's own value in place, while a
 * refusal further on leaves the words that were already looked up -- which a caller that ignores the
 * return value would read as a mnemonic. */
static void test_from_string_leaves_what_it_read(void) {
  const uint32_t sentinel = 0x99;

  struct {
    const char* what;
    bool ok;
    uint32_t out_len;
  } cases[] = {
      {"a word in uppercase", false, 0},
      {"a word of ten letters", false, 0},
      {"a word that is not in the list", false, 0},
      {"the last word unknown, after eleven good ones", false, 11},
      {"a doubled space, which counts as a word", false, sentinel},
      {"a trailing space, which counts as a word", false, sentinel},
      {"a tab where a space should be", false, sentinel},
      {"an empty phrase", false, sentinel},
      {"nothing but spaces", false, 0},
  };

  /* The phrase each case starts from: a published 12-word mnemonic. */
  const char* base = BIP39_VECTORS[0].mnemonic;

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    strcpy(mnemonic, base);
    if (!strcmp(cases[i].what, "a word in uppercase")) {
      for (char* p = mnemonic; *p != '\0'; p++) {
        *p = (char)toupper((unsigned char)*p);
      }
    } else if (!strcmp(cases[i].what, "a word of ten letters")) {
      set_first_word(mnemonic, "abcdefghij");
    } else if (!strcmp(cases[i].what, "a word that is not in the list")) {
      set_first_word(mnemonic, "abandn");
    } else if (!strcmp(cases[i].what, "the last word unknown, after eleven good ones")) {
      char* last = strrchr(mnemonic, ' ');
      TEST_ASSERT_NOT_NULL(last);
      strcpy(last + 1, "abandn");
    } else if (!strcmp(cases[i].what, "a doubled space, which counts as a word")) {
      char* space = strchr(mnemonic, ' ');
      memmove(space + 2, space, strlen(space) + 1);
      space[0] = space[1] = ' ';
    } else if (!strcmp(cases[i].what, "a trailing space, which counts as a word")) {
      strcat(mnemonic, " ");
    } else if (!strcmp(cases[i].what, "a tab where a space should be")) {
      *strchr(mnemonic, ' ') = '\t';
    } else if (!strcmp(cases[i].what, "an empty phrase")) {
      mnemonic[0] = '\0';
    } else if (!strcmp(cases[i].what, "nothing but spaces")) {
      memset(mnemonic, ' ', 11);
      mnemonic[11] = '\0';
    }

    indexes_len = sentinel;
    const bool ok = mnemonic_from_string(indexes, &indexes_len, mnemonic);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].ok ? 1 : 0, ok ? 1 : 0, cases[i].what);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].out_len, indexes_len, cases[i].what);
  }

  /* The phrase itself is fine, and is the only way in from a typed recovery. */
  indexes_len = sentinel;
  TEST_ASSERT_TRUE(mnemonic_from_string(indexes, &indexes_len, base));
  TEST_ASSERT_EQUAL_UINT32(12, indexes_len);

  /* No phrase at all. */
  indexes_len = sentinel;
  TEST_ASSERT_FALSE(mnemonic_from_string(indexes, &indexes_len, NULL));
  TEST_ASSERT_EQUAL_UINT32(sentinel, indexes_len);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_wordlist_matches_spec);
  RUN_TEST(test_entropy_to_mnemonic);
  RUN_TEST(test_mnemonic_to_indexes_and_back);
  RUN_TEST(test_checksum);
  RUN_TEST(test_seed);
  RUN_TEST(test_seedqr_standard);
  RUN_TEST(test_last_word_mask);
  RUN_TEST(test_eighteen_word_checksum);
  RUN_TEST(test_word_count_bounds);
  RUN_TEST(test_from_string_leaves_what_it_read);
  return UNITY_END();
}
