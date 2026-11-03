#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hmac.h"
#include "crypto/shamir.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_shamir.h"

/* shamir.c is two things at once: Lagrange interpolation over GF(2^8), and SLIP-39's sharing
 * construction built on top of it (secret at index 255, an integrity share at 254). The SLIP-39
 * suite already reconstructs all of Trezor's published sets through this interpolation, so the
 * field arithmetic has external approval; what this suite covers is what those sets never reach --
 * colliding and coincident share indices, refused lengths, every threshold from 1 to 16, tampered
 * shares, and the split side, which a recovery-only test set cannot see at all.
 *
 * Expectations come from a Python implementation of SLIP-39's own formulas, not from this file. */

#define POOL_SHARES SHAMIR_MAX_SHARE_COUNT
/* One more than the maximum, for the row whose share values are deliberately too long: those are
   inputs, so they have to fit even though the call itself must be refused. */
#define POOL_LEN (SHAMIR_MAX_SECRET_SIZE + 1)
#define CANARY 0xA5

static uint8_t pool[POOL_SHARES][POOL_LEN];
static const uint8_t* values[POOL_SHARES];
static uint8_t indices[POOL_SHARES];
static uint8_t result[SHAMIR_MAX_SECRET_SIZE + 8];

void setUp(void) {
  memset(pool, 0, sizeof(pool));
  memset(result, CANARY, sizeof(result));
  for (size_t i = 0; i < POOL_SHARES; i++) {
    values[i] = pool[i];
  }
}

void tearDown(void) {}

/* A recovery that refuses must not leave the value it interpolated behind: it was derived from
 * shares that do not add up, and even a wrong interpolation leaks information about the real one.
 * Only the bytes recovery was asked to write are checked -- a refusal that never got as far as
 * interpolating, which is what the parameter errors are, leaves the caller's buffer alone. */
static void assert_refused_leaves_nothing(const uint8_t* out, uint32_t length, const char* label) {
  for (uint32_t i = 0; i < length; i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, out[i], label);
  }
}

/* Loads a row's indices and share values into the module's calling convention, returning the count
 * of shares or 0 for a row whose values do not fit this harness. */
static uint8_t load_row(const char* xs_hex, const char* const* ys_hex, uint8_t length,
                        uint8_t count) {
  if (count > POOL_SHARES || length > POOL_LEN ||
      test_unhex(xs_hex, indices, sizeof(indices)) != count) {
    return 0;
  }
  for (uint8_t i = 0; i < count; i++) {
    if (test_unhex(ys_hex[i], pool[i], POOL_LEN) != length) {
      return 0;
    }
    values[i] = pool[i];
  }
  return count;
}

void test_interpolate_cases(void) {
  for (size_t i = 0; i < INTERPOLATE_CASES_COUNT; i++) {
    const interpolate_case_t* v = &INTERPOLATE_CASES[i];
    uint8_t count = (uint8_t)(strlen(v->xs) / 2);
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    if (load_row(v->xs, v->ys, v->length, count) == 0) {
      TEST_FAIL_MESSAGE(label);
    }
    /* Rows are longer or shorter than their neighbours, and the checks below look for bytes the
     * call had no business touching. */
    memset(result, CANARY, sizeof(result));

    /* A refused call must not write at all, so the buffer it would have been handed is exactly the
     * maximum size: anything spilling past that is a bug the sanitizer reports. */
    uint8_t* overlong = v->refuses ? malloc(SHAMIR_MAX_SECRET_SIZE) : NULL;
    uint8_t* out = overlong ? overlong : result;
    if (overlong) {
      memset(overlong, CANARY, SHAMIR_MAX_SECRET_SIZE);
    }

    const bool ok =
        shamir_interpolate(out, v->result_index, indices, values, count, v->length);

    if (v->expect == NULL) {
      TEST_ASSERT_FALSE_MESSAGE(ok, label);
      if (v->refuses) {
        for (size_t b = 0; b < SHAMIR_MAX_SECRET_SIZE; b++) {
          TEST_ASSERT_EQUAL_UINT8_MESSAGE(CANARY, out[b], label);
        }
      }
    } else {
      TEST_ASSERT_TRUE_MESSAGE(ok, label);
      TEST_ASSERT_HEX_MESSAGE(out, v->length, v->expect, label);
      /* Only `length` bytes belong to the caller, however the bitsliced form moves them about. */
      for (size_t b = v->length; b < sizeof(result); b++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(CANARY, result[b], label);
      }
    }
    free(overlong);
  }
}

void test_create_digest_cases(void) {
  for (size_t i = 0; i < DIGEST_CASES_COUNT; i++) {
    const digest_case_t* v = &DIGEST_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t random_data[64] = {0};
    uint8_t secret[SHAMIR_MAX_SECRET_SIZE] = {0};
    const size_t rdlen = test_unhex(v->random_data, random_data, sizeof(random_data));
    const size_t sslen = test_unhex(v->secret, secret, sizeof(secret));
    TEST_ASSERT_TRUE_MESSAGE(rdlen > 0 && sslen > 0, label);

    uint8_t digest[4] = {0};
    TEST_ASSERT_EQUAL_PTR_MESSAGE(digest, shamir_create_digest(random_data, rdlen, secret, sslen,
                                                               digest),
                                  label);
    TEST_ASSERT_HEX_MESSAGE(digest, sizeof(digest), v->expect, label);
  }
}

void test_recover_cases(void) {
  for (size_t i = 0; i < RECOVER_CASES_COUNT; i++) {
    const recover_case_t* v = &RECOVER_CASES[i];
    uint8_t count = (uint8_t)(strlen(v->xs) / 2);
    char label[160];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    if (load_row(v->xs, v->ys, (uint8_t)(strlen(v->ys[0]) / 2), count) == 0) {
      TEST_FAIL_MESSAGE(label);
    }
    const uint32_t length = (uint32_t)(strlen(v->ys[0]) / 2);

    if (v->digest_share) {
      /* The integrity share is a share like any other, so it is read back through the
       * interpolation rather than through recovery. */
      uint8_t digest[SHAMIR_MAX_SECRET_SIZE] = {0};
      TEST_ASSERT_TRUE_MESSAGE(
          shamir_interpolate(digest, 254, indices, values, v->threshold, length), label);
      TEST_ASSERT_HEX_MESSAGE(digest, length, v->expect_secret, label);
      continue;
    }

    uint8_t secret[SHAMIR_MAX_SECRET_SIZE];
    memset(secret, CANARY, sizeof(secret));
    const int32_t got = shamir_recover_secret(v->threshold, indices, values, length, secret);

    if (v->expect_secret == NULL) {
      TEST_ASSERT_EQUAL_INT32_MESSAGE(v->error, got, label);
      assert_refused_leaves_nothing(secret, length, label);
    } else {
      TEST_ASSERT_EQUAL_INT32_MESSAGE((int32_t)length, got, label);
      TEST_ASSERT_HEX_MESSAGE(secret, length, v->expect_secret, label);
    }
  }
}

/* SplitSecret and RecoverSecret are the two halves of one construction, so each is checked against
 * the other plus the properties SLIP-39 states about them: any T of the N shares reconstruct the
 * secret, fewer do not, and a corrupted share is refused rather than believed. */

static void fill_secret(uint8_t* secret, uint32_t length, uint32_t salt) {
  for (uint32_t i = 0; i < length; i++) {
    secret[i] = (uint8_t)(0x31 + i * 7 + salt * 11);
  }
}

/* Every subset of `count` indices of size `threshold`: all of them while that is cheap, then a
 * rotating window plus the whole set, which is what catches a share being ignored by position. */
static bool next_subset(uint8_t threshold, uint8_t count, uint8_t* subset, uint8_t* cursor) {
  if (count <= 8) {
    for (uint32_t mask = (*cursor) + 1; mask < (1u << count); mask++) {
      *cursor = (uint8_t)mask;
      if (__builtin_popcount(mask) != threshold) {
        continue;
      }
      uint8_t n = 0;
      for (uint8_t i = 0; i < count; i++) {
        if (mask & (1u << i)) {
          subset[n++] = (uint8_t)i;
        }
      }
      return n == threshold;
    }
    return false;
  }
  if (*cursor >= count) {
    return false;
  }
  for (uint8_t i = 0; i < threshold; i++) {
    subset[i] = (uint8_t)((*cursor + i) % count);
  }
  (*cursor)++;
  return true;
}

void test_split_recover_roundtrip(void) {
  static const uint8_t combos[][2] = {
      {1, 1},  {1, 3},  {2, 2},  {2, 5},  {3, 3},  {3, 6},  {4, 7},
      {5, 5},  {6, 9},  {8, 16}, {9, 11}, {12, 16}, {16, 16},
  };
  static const uint32_t lengths[] = {16, 18, 20, 24, 32};

  for (size_t c = 0; c < sizeof(combos) / sizeof(combos[0]); c++) {
    for (size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++) {
      const uint8_t threshold = combos[c][0];
      const uint8_t count = combos[c][1];
      const uint32_t length = lengths[l];
      char label[128];
      snprintf(label, sizeof(label), "T=%u N=%u n=%u", threshold, count, length);

      uint8_t secret[SHAMIR_MAX_SECRET_SIZE];
      fill_secret(secret, length, (uint32_t)(c * 8 + l));

      /* Exactly count shares of `length` bytes, so that a share written past the
       * end of the caller's buffer is a sanitizer report rather than a silent overwrite. */
      uint8_t* shares = malloc((size_t)count * length);
      TEST_ASSERT_NOT_NULL_MESSAGE(shares, label);
      const int32_t split = shamir_split_secret(threshold, count, secret, length, shares);
      /* Split reports how many shares it wrote, recover how many bytes it restored: the two
       * returns are not the same unit, and both are pinned here. */
      TEST_ASSERT_EQUAL_INT32_MESSAGE(count, split, label);

      uint8_t subset[SHAMIR_MAX_SHARE_COUNT];
      uint8_t cursor = 0;
      unsigned checked = 0;
      while (next_subset(threshold, count, subset, &cursor)) {
        for (uint8_t i = 0; i < threshold; i++) {
          indices[i] = subset[i];
          values[i] = shares + (size_t)subset[i] * length;
        }
        uint8_t recovered[SHAMIR_MAX_SECRET_SIZE] = {0};
        const int32_t got =
            shamir_recover_secret(threshold, indices, values, length, recovered);
        TEST_ASSERT_EQUAL_INT32_MESSAGE((int32_t)length, got, label);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(secret, recovered, length, label);
        checked++;
      }
      TEST_ASSERT_TRUE_MESSAGE(checked > 0, label);

      if (threshold == 1) {
        /* The spec's step 2: with a threshold of one every share is the secret, and there is no
         * digest share to check it against. */
        for (uint8_t i = 0; i < count; i++) {
          TEST_ASSERT_EQUAL_MEMORY_MESSAGE(secret, shares + (size_t)i * length, length, label);
        }
      } else {
        /* The spec's step 3, read back out of the shares the split produced: the interpolation at
         * 254 has to be HMAC-SHA256(key=R, msg=S)[:4] || R, for R carried in that same share. The
         * HMAC is the one the hmac suite pins to RFC 4231. */
        for (uint8_t i = 0; i < threshold; i++) {
          indices[i] = i;
          values[i] = shares + (size_t)i * length;
        }
        uint8_t digest[SHAMIR_MAX_SECRET_SIZE] = {0};
        TEST_ASSERT_TRUE_MESSAGE(
            shamir_interpolate(digest, 254, indices, values, threshold, length), label);
        uint8_t mac[32] = {0};
        hmac_sha256(digest + 4, (uint32_t)(length - 4), secret, length, mac);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(mac, digest, 4, label);
      }

      /* A corrupted share has to be refused: it moves the recovered secret and the digest share by
       * the same amount, so the four digest bytes stop matching the HMAC of what came out. This is
       * also what proves no share is being ignored -- a skipped share would sail through. */
      if (threshold > 1) {
        for (uint8_t victim = 0; victim < count; victim++) {
          const uint32_t position = (uint32_t)victim % length;
          uint8_t* byte = shares + (size_t)victim * length + position;
          *byte ^= 0x40;
          for (uint8_t i = 0; i < threshold; i++) {
            indices[i] = (uint8_t)((victim + i) % count);
            values[i] = shares + (size_t)((victim + i) % count) * length;
          }
          /* The subset has to contain the damaged share, otherwise the recovery is honest. */
          indices[0] = victim;
          uint8_t refused[SHAMIR_MAX_SECRET_SIZE];
          memset(refused, CANARY, sizeof(refused));
          const int32_t got =
              shamir_recover_secret(threshold, indices, values, length, refused);
          TEST_ASSERT_EQUAL_INT32_MESSAGE(SHAMIR_ERROR_CHECKSUM_FAILURE, got, label);
          assert_refused_leaves_nothing(refused, length, label);
          *byte ^= 0x40;
        }
      }

      free(shares);
    }
  }
}

void test_parameter_errors(void) {
  uint8_t secret[SHAMIR_MAX_SECRET_SIZE + 8];
  fill_secret(secret, sizeof(secret), 3);
  uint8_t shares[16 * SHAMIR_MAX_SECRET_SIZE];
  uint8_t recovered[SHAMIR_MAX_SECRET_SIZE];
  const uint8_t* values_ptr[2] = {shares, shares + SHAMIR_MAX_SECRET_SIZE};
  const uint8_t x[2] = {0, 1};

  /* One fault at a time, so the code can be asked for a specific answer. */
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_TOO_MANY_SHARES,
                          shamir_split_secret(2, 17, secret, 32, shares));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_INVALID_THRESHOLD,
                          shamir_split_secret(0, 3, secret, 32, shares));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_INVALID_THRESHOLD,
                          shamir_split_secret(4, 3, secret, 32, shares));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_TOO_LONG,
                          shamir_split_secret(2, 3, secret, 33, shares));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_TOO_SHORT,
                          shamir_split_secret(2, 3, secret, 15, shares));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_NOT_EVEN_LEN,
                          shamir_split_secret(2, 3, secret, 17, shares));

  /* Recovery validates the threshold as the number of shares it has been handed, so an oversized
   * threshold is reported as too many shares rather than as an invalid one. */
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_TOO_MANY_SHARES,
                          shamir_recover_secret(17, x, values_ptr, 32, recovered));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_INVALID_THRESHOLD,
                          shamir_recover_secret(0, x, values_ptr, 32, recovered));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_TOO_LONG,
                          shamir_recover_secret(2, x, values_ptr, 33, recovered));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_TOO_SHORT,
                          shamir_recover_secret(2, x, values_ptr, 15, recovered));
  TEST_ASSERT_EQUAL_INT32(SHAMIR_ERROR_SECRET_NOT_EVEN_LEN,
                          shamir_recover_secret(2, x, values_ptr, 17, recovered));

  /* Where several faults overlap the module answers with whichever it checks first; which one that
   * is is not specified, so only "refused" is pinned. */
  TEST_ASSERT_TRUE(shamir_split_secret(0, 0, secret, 33, shares) < 0);
  TEST_ASSERT_TRUE(shamir_recover_secret(17, x, values_ptr, 17, recovered) < 0);

  /* SLIP-39's range: at least 128 bits and a multiple of 16 bits, up to the module's own maximum.
   * These are accepted, which is the other half of the boundary above. */
  for (uint32_t length = 16; length <= SHAMIR_MAX_SECRET_SIZE; length += 2) {
    TEST_ASSERT_EQUAL_INT32_MESSAGE(3, shamir_split_secret(2, 3, secret, length, shares),
                                    "accepted length");
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_interpolate_cases);
  RUN_TEST(test_create_digest_cases);
  RUN_TEST(test_recover_cases);
  RUN_TEST(test_split_recover_roundtrip);
  RUN_TEST(test_parameter_errors);
  return UNITY_END();
}
