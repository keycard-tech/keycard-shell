#include <stdbool.h>
#include <string.h>

#include "crypto/rand.h"
#include "framework/test_util.h"
#include "hal_host.h"
#include "unity.h"

/*
 * This is the only source of unpredictability in the device: the PUK and the duress code are digits drawn
 * here (keycard.c:37,44), and so are the recovery words the user is asked to confirm (ui.c:526-574). What
 * is checkable without silicon is the mapping from the raw stream to the shapes the callers ask for -- a
 * value below n, n distinct values below max, a rearrangement that loses nothing. The stream is a seeded
 * generator, so a failure reproduces on one draw rather than on the run.
 */

#define MAX_RANGE 32 /* random_unique_in_range()'s own ceiling */

void setUp(void) {
  hal_host_rng_seed(0x5eed);
}

void tearDown(void) {}

static void test_random32_is_four_bytes_of_the_stream(void) {
  uint8_t stream[4];
  random_buffer(stream, sizeof(stream));

  hal_host_rng_seed(0x5eed);

  const uint32_t drawn = random32();

  /* Compared as bytes, not as a number: the value is the stream in whatever order the machine lays it
   * out, and what matters is that the four bytes are those four bytes. */
  TEST_ASSERT_EQUAL_MEMORY(stream, &drawn, sizeof(drawn));
  TEST_ASSERT_EQUAL_UINT(sizeof(drawn), hal_host_rng_count());
}

static void test_random_uniform_stays_below_n(void) {
  static const uint32_t sizes[] = {1, 2, 3, 7, 10, 64, 255, 256, 1000, 65535, 0x7ffffffe, 0x7fffffff, 0xfffffffe, 0xffffffff};

  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    for (size_t draw = 0; draw < 500; draw++) {
      hal_host_rng_seed(0x1000 + draw);

      const uint32_t got = random_uniform(sizes[i]);

      TEST_ASSERT_LESS_THAN_UINT_MESSAGE(sizes[i], got, "random_uniform answered outside [0,n)");
    }
  }
}

static void test_random_uniform_reaches_every_value(void) {
  /* The rejection bound is a hair under 2^32, so a divisor that loses the top values -- or an off-by-one
   * in the cap -- still answers in range. Only a census says the whole range is reachable. */
  bool seen[256] = {0};

  for (size_t i = 0; i < 200000; i++) {
    seen[random_uniform(256)] = true;
  }

  for (size_t v = 0; v < 256; v++) {
    TEST_ASSERT_TRUE_MESSAGE(seen[v], "a value in [0,n) was never drawn");
  }
}

static void test_random_unique_in_range_answers_distinct_values_below_max(void) {
  static const uint8_t maxes[] = {1, 2, 5, 12, 24, MAX_RANGE};

  for (size_t m = 0; m < sizeof(maxes) / sizeof(maxes[0]); m++) {
    const uint8_t max = maxes[m];

    for (uint8_t count = 1; count <= max; count++) {
      for (size_t seed = 0; seed < 20; seed++) {
        hal_host_rng_seed(0xa11ce + seed);

        uint8_t out[MAX_RANGE];
        bool used[MAX_RANGE + 1] = {0};
        random_unique_in_range(max, count, out);

        for (uint8_t i = 0; i < count; i++) {
          TEST_ASSERT_LESS_THAN_UINT_MESSAGE(max, out[i], "a value outside [0,max)");
          TEST_ASSERT_FALSE_MESSAGE(used[out[i]], "a value drawn twice");
          used[out[i]] = true;
        }
      }
    }
  }
}

static void test_asking_for_every_value_returns_every_value(void) {
  /* count == max is the case where the draw loop collides on nearly every attempt: the answer is still
   * each value exactly once. */
  for (uint8_t max = 1; max <= MAX_RANGE; max++) {
    uint8_t out[MAX_RANGE];
    bool used[MAX_RANGE + 1] = {0};

    random_unique_in_range(max, max, out);

    for (uint8_t i = 0; i < max; i++) {
      TEST_ASSERT_LESS_THAN_UINT(max, out[i]);
      TEST_ASSERT_FALSE(used[out[i]]);
      used[out[i]] = true;
    }
  }
}

static void sort_bytes(char* buf, size_t len) {
  for (size_t i = 1; i < len; i++) {
    for (size_t j = i; j > 0 && buf[j - 1] > buf[j]; j--) {
      const char t = buf[j - 1];
      buf[j - 1] = buf[j];
      buf[j] = t;
    }
  }
}

static void test_random_permute_reorders_without_losing_a_byte(void) {
  static const char src[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  char permuted[sizeof(src)];
  char reference[sizeof(src)];

  strcpy(permuted, src);
  random_permute(permuted, strlen(permuted));

  TEST_ASSERT_EQUAL_UINT(sizeof(src) - 1, strlen(permuted));

  strcpy(reference, src);
  sort_bytes(reference, strlen(reference));
  sort_bytes(permuted, strlen(permuted));
  TEST_ASSERT_EQUAL_STRING(reference, permuted);

  /* A permutation that is the identity for every seed is the loop never running. */
  strcpy(permuted, src);
  hal_host_rng_seed(0x1234);
  random_permute(permuted, strlen(permuted));
  TEST_ASSERT_TRUE_MESSAGE(strcmp(src, permuted) != 0, "random_permute left the string alone");
}

static void test_permuting_nothing_and_one_byte_touches_nothing(void) {
  char buf[] = "abc";

  random_permute(buf, 0);
  random_permute(buf, 1);

  TEST_ASSERT_EQUAL_STRING("abc", buf);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_random32_is_four_bytes_of_the_stream);
  RUN_TEST(test_random_uniform_stays_below_n);
  RUN_TEST(test_random_uniform_reaches_every_value);
  RUN_TEST(test_random_unique_in_range_answers_distinct_values_below_max);
  RUN_TEST(test_asking_for_every_value_returns_every_value);
  RUN_TEST(test_random_permute_reorders_without_losing_a_byte);
  RUN_TEST(test_permuting_nothing_and_one_byte_touches_nothing);
  return UNITY_END();
}
