#include <stddef.h>
#include <stdint.h>

#include "crypto/railgun_poseidon_t6.h"
#include "framework/test_util.h"
#include "unity.h"

#define ZERO  "0000000000000000000000000000000000000000000000000000000000000000"
#define ONE   "0000000000000000000000000000000000000000000000000000000000000001"
#define TWO   "0000000000000000000000000000000000000000000000000000000000000002"
#define THREE "0000000000000000000000000000000000000000000000000000000000000003"
#define FOUR  "0000000000000000000000000000000000000000000000000000000000000004"
#define FIVE  "0000000000000000000000000000000000000000000000000000000000000005"

#define BASE_X \
  "0bb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051"
#define BASE_Y \
  "25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b"
#define DOUBLE_X \
  "162d7e417903fa1c82f2d227e35b846b1133cfca4f558b5feb9fdcd5f81dd902"
#define DOUBLE_Y \
  "01666cafbf0a30da8b9ebeaf848a1da067a892296f1043188e1705402b6d6853"

void setUp(void) {}
void tearDown(void) {}

static void assert_poseidon(
    const char *values[5], const char *expected_hex) {
  uint8_t inputs[5][32];
  uint8_t expected[32], actual[32];

  for (unsigned i = 0; i < 5; i++) {
    TEST_ASSERT_EQUAL_UINT(32, test_unhex(values[i], inputs[i], 32));
  }

  TEST_ASSERT_EQUAL_UINT(32, test_unhex(expected_hex, expected, 32));
  TEST_ASSERT_EQUAL_INT(
      HAL_SUCCESS, railgun_poseidon_t6_hash(inputs, actual));

  TEST_ASSERT_EQUAL_MEMORY(expected, actual, 32);
}

static void test_upstream_t6_known_answer(void) {
  const char *inputs[5] = {ONE, TWO, THREE, FOUR, FIVE};

  assert_poseidon(
      inputs,
      "0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0");
}

static void test_sequential_input(void) {
  const char *inputs[5] = {ONE, TWO, THREE, FOUR, ZERO};

  assert_poseidon(
      inputs,
      "0cf722cffadc13705135a2f06f7fbeb230f8810ce3aa4f7fffe0b36faaaa4913");
}

static void test_signing_challenge_message_zero(void) {
  const char *inputs[5] = {
      BASE_X, BASE_Y, DOUBLE_X, DOUBLE_Y, ZERO
  };

  assert_poseidon(
      inputs,
      "21294b30f26bf9745b5b10fa865aa7511fd771f9f97ba0a46f5154403e9cf4a3");
}

static void test_signing_challenge_message_one(void) {
  const char *inputs[5] = {
      BASE_X, BASE_Y, DOUBLE_X, DOUBLE_Y, ONE
  };

  assert_poseidon(
      inputs,
      "043f3158943764c52ff052dd081b1833196e3e788eb2feb08c85073b0a086882");
}


/*
 * Check the same big-endian U256 -> Fr reduction used by kohaku_crypto.
 * All inputs are public test constants.
 */
static void assert_equivalent_inputs(
    const char *canonical[5],
    const char *noncanonical[5]) {
  uint8_t a[5][32], b[5][32];
  uint8_t first[32], second[32];

  for (unsigned i = 0; i < 5; i++) {
    TEST_ASSERT_EQUAL_UINT(
        32, test_unhex(canonical[i], a[i], 32));
    TEST_ASSERT_EQUAL_UINT(
        32, test_unhex(noncanonical[i], b[i], 32));
  }

  TEST_ASSERT_EQUAL_INT(
      HAL_SUCCESS, railgun_poseidon_t6_hash(a, first));
  TEST_ASSERT_EQUAL_INT(
      HAL_SUCCESS, railgun_poseidon_t6_hash(b, second));
  TEST_ASSERT_EQUAL_MEMORY(first, second, 32);
}

static void test_poseidon_field_reduction(void) {
  const char *fr =
      "30644e72e131a029b85045b68181585"
      "d2833e84879b9709143e1f593f0000001";
  const char *fr_plus_one =
      "30644e72e131a029b85045b68181585"
      "d2833e84879b9709143e1f593f0000002";
  const char *max_u256 =
      "ffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffff";
  const char *max_u256_remainder =
      "0e0a77c19a07df2f666ea36f7879462e"
      "36fc76959f60cd29ac96341c4ffffffa";

  const char *zero_case[5] = {
      ZERO, ONE, TWO, THREE, FOUR
  };
  const char *fr_case[5] = {
      fr, ONE, TWO, THREE, FOUR
  };
  assert_equivalent_inputs(zero_case, fr_case);

  const char *one_case[5] = {
      ONE, TWO, THREE, FOUR, FIVE
  };
  const char *fr_plus_one_case[5] = {
      fr_plus_one, TWO, THREE, FOUR, FIVE
  };
  assert_equivalent_inputs(one_case, fr_plus_one_case);

  const char *max_reduced_case[5] = {
      max_u256_remainder, ONE, TWO, THREE, FOUR
  };
  const char *max_case[5] = {
      max_u256, ONE, TWO, THREE, FOUR
  };
  assert_equivalent_inputs(max_reduced_case, max_case);
}

static void test_poseidon_rejects_null_arguments(void) {
  uint8_t inputs[5][32] = {{0}};
  uint8_t output[32];

  TEST_ASSERT_EQUAL_INT(
      HAL_FAIL, railgun_poseidon_t6_hash(NULL, output));
  TEST_ASSERT_EQUAL_INT(
      HAL_FAIL, railgun_poseidon_t6_hash(inputs, NULL));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_upstream_t6_known_answer);
  RUN_TEST(test_sequential_input);
  RUN_TEST(test_signing_challenge_message_zero);
  RUN_TEST(test_signing_challenge_message_one);
  RUN_TEST(test_poseidon_field_reduction);
  RUN_TEST(test_poseidon_rejects_null_arguments);
  return UNITY_END();
}
