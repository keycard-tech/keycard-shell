#include <stdint.h>
#include <string.h>

#include "crypto/privacy_pools_v1.h"
#include "framework/test_util.h"
#include "unity.h"

static uint8_t root[32];
static uint8_t output[32];

void setUp(void) {
  for (size_t i = 0; i < sizeof(root); i++) {
    root[i] = (uint8_t)i;
  }
  memset(output, 0, sizeof(output));
}

void tearDown(void) {}

static void check_vector(const char *path, const char *expected) {
  TEST_ASSERT_EQUAL_INT(
      ERR_OK,
      privacy_pools_v1_derive_at(
          root, path, strlen(path), output));
  TEST_ASSERT_HEX(output, sizeof(output), expected);
}

static void test_v3_derivation_vectors(void) {
  check_vector(
      "m/28784'/1'/0'",
      "fe3e26d289a07d4cb4a2b38181a5060998688cd74d102a13cbcbb79ccff1faf9");

  check_vector(
      "m/28784'/1'/0'/17'/1'",
      "705e47a802658650d835b9a08c9e9da7d4d7c362638c5c86070c2e356b65c91e");
}

static void test_invalid_paths(void) {
  const char *invalid[] = {
      "",
      "m/28784'/1'",
      "m/28784'/1'/01'",
      "m/28784'/1'/0",
      "m/28784'/2'/0'",
      "m/28784'/1'/0'junk",
      "m/28784'/1'/0'/"
  };
  uint8_t zero[32] = {0};

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    memset(output, 0xaa, sizeof(output));
    TEST_ASSERT_EQUAL_INT(
        ERR_DATA,
        privacy_pools_v1_derive_at(
            root, invalid[i], strlen(invalid[i]), output));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, output, sizeof(output));
  }
}

static void test_overlapping_secret_buffers(void) {
  const char *path = "m/28784'/1'/0'";
  uint8_t shared[64];
  uint8_t original[64];

  for (size_t i = 0; i < sizeof(shared); i++) {
    shared[i] = (uint8_t)i;
  }
  memcpy(original, shared, sizeof(shared));

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA,
      privacy_pools_v1_derive_at(
          shared, path, strlen(path), shared));
  TEST_ASSERT_EQUAL_MEMORY(original, shared, sizeof(shared));

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA,
      privacy_pools_v1_derive_at(
          shared, path, strlen(path), shared + 1));
  TEST_ASSERT_EQUAL_MEMORY(original, shared, sizeof(shared));

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA,
      privacy_pools_v1_derive_at(
          shared + 1, path, strlen(path), shared));
  TEST_ASSERT_EQUAL_MEMORY(original, shared, sizeof(shared));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_v3_derivation_vectors);
  RUN_TEST(test_invalid_paths);
  RUN_TEST(test_overlapping_secret_buffers);
  return UNITY_END();
}
