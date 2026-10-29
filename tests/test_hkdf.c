#include <stdlib.h>
#include <string.h>
#include "crypto/hkdf.h"
#include "framework/test_util.h"
#include "vectors/vectors_hkdf.h"
#include "unity.h"

#define MAX_IO 256

static uint8_t ikm[MAX_IO];
static size_t ikm_len;
static uint8_t salt[MAX_IO];
static size_t salt_len;
static uint8_t info[MAX_IO];
static size_t info_len;
static uint8_t prk[HKDF_SHA256_DIGEST_LENGTH];
static uint8_t okm[HKDF_SHA256_MAX_OKM_LEN + 1];

void setUp(void) {
  ikm_len = 0;
  salt_len = 0;
  info_len = 0;
}

void tearDown(void) {}

static size_t load(const char* hex, uint8_t* out) {
  size_t len = 0;
  for (const char* p = hex; *p; p += 2) {
    TEST_ASSERT_TRUE(len < MAX_IO);
    TEST_ASSERT_EQUAL_INT(1, sscanf(p, "%2hhx", &out[len++]));
  }
  return len;
}

static void test_extract_expand(void) {
  for (size_t i = 0; i < HKDF_KAT_COUNT; i++) {
    ikm_len = load(HKDF_KAT[i].ikm, ikm);
    salt_len = load(HKDF_KAT[i].salt, salt);
    info_len = load(HKDF_KAT[i].info, info);

    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    TEST_ASSERT_HEX(prk, sizeof(prk), HKDF_KAT[i].prk);

    TEST_ASSERT_EQUAL_INT(0, hkdf_sha256_expand(prk, info, info_len, okm, HKDF_KAT[i].l));
    TEST_ASSERT_HEX(okm, HKDF_KAT[i].l, HKDF_KAT[i].okm);
  }
}

static void test_all_in_one(void) {
  for (size_t i = 0; i < HKDF_KAT_COUNT; i++) {
    ikm_len = load(HKDF_KAT[i].ikm, ikm);
    salt_len = load(HKDF_KAT[i].salt, salt);
    info_len = load(HKDF_KAT[i].info, info);

    memset(okm, 0, HKDF_KAT[i].l);
    TEST_ASSERT_EQUAL_INT(
        0, hkdf_sha256(salt, salt_len, ikm, ikm_len, info, info_len, okm, HKDF_KAT[i].l));
    TEST_ASSERT_HEX(okm, HKDF_KAT[i].l, HKDF_KAT[i].okm);
  }
}

static void test_rejects_over_long_output(void) {
  memset(prk, 0x2a, sizeof(prk));

  TEST_ASSERT_EQUAL_INT(0, hkdf_sha256_expand(prk, NULL, 0, okm, HKDF_SHA256_MAX_OKM_LEN));
  TEST_ASSERT_EQUAL_INT(-1, hkdf_sha256_expand(prk, NULL, 0, okm, HKDF_SHA256_MAX_OKM_LEN + 1));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_extract_expand);
  RUN_TEST(test_all_in_one);
  RUN_TEST(test_rejects_over_long_output);
  return UNITY_END();
}
