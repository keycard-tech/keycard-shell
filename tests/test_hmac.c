#include <stdlib.h>
#include <string.h>
#include "crypto/hmac.h"
#include "framework/test_util.h"
#include "vectors/vectors_hmac.h"
#include "unity.h"

#define MAX_IO 512

static uint8_t key[MAX_IO];
static size_t key_len;
static uint8_t data[MAX_IO];
static size_t data_len;
static uint8_t mac[SHA512_DIGEST_LENGTH];

void setUp(void) {
  key_len = 0;
  data_len = 0;
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

static void check(const char* expected) {
  TEST_ASSERT_HEX(mac, strlen(expected) / 2, expected);
}

static void test_hmac_sha256(void) {
  for (size_t i = 0; i < HMAC_KAT_COUNT; i++) {
    key_len = load(HMAC_KAT[i].key, key);
    data_len = load(HMAC_KAT[i].data, data);

    hmac_sha256(key, key_len, data, data_len, mac);
    check(HMAC_KAT[i].sha256);

    HMAC_SHA256_CTX ctx;
    hmac_sha256_Init(&ctx, key, key_len);
    for (size_t off = 0; off < data_len; off += 3) {
      hmac_sha256_Update(&ctx, &data[off], (data_len - off < 3) ? data_len - off : 3);
    }
    hmac_sha256_Final(&ctx, mac);
    check(HMAC_KAT[i].sha256);
  }
}

static void test_hmac_sha512(void) {
  for (size_t i = 0; i < HMAC_KAT_COUNT; i++) {
    key_len = load(HMAC_KAT[i].key, key);
    data_len = load(HMAC_KAT[i].data, data);

    hmac_sha512(key, key_len, data, data_len, mac);
    check(HMAC_KAT[i].sha512);

    HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx, key, key_len);
    hmac_sha512_Update(&ctx, data, data_len);
    hmac_sha512_Final(&ctx, mac);
    check(HMAC_KAT[i].sha512);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_hmac_sha256);
  RUN_TEST(test_hmac_sha512);
  return UNITY_END();
}
