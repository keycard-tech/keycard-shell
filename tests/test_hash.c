#include <stdlib.h>
#include <string.h>
#include "crypto/crc32.h"
#include "crypto/ripemd160.h"
#include "crypto/sha2.h"
#include "crypto/sha3.h"
#include "framework/test_util.h"
#include "vectors/vectors_hash.h"
#include "unity.h"

#define MAX_MSG 1024

static uint8_t msg[MAX_MSG];
static size_t msg_len;
static uint8_t digest[SHA512_DIGEST_LENGTH];

void setUp(void) {
  memset(msg, 0, sizeof(msg));
  msg_len = 0;
  memset(digest, 0, sizeof(digest));
}

void tearDown(void) {}

static void load(const char* hex) {
  msg_len = 0;
  for (const char* p = hex; *p; p += 2) {
    uint8_t byte = 0;
    TEST_ASSERT_EQUAL_INT(1, sscanf(p, "%2hhx", &byte));
    TEST_ASSERT_TRUE(msg_len < MAX_MSG);
    msg[msg_len++] = byte;
  }
}

static void sha256_chunked(size_t chunk) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  for (size_t off = 0; off < msg_len; off += chunk) {
    size_t n = (msg_len - off < chunk) ? msg_len - off : chunk;
    sha256_Update(&ctx, &msg[off], n);
  }
  sha256_Final(&ctx, digest);
}

static void sha512_chunked(size_t chunk) {
  SHA512_CTX ctx;
  sha512_Init(&ctx);
  for (size_t off = 0; off < msg_len; off += chunk) {
    size_t n = (msg_len - off < chunk) ? msg_len - off : chunk;
    sha512_Update(&ctx, &msg[off], n);
  }
  sha512_Final(&ctx, digest);
}

static void sha3_chunked(size_t chunk, int five12) {
  SHA3_CTX ctx;
  if (five12) {
    sha3_512_Init(&ctx);
  } else {
    sha3_256_Init(&ctx);
  }
  for (size_t off = 0; off < msg_len; off += chunk) {
    size_t n = (msg_len - off < chunk) ? msg_len - off : chunk;
    sha3_Update(&ctx, &msg[off], n);
  }
  sha3_Final(&ctx, digest);
}

static void keccak_chunked(size_t chunk) {
  SHA3_CTX ctx;
  keccak_256_Init(&ctx);
  for (size_t off = 0; off < msg_len; off += chunk) {
    size_t n = (msg_len - off < chunk) ? msg_len - off : chunk;
    keccak_Update(&ctx, &msg[off], n);
  }
  keccak_Final(&ctx, digest);
}

static void test_sha256(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);
    sha256_Raw(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, SHA256_DIGEST_LENGTH, HASH_KAT[i].sha256);

    sha256_chunked(1);
    TEST_ASSERT_HEX(digest, SHA256_DIGEST_LENGTH, HASH_KAT[i].sha256);
    sha256_chunked(7);
    TEST_ASSERT_HEX(digest, SHA256_DIGEST_LENGTH, HASH_KAT[i].sha256);
  }
}

static void test_sha512(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);
    sha512_Raw(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, SHA512_DIGEST_LENGTH, HASH_KAT[i].sha512);

    sha512_chunked(1);
    TEST_ASSERT_HEX(digest, SHA512_DIGEST_LENGTH, HASH_KAT[i].sha512);
    sha512_chunked(9);
    TEST_ASSERT_HEX(digest, SHA512_DIGEST_LENGTH, HASH_KAT[i].sha512);
  }
}

static void test_ripemd160(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);
    ripemd160(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, RIPEMD160_DIGEST_LENGTH, HASH_KAT[i].ripemd160);
  }
}

static void test_sha3(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);

    sha3_256(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, SHA3_256_DIGEST_LENGTH, HASH_KAT[i].sha3_256);
    sha3_chunked(1, 0);
    TEST_ASSERT_HEX(digest, SHA3_256_DIGEST_LENGTH, HASH_KAT[i].sha3_256);

    sha3_512(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, SHA3_512_DIGEST_LENGTH, HASH_KAT[i].sha3_512);
    sha3_chunked(5, 1);
    TEST_ASSERT_HEX(digest, SHA3_512_DIGEST_LENGTH, HASH_KAT[i].sha3_512);
  }
}

static void test_keccak(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);
    keccak_256(msg, msg_len, digest);
    TEST_ASSERT_HEX(digest, SHA3_256_DIGEST_LENGTH, HASH_KAT[i].keccak_256);
    keccak_chunked(3);
    TEST_ASSERT_HEX(digest, SHA3_256_DIGEST_LENGTH, HASH_KAT[i].keccak_256);
  }
}

static void test_crc32(void) {
  for (size_t i = 0; i < HASH_KAT_COUNT; i++) {
    load(HASH_KAT[i].msg);
    TEST_ASSERT_EQUAL_HEX32((uint32_t)strtoul(HASH_KAT[i].crc32, NULL, 16), crc32(msg, msg_len));

    crc32_ctx_t ctx;
    uint32_t out;
    crc32_init(&ctx);
    crc32_update(&ctx, msg, msg_len);
    crc32_finish(&ctx, &out);
    TEST_ASSERT_EQUAL_HEX32((uint32_t)strtoul(HASH_KAT[i].crc32, NULL, 16), out);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_sha256);
  RUN_TEST(test_sha512);
  RUN_TEST(test_ripemd160);
  RUN_TEST(test_sha3);
  RUN_TEST(test_keccak);
  RUN_TEST(test_crc32);
  return UNITY_END();
}
