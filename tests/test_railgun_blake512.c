#include <stdint.h>
#include <string.h>

#include "crypto/railgun_blake512.h"
#include "framework/test_util.h"
#include "unity.h"

#define KEY_HASH \
  "d5fd3ee4e647c91d1029e83e2ef11401069e3fc7a75563c892489e1ef2a64f1d" \
  "5dc8cd2a722c7bb8038681d2f894217f75950a69ef24253426168a365a10bb82"

void setUp(void) {}
void tearDown(void) {}

static void assert_digest(
    const uint8_t *input, size_t length, const char *expected_hex) {
  uint8_t expected[64];
  uint8_t actual[64];

  TEST_ASSERT_EQUAL_UINT(
      64, test_unhex(expected_hex, expected, sizeof(expected)));
  TEST_ASSERT_TRUE(railgun_blake512(input, length, actual));
  TEST_ASSERT_EQUAL_MEMORY(expected, actual, sizeof(actual));
}

static void test_empty(void) {
  assert_digest(
      NULL, 0,
      "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b"
      "628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8");
}

static void test_abc(void) {
  assert_digest(
      (const uint8_t *)"abc", 3,
      "14266c7c704a3b58fb421ee69fd005fcc6eeff742136be67435df995b7c986e7"
      "cbde4dbde135e7689c354d2bc5b8d260536c554b4f84c118e61efc576fed7cd3");
}

static void test_synthetic_key(void) {
  uint8_t key[32];
  memset(key, 1, sizeof(key));
  assert_digest(key, sizeof(key), KEY_HASH);
}

static void assert_nonce(uint32_t message, const char *expected) {
  uint8_t key_hash[64];
  uint8_t nonce_input[64] = {0};

  TEST_ASSERT_EQUAL_UINT(
      64, test_unhex(KEY_HASH, key_hash, sizeof(key_hash)));

  memcpy(nonce_input, key_hash + 32, 32);

  nonce_input[32] = (uint8_t)message;
  nonce_input[33] = (uint8_t)(message >> 8);
  nonce_input[34] = (uint8_t)(message >> 16);
  nonce_input[35] = (uint8_t)(message >> 24);

  assert_digest(nonce_input, sizeof(nonce_input), expected);
}

static void test_nonce_zero(void) {
  assert_nonce(
      0,
      "e78f6e64c3c7057fa9f73204e8949c3c918271500b6ec1c4447ecfbfe9008596"
      "c1514687e4e8358666c2ed8c9ba6f91af2c77b68b09522f85b10c074cff140d5");
}

static void test_nonce_one(void) {
  assert_nonce(
      1,
      "c3879ae9e093e1c3575a3e87802f7c37296c19c733369be87d242ff6b08348e0"
      "68fa94638d2ae9bf9d52043a3aa2bf8520b2a4761e33e7bcfad48a120e2bed75");
}

static void test_nonce_12345(void) {
  assert_nonce(
      12345,
      "721677225ff6ca56508eb32565ccdeefa7cea1842891b02016d31ef571f3575b8"
      "1991a42aa5d496e3b4c4bd2b49d43adca35f0e7907c2e3657bd6548322ad5b3");
}


static void test_block_boundary_vectors(void) {
  static const struct {
    size_t length;
    const char *expected;
  } vectors[] = {
    {1,
      "d34a3e87e9014e86ede936eed877c465b8d6ad77b0d051061e2f82e5b1cf652c"
      "b8715f638783dc7dedabef3080a4984308e7b2dfec7b16239087f7e84dee62b2"},
    {111,
      "4c3758fb1245ca54cf7bb798981b39dc4b3af7d25ee691a7bd44f7a59038958d"
      "c95a2f79283b47b3817aee4d60d34f3cd5e378a3907458d6152faa3fd9ce94eb"},
    {112,
      "43004df206f0a5fb912de57a5859c2393d4ee0594094fe6797bf946b99fc76c5"
      "ec6bc607bf29674c928b66f4ad78754283188a5665b34fd3ac0a1ef9622cccf4"},
    {127,
      "125acb45c9010884c88cba995404f850bf4a50f1d6973cac0cacfe4e261db2ee"
      "168e5639beeba397dc7d694bb2719faaeb19bd1938a69bd87cdc85c92deb3195"},
    {128,
      "2c93ecf41e36bcd3b5a075cce12a28c5fcfeab6d8bfca497a076cbaed6c08f26"
      "4189e7c63d0dd045732af8c7c79cae15b3cbf04fe2ba43b22fffdf1e5f3e3886"},
    {129,
      "5f75508e2b3c4988de2a7521a05dd09306d43c01873110225d168bedd7a64b89"
      "6a0389a42ff642734261ff43076d3d44d6f20e9c4897b511dfa88bbd9dbf1a70"},
    {255,
      "8390fd910ac83db859c971e7137300ac3525d5edcddd3fdbba721e41ab3181da"
      "036756bd95ae7239eb3e9c4dfa63e07b7ccc6e06640f243c9f562064c6e23a08"},
    {256,
      "f09cca30917c28032ebf5accb991937e9f495ab2ec3feacb9787290d97c6d8c7"
      "b52586b2df8ed727304bab3ddbef57e5be342bdeb0d518078b360866ed9fd782"},
    {257,
      "dd5301c99bfd4e13978f4c9ec1bc5f4b1bcbba6162b1b279c7658ea69e104a16"
      "8fcbda00fa7bd478090cfc67a4c455f8ff8f411afbed10476142b1f065f3afd0"},
    {1024,
      "bd9249d9f10cffd2d963dc3a7535e198087e3701164149ad2f4a34c975118e22"
      "64ad13d8027805c9891f2f70516178bb20cbbbcec812308f2024b9f7262c5361"},
  };

  uint8_t message[1024];

  for (size_t i = 0; i < sizeof(message); i++) {
    message[i] = (uint8_t)((i * 17u + 29u) & 0xffu);
  }

  for (size_t i = 0;
       i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    assert_digest(
        message, vectors[i].length, vectors[i].expected);
  }
}

static void test_null_arguments(void) {
  uint8_t output[64];

  TEST_ASSERT_FALSE(railgun_blake512(NULL, 1, output));
  TEST_ASSERT_FALSE(railgun_blake512(
      (const uint8_t *)"abc", 3, NULL));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_empty);
  RUN_TEST(test_abc);
  RUN_TEST(test_synthetic_key);
  RUN_TEST(test_nonce_zero);
  RUN_TEST(test_nonce_one);
  RUN_TEST(test_nonce_12345);
  RUN_TEST(test_block_boundary_vectors);
  RUN_TEST(test_null_arguments);
  return UNITY_END();
}
