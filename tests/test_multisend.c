#include "unity.h"
#include "ethereum/eth_multisend.h"
#include <string.h>

static uint8_t data[4096];
void setUp(void) { memset(data, 0, sizeof(data)); }
void tearDown(void) {}
/* Independent canonical ABI encoder; uint256 words are emitted bytewise. */
static void word(uint8_t* p, size_t v) {
  for (int i = 31; i >= 0; i--) { p[i] = v & 255; v >>= 8; }
}
static size_t fixture(unsigned count, size_t child_len) {
  memset(data, 0, sizeof(data));
  memcpy(data, "\x8d\x80\xff\x0a", 4); word(data + 4, 32);
  size_t length = count * (85 + child_len);
  word(data + 36, length);
  for (unsigned i = 0; i < count; i++) {
    uint8_t* p = data + 68 + i * (85 + child_len);
    memset(p + 1, i + 1, 20); p[21] = 0x80; p[52] = i;
    word(p + 53, child_len); memset(p + 85, 0xab, child_len);
  }
  return 68 + (length + 31) / 32 * 32;
}
static void valid(void) {
  for (unsigned count = 1; count <= 16; count++) {
    for (size_t child_len = 0; child_len < 5; child_len++) {
      size_t len = fixture(count, child_len);
      eth_multisend_t b;
      TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
      TEST_ASSERT_EQUAL(count, b.count);
      for (unsigned i = 0; i < count; i++) {
        eth_multisend_call_t c;
        TEST_ASSERT_TRUE(eth_multisend_next(&b, &c));
        TEST_ASSERT_EQUAL(0, c.operation); TEST_ASSERT_EQUAL(i + 1, c.to[0]);
        TEST_ASSERT_EQUAL(0x80, c.value[0]); TEST_ASSERT_EQUAL(i, c.value[31]);
        TEST_ASSERT_EQUAL(child_len, c.data_len);
        if (child_len) TEST_ASSERT_EQUAL(0xab, c.data[child_len - 1]);
      }
      eth_multisend_call_t c;
      TEST_ASSERT_FALSE(eth_multisend_next(&b, &c));
    }
  }
}
static void invalid(void) {
  eth_multisend_t b;
  size_t len = fixture(2, 0);
  data[153] = 2;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
  TEST_ASSERT_EQUAL(0, b.count);
  data[153] = 1;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_CALL_ONLY_V141));
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, ETH_MULTISEND_V150));
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_CALL_ONLY_V150));
  data[153] = 0; data[121] = 1;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
  data[121] = 0; data[len - 1] = 1;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
  data[len - 1] = 0; data[35] = 64;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
}
static void limits(void) {
  eth_multisend_t b;
  size_t len = fixture(17, 0);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_LIMIT, eth_multisend_init(&b, data, len, ETH_MULTISEND_V130));
  len = fixture(0, 0);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_EMPTY, eth_multisend_init(&b, data, len, ETH_MULTISEND_V130));
  for (size_t n = 0; n < 68; n++)
    TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, n, ETH_MULTISEND_V130));
  word(data + 36, 1);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, 100, ETH_MULTISEND_V130));
}
static void deployments(void) {
  const uint8_t target[20] = {0x38,0x86,0x9b,0xf6,0x6a,0x61,0xcf,0x6b,0xdb,0x99,0x6a,0x6a,0xe4,0x0d,0x58,0x53,0xfd,0x43,0xb5,0x26};
  TEST_ASSERT_EQUAL(ETH_MULTISEND_V141, eth_multisend_classify(target));
  const uint8_t multisend150[20] = {0x21,0x85,0x43,0x28,0x80,0x04,0xcd,0x07,0x83,0x24,0x72,0xd4,0x64,0x64,0x81,0x73,0xc7,0x7d,0x7e,0xb7};
  const uint8_t callonly150[20] = {0xa8,0x3c,0x33,0x6b,0x20,0x40,0x1a,0xf7,0x73,0xb6,0x21,0x9b,0xa5,0x02,0x71,0x74,0x33,0x8d,0x18,0x36};
  TEST_ASSERT_EQUAL(ETH_MULTISEND_V150, eth_multisend_classify(multisend150));
  TEST_ASSERT_EQUAL(ETH_MULTISEND_CALL_ONLY_V150, eth_multisend_classify(callonly150));
  uint8_t unknown[20] = {0};
  TEST_ASSERT_EQUAL(ETH_MULTISEND_NONE, eth_multisend_classify(unknown));
  size_t len = fixture(1, 0);
  memcpy(data + 69, target, 20);
  eth_multisend_t b;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
  memset(data + 69, 0, 20);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, ETH_MULTISEND_V141));
}
static void boundaries(void) {
  eth_multisend_t b;
  for (int variant = ETH_MULTISEND_V130; variant <= ETH_MULTISEND_CALL_ONLY_V150; variant++) {
    size_t len = fixture(2, 3);
    TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len, variant));
    for (size_t truncated = 0; truncated < len; truncated++)
      TEST_ASSERT_NOT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, truncated, variant));
    /* Exact payload consumption: 85-byte valid record plus one trailing byte. */
    fixture(1, 0); word(data + 36, 86);
    TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, 164, variant));
    fixture(1, 0); data[0] ^= 1;
    TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, 164, variant));
  }
}
static void random_inputs(void) {
  uint32_t seed = 1234567;
  eth_multisend_t b;
  for (unsigned i = 0; i < 10000; i++) {
    seed = seed * 1664525 + 1013904223;
    size_t len = seed % sizeof(data);
    for (size_t j = 0; j < len; j++) {
      seed = seed * 1664525 + 1013904223; data[j] = seed >> 24;
    }
    eth_multisend_init(&b, data, len, ETH_MULTISEND_V141);
  }
}
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(valid); RUN_TEST(invalid); RUN_TEST(limits); RUN_TEST(deployments); RUN_TEST(random_inputs); RUN_TEST(boundaries);
  return UNITY_END();
}
