#include <stdlib.h>
#include <string.h>
#include "bitcoin/compactsize.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_compactsize.h"

#define MAX_ENC 16

static uint8_t buf[MAX_ENC];

void setUp(void) {
  memset(buf, 0xa5, sizeof(buf));
}

void tearDown(void) {}

static void test_write(void) {
  for (size_t i = 0; i < COMPACTSIZE_VECTOR_COUNT; i++) {
    memset(buf, 0xa5, sizeof(buf));
    uint64_t value = COMPACTSIZE_VECTORS[i].value;
    size_t len = strlen(COMPACTSIZE_VECTORS[i].encoding) / 2;

    TEST_ASSERT_EQUAL_UINT32(len, compactsize_length(value));
    compactsize_write(buf, value);
    TEST_ASSERT_HEX(buf, len, COMPACTSIZE_VECTORS[i].encoding);

    /* Nothing past the encoded width is touched. */
    TEST_ASSERT_EQUAL_UINT8(0xa5, buf[len]);
  }
}

static void test_read(void) {
  for (size_t i = 0; i < COMPACTSIZE_VECTOR_COUNT; i++) {
    size_t len = test_unhex(COMPACTSIZE_VECTORS[i].encoding, buf, sizeof(buf));
    TEST_ASSERT_TRUE(len < sizeof(buf));

    psbt_result_t err = PSBT_OK;
    uint64_t read = compactsize_read(buf, &err);

    if (!COMPACTSIZE_VECTORS[i].readable) {
      /* Over MAX_SERIALIZE_SIZE the reader rejects the length; the decoded value is then
       * meaningless and only the error is contractual. */
      TEST_ASSERT_EQUAL_INT_MESSAGE(PSBT_COMPACT_READ_ERROR, err,
                                    COMPACTSIZE_VECTORS[i].encoding);
      continue;
    }

    TEST_ASSERT_EQUAL_INT(PSBT_OK, err);
    TEST_ASSERT_EQUAL_UINT64(COMPACTSIZE_VECTORS[i].value, read);
  }
}

static void test_peek_length(void) {
  for (size_t i = 0; i < COMPACTSIZE_VECTOR_COUNT; i++) {
    uint8_t prefix;
    TEST_ASSERT_EQUAL_INT(1, sscanf(COMPACTSIZE_VECTORS[i].encoding, "%2hhx", &prefix));
    TEST_ASSERT_EQUAL_UINT32(strlen(COMPACTSIZE_VECTORS[i].encoding) / 2,
                             compactsize_peek_length(prefix));
  }
}

static void test_roundtrip_within_serialize_limit(void) {
  static const uint64_t values[] = {0, 1, 0xfc, 0xfd, 0xfe, 0xffff, 0x10000, 0x1fffffe,
                                    0x2000000};

  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    memset(buf, 0, sizeof(buf));
    compactsize_write(buf, values[i]);

    /* compactsize_read() only writes *err when it fails, so success is "still PSBT_OK". */
    psbt_result_t err = PSBT_OK;
    TEST_ASSERT_EQUAL_UINT64(values[i], compactsize_read(buf, &err));
    TEST_ASSERT_EQUAL_INT(PSBT_OK, err);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_write);
  RUN_TEST(test_read);
  RUN_TEST(test_peek_length);
  RUN_TEST(test_roundtrip_within_serialize_limit);
  return UNITY_END();
}
