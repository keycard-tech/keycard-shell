#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/address.h"
#include "crypto/segwit_addr.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_bech32.h"

#define MAX_PROG 40

static uint8_t program[MAX_PROG];
static uint8_t decoded[MAX_PROG];
static char address[MAX_ADDR_LEN];

void setUp(void) {
  memset(program, 0, sizeof(program));
  memset(decoded, 0, sizeof(decoded));
  memset(address, 0, sizeof(address));
}

void tearDown(void) {}

static void lowercase(const char* text, char* out) {
  size_t i = 0;
  for (; text[i] != '\0'; i++) {
    out[i] = tolower((unsigned char)text[i]);
  }
  out[i] = '\0';
}

static void check_row(const witness_program_t* row) {
  size_t program_len = test_unhex(row->program, program, sizeof(program));
  TEST_ASSERT_TRUE(program_len >= 2);

  int ver = -1;
  size_t decoded_len = 0;
  TEST_ASSERT_EQUAL_MESSAGE(1,
                            segwit_addr_decode(&ver, decoded, &decoded_len, row->hrp, row->address),
                            row->address);
  TEST_ASSERT_EQUAL_INT(row->witver, ver);
  TEST_ASSERT_EQUAL_UINT32((uint32_t)program_len, (uint32_t)decoded_len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(program, decoded, program_len);

  TEST_ASSERT_EQUAL_INT(1, segwit_addr_encode(address, row->hrp, row->witver, program, program_len));

  char expected[MAX_ADDR_LEN];
  lowercase(row->address, expected);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, address, row->address);
}

static void test_bech32_vectors(void) {
  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    check_row(&BECH32_VALID[i]);
  }
}

static void test_bech32m_vectors(void) {
  for (size_t i = 0; i < BECH32M_VALID_COUNT; i++) {
    check_row(&BECH32M_VALID[i]);
  }
}

static void test_rejects_invalid(void) {
  int ver = -1;
  size_t len = 0;

  for (size_t i = 0; i < BECH32_INVALID_COUNT; i++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(0,
                                  segwit_addr_decode(&ver, decoded, &len, SEGWIT_HRP,
                                                     BECH32_INVALID[i]),
                                  BECH32_INVALID[i]);
  }

  for (size_t i = 0; i < BECH32M_INVALID_COUNT; i++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(0,
                                  segwit_addr_decode(&ver, decoded, &len, SEGWIT_HRP,
                                                     BECH32M_INVALID[i]),
                                  BECH32M_INVALID[i]);
  }
}

/* The checksum type is part of the string: bech32 for witness v0, bech32m above it. A
 * decoder that accepted either for either version would silently trade one for the other. */
static void test_encodings_are_not_interchangeable(void) {
  const witness_program_t* v0 = NULL;
  const witness_program_t* v1 = NULL;

  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    if ((BECH32_VALID[i].witver == 0) && (strcmp(BECH32_VALID[i].hrp, SEGWIT_HRP) == 0)) {
      v0 = &BECH32_VALID[i];
      break;
    }
  }
  for (size_t i = 0; i < BECH32M_VALID_COUNT; i++) {
    if ((BECH32M_VALID[i].witver == 1) && (strcmp(BECH32M_VALID[i].hrp, SEGWIT_HRP) == 0)) {
      v1 = &BECH32M_VALID[i];
      break;
    }
  }

  TEST_ASSERT_NOT_NULL(v0);
  TEST_ASSERT_NOT_NULL(v1);

  char hrp[16];
  uint8_t data[128];
  size_t data_len = 0;

  TEST_ASSERT_EQUAL_INT(BECH32_ENCODING_BECH32, bech32_decode(hrp, data, &data_len, v0->address));
  TEST_ASSERT_EQUAL_STRING(SEGWIT_HRP, hrp);

  data_len = 0;
  TEST_ASSERT_EQUAL_INT(BECH32_ENCODING_BECH32M, bech32_decode(hrp, data, &data_len, v1->address));
  TEST_ASSERT_EQUAL_STRING(SEGWIT_HRP, hrp);

  /* Re-encoding the v0 program as witness version 1 changes the checksum, so the result is
   * a different address rather than the same one under another encoding. */
  size_t program_len = test_unhex(v0->program, program, sizeof(program));
  TEST_ASSERT_EQUAL_INT(1, segwit_addr_encode(address, SEGWIT_HRP, BTC_TAPROOT_WITVER, program,
                                              program_len));
  TEST_ASSERT_TRUE_MESSAGE(strcmp(address, v0->address) != 0, address);
}

static void test_address_format_btc(void) {
  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    const witness_program_t* row = &BECH32_VALID[i];
    if ((strcmp(row->hrp, SEGWIT_HRP) != 0) || (row->witver != 0)) {
      continue;
    }
    size_t program_len = test_unhex(row->program, program, sizeof(program));
    if (program_len != 20) {
      continue;
    }

    char out[MAX_ADDR_LEN];
    char expected[MAX_ADDR_LEN];
    TEST_ASSERT_TRUE(address_format(ADDR_BTC_SEGWIT, program, out));
    lowercase(row->address, expected);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, out, row->address);
  }

  for (size_t i = 0; i < BECH32M_VALID_COUNT; i++) {
    const witness_program_t* row = &BECH32M_VALID[i];
    if ((strcmp(row->hrp, SEGWIT_HRP) != 0) || (row->witver != BTC_TAPROOT_WITVER)) {
      continue;
    }
    size_t program_len = test_unhex(row->program, program, sizeof(program));
    if (program_len != BTC_TAPROOT_WITPROG_LEN) {
      continue;
    }

    char out[MAX_ADDR_LEN];
    char expected[MAX_ADDR_LEN];
    TEST_ASSERT_TRUE(address_format(ADDR_BTC_TAPROOT, program, out));
    lowercase(row->address, expected);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, out, row->address);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_bech32_vectors);
  RUN_TEST(test_bech32m_vectors);
  RUN_TEST(test_rejects_invalid);
  RUN_TEST(test_encodings_are_not_interchangeable);
  RUN_TEST(test_address_format_btc);
  return UNITY_END();
}
