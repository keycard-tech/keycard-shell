#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include "unity.h"

char* test_hex(const uint8_t* data, size_t len);

/* Decodes a hex vector into a buffer; aborts if the vector itself is malformed. Returns the
 * byte count, or max if it would not fit, which the caller is expected to compare against. */
size_t test_unhex(const char* hex, uint8_t* out, size_t max);

void test_assert_hex_(const char* file, int line, const uint8_t* actual, size_t actual_len,
                      const char* expected_hex, const char* message);

/* The vector headers carry expected values as hex strings; this decodes and compares, so a
 * failure prints both sides as hex rather than comparing a digest to its rendering. */
#define TEST_ASSERT_HEX(actual, actual_len, expected_hex) \
  test_assert_hex_(__FILE__, __LINE__, (actual), (actual_len), (expected_hex), NULL)

/* For a table of vectors, where the row is otherwise unidentifiable. */
#define TEST_ASSERT_HEX_MESSAGE(actual, actual_len, expected_hex, message) \
  test_assert_hex_(__FILE__, __LINE__, (actual), (actual_len), (expected_hex), (message))

#endif
