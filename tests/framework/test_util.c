#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_util.h"

static int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

size_t test_unhex(const char* hex, uint8_t* out, size_t max) {
  size_t len = 0;
  while (hex[0] != '\0') {
    int hi = nibble(hex[0]);
    int lo = nibble(hex[1]);
    if ((hi < 0) || (lo < 0)) {
      fprintf(stderr, "\nvector is not hex at offset %zu: %s\n", len * 2, hex);
      abort();
    }
    if (len == max) {
      fprintf(stderr, "\nvector longer than %zu bytes: %s\n", max, hex);
      abort();
    }
    out[len++] = (uint8_t)((hi << 4) | lo);
    hex += 2;
  }
  return len;
}

char* test_hex(const uint8_t* data, size_t len) {
  static char buf[1024];
  if (len > (sizeof(buf) - 1) / 2) {
    len = (sizeof(buf) - 1) / 2;
  }
  for (size_t i = 0; i < len; i++) {
    sprintf(&buf[i * 2], "%02x", data[i]);
  }
  buf[len * 2] = '\0';
  return buf;
}

void test_assert_hex_(const char* file, int line, const uint8_t* actual, size_t actual_len, const char* expected_hex) {
  uint8_t expected[2048];
  size_t expected_len = test_unhex(expected_hex, expected, sizeof(expected));

  UnityAssertEqualNumber((UNITY_INT)expected_len, (UNITY_INT)actual_len,
                         "length differs from vector", (UNITY_LINE_TYPE)line, UNITY_DISPLAY_STYLE_UINT32);
  if (expected_len != actual_len) {
    fprintf(stderr, "\nexpected %s\nactual   %s\n", expected_hex, test_hex(actual, actual_len));
    return;
  }

  UnityAssertEqualMemory((UNITY_INTERNAL_PTR)expected, (UNITY_INTERNAL_PTR)actual,
                         (UNITY_UINT)actual_len, (UNITY_UINT)1, NULL, (UNITY_LINE_TYPE)line, (UNITY_FLAGS_T)0);
}
