#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/util.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_util.h"

/*
 * util.c is where a string becomes a number. Two of its functions sit directly under a signature:
 * eip712.c hands whatever the request said for an int or uint field to str_to_int256, negates the
 * result if it was negative, and hashes it -- so if decimal_to_256 carries a bit wrong, the device
 * approves a number that is not the one it displayed, in a shape that looks entirely plausible. The
 * other two, pad_iso9797_m1 and unpad_iso9797_m1, frame every APDU of the v1 secure channel, which
 * has no other test because it needs a card to talk to.
 */

void setUp(void) {}

void tearDown(void) {}

static uint8_t* exact(const void* src, size_t len) {
  uint8_t* copy = malloc(len ? len : 1);
  memcpy(copy, src, len);
  return copy;
}

static void test_a_typed_number_is_the_integer_it_says(void) {
  for (size_t i = 0; i < INT256_KAT_COUNT; i++) {
    const int256_kat_t* v = &INT256_KAT[i];
    if (v->mag_hex == NULL) {
      continue;
    }

    uint8_t text[128];
    const size_t len = test_unhex(v->text_hex, text, sizeof(text));
    TEST_ASSERT_LESS_OR_EQUAL_INT((int)sizeof(text), (int)len);

    uint8_t mag[32], value[32];
    bool negative = false;

    TEST_ASSERT_TRUE_MESSAGE(str_to_int256((const char*)text, len, mag, &negative), v->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(v->negative, negative, v->name);
    TEST_ASSERT_HEX_MESSAGE(mag, sizeof(mag), v->mag_hex, v->name);
    /* How many bytes of the magnitude carry information, which is what eip712_trim_magnitude turns
     * into the number of bytes of the struct hash. */
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->significant, (unsigned)significant_256(mag), v->name);

    /* eip712_copy_uint: negate in place, and what is left is what goes into the struct hash. */
    memcpy(value, mag, sizeof(value));
    if (negative) {
      negate_256(value);
    }
    TEST_ASSERT_HEX_MESSAGE(value, sizeof(value), v->value_hex, v->name);
  }
}

static void test_what_is_not_a_number_is_refused(void) {
  for (size_t i = 0; i < INT256_KAT_COUNT; i++) {
    const int256_kat_t* v = &INT256_KAT[i];
    if (v->mag_hex != NULL) {
      continue;
    }

    uint8_t text[128], mag[32];
    const size_t len = test_unhex(v->text_hex, text, sizeof(text));
    TEST_ASSERT_LESS_OR_EQUAL_INT((int)sizeof(text), (int)len);
    bool negative = false;

    TEST_ASSERT_FALSE_MESSAGE(str_to_int256((const char*)text, len, mag, &negative), v->name);
  }
}

static void test_negation_round_trips_and_wraps(void) {
  for (size_t i = 0; i < INT256_KAT_COUNT; i++) {
    const int256_kat_t* v = &INT256_KAT[i];
    if (v->value_hex == NULL) {
      continue;
    }

    uint8_t value[32], back[32];
    TEST_GIVEN(v->value_hex, value, sizeof(value));
    memcpy(back, value, sizeof(back));

    negate_256(back);
    negate_256(back);
    TEST_ASSERT_HEX_MESSAGE(back, sizeof(back), v->value_hex, v->name);
  }

  /* Two's complement has one more negative than positive: -2**255 is its own negation mod 2**256,
   * which is where a carry handling mistake in negate_256 shows up. */
  static const char min_int256[] = "8000000000000000000000000000000000000000000000000000000000000000";
  uint8_t v[32];
  TEST_GIVEN(min_int256, v, sizeof(v));
  negate_256(v);
  TEST_ASSERT_HEX(v, sizeof(v), min_int256);
}

static void test_compare_256_orders_as_an_unsigned(void) {
  static const uint8_t zero[32] = {0};
  uint8_t low[32], high[32];

  TEST_ASSERT_EQUAL_INT(0, compare_256(zero, zero));

  memset(low, 0, sizeof(low));
  memset(high, 0, sizeof(high));
  low[31] = 1;
  TEST_ASSERT_EQUAL_INT(-1, compare_256(zero, low));
  TEST_ASSERT_EQUAL_INT(1, compare_256(low, zero));

  /* Only the last byte differs, and only the top bit of the first: the signed reading of the second
   * pair would order them the other way. */
  memset(low, 0xff, sizeof(low));
  low[31] = 0xfe;
  memset(high, 0xff, sizeof(high));
  TEST_ASSERT_EQUAL_INT(-1, compare_256(low, high));

  memset(low, 0, sizeof(low));
  low[0] = 0x80;
  memset(high, 0xff, sizeof(high));
  TEST_ASSERT_EQUAL_INT(-1, compare_256(low, high));
}

static void test_iso7816_m1_padding(void) {
  for (size_t i = 0; i < PAD_KAT_COUNT; i++) {
    const pad_kat_t* v = &PAD_KAT[i];

    uint8_t payload[64];
    const size_t len = test_unhex(v->data_hex, payload, sizeof(payload));

    /* Allocated to the width the call needs, so that one byte more of memset is a sanitizer report. */
    uint8_t* buf = exact(payload, v->room);

    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->padded_len, pad_iso9797_m1(buf, v->block, (uint32_t)len), v->data_hex);
    TEST_ASSERT_HEX_MESSAGE(buf, v->padded_len, v->padded_hex, v->data_hex);

    /* The point of the padding: unpadding recovers the length, whatever the payload ended with. */
    TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)len, unpad_iso9797_m1(buf, v->padded_len), v->data_hex);

    free(buf);
  }
}

static void test_unpadding_a_message_that_was_never_padded(void) {
  /* secure_channel_v1.c takes the return value of unpad_iso9797_m1 as the plaintext length of an
   * already-decrypted APDU with no further check, so what it does on data that carries no 0x80 is
   * what the card gets away with: the scan runs off the end and reports 0, not a crash and not the
   * whole buffer. */
  static const struct {
    const char* data_hex;
    uint32_t want;
  } cases[] = {
      {"", 0},
      {"00", 0},
      {"000000", 0},
      {"a1b2c3", 0},
      {"80", 0},
      {"a180", 1},
      {"a180b2", 1},
      {"a180b28000", 3},
      {"a1b2c3800000", 3},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    uint8_t data[32];
    const size_t len = test_unhex(cases[i].data_hex, data, sizeof(data));
    uint8_t* buf = exact(data, len);

    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].want, unpad_iso9797_m1(buf, (uint32_t)len), cases[i].data_hex);

    free(buf);
  }
}

static void test_u64toa_writes_only_its_own_digits(void) {
  for (size_t i = 0; i < U64TOA_KAT_COUNT; i++) {
    const u64toa_kat_t* v = &U64TOA_KAT[i];
    uint8_t backer[40];
    memset(backer, 0x5a, sizeof(backer));

    /* u64toa fills from the end of the room it is given and hands back a pointer into it, so the
     * room is the digits plus the terminator and nothing before that pointer may change. The
     * region starts partway into a larger buffer so that the byte before it is there to read. */
    uint8_t* region = backer + 8;
    const uint8_t* first = u64toa(v->value, region, v->room);

    TEST_ASSERT_EQUAL_STRING(v->text, (const char*)first);
    TEST_ASSERT_EQUAL_UINT(v->room, (unsigned)(region + v->room - first));
    TEST_ASSERT_EQUAL_UINT8(0x5a, first[-1]);
  }

  static const struct {
    uint32_t value;
    const char* text;
  } u32[] = {{0, "0"}, {9, "9"}, {10, "10"}, {65535, "65535"}, {4294967295U, "4294967295"}};

  for (size_t i = 0; i < sizeof(u32) / sizeof(u32[0]); i++) {
    uint8_t backer[40];
    memset(backer, 0x5a, sizeof(backer));
    const size_t room = strlen(u32[i].text) + 1;
    uint8_t* region = backer + 8;

    const uint8_t* first = u32toa(u32[i].value, region, (uint32_t)room);

    TEST_ASSERT_EQUAL_STRING(u32[i].text, (const char*)first);
    TEST_ASSERT_EQUAL_UINT(room, (unsigned)(region + room - first));
    TEST_ASSERT_EQUAL_UINT8(0x5a, first[-1]);
  }
}

static void test_base16_with_an_odd_number_of_digits(void) {
  /* base16_decode takes the first character on its own when the length is odd, so a bad character
   * at the front is caught there rather than in the pair loop -- the two failures are different
   * code paths and eip712.c can reach either, depending on how the field was written. */
  static const struct {
    const char* text;
    const char* want_hex;
    bool ok;
  } cases[] = {
      {"0", "00", true},
      {"f", "0f", true},
      {"F", "0f", true},
      {"abc", "0abc", true},
      {"ABCDEF0", "0abcdef0", true},
      {"0ff", "00ff", true},
      {"g", NULL, false},
      {"g0", NULL, false},
      {"0g", NULL, false},
      {"a0z", NULL, false},
      {"", "", true},
      {"a0b1c2", "a0b1c2", true},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    uint8_t out[16];
    memset(out, 0x5a, sizeof(out));
    const size_t len = strlen(cases[i].text);

    const bool ok = base16_decode(cases[i].text, out, len);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].ok, ok, cases[i].text);
    if (cases[i].want_hex != NULL && cases[i].want_hex[0] != '\0') {
      TEST_ASSERT_HEX_MESSAGE(out, len / 2 + len % 2, cases[i].want_hex, cases[i].text);
    }
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_a_typed_number_is_the_integer_it_says);
  RUN_TEST(test_what_is_not_a_number_is_refused);
  RUN_TEST(test_negation_round_trips_and_wraps);
  RUN_TEST(test_compare_256_orders_as_an_unsigned);
  RUN_TEST(test_iso7816_m1_padding);
  RUN_TEST(test_unpadding_a_message_that_was_never_padded);
  RUN_TEST(test_u64toa_writes_only_its_own_digits);
  RUN_TEST(test_base16_with_an_odd_number_of_digits);
  return UNITY_END();
}
