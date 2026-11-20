#include "unity.h"
#include <string.h>

#include "crypto/bignum.h"
#include "ui/amount.h"
#include "ui/i18n.h"

void setUp(void) { i18n_set_strings(i18n_english_strings); }
void tearDown(void) {}

static void ten_to_the(unsigned exponent, bignum256* out) {
  uint8_t bytes[32] = {0};
  bytes[31] = 1;

  for (unsigned i = 0; i < exponent; i++) {
    unsigned carry = 0;
    for (int b = 31; b >= 0; b--) {
      const unsigned v = bytes[b] * 10u + carry;
      bytes[b] = v & 0xff;
      carry = v >> 8;
    }
  }

  bn_read_be(bytes, out);
}

static const bignum256* max_uint(unsigned bytes_set) {
  static bignum256 v;
  static uint8_t bytes[32];
  memset(bytes, 0, sizeof(bytes));
  memset(bytes + 32 - bytes_set, 0xff, bytes_set);
  bn_read_be(bytes, &v);
  return &v;
}

/* What the field contract in amount.h promises, on every render: neither blank nor wider than the
 * field, and nothing written past it. */
static void render(const bignum256* value, const char* ticker, unsigned int decimals, char out[UI_AMOUNT_FIELD_LEN + 1]) {
  char buf[UI_AMOUNT_FIELD_LEN + 8];
  memset(buf, '#', sizeof(buf));

  ui_amount_format(value, ticker, decimals, buf);

  const size_t len = strlen(buf);
  TEST_ASSERT_TRUE_MESSAGE(len > 0 && len <= UI_AMOUNT_FIELD_LEN, buf);
  TEST_ASSERT_EQUAL_MESSAGE('#', buf[UI_AMOUNT_FIELD_LEN + 1], buf);
  memcpy(out, buf, len + 1);
}

static void expect_power(const char* expected, unsigned exponent, unsigned int decimals, const char* ticker) {
  bignum256 value;
  ten_to_the(exponent, &value);

  char field[UI_AMOUNT_FIELD_LEN + 1];
  render(&value, ticker, decimals, field);
  TEST_ASSERT_EQUAL_STRING(expected, field);
}

static const char* const TICKERS[] = {"", "ETH", "USDC", "0123456789abcdef"};

static void full_digits(void) {
  expect_power("1 ETH", 18, 18, "ETH");
  expect_power("0.000000001 ETH", 9, 18, "ETH");
  expect_power("1,000,000 ETH", 6, 0, "ETH");

  /* The wall is a width, so 1e14 units is the last that a 3 character ticker spells -- whether they are
   * held as 1e14 raw or as 1e32 of a token with 18 decimals. */
  expect_power("100,000,000,000,000 ETH", 14, 0, "ETH");
  expect_power("100,000,000,000,000 ETH", 32, 18, "ETH");

  /* A 4 character ticker pays for itself with one group of digits. */
  expect_power("10,000,000,000,000 USDC", 13, 0, "USDC");
}

static void unlimited_above_the_wall(void) {
  expect_power("Unlimited ETH", 15, 0, "ETH");
  expect_power("Unlimited ETH", 33, 18, "ETH");
  expect_power("Unlimited USDC", 14, 0, "USDC");
  expect_power("Unlimited 0123456789abc", 14, 0, "0123456789abcdef");

  char field[UI_AMOUNT_FIELD_LEN + 1];
  render(max_uint(32), "ETH", 18, field);
  TEST_ASSERT_EQUAL_STRING("Unlimited ETH", field);
  render(max_uint(32), "ETH", 0, field);
  TEST_ASSERT_EQUAL_STRING("Unlimited ETH", field);
  render(max_uint(16), "USDC", 6, field);
  TEST_ASSERT_EQUAL_STRING("Unlimited USDC", field);

  /* An allowance of everything there is, quoted in no ticker at all -- the nonce and gas fields pass an
   * empty one, and get the label without the space a ticker would have been separated by. */
  render(max_uint(32), "", 18, field);
  TEST_ASSERT_EQUAL_STRING("Unlimited", field);
}

static void fraction_shortens_first(void) {
  bignum256 value;
  bn_read_uint64(1234567890123456789ULL, &value);

  char field[UI_AMOUNT_FIELD_LEN + 1];
  render(&value, "ETH", 18, field);
  TEST_ASSERT_EQUAL_STRING("1.23456789012345678 ETH", field);

  render(&value, "0123456789abcdef", 18, field);
  TEST_ASSERT_EQUAL_STRING("1.2345 0123456789abcdef", field);
  TEST_ASSERT_EQUAL(UI_AMOUNT_FIELD_LEN, strlen(field));

  render(&value, "", 18, field);
  TEST_ASSERT_EQUAL_STRING("1.234567890123456789", field);
}

static void too_small_to_show(void) {
  bignum256 one;
  bn_read_uint64(1, &one);

  char field[UI_AMOUNT_FIELD_LEN + 1];
  render(&one, "ETH", 18, field);
  TEST_ASSERT_EQUAL_STRING("A bit of ETH", field);

  render(&one, "0123456789abcdef", 18, field);
  TEST_ASSERT_EQUAL_STRING("A bit of 0123456789abcd", field);

  render(&one, "ETH", 0, field);
  TEST_ASSERT_EQUAL_STRING("1 ETH", field);
}

static void zero_is_a_number(void) {
  bignum256 zero;
  bn_read_uint64(0, &zero);

  char field[UI_AMOUNT_FIELD_LEN + 1];
  render(&zero, "ETH", 18, field);
  TEST_ASSERT_EQUAL_STRING("0 ETH", field);

  render(&zero, "", 0, field);
  TEST_ASSERT_EQUAL_STRING("0", field);
}

/* Every power of ten a bignum256 holds, at both ends of the decimal point, under every ticker width. */
static void always_within_field(void) {
  char field[UI_AMOUNT_FIELD_LEN + 1];

  for (unsigned exponent = 0; exponent <= 77; exponent++) {
    bignum256 value;
    ten_to_the(exponent, &value);

    for (unsigned i = 0; i < sizeof(TICKERS) / sizeof(TICKERS[0]); i++) {
      render(&value, TICKERS[i], 0, field);
      render(&value, TICKERS[i], 18, field);
    }
  }

  for (unsigned i = 0; i < sizeof(TICKERS) / sizeof(TICKERS[0]); i++) {
    render(max_uint(32), TICKERS[i], 18, field);
    render(max_uint(32), TICKERS[i], 0, field);
    render(max_uint(16), TICKERS[i], 6, field);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(full_digits);
  RUN_TEST(unlimited_above_the_wall);
  RUN_TEST(fraction_shortens_first);
  RUN_TEST(too_small_to_show);
  RUN_TEST(zero_is_a_number);
  RUN_TEST(always_within_field);
  return UNITY_END();
}
