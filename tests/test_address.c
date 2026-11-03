#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/address.h"
#include "crypto/segwit_addr.h"
#include "crypto/util.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_address.h"
#include "vectors/vectors_base58.h"
#include "vectors/vectors_bech32.h"

/* address.c is what the user reads on screen and what a cosigner compares a foreign address
 * against, so this covers the mapping from raw bytes to a rendering -- which version byte, which
 * encoder, which case may be accepted -- and not the encoders themselves, which have their own
 * suites. */

/* The formatters are declared to take char[MAX_ADDR_LEN]; an array parameter is a pointer, so the
 * tests hand them a larger buffer with poison after it and check the poison. */
typedef struct {
  char out[MAX_ADDR_LEN];
  uint8_t canary[16];
} formatted_t;

static formatted_t formatted;
static formatted_t second;
static uint8_t raw[MAX_ADDR_LEN];

void setUp(void) {
  memset(&formatted, 0, sizeof(formatted));
  memset(&second, 0, sizeof(second));
  memset(raw, 0, sizeof(raw));
}

void tearDown(void) {}

static formatted_t* arm(formatted_t* buffer) {
  memset(buffer->out, 0, sizeof(buffer->out));
  memset(buffer->canary, 0xA5, sizeof(buffer->canary));
  return buffer;
}

static void assert_untouched(const formatted_t* buffer, const char* label) {
  for (size_t i = 0; i < sizeof(buffer->canary); i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xA5, buffer->canary[i], label);
  }
}

static void every_case(char* text, int upper) {
  for (; *text != '\0'; text++) {
    *text = upper ? (char) toupper((unsigned char) *text) : (char) tolower((unsigned char) *text);
  }
}

/* Flips the case of the first letter and reports whether the string is left with both cases --
 * neither of the two renderings BIP-173, and the only one carrying an EIP-55 checksum, has one
 * case throughout. */
static int flip_first_letter(char* text) {
  for (char* pos = text; *pos != '\0'; pos++) {
    if (isalpha((unsigned char) *pos)) {
      *pos = islower((unsigned char) *pos) ? (char) toupper((unsigned char) *pos)
                                           : (char) tolower((unsigned char) *pos);
      break;
    }
  }

  int upper = 0;
  int lower = 0;
  for (const char* pos = text; *pos != '\0'; pos++) {
    upper |= isupper((unsigned char) *pos) != 0;
    lower |= islower((unsigned char) *pos) != 0;
  }
  return upper && lower;
}

static void test_prefix_length(void) {
  for (size_t i = 0; i < ADDR_PREFIX_VECTOR_COUNT; i++) {
    const addr_prefix_vector_t* v = &ADDR_PREFIX_VECTORS[i];
    char label[24];
    snprintf(label, sizeof(label), "0x%08X", (unsigned) v->version);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->len, address_prefix_bytes_len(v->version), label);
  }
}

static void test_prefix_written_big_endian(void) {
  for (size_t i = 0; i < ADDR_PREFIX_VECTOR_COUNT; i++) {
    const addr_prefix_vector_t* v = &ADDR_PREFIX_VECTORS[i];
    char label[24];
    snprintf(label, sizeof(label), "0x%08X", (unsigned) v->version);

    uint8_t expected[4];
    TEST_ASSERT_EQUAL_MESSAGE(v->len, test_unhex(v->bytes, expected, sizeof(expected)), label);

    uint8_t written[8];
    memset(written, 0xA5, sizeof(written));
    address_write_prefix_bytes(v->version, written);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, written, v->len, label);

    /* ecdsa_soft.c sizes its buffers by address_prefix_bytes_len() and keeps writing after the
     * prefix, so the writer must stop at exactly that many bytes. */
    for (size_t pos = v->len; pos < sizeof(written); pos++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xA5, written[pos], label);
    }
  }
}

static void test_prefix_check(void) {
  size_t checked = 0;

  for (size_t i = 0; i < ADDR_PREFIX_VECTOR_COUNT; i++) {
    const addr_prefix_vector_t* v = &ADDR_PREFIX_VECTORS[i];
    char label[32];
    snprintf(label, sizeof(label), "0x%08X", (unsigned) v->version);

    uint8_t written[4];
    address_write_prefix_bytes(v->version, written);
    TEST_ASSERT_TRUE_MESSAGE(address_check_prefix(written, v->version), label);

    uint8_t wrong[4];
    memcpy(wrong, written, sizeof(wrong));
    wrong[v->len - 1] ^= 0x01;
    TEST_ASSERT_FALSE_MESSAGE(address_check_prefix(wrong, v->version), label);

    if (v->len > 1) {
      /* Reading the prefix little-endian would accept this. Palindromes are their own reversal
       * and say nothing, so they are skipped and the count checked below. */
      uint8_t reversed[4];
      for (size_t pos = 0; pos < v->len; pos++) {
        reversed[pos] = written[v->len - 1 - pos];
      }
      if (memcmp(reversed, written, v->len) != 0) {
        TEST_ASSERT_FALSE_MESSAGE(address_check_prefix(reversed, v->version), label);
        checked++;
      }
    }
  }

  TEST_ASSERT_TRUE_MESSAGE(checked > 0, "no multi byte prefix exercised");
}

static void test_format_base58_types(void) {
  size_t p2pkh = 0;
  size_t p2sh = 0;

  for (size_t i = 0; i < LEGACY_ADDRESS_VECTOR_COUNT; i++) {
    const legacy_address_vector_t* v = &LEGACY_ADDRESS_VECTORS[i];

    addr_type_t type;
    if (v->prefix == BTC_P2PKH_ADDR_PREFIX) {
      type = ADDR_BTC_LEGACY;
      p2pkh++;
    } else if (v->prefix == BTC_P2SH_ADDR_PREFIX) {
      type = ADDR_BTC_NESTED_SEGWIT;
      p2sh++;
    } else {
      TEST_FAIL_MESSAGE("vector prefix that no addr_type_t renders");
      return;
    }

    uint8_t hash160[RIPEMD160_DIGEST_LENGTH];
    TEST_ASSERT_EQUAL(sizeof(hash160), test_unhex(v->hash160, hash160, sizeof(hash160)));

    TEST_ASSERT_EQUAL_INT(1, address_format(type, hash160, arm(&formatted)->out));
    TEST_ASSERT_EQUAL_STRING(v->address, formatted.out);
    assert_untouched(&formatted, v->address);
  }

  TEST_ASSERT_TRUE_MESSAGE(p2pkh > 0, "no P2PKH vector exercised");
  TEST_ASSERT_TRUE_MESSAGE(p2sh > 0, "no P2SH vector exercised");
}

/* The two base58 types differ only by the version byte, so a dispatch mistake would send a
 * script address to a key screen and back. */
static void test_format_base58_types_differ(void) {
  uint8_t hash160[RIPEMD160_DIGEST_LENGTH];
  TEST_ASSERT_EQUAL(sizeof(hash160), test_unhex(LEGACY_ADDRESS_VECTORS[0].hash160, hash160,
                                                sizeof(hash160)));

  TEST_ASSERT_EQUAL_INT(1, address_format(ADDR_BTC_LEGACY, hash160, arm(&formatted)->out));
  TEST_ASSERT_EQUAL_INT(1, address_format(ADDR_BTC_NESTED_SEGWIT, hash160, arm(&second)->out));
  TEST_ASSERT_EQUAL_STRING(LEGACY_ADDRESS_VECTORS[0].address, formatted.out);
  TEST_ASSERT_NOT_EQUAL(0, strcmp(formatted.out, second.out));
}

static void test_format_witness_types(void) {
  char want[MAX_ADDR_LEN];
  size_t segwit = 0;
  size_t taproot = 0;

  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    const witness_program_t* v = &BECH32_VALID[i];
    if (strcmp(v->hrp, SEGWIT_HRP) != 0) {
      continue;
    }
    TEST_ASSERT_EQUAL(RIPEMD160_DIGEST_LENGTH, test_unhex(v->program, raw, sizeof(raw)));

    TEST_ASSERT_EQUAL_INT(1, address_format(ADDR_BTC_SEGWIT, raw, arm(&formatted)->out));
    strcpy(want, v->address);
    every_case(want, 0);
    TEST_ASSERT_EQUAL_STRING(want, formatted.out);
    assert_untouched(&formatted, v->address);
    segwit++;
  }

  for (size_t i = 0; i < BECH32M_VALID_COUNT; i++) {
    const witness_program_t* v = &BECH32M_VALID[i];
    if (strcmp(v->hrp, SEGWIT_HRP) != 0) {
      continue;
    }
    if (test_unhex(v->program, raw, sizeof(raw)) != BTC_TAPROOT_WITPROG_LEN) {
      continue;  /* BIP-350 also lists other witness v1 program lengths, which are invalid. */
    }

    TEST_ASSERT_EQUAL_INT(1, address_format(ADDR_BTC_TAPROOT, raw, arm(&formatted)->out));
    strcpy(want, v->address);
    every_case(want, 0);
    TEST_ASSERT_EQUAL_STRING(want, formatted.out);
    assert_untouched(&formatted, v->address);
    taproot++;
  }

  TEST_ASSERT_TRUE_MESSAGE(segwit > 0, "no mainnet P2WPKH vector exercised");
  TEST_ASSERT_TRUE_MESSAGE(taproot > 0, "no mainnet P2TR vector exercised");
}

/* The screen picks the renderer from a value that arrives over the wire. */
static void test_format_rejects_unknown_type(void) {
  static const addr_type_t bogus[] = {(addr_type_t) -1, (addr_type_t) (ADDR_BTC_TAPROOT + 1),
                                      (addr_type_t) 0x7F};

  memset(raw, 0x5A, sizeof(raw));
  for (size_t i = 0; i < sizeof(bogus) / sizeof(bogus[0]); i++) {
    TEST_ASSERT_EQUAL_INT(0, address_format(bogus[i], raw, arm(&formatted)->out));
    TEST_ASSERT_EQUAL_INT('\0', formatted.out[0]);
    assert_untouched(&formatted, "unknown address type");
  }
}

static void test_eth_checksum(void) {
  for (size_t i = 0; i < ERC55_VECTOR_COUNT; i++) {
    const erc55_vector_t* v = &ERC55_VECTORS[i];

    uint8_t addr[20];
    TEST_ASSERT_EQUAL(sizeof(addr), test_unhex(v->lower, addr, sizeof(addr)));

    TEST_ASSERT_EQUAL_INT(1, address_format(ADDR_ETH, addr, arm(&formatted)->out));
    TEST_ASSERT_EQUAL_STRING_LEN("0x", formatted.out, 2);
    TEST_ASSERT_EQUAL_STRING(v->mixed, &formatted.out[2]);
    assert_untouched(&formatted, v->mixed);

    ethereum_address_checksum(addr, arm(&formatted)->out);
    TEST_ASSERT_EQUAL_STRING(v->mixed, formatted.out);
    assert_untouched(&formatted, v->mixed);
  }
}

/* EIP-55: uniform case commits to no checksum, so both uniform renderings verify against these
 * bytes whatever they claim. A caller cannot infer this from a successful verify -- an
 * all-uppercase address has been decoded, not authenticated. */
static void test_eth_checksum_verify_uniform_case(void) {
  for (size_t i = 0; i < ERC55_VECTOR_COUNT; i++) {
    const erc55_vector_t* v = &ERC55_VECTORS[i];

    uint8_t addr[20];
    TEST_ASSERT_EQUAL(sizeof(addr), test_unhex(v->lower, addr, sizeof(addr)));

    strcpy(arm(&formatted)->out, v->lower);
    TEST_ASSERT_TRUE_MESSAGE(ethereum_address_checksum_verify(formatted.out, addr), formatted.out);

    strcpy(formatted.out, v->mixed);
    every_case(formatted.out, 0);
    TEST_ASSERT_TRUE_MESSAGE(ethereum_address_checksum_verify(formatted.out, addr), formatted.out);

    every_case(formatted.out, 1);
    TEST_ASSERT_TRUE_MESSAGE(ethereum_address_checksum_verify(formatted.out, addr), formatted.out);
  }
}

/* Mixed case is the checksum, so it binds the string to exactly these twenty bytes. Four of the
 * document's eight addresses happen to have a checksum rendering that is uniform case -- those
 * are the "all caps" and "all lower" examples -- and no verifier can tie them to anything; they
 * still appear here, because changing one letter's case turns them into a checksum claim that
 * has to be refused. */
static int carries_checksum(const char* text) {
  int upper = 0;
  int lower = 0;
  for (const char* pos = text; *pos != '\0'; pos++) {
    upper |= isupper((unsigned char) *pos) != 0;
    lower |= islower((unsigned char) *pos) != 0;
  }
  return upper && lower;
}

static void test_eth_checksum_verify_binds_the_address(void) {
  size_t bound = 0;

  for (size_t i = 0; i < ERC55_VECTOR_COUNT; i++) {
    const erc55_vector_t* v = &ERC55_VECTORS[i];
    const erc55_vector_t* next = &ERC55_VECTORS[(i + 1) % ERC55_VECTOR_COUNT];

    uint8_t addr[20];
    TEST_ASSERT_EQUAL(sizeof(addr), test_unhex(v->lower, addr, sizeof(addr)));

    uint8_t other[20];
    TEST_ASSERT_EQUAL(sizeof(other), test_unhex(next->lower, other, sizeof(other)));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(v->lower, next->lower, sizeof(other)));

    if (carries_checksum(v->mixed)) {
      TEST_ASSERT_FALSE_MESSAGE(ethereum_address_checksum_verify(v->mixed, other), v->mixed);
      bound++;
    }

    strcpy(arm(&formatted)->out, v->mixed);
    TEST_ASSERT_TRUE_MESSAGE(flip_first_letter(formatted.out), v->mixed);
    TEST_ASSERT_FALSE_MESSAGE(ethereum_address_checksum_verify(formatted.out, addr), formatted.out);
  }

  TEST_ASSERT_TRUE_MESSAGE(bound > 0, "no checksummed vector exercised");
}

static void assert_eq(const char* expected, const char* candidate, int match, const char* label) {
  TEST_ASSERT_EQUAL_INT_MESSAGE(match, bitcoin_address_eq(expected, candidate), label);
}

static void test_bitcoin_address_eq(void) {
  char expected[MAX_ADDR_LEN];
  char candidate[MAX_ADDR_LEN];
  size_t seen = 0;

  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    const witness_program_t* v = &BECH32_VALID[i];
    if (strcmp(v->hrp, SEGWIT_HRP) != 0) {
      continue;
    }
    seen++;

    strcpy(expected, v->address);
    every_case(expected, 0);

    strcpy(candidate, expected);
    assert_eq(expected, candidate, 1, "witness address equals itself");

    every_case(candidate, 1);
    assert_eq(expected, candidate, 1, "witness address is case insensitive");

    strcpy(candidate, expected);
    TEST_ASSERT_TRUE(flip_first_letter(candidate));
    assert_eq(expected, candidate, 0, "mixed case witness address");

    strcpy(candidate, expected);
    candidate[strlen(candidate) - 1] = '\0';
    assert_eq(expected, candidate, 0, "truncated witness address, lowercase");

    /* Stopping short has to be refused by the comparison itself: in the tolerated case the case
     * rule above never fires. */
    strcpy(candidate, expected);
    every_case(candidate, 1);
    candidate[strlen(candidate) - 1] = '\0';
    assert_eq(expected, candidate, 0, "truncated witness address, uppercase");

    strcpy(candidate, expected);
    strcat(candidate, "q");
    assert_eq(expected, candidate, 0, "extended witness address, lowercase tail");

    /* The same in the tolerated case reaches the character comparison instead of the case rule. */
    strcpy(candidate, expected);
    every_case(candidate, 1);
    strcat(candidate, "Q");
    assert_eq(expected, candidate, 0, "extended witness address, uppercase tail");
  }
  TEST_ASSERT_TRUE_MESSAGE(seen > 0, "no mainnet witness vector exercised");

  for (size_t i = 0; i < LEGACY_ADDRESS_VECTOR_COUNT; i++) {
    const char* address = LEGACY_ADDRESS_VECTORS[i].address;

    strcpy(expected, address);
    strcpy(candidate, address);
    assert_eq(expected, candidate, 1, "base58 address equals itself");

    strcpy(candidate, address);
    every_case(candidate, 1);
    assert_eq(expected, candidate, 0, "base58 case carries data");

    strcpy(candidate, address);
    every_case(candidate, 0);
    assert_eq(expected, candidate, 0, "base58 case carries data, other direction");
  }
}

/* Only the expected side is required to be canonical: it is the address we derived, and the
 * candidate is the foreign one being tolerated or rejected. Reversing the two matches nothing,
 * which a caller that echoed a host's uppercase address back as `expected` would trip over. */
static void test_bitcoin_address_eq_expected_is_canonical(void) {
  char expected[MAX_ADDR_LEN];
  char candidate[MAX_ADDR_LEN];

  strcpy(expected, BECH32_VALID[0].address);
  every_case(expected, 1);
  strcpy(candidate, expected);
  every_case(candidate, 0);

  TEST_ASSERT_FALSE(bitcoin_address_eq(expected, candidate));
  TEST_ASSERT_TRUE(bitcoin_address_eq(candidate, expected));
}

/* Case tolerance is defined for the prefix this device renders, and the comparison is a
 * comparison: it says nothing about whether either side is a well-formed address. */
static void test_bitcoin_address_eq_other_prefix(void) {
  char expected[MAX_ADDR_LEN];
  char candidate[MAX_ADDR_LEN];
  size_t seen = 0;

  for (size_t i = 0; i < BECH32_VALID_COUNT; i++) {
    const witness_program_t* v = &BECH32_VALID[i];
    if (strcmp(v->hrp, SEGWIT_HRP) == 0) {
      continue;
    }
    strcpy(expected, v->address);
    every_case(expected, 0);
    strcpy(candidate, expected);
    every_case(candidate, 1);
    assert_eq(expected, candidate, 0, v->address);
    seen++;
  }
  TEST_ASSERT_TRUE_MESSAGE(seen > 0, "no non-mainnet witness vector exercised");

  assert_eq("bc1q", "BC1Q", 1, "equality is not validity");
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_prefix_length);
  RUN_TEST(test_prefix_written_big_endian);
  RUN_TEST(test_prefix_check);
  RUN_TEST(test_format_base58_types);
  RUN_TEST(test_format_base58_types_differ);
  RUN_TEST(test_format_witness_types);
  RUN_TEST(test_format_rejects_unknown_type);
  RUN_TEST(test_eth_checksum);
  RUN_TEST(test_eth_checksum_verify_uniform_case);
  RUN_TEST(test_eth_checksum_verify_binds_the_address);
  RUN_TEST(test_bitcoin_address_eq);
  RUN_TEST(test_bitcoin_address_eq_expected_is_canonical);
  RUN_TEST(test_bitcoin_address_eq_other_prefix);
  return UNITY_END();
}
