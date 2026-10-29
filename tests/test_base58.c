#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/address.h"
#include "crypto/base58.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_address.h"
#include "vectors/vectors_base58.h"

#define MAX_PAYLOAD 128
#define MAX_ENCODED 256

static bool has_both_cases(const char* text) {
  bool upper = false;
  bool lower = false;
  for (const char* p = text; *p != '\0'; p++) {
    upper |= isupper((unsigned char)*p) != 0;
    lower |= islower((unsigned char)*p) != 0;
  }
  return upper && lower;
}

static uint8_t payload[MAX_PAYLOAD];
static char encoded[MAX_ENCODED];

void setUp(void) {
  memset(payload, 0, sizeof(payload));
  memset(encoded, 0, sizeof(encoded));
}

void tearDown(void) {}

static void test_alphabet(void) {
  TEST_ASSERT_EQUAL_STRING(B58_ALPHABET, b58digits_ordered);
}

static void test_decode_check(void) {
  for (size_t i = 0; i < BASE58_VECTOR_COUNT; i++) {
    int len = base58_decode_check(BASE58_VECTORS[i].encoded, payload, MAX_PAYLOAD);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)(strlen(BASE58_VECTORS[i].payload) / 2), len,
                                  BASE58_VECTORS[i].encoded);
    TEST_ASSERT_HEX(payload, len, BASE58_VECTORS[i].payload);
  }
}

static void test_encode_check(void) {
  for (size_t i = 0; i < BASE58_VECTOR_COUNT; i++) {
    size_t payload_len = test_unhex(BASE58_VECTORS[i].payload, payload, sizeof(payload));
    TEST_ASSERT_TRUE(payload_len < sizeof(payload));

    int len = base58_encode_check(payload, payload_len, encoded, sizeof(encoded));
    TEST_ASSERT_EQUAL_INT(strlen(BASE58_VECTORS[i].encoded), len);
    TEST_ASSERT_EQUAL_STRING(BASE58_VECTORS[i].encoded, encoded);
  }
}

static void test_rejects_corrupt_checksum(void) {
  for (size_t i = 0; i < BASE58_VECTOR_COUNT; i++) {
    const char* source = BASE58_VECTORS[i].encoded;
    size_t len = strlen(source);

    /* Changing a payload character leaves a well-formed base58 string whose 4-byte
     * double-SHA256 checksum no longer matches. */
    for (size_t pos = 0; pos < len; pos++) {
      const char* replacement = strchr(B58_ALPHABET, source[pos]);
      TEST_ASSERT_NOT_NULL(replacement);
      char next = replacement[1];

      char corrupt[MAX_ENCODED];
      memcpy(corrupt, source, len);
      corrupt[len] = '\0';
      corrupt[pos] = (next == '\0') ? B58_ALPHABET[0] : next;

      TEST_ASSERT_EQUAL_INT_MESSAGE(0, base58_decode_check(corrupt, payload, MAX_PAYLOAD), corrupt);
    }
  }
}

static void test_rejects_wrong_length(void) {
  /* A 78 byte extended key cannot be decoded into a 20 byte buffer. */
  TEST_ASSERT_EQUAL_INT(0, base58_decode_check(BASE58_VECTORS[0].encoded, payload, 20));
}

static void test_legacy_addresses(void) {
  for (size_t i = 0; i < LEGACY_ADDRESS_VECTOR_COUNT; i++) {
    uint8_t hash160[RIPEMD160_DIGEST_LENGTH];
    TEST_ASSERT_EQUAL(sizeof(hash160), test_unhex(LEGACY_ADDRESS_VECTORS[i].hash160, hash160,
                                                  sizeof(hash160)));

    char address[MAX_ADDR_LEN];
    size_t len = bitcoin_legacy_address(hash160, LEGACY_ADDRESS_VECTORS[i].prefix, address);
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_STRING(LEGACY_ADDRESS_VECTORS[i].address, address);
  }
}

static void test_ethereum_addresses(void) {
  for (size_t i = 0; i < ETH_ADDRESS_VECTOR_COUNT; i++) {
    uint8_t pubkey[65];
    TEST_ASSERT_EQUAL(sizeof(pubkey), test_unhex(ETH_ADDRESS_VECTORS[i].pubkey_uncompressed,
                                                 pubkey, sizeof(pubkey)));

    uint8_t address[20];
    ethereum_address(pubkey, address);
    TEST_ASSERT_HEX(address, sizeof(address), ETH_ADDRESS_VECTORS[i].eth_address);

    char checksummed[MAX_ADDR_LEN];
    ethereum_address_checksum(address, checksummed);
    TEST_ASSERT_EQUAL_STRING(ETH_ADDRESS_VECTORS[i].eth_address_checksummed, checksummed);

    TEST_ASSERT_TRUE(ethereum_address_checksum_verify(checksummed, address));

    char lowered[MAX_ADDR_LEN];
    strcpy(lowered, checksummed);
    for (char* p = lowered; *p != '\0'; p++) {
      *p = tolower(*p);
    }
    TEST_ASSERT_TRUE_MESSAGE(ethereum_address_checksum_verify(lowered, address), lowered);

    /* Flipping the case of a letter breaks the EIP-55 binding to these bytes. Uniform case
     * is not a checksum at all, so the flip has to leave the string mixed. */
    char wrong[MAX_ADDR_LEN];
    strcpy(wrong, checksummed);
    char* flip = NULL;
    for (char* p = wrong; *p != '\0'; p++) {
      if (isalpha((unsigned char)*p)) {
        flip = p;
        break;
      }
    }
    TEST_ASSERT_NOT_NULL(flip);
    *flip = islower(*flip) ? toupper(*flip) : tolower(*flip);
    TEST_ASSERT_TRUE(has_both_cases(wrong));
    TEST_ASSERT_FALSE_MESSAGE(ethereum_address_checksum_verify(wrong, address), wrong);
  }
}

static void test_address_format_eth(void) {
  for (size_t i = 0; i < ETH_ADDRESS_VECTOR_COUNT; i++) {
    uint8_t address[20];
    TEST_ASSERT_EQUAL(sizeof(address), test_unhex(ETH_ADDRESS_VECTORS[i].eth_address, address,
                                                  sizeof(address)));
    char out[MAX_ADDR_LEN];
    TEST_ASSERT_TRUE(address_format(ADDR_ETH, address, out));
    TEST_ASSERT_EQUAL_STRING_LEN("0x", out, 2);
    TEST_ASSERT_EQUAL_STRING(ETH_ADDRESS_VECTORS[i].eth_address_checksummed, &out[2]);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_alphabet);
  RUN_TEST(test_decode_check);
  RUN_TEST(test_encode_check);
  RUN_TEST(test_rejects_corrupt_checksum);
  RUN_TEST(test_rejects_wrong_length);
  RUN_TEST(test_legacy_addresses);
  RUN_TEST(test_ethereum_addresses);
  RUN_TEST(test_address_format_eth);
  return UNITY_END();
}
