#include <string.h>

#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "storage/keys.h"
#include "unity.h"

#include "vectors/vectors_keys.h"

/*
 * keys.c is two switches. One hands out the private halves, which are not stored anywhere and come out of
 * hal_derive_device_unique_secret() -- a wrap under the fused key, so what a test can pin is the property
 * the callers rely on: a pure function of a per-purpose salt, and different on every device. The other
 * switch hands out the trust anchors, and for those the interesting question is not whether the code
 * returns the array it declares but whether the array is the right one.
 */

void setUp(void) {
  hal_host_flash_reset();
  hal_host_aes_reset();
  hal_host_derive_reset();
}

void tearDown(void) {}

static void test_a_private_key_belongs_to_its_purpose_and_to_the_device(void) {
  uint8_t dev_auth[SHA256_DIGEST_LENGTH], dev_auth_again[SHA256_DIGEST_LENGTH];
  uint8_t pairing[SHA256_DIGEST_LENGTH], pairing_on_another_device[SHA256_DIGEST_LENGTH];

  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_private(DEV_AUTH_PRIV_KEY, dev_auth));
  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_private(PAIRING_ENC_PRIV_KEY, pairing));
  TEST_ASSERT_EQUAL_UINT(2, hal_host_derive_calls());

  /* Two purposes, two salts, two keys: a device-authentication key is not a pairing key. */
  TEST_ASSERT_TRUE(memcmp(dev_auth, pairing, sizeof(dev_auth)) != 0);

  hal_host_derive_reset();
  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_private(DEV_AUTH_PRIV_KEY, dev_auth_again));
  TEST_ASSERT_EQUAL_MEMORY(dev_auth, dev_auth_again, sizeof(dev_auth));

  /* The fused key is the other input, and it is the reason a pairing record is useless elsewhere. */
  const uint8_t another_device[AES_256_KEY_SIZE] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
  };
  hal_host_device_secret_set(another_device);
  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_private(PAIRING_ENC_PRIV_KEY, pairing_on_another_device));
  TEST_ASSERT_TRUE(memcmp(pairing, pairing_on_another_device, sizeof(pairing)) != 0);
}

static void test_a_key_can_only_be_read_the_way_it_exists(void) {
  uint8_t out[SHA256_DIGEST_LENGTH];
  const uint8_t* pub;

  /* The two switches are disjoint on purpose: asking a public key to be read as a private one derives
   * nothing at all. */
  TEST_ASSERT_EQUAL_INT(ERR_DATA, key_read_private(FW_VERIFICATION_KEY, out));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, key_read_private(DB_VERIFICATION_KEY, out));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, key_read_private(KEYCARD_CA_KEY, out));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_derive_calls());

  TEST_ASSERT_EQUAL_INT(ERR_DATA, key_read_public(DEV_AUTH_PRIV_KEY, &pub));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, key_read_public(PAIRING_ENC_PRIV_KEY, &pub));
}

static void test_the_database_key_is_the_key_the_release_was_signed_with(void) {
  const uint8_t* key;
  uint8_t digest[SHA256_DIGEST_LENGTH], signature[64];

  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_public(DB_VERIFICATION_KEY, &key));
  TEST_GIVEN(DB_RELEASE_BODY_SHA256, digest, sizeof(digest));
  TEST_ASSERT_EQUAL_UINT(64, test_unhex(DB_RELEASE_SIGNATURE, signature, sizeof(signature)));

  /* updater_verify_db() treats a nonzero return as "not ours". */
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdsa_verify(&secp256k1, key, signature, digest),
                                "the shipped database does not verify under the shipped key");

  /* The failure is the key's doing and not the shape of the call: one bit of the digest, and another
   * anchor of the same curve and the same encoding -- so a refusal cannot be blamed on a malformed
   * point -- both refuse it. */
  digest[0] ^= 0x01;
  TEST_ASSERT_EQUAL_INT(1, ecdsa_verify(&secp256k1, key, signature, digest));
  digest[0] ^= 0x01;

  const uint8_t* other_anchor;
  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_public(KEYCARD_CA_KEY, &other_anchor));
  TEST_ASSERT_EQUAL_INT(1, ecdsa_verify(&secp256k1, other_anchor, signature, digest));
}

static void test_the_firmware_key_is_read_where_the_header_lands(void) {
  const uint8_t header[33] = {
    0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  };
  uint8_t* where = (uint8_t*)(uintptr_t)(HAL_FLASH_ADDR + HAL_FW_HEADER_OFFSET);
  const uint8_t* read_back;

  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_flash_begin_program());
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_flash_erase(HAL_FLASH_ADDR_TO_BLOCK(HAL_FLASH_ADDR + HAL_FW_HEADER_OFFSET)));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_flash_program(header, where, sizeof(header)));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_flash_end_program());

  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_public(FW_VERIFICATION_KEY, &read_back));

  /* It is a pointer into the mmap, not a copy -- which is what lets updater_verify_firmware() read the
   * signature of whatever is installed there rather than of a fixed constant. */
  TEST_ASSERT_EQUAL_PTR(where, read_back);
  TEST_ASSERT_EQUAL_MEMORY(header, read_back, sizeof(header));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());
}

static void test_the_anchors_are_the_lengths_the_callers_assume(void) {
  const uint8_t* key;

  /* Every embedded anchor is a compressed secp256k1 point: 33 bytes, prefix 0x02 or 0x03. The callers
   * hand these straight to ecdsa_verify(), which reads the prefix and 32 bytes and nothing else. */
  const key_type_t anchors[] = {DB_VERIFICATION_KEY, KEYCARD_CA_KEY};

  for (size_t i = 0; i < sizeof(anchors) / sizeof(anchors[0]); i++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, key_read_public(anchors[i], &key), "anchor missing");
    TEST_ASSERT_TRUE_MESSAGE((key[0] == 0x02) || (key[0] == 0x03), "anchor is not a compressed point");

    /* A compressed point is 32 bytes of x followed by nothing the caller can read past it, so the last
     * byte must not be zero either: 0x00 would mean the constant was truncated. */
    TEST_ASSERT_NOT_EQUAL(0, key[32]);
  }
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_private_key_belongs_to_its_purpose_and_to_the_device);
  RUN_TEST(test_a_key_can_only_be_read_the_way_it_exists);
  RUN_TEST(test_the_database_key_is_the_key_the_release_was_signed_with);
  RUN_TEST(test_the_firmware_key_is_read_where_the_header_lands);
  RUN_TEST(test_the_anchors_are_the_lengths_the_callers_assume);

  return UNITY_END();
}
