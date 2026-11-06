#include <string.h>

#include "crypto/aes.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "unity.h"

#include "vectors/vectors_hal_aes.h"

/*
 * app/crypto/aes.c and app/crypto/aes_ccm.c, which are the firmware's own branches: the hardware calls
 * both make go to the model in host/hal_aes_host.c, pinned on its own in test_hal_aes.c.
 */

#define IO_LEN 2048

static uint8_t plaintext[IO_LEN];
static uint8_t io[IO_LEN];
static uint8_t ref[IO_LEN];
static uint8_t key[AES_256_KEY_SIZE];
static uint8_t iv[AES_IV_SIZE];

void setUp(void) {
  hal_host_aes_reset();
  memset(plaintext, 0, sizeof(plaintext));
  memset(io, 0, sizeof(io));
  memset(ref, 0, sizeof(ref));
  memset(iv, 0, sizeof(iv));
}

void tearDown(void) {}

static void test_cbc_encrypts_and_decrypts(void) {
  for (size_t i = 0; i < AES_CBC_KAT_COUNT; i++) {
    const aes_cbc_kat_t* v = &AES_CBC_KAT[i];
    const size_t len = test_unhex(v->data, plaintext, sizeof(plaintext));

    TEST_ASSERT_EQUAL_UINT(AES_256_KEY_SIZE, test_unhex(v->key, key, sizeof(key)));
    TEST_ASSERT_EQUAL_UINT(AES_IV_SIZE, test_unhex(v->iv, iv, sizeof(iv)));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, test_unhex(v->out, ref, sizeof(ref)) - len, "vector lengths");

    TEST_ASSERT_EQUAL_INT(1, aes_encrypt_cbc(key, iv, plaintext, (uint32_t)len, io));
    TEST_ASSERT_HEX_MESSAGE(io, len, v->out, "ciphertext");

    hal_host_aes_reset();
    memset(io, 0, sizeof(io));

    TEST_ASSERT_EQUAL_INT(1, aes_decrypt_cbc(key, iv, ref, (uint32_t)len, io));
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plaintext, io, len, "plaintext");
  }
}

static void test_cbc_mac_is_the_last_block_of_a_chain_starting_at_zero(void) {
  for (size_t i = 0; i < AES_CBC_MAC_KAT_COUNT; i++) {
    const aes_cbc_kat_t* v = &AES_CBC_MAC_KAT[i];
    const size_t len = test_unhex(v->data, plaintext, sizeof(plaintext));
    uint8_t mac[AES_BLOCK_SIZE];

    TEST_ASSERT_EQUAL_UINT(AES_256_KEY_SIZE, test_unhex(v->key, key, sizeof(key)));

    TEST_ASSERT_EQUAL_INT(1, aes_cbc_mac(key, plaintext, (uint32_t)len, mac));
    TEST_ASSERT_HEX_MESSAGE(mac, sizeof(mac), v->out, "mac");
  }
}

static void test_a_message_that_is_not_a_whole_block_runs_on_into_what_follows(void) {
  uint8_t mac_a[AES_BLOCK_SIZE], mac_b[AES_BLOCK_SIZE];
  const size_t declared = 24;

  TEST_ASSERT_EQUAL_UINT(AES_256_KEY_SIZE, test_unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, sizeof(key)));

  memset(plaintext, 0x11, 32);

  TEST_ASSERT_EQUAL_INT(1, aes_cbc_mac(key, plaintext, (uint32_t)declared, mac_a));

  /* Nothing in aes_cbc_mac counts bytes: the loop steps by blocks, so the tail is a block of whatever
   * happens to sit after the message. Callers pad first -- secure_channel_v1_protect_apdu() runs its
   * data through pad_iso9797_m1() -- and this is the shape that precondition avoids. */
  plaintext[declared] = 0x22;

  TEST_ASSERT_EQUAL_INT(1, aes_cbc_mac(key, plaintext, (uint32_t)declared, mac_b));
  TEST_ASSERT_TRUE_MESSAGE(memcmp(mac_a, mac_b, sizeof(mac_a)) != 0, "the bytes past the declared length were ignored");

  /* The same holds going the other way: one byte of "length" still writes a block. */
  memset(io, 0, sizeof(io));
  TEST_ASSERT_EQUAL_INT(1, aes_encrypt_cbc(key, iv, plaintext, 1, io));

  memset(plaintext + 16, 0, 16);
  hal_host_aes_reset();
  TEST_ASSERT_EQUAL_INT(1, aes_encrypt_cbc(key, iv, plaintext, 16, ref));
  TEST_ASSERT_EQUAL_MEMORY(io, ref, AES_BLOCK_SIZE);
}

static void test_ccm_encrypts_the_way_the_reference_does(void) {
  for (size_t i = 0; i < AES_CCM_DEVICE_COUNT; i++) {
    const aes_ccm_kat_t* v = &AES_CCM_DEVICE[i];
    uint8_t ccm_key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE];
    const size_t len = test_unhex(v->plaintext, plaintext, sizeof(plaintext));

    TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, ccm_key, sizeof(ccm_key)));
    TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));

    TEST_ASSERT_EQUAL_INT(1, aes128_ccm_encrypt(ccm_key, nonce, plaintext, (uint32_t)len, io));
    TEST_ASSERT_HEX_MESSAGE(io, len + CCM_TAG_SIZE, v->out, "ciphertext and tag");
  }
}

static void test_ccm_decrypt_verifies_and_recovers(void) {
  for (size_t i = 0; i < AES_CCM_DEVICE_COUNT; i++) {
    const aes_ccm_kat_t* v = &AES_CCM_DEVICE[i];
    uint8_t ccm_key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE];
    const size_t len = test_unhex(v->plaintext, plaintext, sizeof(plaintext));

    TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, ccm_key, sizeof(ccm_key)));
    TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));

    const size_t packed = test_unhex(v->out, ref, sizeof(ref));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(len + CCM_TAG_SIZE, packed, "vector is ciphertext then tag");

    memset(io, 0, sizeof(io));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, aes128_ccm_decrypt(ccm_key, nonce, ref, (uint32_t)packed, io), v->nonce);

    if (len != 0) {
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plaintext, io, len, "plaintext");
    }
  }
}

static void test_a_tampered_ciphertext_or_tag_is_refused(void) {
  const aes_ccm_kat_t* v = &AES_CCM_DEVICE[AES_CCM_DEVICE_COUNT - 1];
  uint8_t ccm_key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE];
  const size_t len = test_unhex(v->plaintext, plaintext, sizeof(plaintext));

  TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, ccm_key, sizeof(ccm_key)));
  TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));
  TEST_ASSERT_TRUE(len > 0);

  TEST_ASSERT_EQUAL_INT(1, aes128_ccm_encrypt(ccm_key, nonce, plaintext, (uint32_t)len, ref));

  /* A byte of the tag: nothing else changes, so only the comparison can fail. */
  ref[len] ^= 0x01;
  hal_host_aes_reset();
  TEST_ASSERT_EQUAL_INT(0, aes128_ccm_decrypt(ccm_key, nonce, ref, (uint32_t)(len + CCM_TAG_SIZE), io));

  ref[len] ^= 0x01;
  hal_host_aes_reset();
  TEST_ASSERT_EQUAL_INT(1, aes128_ccm_decrypt(ccm_key, nonce, ref, (uint32_t)(len + CCM_TAG_SIZE), io));

  /* A byte of the ciphertext changes the plaintext, and with it the MAC over it. */
  ref[0] ^= 0x80;
  hal_host_aes_reset();
  TEST_ASSERT_EQUAL_INT(0, aes128_ccm_decrypt(ccm_key, nonce, ref, (uint32_t)(len + CCM_TAG_SIZE), io));
}

static void test_a_message_of_nothing_authenticates(void) {
  const aes_ccm_kat_t* v = &AES_CCM_DEVICE[0];
  uint8_t ccm_key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE];

  TEST_ASSERT_EQUAL_UINT(0, strlen(v->plaintext));
  TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, ccm_key, sizeof(ccm_key)));
  TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));

  TEST_ASSERT_EQUAL_INT(1, aes128_ccm_encrypt(ccm_key, nonce, plaintext, 0, io));
  TEST_ASSERT_HEX_MESSAGE(io, CCM_TAG_SIZE, v->out, "tag alone");

  hal_host_aes_reset();
  TEST_ASSERT_EQUAL_INT(1, aes128_ccm_decrypt(ccm_key, nonce, io, CCM_TAG_SIZE, ref));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_cbc_encrypts_and_decrypts);
  RUN_TEST(test_cbc_mac_is_the_last_block_of_a_chain_starting_at_zero);
  RUN_TEST(test_a_message_that_is_not_a_whole_block_runs_on_into_what_follows);
  RUN_TEST(test_ccm_encrypts_the_way_the_reference_does);
  RUN_TEST(test_ccm_decrypt_verifies_and_recovers);
  RUN_TEST(test_a_tampered_ciphertext_or_tag_is_refused);
  RUN_TEST(test_a_message_of_nothing_authenticates);

  return UNITY_END();
}
