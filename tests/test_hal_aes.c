#include <string.h>

#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "unity.h"

#include "vectors/vectors_hal_aes.h"

/*
 * Pins host/hal_aes_host.c -- the model of the AES peripheral -- to FIPS-197 and to SP 800-38C. The
 * firmware's own use of the model is test_aes.c; keeping the two apart is the point, because a model
 * written from how app/crypto/aes_ccm.c drives the peripheral would prove nothing about either.
 */

#define IO_LEN 2048

static uint8_t io[IO_LEN];
static uint8_t ref[IO_LEN];
static uint8_t b0[16];

void setUp(void) {
  hal_host_aes_reset();
  memset(io, 0, sizeof(io));
  memset(ref, 0, sizeof(ref));
  memset(b0, 0, sizeof(b0));
}

void tearDown(void) {}

/* B0 as SP 800-38C A.2.1 formats it. The device always asks for L = 2; the published vectors do not, so
 * the length field is derived here rather than assumed. */
static void build_b0(uint8_t* out, const uint8_t* nonce, size_t nonce_len, size_t len, bool aad, size_t tag_len) {
  const size_t len_field = 15 - nonce_len;

  out[0] = (uint8_t)((((tag_len / 2) - 1) << 3) | (len_field - 1) | (aad ? 0x40 : 0x00));
  memcpy(&out[1], nonce, nonce_len);

  for (size_t i = 0; i < len_field; i++) {
    out[15 - i] = (uint8_t)(len >> (8 * i));
  }
}

static bool ccm_run(hal_aes_mode_t mode, const uint8_t* key, const uint8_t* nonce, size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* in, size_t len, uint8_t* out, uint8_t* tag) {
  build_b0(b0, nonce, nonce_len, len, aad_len != 0, CCM_TAG_SIZE);

  if (hal_aes128_ccm_init(mode, key, b0) != HAL_SUCCESS) {
    return false;
  }

  if (aad_len != 0) {
    hal_host_aes_ccm_aad(aad, aad_len);
  }

  size_t off = 0;

  while (len - off >= AES_BLOCK_SIZE) {
    hal_aes128_ccm_block_process(&in[off], &out[off]);
    off += AES_BLOCK_SIZE;
  }

  if (len - off != 0) {
    hal_aes128_ccm_block_process_last(mode, &in[off], &out[off], len - off);
  }

  return hal_aes128_ccm_finish(tag) == HAL_SUCCESS;
}

static void test_the_block_cipher_is_the_one_fips_197_describes(void) {
  uint8_t key[AES_256_KEY_SIZE], plaintext[AES_BLOCK_SIZE], ciphertext[AES_BLOCK_SIZE], back[AES_BLOCK_SIZE];
  const uint8_t iv[AES_BLOCK_SIZE] = {0};

  TEST_GIVEN(AES256_BLOCK_KEY, key, sizeof(key));
  TEST_GIVEN(AES256_BLOCK_PLAINTEXT, plaintext, sizeof(plaintext));

  /* A CBC chain opened at a zero IV is a single block of the raw cipher. */
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_init(AES_ENCRYPT, AES_CBC, key, iv));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_block_process(plaintext, ciphertext));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_finalize());
  TEST_ASSERT_HEX(ciphertext, sizeof(ciphertext), AES256_BLOCK_CIPHERTEXT);

  hal_host_aes_reset();

  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_init(AES_DECRYPT, AES_CBC, key, iv));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_block_process(ciphertext, back));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes256_finalize());
  TEST_ASSERT_HEX(back, sizeof(back), AES256_BLOCK_PLAINTEXT);
}

static void test_the_published_ccm_example_with_associated_data(void) {
  for (size_t i = 0; i < AES_CCM_SPEC_COUNT; i++) {
    const aes_ccm_kat_t* v = &AES_CCM_SPEC[i];
    uint8_t key[AES_128_KEY_SIZE], nonce[16], aad[64], plaintext[64], out[128], tag[CCM_TAG_SIZE];
    size_t nonce_len = test_unhex(v->nonce, nonce, sizeof(nonce));
    size_t aad_len = test_unhex(v->aad, aad, sizeof(aad));
    size_t len = test_unhex(v->plaintext, plaintext, sizeof(plaintext));

    TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, key, sizeof(key)));
    const size_t packed = test_unhex(v->out, ref, sizeof(ref));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(len + CCM_TAG_SIZE, packed, "vector is ciphertext then tag");

    TEST_ASSERT_TRUE(ccm_run(AES_ENCRYPT, key, nonce, nonce_len, aad, aad_len, plaintext, len, out, tag));
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(out, ref, len, "ciphertext");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(tag, ref + len, CCM_TAG_SIZE, "tag");

    hal_host_aes_reset();

    /* The MAC runs over the plaintext, so verification recovers the same tag the sender wrote. */
    TEST_ASSERT_TRUE(ccm_run(AES_DECRYPT, key, nonce, nonce_len, aad, aad_len, out, len, io, tag));
    TEST_ASSERT_HEX_MESSAGE(io, len, v->plaintext, "decrypted");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(tag, ref + len, CCM_TAG_SIZE, "tag on decrypt");
  }
}

static void test_ccm_at_the_parameters_the_device_uses(void) {
  for (size_t i = 0; i < AES_CCM_DEVICE_COUNT; i++) {
    const aes_ccm_kat_t* v = &AES_CCM_DEVICE[i];
    uint8_t key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE], plaintext[IO_LEN], out[IO_LEN], tag[CCM_TAG_SIZE];
    const size_t len = test_unhex(v->plaintext, plaintext, sizeof(plaintext));

    TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, key, sizeof(key)));
    TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));

    const size_t packed = test_unhex(v->out, ref, sizeof(ref));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(len + CCM_TAG_SIZE, packed, "vector is ciphertext then tag");

    TEST_ASSERT_TRUE_MESSAGE(ccm_run(AES_ENCRYPT, key, nonce, CCM_NONCE_SIZE, NULL, 0, plaintext, len, out, tag), v->nonce);

    if (len != 0) {
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(out, ref, len, "ciphertext");
    }

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(tag, ref + len, CCM_TAG_SIZE, "tag");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(len, hal_host_aes_ccm_bytes(), "payload counted by the model");

    hal_host_aes_reset();

    memset(io, 0, sizeof(io));
    TEST_ASSERT_TRUE_MESSAGE(ccm_run(AES_DECRYPT, key, nonce, CCM_NONCE_SIZE, NULL, 0, out, len, io, tag), v->nonce);

    if (len != 0) {
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plaintext, io, len, "decrypt");
    }

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(tag, ref + len, CCM_TAG_SIZE, "tag");
  }
}

static void test_a_message_of_nothing_still_authenticates(void) {
  uint8_t key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE], tag[CCM_TAG_SIZE];
  const aes_ccm_kat_t* v = &AES_CCM_DEVICE[0];

  TEST_ASSERT_EQUAL_UINT(0, strlen(v->plaintext));
  TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex(v->key, key, sizeof(key)));
  TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex(v->nonce, nonce, sizeof(nonce)));

  TEST_ASSERT_TRUE(ccm_run(AES_ENCRYPT, key, nonce, CCM_NONCE_SIZE, NULL, 0, io, 0, io, tag));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_aes_ccm_bytes());
  TEST_ASSERT_HEX(tag, sizeof(tag), v->out);
}

static void test_a_b0_the_caller_could_not_read_back_is_refused(void) {
  uint8_t key[AES_128_KEY_SIZE], nonce[12];
  size_t nonce_len = test_unhex("101112131415161718191a1b", nonce, sizeof(nonce));

  TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex("404142434445464748494a4b4c4d4e4f", key, sizeof(key)));

  /* A 12-byte tag would run off the end of the tag[CCM_TAG_SIZE] the API hands over. */
  build_b0(b0, nonce, nonce_len, 16, false, 12);
  TEST_ASSERT_EQUAL_INT(HAL_FAIL, hal_aes128_ccm_init(AES_ENCRYPT, key, b0));
  TEST_ASSERT_EQUAL_UINT(1, hal_host_aes_rejections());
}

static void test_the_stream_refuses_to_run_without_a_start(void) {
  uint8_t block[AES_BLOCK_SIZE] = {0}, out[AES_BLOCK_SIZE], tag[CCM_TAG_SIZE];

  TEST_ASSERT_EQUAL_INT(HAL_FAIL, hal_aes128_ccm_block_process(block, out));
  TEST_ASSERT_EQUAL_INT(HAL_FAIL, hal_aes128_ccm_block_process_last(AES_ENCRYPT, block, out, 4));
  TEST_ASSERT_EQUAL_INT(HAL_FAIL, hal_aes128_ccm_finish(tag));
  TEST_ASSERT_EQUAL_INT(HAL_FAIL, hal_aes256_block_process(block, out));
  TEST_ASSERT_EQUAL_UINT(4, hal_host_aes_rejections());
}

static void test_payload_that_does_not_match_what_b0_declared_is_counted(void) {
  uint8_t key[AES_128_KEY_SIZE], nonce[CCM_NONCE_SIZE], tag[CCM_TAG_SIZE];

  TEST_ASSERT_EQUAL_UINT(AES_128_KEY_SIZE, test_unhex("404142434445464748494a4b4c4d4e4f", key, sizeof(key)));
  TEST_ASSERT_EQUAL_UINT(CCM_NONCE_SIZE, test_unhex("101112131415161718191a1b1c", nonce, sizeof(nonce)));

  build_b0(b0, nonce, CCM_NONCE_SIZE, 2 * AES_BLOCK_SIZE, false, CCM_TAG_SIZE);
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes128_ccm_init(AES_ENCRYPT, key, b0));
  hal_aes128_ccm_block_process(io, io);
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_aes128_ccm_finish(tag));

  /* One block of a message that B0 said was two: the tag is the answer to a question nobody asked, and
   * the model says so rather than inventing the missing block. */
  TEST_ASSERT_EQUAL_UINT(1, hal_host_aes_rejections());
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_the_block_cipher_is_the_one_fips_197_describes);
  RUN_TEST(test_the_published_ccm_example_with_associated_data);
  RUN_TEST(test_ccm_at_the_parameters_the_device_uses);
  RUN_TEST(test_a_message_of_nothing_still_authenticates);
  RUN_TEST(test_a_b0_the_caller_could_not_read_back_is_refused);
  RUN_TEST(test_the_stream_refuses_to_run_without_a_start);
  RUN_TEST(test_payload_that_does_not_match_what_b0_declared_is_counted);

  return UNITY_END();
}
