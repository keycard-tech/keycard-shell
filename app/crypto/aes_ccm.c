#include "aes.h"
#include "hal.h"
#include "crypto/memzero.h"
#include "crypto/util.h"
#include <string.h>

#define CCM_FMT_SIZE 16

static void _ccm_build_b0(uint8_t b0[CCM_FMT_SIZE], const uint8_t nonce[CCM_NONCE_SIZE], uint32_t len) {
  b0[0] = 0x19;
  memcpy(&b0[1], nonce, CCM_NONCE_SIZE);
  b0[14] = (len >> 8) & 0xff;
  b0[15] = len & 0xff;
}

uint8_t aes128_ccm_encrypt(const uint8_t key[AES_128_KEY_SIZE], const uint8_t nonce[CCM_NONCE_SIZE],
                           const uint8_t* plaintext, uint32_t len, uint8_t* out) {
  uint8_t b0[CCM_FMT_SIZE] __attribute__((aligned(4)));
  uint32_t blocks = len / AES_BLOCK_SIZE;
  uint32_t remainder = len % AES_BLOCK_SIZE;

  _ccm_build_b0(b0, nonce, len);

  /* CCM init: load key + B0, run init phase */
  hal_err_t hal_err = hal_aes128_ccm_init(AES_ENCRYPT, key, b0);

  /* Payload phase: encrypt full plaintext blocks */
  for (uint32_t i = 0; (hal_err == HAL_SUCCESS) && (i < blocks); i++) {
    hal_err = hal_aes128_ccm_block_process(&plaintext[i * AES_BLOCK_SIZE], &out[i * AES_BLOCK_SIZE]);
  }

  /* Encrypt final partial block */
  if ((hal_err == HAL_SUCCESS) && remainder) {
    hal_err = hal_aes128_ccm_block_process_last(AES_ENCRYPT, &plaintext[blocks * AES_BLOCK_SIZE], &out[blocks * AES_BLOCK_SIZE], remainder);
  }

  /* Final phase: extract authentication tag and reset peripheral */
  if (hal_err == HAL_SUCCESS) {
    hal_err = hal_aes128_ccm_finish(&out[len]);
  }

  memzero(b0, sizeof(b0));

  return hal_err == HAL_SUCCESS;
}

uint8_t aes128_ccm_decrypt(const uint8_t key[AES_128_KEY_SIZE], const uint8_t nonce[CCM_NONCE_SIZE],
                           const uint8_t* ciphertext, uint32_t len, uint8_t* out) {
  uint8_t b0[CCM_FMT_SIZE] __attribute__((aligned(4)));
  uint8_t tag[CCM_TAG_SIZE] __attribute__((aligned(4)));
  uint32_t ct_len = len - CCM_TAG_SIZE;
  uint32_t blocks = ct_len / AES_BLOCK_SIZE;
  uint32_t remainder = ct_len % AES_BLOCK_SIZE;

  /* Extract expected tag from end of ciphertext */
  memcpy(tag, &ciphertext[ct_len], CCM_TAG_SIZE);

  _ccm_build_b0(b0, nonce, ct_len);

  /* CCM init: load key + B0, run init phase */
  hal_err_t hal_err = hal_aes128_ccm_init(AES_DECRYPT, key, b0);

  /* Payload phase: decrypt full ciphertext blocks */
  for (uint32_t i = 0; (hal_err == HAL_SUCCESS) && (i < blocks); i++) {
    hal_err = hal_aes128_ccm_block_process(&ciphertext[i * AES_BLOCK_SIZE], &out[i * AES_BLOCK_SIZE]);
  }

  /* Decrypt final partial block */
  if ((hal_err == HAL_SUCCESS) && remainder) {
    hal_err = hal_aes128_ccm_block_process_last(AES_DECRYPT, &ciphertext[blocks * AES_BLOCK_SIZE], &out[blocks * AES_BLOCK_SIZE], remainder);
  }

  /* Final phase: get computed tag and reset peripheral */
  uint8_t computed_tag[CCM_TAG_SIZE] __attribute__((aligned(4))) = {0};
  if (hal_err == HAL_SUCCESS) {
    hal_err = hal_aes128_ccm_finish(computed_tag);
  }

  /* Constant-time tag comparison. */
  int valid = (hal_err == HAL_SUCCESS) && (memcmp_ct(computed_tag, tag, CCM_TAG_SIZE) == 0);

  memzero(b0, sizeof(b0));
  memzero(tag, sizeof(tag));
  memzero(computed_tag, sizeof(computed_tag));

  return valid;
}
