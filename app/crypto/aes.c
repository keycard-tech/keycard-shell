#include "aes.h"
#include "hal.h"
#include "mem.h"

uint8_t aes_encrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out) {
  hal_err_t hal_err = hal_aes256_init(AES_ENCRYPT, AES_CBC, key, iv);

  for (uint32_t i = 0; (hal_err == HAL_SUCCESS) && (i < len); i += AES_BLOCK_SIZE) {
    hal_err = hal_aes256_block_process(&data[i], &out[i]);
  }

  if (hal_err == HAL_SUCCESS) {
    hal_err = hal_aes256_finalize();
  }

  return hal_err == HAL_SUCCESS;
}

uint8_t aes_decrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out) {
  hal_err_t hal_err = hal_aes256_init(AES_DECRYPT, AES_CBC, key, iv);

  for (uint32_t i = 0; (hal_err == HAL_SUCCESS) && (i < len); i += AES_BLOCK_SIZE) {
    hal_err = hal_aes256_block_process(&data[i], &out[i]);
  }

  if (hal_err == HAL_SUCCESS) {
    hal_err = hal_aes256_finalize();
  }

  return hal_err == HAL_SUCCESS;
}

uint8_t aes_cbc_mac(const uint8_t* key, const uint8_t* data, uint32_t len, uint8_t* out) {
  hal_err_t hal_err = hal_aes256_init(AES_ENCRYPT, AES_CBC, key, ZERO32);

  for (uint32_t i = 0; (hal_err == HAL_SUCCESS) && (i < len); i += AES_BLOCK_SIZE) {
    hal_err = hal_aes256_block_process(&data[i], out);
  }

  if (hal_err == HAL_SUCCESS) {
    hal_err = hal_aes256_finalize();
  }

  return hal_err == HAL_SUCCESS;
}
