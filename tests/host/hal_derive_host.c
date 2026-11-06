#include "hal.h"
#include "hal_host.h"

#include <string.h>

#include "crypto/memzero.h"
#include "crypto/sha2.h"

/*
 * hal_derive_device_unique_secret(), which on the device is a SAES key wrap followed by SHA-256
 * (stm32_crypto.c:322): the salt is wrapped under whatever AES_CR_KEYSEL_0 selects -- the fused key in
 * KEYRING, which no code path can read -- and the 32 wrapped bytes are hashed into the caller's output.
 *
 * What is modelled is the property the callers depend on: the answer is a pure function of the salt and of
 * a device secret that is not in the image, so two devices derive different keys from the same salt and a
 * pairing record cannot leave the device it was made on. The two-block single chain and the SHA-256 over
 * the wrapped bytes come from the driver. The fused key itself cannot be modelled, so it is a value the
 * test sets; nothing here claims to be the KDF of a particular chip.
 */

static const uint8_t DEFAULT_DEVICE_SECRET[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static uint8_t device_secret[32];
static size_t derivations;

void hal_host_derive_reset(void) {
  memcpy(device_secret, DEFAULT_DEVICE_SECRET, sizeof(device_secret));
  derivations = 0;
}

void hal_host_device_secret_set(const uint8_t secret[32]) {
  memcpy(device_secret, secret, 32);
}

size_t hal_host_derive_calls(void) {
  return derivations;
}

hal_err_t hal_derive_device_unique_secret(const uint8_t salt[32], uint8_t out[32]) {
  const uint8_t zero_iv[AES_IV_SIZE] = {0};
  uint8_t wrapped[32];

  if (hal_aes256_init(AES_ENCRYPT, AES_CBC, device_secret, zero_iv) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  if (hal_aes256_block_process(salt, wrapped) != HAL_SUCCESS) {
    hal_aes256_finalize();
    return HAL_FAIL;
  }

  if (hal_aes256_block_process(&salt[AES_BLOCK_SIZE], &wrapped[AES_BLOCK_SIZE]) != HAL_SUCCESS) {
    hal_aes256_finalize();
    return HAL_FAIL;
  }

  hal_aes256_finalize();

  SHA256_CTX sha;
  sha256_Init(&sha);
  sha256_Update(&sha, wrapped, sizeof(wrapped));
  sha256_Final(&sha, out);

  memzero(wrapped, sizeof(wrapped));
  derivations++;

  return HAL_SUCCESS;
}
