#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#define AES_256_KEY_SIZE 32
#define AES_128_KEY_SIZE 16
#define AES_IV_SIZE 16
#define AES_BLOCK_SIZE 16

/* AES-256-CBC (Secure Channel V1) */
uint8_t aes_encrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out);
uint8_t aes_decrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out);
uint8_t aes_cbc_mac(const uint8_t* key, const uint8_t* data, uint32_t len, uint8_t* out);

/* AES-128-CCM (Secure Channel V2) */
#define CCM_TAG_SIZE 8
#define CCM_NONCE_SIZE 13

uint8_t aes128_ccm_encrypt(const uint8_t key[AES_128_KEY_SIZE], const uint8_t nonce[CCM_NONCE_SIZE],
                           const uint8_t* plaintext, uint32_t len, uint8_t* out);
uint8_t aes128_ccm_decrypt(const uint8_t key[AES_128_KEY_SIZE], const uint8_t nonce[CCM_NONCE_SIZE],
                           const uint8_t* ciphertext, uint32_t len, uint8_t* out);

#endif
