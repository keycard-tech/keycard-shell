#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#define AES_256_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_BLOCK_SIZE 16

uint8_t aes_encrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out);
uint8_t aes_decrypt_cbc(const uint8_t* key, const uint8_t* iv, const uint8_t* data, uint32_t len, uint8_t* out);
uint8_t aes_cbc_mac(const uint8_t* key, const uint8_t* data, uint32_t len, uint8_t* out);

#endif
