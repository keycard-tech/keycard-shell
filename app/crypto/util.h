#ifndef __PAD_H__
#define __PAD_H__

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto/sha2.h"
#include "crypto/ripemd160.h"

#define UINT32_STRING_LEN 11
#define UINT64_STRING_LEN 21

extern const char* const HEX_DIGITS;

uint32_t pad_iso9797_m1(uint8_t* data, uint8_t plen, uint32_t size);
uint32_t unpad_iso9797_m1(uint8_t* data, uint32_t size);
uint8_t* u32toa(uint32_t value, uint8_t* buf, uint32_t len);
uint8_t* u64toa(uint64_t value, uint8_t* buf, uint32_t len);

size_t strnlen(const char *s, size_t maxlen);
/* decode consumes hex_len characters and yields hex_len / 2 bytes; encode takes a byte count */
bool base16_decode(const char* s, uint8_t* out, size_t hex_len);
void base16_encode(const uint8_t* data, char* out, size_t len);
bool atoi256BE(const char* str, size_t len, uint8_t out[32]);

static inline int memcmp_ct(const uint8_t* a, const uint8_t* b, size_t length) {
  int compareSum = 0;

  for (int i = 0; i < length; i++) {
    compareSum |= a[i] ^ b[i];
  }

  return compareSum;
}

static inline bool all_zero(const uint8_t* data, size_t len) {
  for (int i = 0; i < len; i++) {
    if (data[i] != 0) {
      return false;
    }
  }

  return true;
}

static inline void hash160(const uint8_t* data, size_t data_len, uint8_t out[RIPEMD160_DIGEST_LENGTH]) {
  uint8_t tmp[SHA256_DIGEST_LENGTH];
  sha256_Raw(data, data_len, tmp);
  ripemd160(tmp, SHA256_DIGEST_LENGTH, out);
}

static inline void sha256d(const uint8_t* data, size_t data_len, uint8_t out[SHA256_DIGEST_LENGTH]) {
  sha256_Raw(data, data_len, out);
  sha256_Raw(out, SHA256_DIGEST_LENGTH, out);
}

#endif
