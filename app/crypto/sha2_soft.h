#ifndef _SHA2_SOFT_
#define _SHA2_SOFT_

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
  uint32_t  state[8];
  uint64_t  bitcount;
  uint32_t  buffer[SHA256_BLOCK_LENGTH/sizeof(uint32_t)];
} SOFT_SHA256_CTX;

void soft_sha256_Init(SOFT_SHA256_CTX* ctx);
void soft_sha256_Update(SOFT_SHA256_CTX* ctx, const uint8_t* data, size_t len);
void soft_sha256_Final(SOFT_SHA256_CTX* ctx, uint8_t data[SHA256_DIGEST_LENGTH]);

#endif
