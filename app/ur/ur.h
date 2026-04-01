#ifndef _UR_H_
#define _UR_H_

#include <stdint.h>
#include <string.h>
#include "error.h"
#include "ur_types.h"

#define UR_MAX_PART_COUNT 128
#define UR_PART_DESC_COUNT (UR_MAX_PART_COUNT + 16)

typedef struct {
  uint32_t w[4];
} ur_desc_t;

static inline void ur_desc_zero(ur_desc_t* x) {
  x->w[0] = x->w[1] = x->w[2] = x->w[3] = 0;
}

static inline void ur_desc_set_bit(ur_desc_t* x, uint32_t idx) {
  x->w[idx >> 5] |= 1u << (idx & 31);
}

static inline int ur_desc_get_bit(const ur_desc_t* x, uint32_t idx) {
  return (x->w[idx >> 5] >> (idx & 31)) & 1;
}

static inline void ur_desc_or_assign(ur_desc_t* x, const ur_desc_t* y) {
  x->w[0] |= y->w[0];
  x->w[1] |= y->w[1];
  x->w[2] |= y->w[2];
  x->w[3] |= y->w[3];
}

static inline void ur_desc_xor(ur_desc_t* result, const ur_desc_t* x, const ur_desc_t* y) {
  result->w[0] = x->w[0] ^ y->w[0];
  result->w[1] = x->w[1] ^ y->w[1];
  result->w[2] = x->w[2] ^ y->w[2];
  result->w[3] = x->w[3] ^ y->w[3];
}

static inline int ur_desc_is_zero(const ur_desc_t* x) {
  return (x->w[0] | x->w[1] | x->w[2] | x->w[3]) == 0;
}

static inline int ur_desc_popcount(const ur_desc_t* x) {
  return __builtin_popcount(x->w[0]) + __builtin_popcount(x->w[1]) +
         __builtin_popcount(x->w[2]) + __builtin_popcount(x->w[3]);
}

static inline int ur_desc_ctz(const ur_desc_t* x) {
  if (x->w[0]) return __builtin_ctz(x->w[0]);
  if (x->w[1]) return 32 + __builtin_ctz(x->w[1]);
  if (x->w[2]) return 64 + __builtin_ctz(x->w[2]);
  if (x->w[3]) return 96 + __builtin_ctz(x->w[3]);
  return 128;
}

static inline void ur_desc_assign(ur_desc_t* x, const ur_desc_t* y) {
  x->w[0] = y->w[0];
  x->w[1] = y->w[1];
  x->w[2] = y->w[2];
  x->w[3] = y->w[3];
}

static inline int ur_desc_is_subset(const ur_desc_t* x, const ur_desc_t* y) {
  return ((x->w[0] & ~y->w[0]) | (x->w[1] & ~y->w[1]) |
          (x->w[2] & ~y->w[2]) | (x->w[3] & ~y->w[3])) == 0;
}

typedef enum {
  BYTES = 0,
  ETH_SIGN_REQUEST = 1,
  CRYPTO_PSBT = 3,
  CRYPTO_MULTI_ACCOUNTS = 4,
  FW_UPDATE = 6,
  CRYPTO_HDKEY = 7,
  BTC_SIGNATURE = 8,
  CRYPTO_ACCOUNT = 9,
  ETH_SIGNATURE = 11,
  DEV_AUTH = 12,
  FS_DATA = 13,
  BTC_SIGN_REQUEST = 14,
  CRYPTO_OUTPUT = 15,
  UR_ANY_TX = 254,
  NO_UR = 255,
} ur_type_t;

typedef struct {
  ur_type_t type;
  uint32_t crc;
  ur_desc_t part_desc[UR_PART_DESC_COUNT];
  ur_desc_t part_mask;
  double sampler_probs[UR_MAX_PART_COUNT];
  int sampler_aliases[UR_MAX_PART_COUNT];
  size_t data_max_len;
  size_t data_len;
  uint8_t* data;
  uint8_t percent_done;
} ur_t;

typedef struct {
  ur_type_t type;
  struct ur_part part;
  double sampler_probs[UR_MAX_PART_COUNT];
  int sampler_aliases[UR_MAX_PART_COUNT];
  const uint8_t* data;
} ur_out_t;

app_err_t ur_process_part(ur_t* ur, const uint8_t* in, size_t in_len);

void ur_out_init(ur_out_t* ur, ur_type_t type, const uint8_t* data, size_t len, size_t segment_len);
app_err_t ur_encode_next(ur_out_t* ur, char* out, size_t max_len);
app_err_t ur_encode(ur_out_t* ur, char* out, size_t max_len);

#endif
