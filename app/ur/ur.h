#ifndef _UR_H_
#define _UR_H_

#include <stdint.h>
#include "error.h"
#include "ur_decode.h"

#define UR_MAX_PART_COUNT 64
#define UR_PART_DESC_COUNT (UR_MAX_PART_COUNT + 16)

#if UR_MAX_PART_COUNT > 32
typedef uint64_t ur_desc_t;
#define UR_DESC_POPCOUNT(__X__) __builtin_popcountll(__X__)
#define UR_DESC_CTZ(__X__) __builtin_ctzll(__X__)
#else
typedef uint32_t ur_desc_t;
#define UR_DESC_POPCOUNT(__X__) __builtin_popcount(__X__)
#define UR_DESC_CTZ(__X__) __builtin_ctz(__X__)
#endif

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
  UR_ANY_TX = 255
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
