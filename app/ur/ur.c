#include <ctype.h>
#include "bytewords.h"
#include "common.h"
#include "crypto/crc32.h"
#include "crypto/util.h"
#include "sampler.h"
#include "ur.h"
#include "ur_encode.h"

#define MIN_ENCODED_LEN 22
#define MAX_CBOR_HEADER_LEN 32

#define UR_LOOKUP_MULT 88116301
#define UR_TYPE(t) (ur_type_t)(((t * UR_LOOKUP_MULT) >> 28) & 0xf)

const char *const ur_type_string[] = {
  "BYTES",
  "ETH-SIGN-REQUEST",
  NULL,
  "CRYPTO-PSBT",
  "CRYPTO-MULTI-ACCOUNTS",
  NULL,
  "FW-UPDATE",
  "CRYPTO-HDKEY",
  "BTC-SIGNATURE",
  "CRYPTO-ACCOUNT",
  NULL,
  "ETH-SIGNATURE",
  "DEV-AUTH",
  "FS-DATA",
  "BTC-SIGN-REQUEST",
  "CRYPTO-OUTPUT",
};

static app_err_t ur_process_simple(ur_t* ur, uint8_t* parts, uint8_t* part_data, size_t part_len, uint32_t desc_idx, struct ur_part* part) {
  if (ur->part_desc[desc_idx]) {
    return ERR_NEED_MORE_DATA;
  }

  memcpy(&parts[desc_idx * part_len], part_data, part_len);
  ur_desc_t tmp = ((ur_desc_t) 1) << desc_idx;
  ur->part_desc[desc_idx] = tmp;
  ur->part_mask |= tmp;

  uint32_t part_count = UR_DESC_POPCOUNT(ur->part_mask);
  ur->percent_done = (part_count * 100) / part->ur_part_seqLen;

  if (part->ur_part_seqLen == part_count) {
    ur->data = parts;
    ur->data_len = part->ur_part_messageLen;
    return ERR_OK;
  }

  return ERR_NEED_MORE_DATA;
}

app_err_t ur_process_part(ur_t* ur, const uint8_t* in, size_t in_len) {
  if (in_len < 10) {
    return ERR_DATA;
  }

  if (!(toupper(in[0]) == 'U' && toupper(in[1]) == 'R' && in[2] == ':')) {
    return ERR_DATA;
  }

  size_t offset;
  uint32_t tmp = 0;

  for (offset = 3; offset < in_len; offset++) {
    if (in[offset] == '/') {
      break;
    }

    tmp += toupper(in[offset]);
  }

  if (offset == in_len) {
    return ERR_DATA;
  }

  // we assume we are dealing with a supported type and moving the
  // case where we are not to actual payload validation
  ur->type = UR_TYPE(tmp);

  if (isdigit(in[++offset])) {
    while((offset < in_len) && in[offset++] != '/') { /*we don't need this*/}
    if (offset == in_len) {
      return ERR_DATA;
    }

    tmp = 0;
  } else {
    tmp = 1;
  }

  uint32_t part_len = bytewords_decode(&in[offset], (in_len - offset), ur->data, ur->data_max_len);

  if (!part_len) {
    return ERR_DATA;
  }

  if (tmp == 1) {
    ur->crc = 0;
    ur->data_len = part_len;
    return ERR_OK;
  }

  struct ur_part part;
  if ((cbor_decode_ur_part(ur->data, part_len, &part, NULL) != ZCBOR_SUCCESS) ||
      (part.ur_part_seqLen > UR_MAX_PART_COUNT) ||
      (part.ur_part_messageLen > (ur->data_max_len - part_len))) {
    ur->crc = 0;
    return ERR_DATA;
  }

  if (part.ur_part_checksum != ur->crc) {
    ur->crc = part.ur_part_checksum;
    ur->part_mask = 0;
    for (int i = 0; i < UR_PART_DESC_COUNT; i++) {
      ur->part_desc[i] = 0;
    }

    random_sampler_init(part.ur_part_seqLen, ur->sampler_probs, ur->sampler_aliases);
  }

  part_len = part.ur_part_data.len;
  uint8_t* parts = &ur->data[part_len + MAX_CBOR_HEADER_LEN];
  uint8_t* part_data = (uint8_t*) part.ur_part_data.value;

  if (part.ur_part_seqNum <= part.ur_part_seqLen) {
    return ur_process_simple(ur, parts, part_data, part_len, part.ur_part_seqNum - 1, &part);
  }

  ur_desc_t indexes = fountain_part_indexes(part.ur_part_seqNum, ur->crc, part.ur_part_seqLen, ur->sampler_probs, ur->sampler_aliases);
  if ((indexes & (~ur->part_mask)) == 0) {
    return ERR_NEED_MORE_DATA;
  }

  int desc_idx = 0;
  int store_idx = -1;

  // reduce new part by existing
  while(desc_idx < UR_PART_DESC_COUNT) {
    if (UR_DESC_POPCOUNT(indexes) == 1) {
      int target_idx = UR_DESC_CTZ(indexes);
      if (ur_process_simple(ur, parts, part_data, part_len, target_idx, &part) == ERR_OK) {
        return ERR_OK;
      } else {
        store_idx = target_idx;
        break;
      }
    }

    if (ur->part_desc[desc_idx] == 0) {
      if (desc_idx >= part.ur_part_seqLen) {
        store_idx = desc_idx;
      }
    } else if ((ur->part_desc[desc_idx] & indexes) == (ur->part_desc[desc_idx])) {
      indexes = indexes ^ ur->part_desc[desc_idx];
      if (indexes == 0) {
        return ERR_NEED_MORE_DATA;
      }

      uint8_t* xorpart = &parts[desc_idx * part_len];
      for (int i = 0; i < part_len; i++) {
        part_data[i] ^= xorpart[i];
      }
    }

    desc_idx++;
  }

  // all buffers are full, but we don't give up yet. If one of the buffered parts is more mixed
  // then the current part, we overwrite it since parts easier to reduce are better for us
  if (store_idx == -1) {
    int worst_count = UR_DESC_POPCOUNT(indexes);

    desc_idx = part.ur_part_seqLen;

    while(desc_idx < UR_PART_DESC_COUNT) {
      int count = UR_DESC_POPCOUNT(ur->part_desc[desc_idx]);

      if (count > worst_count) {
        store_idx = desc_idx;
        worst_count = count;
      }

      desc_idx++;
    }

    if (store_idx == -1) {
      return ERR_NEED_MORE_DATA;
    }
  }

  if (store_idx >= part.ur_part_seqLen) {
    memcpy(&parts[store_idx * part_len], part_data, part_len);
    ur->part_desc[store_idx] = indexes;
  }

  //reduce existing parts by new part
  desc_idx = part.ur_part_seqLen;

  while(desc_idx < UR_PART_DESC_COUNT) {
    if ((desc_idx != store_idx) && ((ur->part_desc[desc_idx] & indexes) == indexes)) {
      ur->part_desc[desc_idx] = indexes ^ ur->part_desc[desc_idx];

      if (ur->part_desc[desc_idx] == 0) {
        desc_idx++;
        continue;
      }

      uint8_t* target_part = &parts[desc_idx * part_len];
      for (int i = 0; i < part_len; i++) {
        target_part[i] ^= part_data[i];
      }

      if (UR_DESC_POPCOUNT(ur->part_desc[desc_idx]) == 1) {
        int target_idx = UR_DESC_CTZ(ur->part_desc[desc_idx]);
        if (ur_process_simple(ur, parts, target_part, part_len, target_idx, &part) == ERR_OK) {
          return ERR_OK;
        }

        ur->part_desc[desc_idx] = 0;
      }
    }

    desc_idx++;
  }

  return ERR_NEED_MORE_DATA;
}

void ur_out_init(ur_out_t* ur, ur_type_t type, const uint8_t* data, size_t len, size_t segment_len) {
  memset(ur, 0, sizeof(ur_out_t));

  ur->data = data;
  ur->type = type;
  ur->part.ur_part_messageLen = len;

  if (len > segment_len) {
    ur->part.ur_part_checksum = crc32(ur->data, len);
    ur->part.ur_part_seqLen = (len + (segment_len - 1)) / segment_len;
    ur->part.ur_part_data.len = segment_len;
    random_sampler_init(ur->part.ur_part_seqLen, ur->sampler_probs, ur->sampler_aliases);
  }
}

static app_err_t ur_encode_part(ur_out_t* ur, const uint8_t* data, size_t data_len, char* out, size_t max_len) {
  if (max_len < MIN_ENCODED_LEN) {
    return ERR_DATA;
  }

  size_t off = 0;
  out[off++] = 'U';
  out[off++] = 'R';
  out[off++] = ':';

  const char* typestr = ur_type_string[ur->type];

  while(*typestr != '\0') {
    out[off++] = *(typestr++);
  }

  out[off++] = '/';

  if (ur->part.ur_part_seqLen > 1) {
    uint8_t num[UINT32_STRING_LEN];
    uint8_t* p = u32toa(ur->part.ur_part_seqNum, num, UINT32_STRING_LEN);
    while(*p != '\0') {
      out[off++] = *(p++);
    }

    out[off++] = '-';

    p = u32toa(ur->part.ur_part_seqLen, num, UINT32_STRING_LEN);
    while(*p != '\0') {
      out[off++] = *(p++);
    }

    out[off++] = '/';
  }

  size_t outlen = bytewords_encode(data, data_len, (uint8_t*)&out[off], (max_len-off-1));
  if (!outlen) {
    return ERR_DATA;
  }

  out[off+outlen] = '\0';
  return ERR_OK;
}

app_err_t ur_encode_next(ur_out_t* ur, char* out, size_t max_len) {
  uint8_t part_buf[ur->part.ur_part_data.len];
  uint8_t part_cbor[ur->part.ur_part_data.len + MAX_CBOR_HEADER_LEN];

  ur->part.ur_part_data.value = part_buf;

  memset(part_buf, 0, ur->part.ur_part_data.len);

  if (ur->part.ur_part_seqNum < ur->part.ur_part_seqLen) {
    size_t off = ur->part.ur_part_seqNum * ur->part.ur_part_data.len;
    ur->part.ur_part_seqNum++;

    size_t copy_len = APP_MIN((ur->part.ur_part_messageLen - off), ur->part.ur_part_data.len);
    memcpy(part_buf, &ur->data[off], copy_len);
  } else {
    ur->part.ur_part_seqNum++;
    ur_desc_t indexes = fountain_part_indexes(ur->part.ur_part_seqNum, ur->part.ur_part_checksum, ur->part.ur_part_seqLen, ur->sampler_probs, ur->sampler_aliases);

    for (int part_num = 0; part_num < ur->part.ur_part_seqLen; part_num++) {
      if (indexes & 1) {
        size_t off = part_num * ur->part.ur_part_data.len;
        size_t copy_len = APP_MIN((ur->part.ur_part_messageLen - off), ur->part.ur_part_data.len);

        for (int i = 0; i < copy_len; i++) {
          part_buf[i] ^= ur->data[off + i];
        }
      }

      indexes >>= 1;
    }
  }

  size_t part_cbor_len;
  cbor_encode_ur_part(part_cbor, (ur->part.ur_part_data.len + MAX_CBOR_HEADER_LEN), &ur->part, &part_cbor_len);
  return ur_encode_part(ur, part_cbor, part_cbor_len, out, max_len);
}

app_err_t ur_encode(ur_out_t* ur, char* out, size_t max_len) {
  return ur_encode_part(ur, ur->data, ur->part.ur_part_messageLen, out, max_len);
}
