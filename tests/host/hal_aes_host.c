#include "hal.h"
#include "hal_host.h"

#include <string.h>

/*
 * AES, modelled at the hal_aes256_* / hal_aes128_ccm_* boundary so the firmware's own branches of
 * app/crypto/aes.c and aes_ccm.c run on a host. The cipher and CCM here are written from FIPS-197 and
 * SP 800-38C rather than from how aes_ccm.c drives them -- that is the whole point of modelling the
 * peripheral instead of the aes_* functions -- and what the two documents leave open is refused loudly
 * rather than guessed at, in the counters host/hal_host.h exposes.
 *
 * Two things the silicon does and this cannot: nothing here is constant-time or side-channel-shaped,
 * and the CCM peripheral's internal ordering of the counter and MAC is invisible to the app, so what is
 * pinned is the observable contract -- bytes out, tag out -- not the register traffic.
 */

#define AES_ROUNDS_MAX 14
#define AES_RK_BYTES (16 * (AES_ROUNDS_MAX + 1))

typedef struct {
  uint8_t rk[AES_RK_BYTES];
  uint8_t rounds;
} aes_key_t;

static size_t rejections;
static size_t refuse_init;

/* ------------------------------------------------------------------ FIPS-197 core */

static uint8_t xtime(uint8_t b) {
  return (uint8_t)((b << 1) ^ (((b & 0x80) != 0) ? 0x1b : 0x00));
}

static uint8_t mul(uint8_t a, uint8_t b) {
  uint8_t out = 0;

  while (b != 0) {
    if (b & 1) {
      out ^= a;
    }

    a = xtime(a);
    b = (uint8_t)(b >> 1);
  }

  return out;
}

static uint8_t sbox[256];
static uint8_t inv_sbox[256];
static bool tables_ready;

static uint8_t gf_inv(uint8_t b) {
  if (b == 0) {
    return 0;
  }

  /* Brute force over GF(2^8) mod x^8 + x^4 + x^3 + x + 1 -- the tables are built once per process and
   * this keeps both S-boxes derived rather than transcribed. */
  for (uint8_t candidate = 1; candidate != 0; candidate++) {
    if (mul(candidate, b) == 1) {
      return candidate;
    }
  }

  return 0;
}

/* FIPS-197 5.1: b'i = b'i xor b'(i+4) xor b'(i+5) xor b'(i+6) xor b'(i+7) xor c'i, c = 0x63. */
static uint8_t affine(uint8_t b) {
  uint8_t out = 0x63;

  for (int i = 0; i < 8; i++) {
    uint8_t bit = 0;

    for (int k = 0; k < 4; k++) {
      bit ^= (uint8_t)((b >> ((i + 4 + k) % 8)) & 1);
    }

    bit ^= (uint8_t)((b >> i) & 1);
    out ^= (uint8_t)(bit << i);
  }

  return out;
}

static void build_tables(void) {
  for (int b = 0; b < 256; b++) {
    const uint8_t s = affine(gf_inv((uint8_t)b));

    sbox[b] = s;
    inv_sbox[s] = (uint8_t)b;
  }

  tables_ready = true;
}

static const uint8_t rcon[11] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c };

static void aes_setup(aes_key_t* key, const uint8_t* raw, size_t bytes) {
  if (!tables_ready) {
    build_tables();
  }

  const size_t nk = bytes / 4;

  key->rounds = (uint8_t)(6 + nk);

  memcpy(key->rk, raw, bytes);

  for (size_t i = nk; i < 4 * (size_t)(key->rounds + 1); i++) {
    uint8_t temp[4];
    memcpy(temp, &key->rk[(i - 1) * 4], 4);

    if (i % nk == 0) {
      const uint8_t first = temp[0];

      temp[0] = (uint8_t)(sbox[temp[1]] ^ rcon[i / nk - 1]);
      temp[1] = sbox[temp[2]];
      temp[2] = sbox[temp[3]];
      temp[3] = sbox[first];
    } else if ((nk > 6) && (i % nk == 4)) {
      for (int j = 0; j < 4; j++) {
        temp[j] = sbox[temp[j]];
      }
    }

    for (int j = 0; j < 4; j++) {
      key->rk[i * 4 + j] = (uint8_t)(key->rk[(i - nk) * 4 + j] ^ temp[j]);
    }
  }
}

static void add_round_key(uint8_t state[16], const uint8_t* rk) {
  for (int i = 0; i < 16; i++) {
    state[i] ^= rk[i];
  }
}

/* FIPS-197 numbers the state column-major: byte i of the block is state[i % 4][i / 4]. */
static void shift_rows(uint8_t s[16], bool inverse) {
  for (int r = 1; r < 4; r++) {
    uint8_t row[4];

    for (int c = 0; c < 4; c++) {
      const int from = inverse ? (c - r + 4) % 4 : (c + r) % 4;
      row[c] = s[from * 4 + r];
    }

    for (int c = 0; c < 4; c++) {
      s[c * 4 + r] = row[c];
    }
  }
}

static void sub_bytes(uint8_t state[16], bool inverse) {
  for (int i = 0; i < 16; i++) {
    state[i] = inverse ? inv_sbox[state[i]] : sbox[state[i]];
  }
}

static void mix_columns(uint8_t s[16], bool inverse) {
  for (int c = 0; c < 4; c++) {
    uint8_t* col = &s[c * 4];
    uint8_t out[4];

    if (!inverse) {
      out[0] = (uint8_t)(xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3]);
      out[1] = (uint8_t)(col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3]);
      out[2] = (uint8_t)(col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]));
      out[3] = (uint8_t)((xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]));
    } else {
      for (int r = 0; r < 4; r++) {
        out[r] = (uint8_t)(mul(col[r], 0x0e) ^ mul(col[(r + 1) & 3], 0x0b) ^ mul(col[(r + 2) & 3], 0x0d) ^ mul(col[(r + 3) & 3], 0x09));
      }
    }

    memcpy(col, out, 4);
  }
}

static void aes_encrypt_block(const aes_key_t* key, const uint8_t in[16], uint8_t out[16]) {
  memcpy(out, in, 16);

  add_round_key(out, key->rk);

  for (uint8_t round = 1; round < key->rounds; round++) {
    sub_bytes(out, false);
    shift_rows(out, false);
    mix_columns(out, false);
    add_round_key(out, &key->rk[round * 16]);
  }

  sub_bytes(out, false);
  shift_rows(out, false);
  add_round_key(out, &key->rk[key->rounds * 16]);
}

static void aes_decrypt_block(const aes_key_t* key, const uint8_t in[16], uint8_t out[16]) {
  memcpy(out, in, 16);

  add_round_key(out, &key->rk[key->rounds * 16]);

  for (int round = key->rounds - 1; round >= 1; round--) {
    shift_rows(out, true);
    sub_bytes(out, true);
    add_round_key(out, &key->rk[round * 16]);
    mix_columns(out, true);
  }

  shift_rows(out, true);
  sub_bytes(out, true);
  add_round_key(out, key->rk);
}

/* ------------------------------------------------------------------ the model's state */

static struct {
  bool open;
  bool decrypt;
  aes_key_t key;
  uint8_t iv[16];
  size_t blocks;
} cbc;

/* ------------------------------------------------------------------ CCM, per SP 800-38C */

static struct {
  bool open;
  bool decrypt;
  bool aad_seen;
  aes_key_t key;
  uint8_t a0[16];   /* CTR* block with counter 0, which masks the tag */
  uint8_t a[16];    /* running CTR* block */
  uint8_t ks[16];   /* current keystream */
  size_t ks_pos;
  uint8_t mac[16];  /* CBC-MAC accumulator over B0 and the payload */
  uint8_t part[16];
  size_t part_len;
  size_t fed;
  size_t message;
  size_t len_field;
  size_t tag_len;
} ccm;

size_t hal_host_aes_rejections(void) {
  return rejections;
}

void hal_host_aes_refuse_next(size_t jobs) {
  refuse_init = jobs;
}

size_t hal_host_aes_cbc_blocks(void) {
  return cbc.blocks;
}

size_t hal_host_aes_ccm_bytes(void) {
  return ccm.fed;
}

void hal_host_aes_reset(void) {
  memset(&cbc, 0, sizeof(cbc));
  memset(&ccm, 0, sizeof(ccm));
  rejections = 0;
  refuse_init = false;
}

hal_err_t hal_aes256_init(hal_aes_mode_t mode, hal_aes_chaining_t chaining, const uint8_t key[AES_256_KEY_SIZE], const uint8_t iv[AES_IV_SIZE]) {
  if (refuse_init) {
    refuse_init--;
    rejections++;
    return HAL_FAIL;
  }

  if (chaining != AES_CBC) {
    rejections++;
    return HAL_FAIL;
  }

  aes_setup(&cbc.key, key, AES_256_KEY_SIZE);
  memcpy(cbc.iv, iv, 16);
  cbc.decrypt = mode == AES_DECRYPT;
  cbc.open = true;

  return HAL_SUCCESS;
}

hal_err_t hal_aes256_block_process(const uint8_t in[16], uint8_t out[16]) {
  if (!cbc.open) {
    rejections++;
    return HAL_FAIL;
  }

  cbc.blocks++;

  if (!cbc.decrypt) {
    uint8_t mixed[16];

    for (int i = 0; i < 16; i++) {
      mixed[i] = (uint8_t)(in[i] ^ cbc.iv[i]);
    }

    aes_encrypt_block(&cbc.key, mixed, out);
    memcpy(cbc.iv, out, 16);
  } else {
    uint8_t plain[16];

    aes_decrypt_block(&cbc.key, in, plain);

    for (int i = 0; i < 16; i++) {
      out[i] = (uint8_t)(plain[i] ^ cbc.iv[i]);
    }

    memcpy(cbc.iv, in, 16);
  }

  return HAL_SUCCESS;
}

hal_err_t hal_aes256_finalize(void) {
  memset(&cbc, 0, sizeof(cbc));

  return HAL_SUCCESS;
}

/* ------------------------------------------------------------------ CCM, per SP 800-38C */

static void ctr_next(uint8_t a[16], size_t len_field) {
  for (size_t i = 16; i-- > 16 - len_field;) {
    if (++a[i] != 0) {
      break;
    }
  }
}

static void ccm_mac_bytes(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    ccm.part[ccm.part_len++] = data[i];

    if (ccm.part_len == 16) {
      for (int j = 0; j < 16; j++) {
        ccm.mac[j] ^= ccm.part[j];
      }

      aes_encrypt_block(&ccm.key, ccm.mac, ccm.mac);
      ccm.part_len = 0;
    }
  }
}

/* Both directions are the same keystream xor; what differs is which side of the xor the MAC runs over,
 * and SP 800-38C is explicit that it is the plaintext. */
/* SP 800-38C A.2.1: the associated data is preceded by its length and, like the payload, joins the MAC
 * as a continuation of the same byte string -- the zero padding comes once, at the end of all of it. */
void hal_host_aes_ccm_aad(const uint8_t* data, size_t len) {
  if (!ccm.open || ccm.fed != 0) {
    rejections++;
    return;
  }

  uint8_t prefix[2];

  /* The four-byte form for 0xff00 and longer is SP 800-38C A.2.1's second case; nothing here reaches it,
   * and the published vectors do not either, so it is refused rather than left unexercised. */
  if (len >= 0xff00) {
    rejections++;
    return;
  }

  prefix[0] = (uint8_t)(len >> 8);
  prefix[1] = (uint8_t)len;

  ccm_mac_bytes(prefix, sizeof(prefix));
  ccm_mac_bytes(data, len);

  /* Each string is zero padded to a block on its own; the payload starts on a fresh one. */
  if (ccm.part_len != 0) {
    const uint8_t zeros[16] = { 0 };
    ccm_mac_bytes(zeros, (size_t)(16 - ccm.part_len));
  }

  ccm.aad_seen = true;
}

static void ccm_stream(const uint8_t* in, uint8_t* out, size_t len) {
  if (((ccm.a0[0] & 0x40) != 0) && !ccm.aad_seen) {
    /* A B0 that announced associated data, and none was ever handed over: the tag will be wrong, which is
     * exactly what the caller deserves, but not without being counted. */
    rejections++;
  }

  for (size_t i = 0; i < len; i++) {
    if (ccm.ks_pos == 16) {
      ctr_next(ccm.a, ccm.len_field);
      aes_encrypt_block(&ccm.key, ccm.a, ccm.ks);
      ccm.ks_pos = 0;
    }

    const uint8_t plain = ccm.decrypt ? (uint8_t)(in[i] ^ ccm.ks[ccm.ks_pos]) : in[i];

    out[i] = ccm.decrypt ? plain : (uint8_t)(in[i] ^ ccm.ks[ccm.ks_pos]);

    ccm_mac_bytes(&plain, 1);
    ccm.ks_pos++;
    ccm.fed++;
  }
}

hal_err_t hal_aes128_ccm_init(hal_aes_mode_t mode, const uint8_t key[AES_128_KEY_SIZE], const uint8_t b0[16]) {
  if (refuse_init) {
    /* Silicon refusing to start a job: no key loaded, no output written. */
    refuse_init = false;
    rejections++;
    return HAL_FAIL;
  }

  const uint8_t flags = b0[0];
  const size_t len_field = (size_t)(flags & 0x07) + 1;
  const size_t tag_len = (size_t)((((flags >> 3) & 0x07) * 2) + 2);
  const size_t nonce = 15 - len_field;

  /* A tag longer than the caller's buffer would be silently truncated, and a nonce shorter than 7 bytes
   * is outside what the length field can carry. Both are refused, not guessed. Associated data is
   * accepted, but no caller in the firmware announces any: hal_host_aes_ccm_aad() exists so the published
   * SP 800-38C vectors, which all carry some, can reach this model. */
  if ((tag_len > CCM_TAG_SIZE) || (nonce < 7)) {
    rejections++;
    return HAL_FAIL;
  }

  aes_setup(&ccm.key, key, AES_128_KEY_SIZE);

  ccm.len_field = len_field;
  ccm.tag_len = tag_len;
  ccm.decrypt = mode == AES_DECRYPT;
  ccm.ks_pos = 16; /* the first payload byte advances to S_1, since S_0 belongs to the tag */
  ccm.part_len = 0;
  ccm.fed = 0;
  ccm.aad_seen = false;

  memcpy(ccm.a0, b0, 16);
  ccm.a0[0] = (uint8_t)(flags & 0x07); /* CTR* carries neither the M bits nor the Adata bit */
  memset(&ccm.a0[16 - len_field], 0, len_field);
  memcpy(ccm.a, ccm.a0, 16);

  memcpy(ccm.mac, b0, 16);
  aes_encrypt_block(&ccm.key, ccm.mac, ccm.mac);

  ccm.message = 0;
  for (size_t i = 0; i < len_field; i++) {
    ccm.message = (ccm.message << 8) | b0[16 - len_field + i];
  }

  (void)nonce;
  ccm.open = true;

  return HAL_SUCCESS;
}

hal_err_t hal_aes128_ccm_block_process(const uint8_t in[16], uint8_t out[16]) {
  if (!ccm.open) {
    rejections++;
    return HAL_FAIL;
  }

  ccm_stream(in, out, 16);

  return HAL_SUCCESS;
}

hal_err_t hal_aes128_ccm_block_process_last(hal_aes_mode_t mode, const uint8_t in[16], uint8_t out[16], size_t len) {
  (void)mode;

  if (!ccm.open || (len > 16)) {
    rejections++;
    return HAL_FAIL;
  }

  ccm_stream(in, out, len);

  return HAL_SUCCESS;
}

hal_err_t hal_aes128_ccm_finish(uint8_t tag[CCM_TAG_SIZE]) {
  if (!ccm.open) {
    rejections++;
    return HAL_FAIL;
  }

  if (ccm.fed != ccm.message) {
    rejections++;
  }

  /* The MAC runs over the payload zero padded to a whole block; the ciphertext does not carry that
   * padding, so it is added here, once, whatever the streaming shape was. */
  if (ccm.part_len != 0) {
    const uint8_t zeros[16] = { 0 };
    ccm_mac_bytes(zeros, (size_t)(16 - ccm.part_len));
  }

  uint8_t s0[16];
  aes_encrypt_block(&ccm.key, ccm.a0, s0);

  for (size_t i = 0; i < CCM_TAG_SIZE; i++) {
    tag[i] = (uint8_t)(ccm.mac[i] ^ s0[i]);
  }

  ccm.open = false;

  return HAL_SUCCESS;
}
