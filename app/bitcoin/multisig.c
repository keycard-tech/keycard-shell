#include "multisig.h"

#include <string.h>

#include "crypto/base58.h"
#include "crypto/bip32.h"
#include "crypto/ecdsa.h"
#include "crypto/memzero.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "crypto/util.h"

#define MULTISIG_OP_CHECKMULTISIG 0xae

static bool _parse_u32_dec(const char* s, size_t len, uint32_t* out) {
  uint32_t v = 0;
  if (len == 0 || len > 10) return false;

  for (size_t i = 0; i < len; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (uint32_t) (s[i] - '0');
  }
  *out = v;
  return true;
}

static bool _parse_path(const char* s, uint32_t* path, uint8_t* path_len) {
  uint8_t count = 0;
  size_t i = 0;

  /* skip the leading "m" / "M" */
  while (i < strlen(s) && s[i] != '/') i++;
  if (i >= strlen(s)) return false;
  i++;

  while (i < strlen(s)) {
    size_t j = i;
    while (j < strlen(s) && s[j] != '/') j++;
    bool hardened = false;
    size_t tok_len = j - i;

    if (tok_len > 0 && s[j - 1] == '\'') {
      hardened = true;
      tok_len--;
    }

    uint32_t idx;
    if (!_parse_u32_dec(&s[i], tok_len, &idx)) return false;
    if (hardened) idx |= 0x80000000;
    if (count >= MULTISIG_MAX_PATH_LEN) return false;

    path[count++] = idx;

    if (j >= strlen(s)) break;
    i = j + 1;
  }

  *path_len = count;
  return count > 0;
}

static size_t _path_to_str(const uint32_t* path, uint8_t path_len, char* out, size_t cap) {
  size_t off = 0;
  if (cap == 0) return 0;

  out[off++] = 'm';
  for (uint8_t i = 0; i < path_len; i++) {
    if (off >= cap - 1) return 0;
    out[off++] = '/';
    uint32_t idx = path[i];
    bool hardened = (idx & 0x80000000) != 0;
    uint8_t buf[UINT32_STRING_LEN];
    uint8_t* p = u32toa(idx & 0x7fffffff, buf, sizeof(buf));
    size_t nd = strlen((char*) p);
    if (off + nd >= cap) return 0;
    memcpy(&out[off], p, nd + 1);
    off += nd;
    if (hardened) out[off++] = '\'';
  }
  out[off] = '\0';
  return off;
}

/* ------------------------------------------------------------------ */
/* header value parsers                                                */
/* ------------------------------------------------------------------ */

static bool _parse_policy(const char* s, uint8_t* m, uint8_t* n) {
  size_t i = 0;
  while (s[i] != '\0' && s[i] != ' ') i++;
  if (i == 0) return false;

  uint32_t mv;
  if (!_parse_u32_dec(s, i, &mv)) return false;

  /* skip " of " */
  i++;
  if (strncmp(&s[i], "of ", 3) != 0) return false;
  i += 3;

  uint32_t nv;
  if (!_parse_u32_dec(&s[i], strlen(&s[i]), &nv)) return false;

  *m = (uint8_t) mv;
  *n = (uint8_t) nv;
  return (*m >= 1) && (*n >= 1) && (*m <= *n);
}

static bool _parse_format(const char* s, multisig_format_t* fmt) {
  size_t len = strlen(s);

  if (len == 5 && !strncmp(s, "P2WSH", 5)) { *fmt = MULTISIG_FORMAT_P2WSH; return true; }
  if (len == 4 && !strncmp(s, "P2SH", 4)) { *fmt = MULTISIG_FORMAT_P2SH; return true; }
  if (len == 10 && !strncmp(s, "P2SH-P2WSH", 10)) { *fmt = MULTISIG_FORMAT_P2WSH_P2SH; return true; }
  if (len == 11 && !strncmp(s, "P2WSH-P2SH", 11)) { *fmt = MULTISIG_FORMAT_P2WSH_P2SH; return true; }
  return false;
}

app_err_t multisig_parse_text(const char* text, size_t len, multisig_t* out) {
  memset(out, 0, sizeof(*out));

  bool pending_path = false;
  size_t pos = 0;

  while (pos < len) {
    size_t le = pos;
    while (le < len && text[le] != '\n') le++;
    size_t llen = le - pos;

    if (llen >= 256) return ERR_DATA;

    char line[256];
    memcpy(line, &text[pos], llen);
    line[llen] = '\0';
    pos = (le < len) ? le + 1 : le;

    char* s = line;
    size_t slen = strlen(s);
    while (slen && (s[slen - 1] == ' ' || s[slen - 1] == '\t')) s[--slen] = '\0';
    while (*s == ' ' || *s == '\t') s++;

    if (*s == '\0' || *s == '#') continue;

    char* colon = strchr(s, ':');
    if (colon == NULL) return ERR_DATA;
    *colon = '\0';

    char* key = s;
    char* value = colon + 1;
    while (*value == ' ' || *value == '\t') value++;
    size_t vlen = strlen(value);
    while (vlen && (value[vlen - 1] == ' ' || value[vlen - 1] == '\t')) value[--vlen] = '\0';

    if (pending_path) {
      /* expecting "<8-hex-fingerprint>: <xpub>" */
      if (out->key_count >= MULTISIG_MAX_KEYS) return ERR_FULL;
      multisig_key_t* k = &out->keys[out->key_count];

      if (strlen(key) != 8 || !base16_decode(key, k->fingerprint, MULTISIG_FP_LEN)) {
        return ERR_DATA;
      }
      if (base58_decode_check(value, k->xpub, MULTISIG_XPUB_LEN) != MULTISIG_XPUB_LEN) {
        return ERR_DATA;
      }
      out->key_count++;
      pending_path = false;
      continue;
    }

    if (!strcmp(key, "Name")) {
      if (strlen(value) >= MULTISIG_MAX_NAME_LEN) return ERR_DATA;
      memcpy(out->name, value, strlen(value) + 1);
    } else if (!strcmp(key, "Policy")) {
      if (!_parse_policy(value, &out->m, &out->n)) return ERR_DATA;
    } else if (!strcmp(key, "Format")) {
      if (!_parse_format(value, &out->format)) return ERR_DATA;
    } else if (!strcmp(key, "Derivation")) {
      if (out->key_count >= MULTISIG_MAX_KEYS) return ERR_FULL;
      if (!_parse_path(value, out->keys[out->key_count].path, &out->keys[out->key_count].path_len)) {
        return ERR_DATA;
      }
      pending_path = true;
    } else {
      return ERR_DATA;
    }
  }

  if (out->n == 0 || out->key_count != out->n || out->m == 0 || out->m > out->n) {
    return ERR_DATA;
  }

  return ERR_OK;
}

static void _put_u32_le(uint8_t* p, uint32_t v) {
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

static uint32_t _get_u32_le(const uint8_t* p) {
  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

app_err_t multisig_serialize(const multisig_t* d, uint8_t* out, size_t cap, size_t* out_len) {
  size_t off = 0;
  uint8_t name_len = (uint8_t) strlen(d->name);

  size_t need = 5 + name_len;
  for (uint8_t i = 0; i < d->key_count; i++) {
    need += 1 + (d->keys[i].path_len * 4) + MULTISIG_FP_LEN + MULTISIG_XPUB_LEN;
  }
  if (cap < need) return ERR_FULL;

  out[off++] = (uint8_t) d->format;
  out[off++] = d->m;
  out[off++] = d->n;
  out[off++] = d->key_count;
  out[off++] = name_len;
  memcpy(&out[off], d->name, name_len);
  off += name_len;

  for (uint8_t i = 0; i < d->key_count; i++) {
    const multisig_key_t* k = &d->keys[i];
    out[off++] = k->path_len;
    for (uint8_t j = 0; j < k->path_len; j++) {
      _put_u32_le(&out[off], k->path[j]);
      off += 4;
    }
    memcpy(&out[off], k->fingerprint, MULTISIG_FP_LEN);
    off += MULTISIG_FP_LEN;
    memcpy(&out[off], k->xpub, MULTISIG_XPUB_LEN);
    off += MULTISIG_XPUB_LEN;
  }

  *out_len = off;
  return ERR_OK;
}

app_err_t multisig_deserialize(const uint8_t* data, size_t len, multisig_t* out) {
  memset(out, 0, sizeof(*out));

  if (len < 5) return ERR_DATA;

  size_t off = 0;
  out->format = (multisig_format_t) data[off++];
  out->m = data[off++];
  out->n = data[off++];
  out->key_count = data[off++];
  uint8_t name_len = data[off++];

  if (name_len >= MULTISIG_MAX_NAME_LEN || out->key_count > MULTISIG_MAX_KEYS) {
    return ERR_DATA;
  }
  if (len < off + name_len) return ERR_DATA;
  memcpy(out->name, &data[off], name_len);
  out->name[name_len] = '\0';
  off += name_len;

  for (uint8_t i = 0; i < out->key_count; i++) {
    multisig_key_t* k = &out->keys[i];
    if (off >= len) return ERR_DATA;
    k->path_len = data[off++];
    if (k->path_len > MULTISIG_MAX_PATH_LEN) return ERR_DATA;
    if (len < off + (size_t) k->path_len * 4) return ERR_DATA;
    for (uint8_t j = 0; j < k->path_len; j++) {
      k->path[j] = _get_u32_le(&data[off]);
      off += 4;
    }
    if (len < off + MULTISIG_FP_LEN) return ERR_DATA;
    memcpy(k->fingerprint, &data[off], MULTISIG_FP_LEN);
    off += MULTISIG_FP_LEN;
    if (len < off + MULTISIG_XPUB_LEN) return ERR_DATA;
    memcpy(k->xpub, &data[off], MULTISIG_XPUB_LEN);
    off += MULTISIG_XPUB_LEN;
  }

  return ERR_OK;
}

static size_t _append(char* out, size_t cap, size_t off, const char* s) {
  size_t n = strlen(s);
  if (off + n >= cap) return off;
  memcpy(&out[off], s, n + 1);
  return off + n;
}

app_err_t multisig_to_text(const multisig_t* d, char* out, size_t cap) {
  static const char* const FORMAT_STR[] = { "P2SH", "P2SH-P2WSH", "P2WSH" };
  size_t off = 0;

  off = _append(out, cap, off, "Name: ");
  off = _append(out, cap, off, d->name);
  off = _append(out, cap, off, "\n");

  {
    uint8_t mb[UINT32_STRING_LEN], nb[UINT32_STRING_LEN];
    off = _append(out, cap, off, "Policy: ");
    off = _append(out, cap, off, (const char*) u32toa(d->m, mb, sizeof(mb)));
    off = _append(out, cap, off, " of ");
    off = _append(out, cap, off, (const char*) u32toa(d->n, nb, sizeof(nb)));
    off = _append(out, cap, off, "\n");
  }

  off = _append(out, cap, off, "Format: ");
  off = _append(out, cap, off, FORMAT_STR[d->format]);
  off = _append(out, cap, off, "\n\n");

  for (uint8_t i = 0; i < d->key_count; i++) {
    const multisig_key_t* k = &d->keys[i];

    off = _append(out, cap, off, "Derivation: ");
    if (_path_to_str(k->path, k->path_len, &out[off], cap - off) == 0) break;
    off += strlen(&out[off]);

    char hex[9];
    base16_encode(k->fingerprint, hex, MULTISIG_FP_LEN);

    off = _append(out, cap, off, "\n");
    off = _append(out, cap, off, hex);
    off = _append(out, cap, off, ": ");
    {
      char b58[128];
      base58_encode_check(k->xpub, MULTISIG_XPUB_LEN, b58, sizeof(b58));
      off = _append(out, cap, off, b58);
    }
    off = _append(out, cap, off, "\n\n");
  }

  return ERR_OK;
}

static int _derive_key_pub(const multisig_key_t* key, uint32_t change, uint32_t index, uint8_t out33[33]) {
  uint8_t pub65[BIP32_PUBKEY_LEN];
  uint8_t chain[BIP32_CHAINCODE_LEN];
  uint8_t point[ECC256_POINT_SIZE];
  int err = ERR_CRYPTO;

  const uint8_t* p = ec_uncompress_key(&secp256k1, &key->xpub[45], point);
  if (p == NULL) goto done;

  memcpy(&pub65[1], p, ECC256_POINT_SIZE);
  pub65[0] = 0x04;
  memcpy(chain, &key->xpub[13], BIP32_CHAINCODE_LEN);

  if (bip32_ckd_pub(pub65, chain, change, pub65, chain) != 0) goto done;
  if (bip32_ckd_pub(pub65, chain, index, pub65, NULL) != 0) goto done;

  out33[0] = 0x02 | (pub65[BIP32_PUBKEY_LEN - 1] & 1);
  memcpy(&out33[1], &pub65[1], 32);
  err = ERR_OK;

done:
  memzero(pub65, sizeof(pub65));
  memzero(chain, sizeof(chain));
  memzero(point, sizeof(point));
  return err;
}

app_err_t multisig_derive_address(const multisig_t* d, uint32_t change, uint32_t index, char addr[MAX_ADDR_LEN]) {
  uint8_t pubs[MULTISIG_MAX_KEYS][33];
  uint8_t script[2 + MULTISIG_MAX_KEYS * 34 + 2];
  size_t off = 0;
  app_err_t err = ERR_CRYPTO;

  memset(pubs, 0, sizeof(pubs));
  memset(script, 0, sizeof(script));

  for (uint8_t i = 0; i < d->key_count; i++) {
    if (_derive_key_pub(&d->keys[i], change, index, pubs[i]) != ERR_OK) goto done;
  }

  script[off++] = (uint8_t) (0x50 + d->m);
  for (uint8_t i = 0; i < d->key_count; i++) {
    script[off++] = 33;
    memcpy(&script[off], pubs[i], 33);
    off += 33;
  }
  script[off++] = (uint8_t) (0x50 + d->n);
  script[off++] = MULTISIG_OP_CHECKMULTISIG;

  switch (d->format) {
  case MULTISIG_FORMAT_P2WSH: {
    uint8_t h[SHA256_DIGEST_LENGTH];
    sha256_Raw(script, off, h);
    segwit_addr_encode(addr, BTC_BECH32_HRP, 0, h, sizeof(h));
    break;
  }
  case MULTISIG_FORMAT_P2SH: {
    uint8_t h[RIPEMD160_DIGEST_LENGTH];
    hash160(script, off, h);
    bitcoin_legacy_address(h, BTC_P2SH_ADDR_PREFIX, addr);
    break;
  }
  case MULTISIG_FORMAT_P2WSH_P2SH: {
    uint8_t s[SHA256_DIGEST_LENGTH];
    uint8_t h[RIPEMD160_DIGEST_LENGTH];
    sha256_Raw(script, off, s);
    hash160(s, sizeof(s), h);
    bitcoin_legacy_address(h, BTC_P2SH_ADDR_PREFIX, addr);
    break;
  }
  default:
    goto done;
  }

  err = ERR_OK;

done:
  memzero(pubs, sizeof(pubs));
  memzero(script, sizeof(script));
  return err;
}

bool multisig_has_fingerprint(const multisig_t* d, uint32_t mfp) {
  uint8_t fp[MULTISIG_FP_LEN];
  fp[0] = (uint8_t) (mfp >> 24);
  fp[1] = (uint8_t) (mfp >> 16);
  fp[2] = (uint8_t) (mfp >> 8);
  fp[3] = (uint8_t) mfp;

  for (uint8_t i = 0; i < d->key_count; i++) {
    if (memcmp(d->keys[i].fingerprint, fp, MULTISIG_FP_LEN) == 0) return true;
  }
  return false;
}
