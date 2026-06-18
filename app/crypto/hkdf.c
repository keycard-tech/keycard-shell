/**
 * HKDF (HMAC-based Key Derivation Function) — RFC 5869
 *
 * Instantiated with SHA-256 via the existing HMAC-SHA256 primitive.
 */

#include <string.h>

#include "hkdf.h"
#include "hmac.h"
#include "mem.h"
#include "memzero.h"

void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[HKDF_SHA256_DIGEST_LENGTH]) {
  /* RFC 5869 Section 2.2: salt MAY be a low-entropy value and MUST NOT be
   * empty. If not provided (or NULL), use a string of HashLen zeros. */
  if (salt == NULL) {
    salt = ZERO32;
    salt_len = HKDF_SHA256_DIGEST_LENGTH;
  }
  hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hkdf_sha256_expand(const uint8_t prk[HKDF_SHA256_DIGEST_LENGTH],
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len) {
  if (okm_len > HKDF_SHA256_MAX_OKM_LEN) {
    return -1;
  }

  /*
   * RFC 5869 Section 2.3:
   *   T(0) = empty string (zero length)
   *   T(1) = HMAC-Hash(PRK, info || 0x01)
   *   T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
   *   T(3) = HMAC-Hash(PRK, T(2) || info || 0x03)
   *   ...
   *   OKM = first okm_len bytes of T(1) || T(2) || ... || T(N)
   */
  uint8_t t_prev[HKDF_SHA256_DIGEST_LENGTH];
  memzero(t_prev, sizeof(t_prev));

  size_t offset = 0;
  uint8_t i = 1;

  while (offset < okm_len) {
    HMAC_SHA256_CTX ctx;
    hmac_sha256_Init(&ctx, prk, HKDF_SHA256_DIGEST_LENGTH);

    /* For i > 1, prepend previous T block */
    if (i > 1) {
      hmac_sha256_Update(&ctx, t_prev, HKDF_SHA256_DIGEST_LENGTH);
    }
    hmac_sha256_Update(&ctx, info, info_len);
    hmac_sha256_Update(&ctx, &i, 1);
    hmac_sha256_Final(&ctx, t_prev);

    size_t chunk = okm_len - offset;
    if (chunk > HKDF_SHA256_DIGEST_LENGTH) {
      chunk = HKDF_SHA256_DIGEST_LENGTH;
    }
    memcpy(&okm[offset], t_prev, chunk);

    offset += chunk;
    i++;
  }

  memzero(t_prev, sizeof(t_prev));
  return 0;
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
  uint8_t prk[HKDF_SHA256_DIGEST_LENGTH];

  hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
  int ret = hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
  memzero(prk, sizeof(prk));
  return ret;
}
