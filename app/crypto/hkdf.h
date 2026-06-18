/**
 * HKDF (HMAC-based Key Derivation Function) — RFC 5869
 *
 * Instantiated with SHA-256 via the existing HMAC-SHA256 primitive.
 *
 * Two-phase construction:
 *   Extract: PRK = HMAC-SHA256(salt, IKM)
 *   Expand:  OKM = T(1) || T(2) || …
 *            T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
 */

#ifndef __HKDF_H__
#define __HKDF_H__

#include <stdint.h>
#include <stddef.h>

#define HKDF_SHA256_DIGEST_LENGTH  32
#define HKDF_SHA256_MAX_OKM_LEN    (255 * HKDF_SHA256_DIGEST_LENGTH)

/**
 * HKDF-Extract: derive a pseudorandom key from input keying material.
 *
 * @param salt     optional salt value (can be NULL, treated as all zeros)
 * @param salt_len length of salt in bytes
 * @param ikm      input keying material
 * @param ikm_len  length of IKM in bytes
 * @param prk      output buffer for the derived PRK (32 bytes)
 */
void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[HKDF_SHA256_DIGEST_LENGTH]);

/**
 * HKDF-Expand: expand a PRK into output keying material.
 *
 * @param prk      pseudorandom key from Extract (32 bytes)
 * @param info     context and application-specific information
 * @param info_len length of info in bytes
 * @param okm      output buffer for the derived key material
 * @param okm_len  desired output length (max 255 * 32 = 8160 bytes)
 * @return 0 on success, -1 if okm_len exceeds maximum
 */
int hkdf_sha256_expand(const uint8_t prk[HKDF_SHA256_DIGEST_LENGTH],
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len);

/**
 * HKDF (Extract + Expand in one call).
 *
 * @param salt     optional salt value (can be NULL, treated as all zeros)
 * @param salt_len length of salt in bytes
 * @param ikm      input keying material
 * @param ikm_len  length of IKM in bytes
 * @param info     context and application-specific information
 * @param info_len length of info in bytes
 * @param okm      output buffer for the derived key material
 * @param okm_len  desired output length (max 255 * 32 = 8160 bytes)
 * @return 0 on success, -1 if okm_len exceeds maximum
 */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

#endif // __HKDF_H__
