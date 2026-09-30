#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "crypto/sha2.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "openpgp/openpgp_v4.h"

#define OPENPGP_ALGO_ECDSA    19
#define OPENPGP_ALGO_EDDSA    22

#define OPENPGP_HASH_SHA256    8

static const uint8_t secp256k1_oid[] = {
  0x2b, 0x81, 0x04, 0x00, 0x0a
};

static size_t openpgp_mpi_bit_length(const uint8_t *data, size_t len) {
  size_t i;
  uint8_t byte;
  size_t bits;

  for (i = 0; i < len; i++) {
    if (data[i] != 0) {
      break;
    }
  }

  if (i == len) {
    return 0;
  }

  byte = data[i];
  bits = (len - i - 1) * 8;

  while (byte) {
    bits++;
    byte >>= 1;
  }

  return bits;
}

static uint16_t openpgp_read_be16(const uint8_t *p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

int openpgp_v4_build_public_key_body(const uint8_t *point, size_t point_len, uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len) {
  size_t p = 0;
  size_t bits;
  size_t needed;

  if (!point || !out || !out_len) {
    return -1;
  }

  if (point_len != 65 || point[0] != 0x04) {
    return -1;
  }

  needed = 1 + 4 + 1 + 1 + sizeof(secp256k1_oid) + 2 + point_len;

  if (out_capacity < needed) {
    return -1;
  }

  out[p++] = 0x04;

  out[p++] = (uint8_t)(creation_time >> 24);
  out[p++] = (uint8_t)(creation_time >> 16);
  out[p++] = (uint8_t)(creation_time >> 8);
  out[p++] = (uint8_t)creation_time;

  out[p++] = OPENPGP_ALGO_ECDSA;

  out[p++] = (uint8_t)sizeof(secp256k1_oid);
  memcpy(&out[p], secp256k1_oid, sizeof(secp256k1_oid));
  p += sizeof(secp256k1_oid);

  bits = openpgp_mpi_bit_length(point, point_len);

  out[p++] = (uint8_t)(bits >> 8);
  out[p++] = (uint8_t)bits;

  memcpy(&out[p], point, point_len);
  p += point_len;

  *out_len = p;
  return 0;
}

int openpgp_v4_build_sig_fields(const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len) {
  return openpgp_v4_build_sig_fields_for_type(0x01, fingerprint, creation_time, out, out_capacity, out_len);
}

int openpgp_v4_build_sig_fields_for_type(uint8_t signature_type, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len) {
  size_t p = 0;

  if (!fingerprint || !out || !out_len) {
    return -1;
  }

  if (out_capacity < OPENPGP_V4_SIG_FIELDS_LEN) {
    return -1;
  }

  /* Version 4 signature. */
  out[p++] = 0x04;

  /* Signature type selected by the trusted protocol operation. */
  out[p++] = signature_type;

  /* Public-key algorithm 19: ECDSA. */
  out[p++] = OPENPGP_ALGO_ECDSA;

  /* Hash algorithm 8: SHA-256. */
  out[p++] = OPENPGP_HASH_SHA256;

  /*
   * Hashed subpacket data is 29 bytes:
   *
   *   issuer fingerprint:
   *     16 21 04 <20-byte fingerprint>
   *
   *   signature creation time:
   *     05 02 <4-byte timestamp>
   */
  out[p++] = 0x00;
  out[p++] = 0x1d;

  out[p++] = 0x16;
  out[p++] = 0x21;
  out[p++] = 0x04;

  memcpy(&out[p], fingerprint, OPENPGP_V4_FINGERPRINT_LEN);
  p += OPENPGP_V4_FINGERPRINT_LEN;

  out[p++] = 0x05;
  out[p++] = 0x02;

  out[p++] = (uint8_t)(creation_time >> 24);
  out[p++] = (uint8_t)(creation_time >> 16);
  out[p++] = (uint8_t)(creation_time >> 8);
  out[p++] = (uint8_t)creation_time;

  if (p != OPENPGP_V4_SIG_FIELDS_LEN) {
    return -1;
  }

  *out_len = p;
  return 0;
}

int openpgp_v4_build_certification_data(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t *user_id, size_t user_id_len, uint8_t *out, size_t out_capacity, size_t *out_len) {
  size_t p = 0;
  uint32_t uid_len32;

  if (!primary_key_body || !user_id || !out || !out_len) {
    return -1;
  }

  if (primary_key_body_len > UINT16_MAX) {
    return -1;
  }

  /*
   * OpenPGP v4 certification hashes the primary-key packet body as:
   *
   *   0x99 || uint16(body length) || body
   */
  if (out_capacity < 3) {
    return -1;
  }

  out[p++] = 0x99;
  out[p++] = (uint8_t)(primary_key_body_len >> 8);
  out[p++] = (uint8_t)primary_key_body_len;

  if (primary_key_body_len > out_capacity - p) {
    return -1;
  }

  memcpy(&out[p], primary_key_body, primary_key_body_len);
  p += primary_key_body_len;

  /*
   * A v4 User-ID certification adds:
   *
   *   0xB4 || uint32(uid length) || uid
   */
  if (out_capacity - p < 5) {
    return -1;
  }

  uid_len32 = (uint32_t)user_id_len;

  out[p++] = 0xb4;
  out[p++] = (uint8_t)(uid_len32 >> 24);
  out[p++] = (uint8_t)(uid_len32 >> 16);
  out[p++] = (uint8_t)(uid_len32 >> 8);
  out[p++] = (uint8_t)uid_len32;

  if (user_id_len > out_capacity - p) {
    return -1;
  }

  memcpy(&out[p], user_id, user_id_len);
  p += user_id_len;

  *out_len = p;
  return 0;
}

int openpgp_v4_primary_key_fingerprint(const uint8_t *primary_key_body, size_t primary_key_body_len, uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]) {
  SHA1_CTX ctx;
  uint8_t prefix[3];

  if (!primary_key_body || !fingerprint) {
    return -1;
  }

  if (primary_key_body_len == 0 ||
      primary_key_body_len > UINT16_MAX ||
      primary_key_body[0] != 0x04) {
    return -1;
  }

  /*
   * OpenPGP v4 primary-key fingerprint:
   *
   *   SHA1(0x99 || uint16(key-body length) || key-body)
   */
  prefix[0] = 0x99;
  prefix[1] = (uint8_t)(primary_key_body_len >> 8);
  prefix[2] = (uint8_t)primary_key_body_len;

  sha1_Init(&ctx);
  sha1_Update(&ctx, prefix, sizeof(prefix));
  sha1_Update(&ctx, primary_key_body, primary_key_body_len);
  sha1_Final(&ctx, fingerprint);

  return 0;
}

int openpgp_v4_digest(const uint8_t *signed_data, size_t signed_data_len, const uint8_t *sig_fields, size_t sig_fields_len, uint8_t digest[OPENPGP_SHA256_LEN]) {
  SHA256_CTX ctx;
  uint8_t trailer[6];
  uint32_t n;

  if (!signed_data || !sig_fields || !digest) {
    return -1;
  }

  if (sig_fields_len == 0 || sig_fields[0] != 0x04) {
    return -1;
  }

  n = (uint32_t)sig_fields_len;

  trailer[0] = 0x04;
  trailer[1] = 0xff;
  trailer[2] = (uint8_t)(n >> 24);
  trailer[3] = (uint8_t)(n >> 16);
  trailer[4] = (uint8_t)(n >> 8);
  trailer[5] = (uint8_t)n;

  sha256_Init(&ctx);
  sha256_Update(&ctx, signed_data, signed_data_len);
  sha256_Update(&ctx, sig_fields, sig_fields_len);
  sha256_Update(&ctx, trailer, sizeof(trailer));
  sha256_Final(&ctx, digest);

  return 0;
}

static int encode_mpi(const uint8_t *value, size_t value_len, uint8_t *out, size_t out_capacity, size_t *out_len) {
  size_t start = 0;
  unsigned leading = 0;
  unsigned bit_len;
  uint8_t first;

  while (start < value_len && value[start] == 0) {
    start++;
  }

  if (start == value_len) {
    return -1;
  }

  first = value[start];

  while ((first & 0x80) == 0) {
    leading++;
    first <<= 1;
  }

  bit_len = (unsigned)((value_len - start) * 8) - leading;

  if (out_capacity < 2 + value_len - start) {
    return -1;
  }

  out[0] = (uint8_t)(bit_len >> 8);
  out[1] = (uint8_t)bit_len;

  memcpy(&out[2], &value[start], value_len - start);

  *out_len = 2 + value_len - start;
  return 0;
}

int openpgp_v4_build_signature_packet(const uint8_t *sig_fields, size_t sig_fields_len, const uint8_t digest[OPENPGP_SHA256_LEN], const uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN], const uint8_t issuer_key_id[8], uint8_t *out, size_t out_capacity, size_t *out_len) {
  uint8_t body[160];
  size_t p = 0;
  size_t mpi_len;

  if (!sig_fields || !digest || !raw_signature ||
      !issuer_key_id || !out || !out_len) {
    return -1;
  }

  if (sig_fields_len != OPENPGP_V4_SIG_FIELDS_LEN) {
    return -1;
  }

  memcpy(&body[p], sig_fields, sig_fields_len);
  p += sig_fields_len;

  /*
   * Unhashed subpacket area:
   *
   *   length = 10 bytes
   *   subpacket length = 9
   *   type 16 = Issuer Key ID
   *   8-byte key ID
   */
  body[p++] = 0x00;
  body[p++] = 0x0a;

  body[p++] = 0x09;
  body[p++] = 0x10;

  memcpy(&body[p], issuer_key_id, 8);
  p += 8;

  /* Leftmost 16 bits of the signed hash. */
  body[p++] = digest[0];
  body[p++] = digest[1];

  if (encode_mpi(&raw_signature[0], 32, &body[p],
                 sizeof(body) - p, &mpi_len) != 0) {
    return -1;
  }

  p += mpi_len;

  if (encode_mpi(&raw_signature[32], 32, &body[p],
                 sizeof(body) - p, &mpi_len) != 0) {
    return -1;
  }

  p += mpi_len;

  /*
   * New-format packet header, tag 2 = Signature Packet.
   * Our body is comfortably below 192 bytes.
   */
  if (p >= 192 || out_capacity < p + 2) {
    return -1;
  }

  out[0] = 0xc2;
  out[1] = (uint8_t)p;

  memcpy(&out[2], body, p);

  *out_len = p + 2;
  return 0;
}

/*
 * Read an OpenPGP MPI into a fixed-width big-endian buffer, left-padding
 * with zeroes. Used for ECDSA r and s, which are at most 32 bytes.
 */
static int openpgp_read_mpi_fixed(const uint8_t *data, size_t data_len, size_t *offset, uint8_t *out, size_t out_len) {
  uint16_t bits;
  size_t bytes;

  if (!data || !offset || !out) {
    return -1;
  }

  if (*offset > data_len || data_len - *offset < 2) {
    return -1;
  }

  bits = openpgp_read_be16(data + *offset);
  *offset += 2;

  bytes = ((size_t)bits + 7) / 8;

  if (bytes == 0 || bytes > out_len) {
    return -1;
  }

  if (*offset > data_len || data_len - *offset < bytes) {
    return -1;
  }

  if (openpgp_mpi_bit_length(data + *offset, bytes) != bits) {
    return -1;
  }

  memset(out, 0, out_len);
  memcpy(out + (out_len - bytes), data + *offset, bytes);

  *offset += bytes;
  return 0;
}

/*
 * Extract the uncompressed SEC1 point from a v4 ECDSA public-key body.
 *
 *   version | creation time | algorithm | OID length | OID | MPI(point)
 */
static int openpgp_ecdsa_point(const uint8_t *primary_key_body, size_t primary_key_body_len, uint8_t point[65]) {

  size_t pos = 6;
  uint16_t point_bits;
  size_t point_bytes;

  if (primary_key_body_len < 8) {
    return -1;
  }

  if (primary_key_body[0] != 0x04 ||
      primary_key_body[5] != OPENPGP_ALGO_ECDSA) {
    return -1;
  }

  if (primary_key_body[pos++] != sizeof(secp256k1_oid)) {
    return -1;
  }

  if (primary_key_body_len - pos < sizeof(secp256k1_oid)) {
    return -1;
  }

  if (memcmp(primary_key_body + pos, secp256k1_oid, sizeof(secp256k1_oid)) != 0) {
    return -1;
  }

  pos += sizeof(secp256k1_oid);

  if (primary_key_body_len - pos < 2) {
    return -1;
  }

  point_bits = openpgp_read_be16(primary_key_body + pos);
  pos += 2;

  point_bytes = ((size_t)point_bits + 7) / 8;

  if (point_bytes != 65 ||
      primary_key_body_len - pos != 65 ||
      primary_key_body[pos] != 0x04) {
    return -1;
  }

  if (openpgp_mpi_bit_length(primary_key_body + pos, point_bytes) !=
      point_bits) {
    return -1;
  }

  memcpy(point, primary_key_body + pos, 65);
  return 0;
}

int openpgp_v4_verify_uid_self_cert(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t *user_id, size_t user_id_len, const uint8_t *signature_body, size_t signature_body_len) {
  uint8_t point[65];
  uint8_t signature[64];
  uint8_t digest[SHA256_DIGEST_LENGTH];

  uint8_t key_prefix[3];
  uint8_t uid_prefix[5];
  uint8_t trailer[6];

  SHA256_CTX ctx;

  size_t hashed_subpacket_len;
  size_t signature_hashed_len;
  size_t pos;
  size_t unhashed_len;

  if (!primary_key_body || !user_id || !signature_body) {
    return -1;
  }

  if (primary_key_body_len > UINT16_MAX) {
    return -1;
  }

  /*
   * This device verifies secp256k1 ECDSA self-certifications only.
   * Keys on curves it cannot verify are refused rather than shown
   * as an unverified identity.
   */
  if (openpgp_ecdsa_point(primary_key_body, primary_key_body_len,
                          point) != 0) {
    return -1;
  }

  /*
   * Version-4 certification signature over SHA-256 with ECDSA.
   */
  if (signature_body_len < 10 ||
      signature_body[0] != 0x04 ||
      signature_body[1] < 0x10 ||
      signature_body[1] > 0x13 ||
      signature_body[2] != OPENPGP_ALGO_ECDSA ||
      signature_body[3] != OPENPGP_HASH_SHA256) {
    return -1;
  }

  hashed_subpacket_len = openpgp_read_be16(signature_body + 4);
  signature_hashed_len = 6 + hashed_subpacket_len;

  if (signature_hashed_len > signature_body_len) {
    return -1;
  }

  /*
   * OpenPGP v4 UID certification hash:
   *
   *   0x99 || uint16(key body length) || key body
   *   0xB4 || uint32(uid length)      || uid
   *   signature fields through hashed subpackets
   *   0x04 || 0xFF || uint32(signature hashed length)
   */
  key_prefix[0] = 0x99;
  key_prefix[1] = (uint8_t)(primary_key_body_len >> 8);
  key_prefix[2] = (uint8_t)primary_key_body_len;

  uid_prefix[0] = 0xb4;
  uid_prefix[1] = (uint8_t)(user_id_len >> 24);
  uid_prefix[2] = (uint8_t)(user_id_len >> 16);
  uid_prefix[3] = (uint8_t)(user_id_len >> 8);
  uid_prefix[4] = (uint8_t)user_id_len;

  trailer[0] = 0x04;
  trailer[1] = 0xff;
  trailer[2] = (uint8_t)(signature_hashed_len >> 24);
  trailer[3] = (uint8_t)(signature_hashed_len >> 16);
  trailer[4] = (uint8_t)(signature_hashed_len >> 8);
  trailer[5] = (uint8_t)signature_hashed_len;

  sha256_Init(&ctx);
  sha256_Update(&ctx, key_prefix, sizeof(key_prefix));
  sha256_Update(&ctx, primary_key_body, primary_key_body_len);
  sha256_Update(&ctx, uid_prefix, sizeof(uid_prefix));
  sha256_Update(&ctx, user_id, user_id_len);
  sha256_Update(&ctx, signature_body, signature_hashed_len);
  sha256_Update(&ctx, trailer, sizeof(trailer));
  sha256_Final(&ctx, digest);

  /*
   * Skip unhashed subpackets and check OpenPGP's two-byte signed-hash
   * prefix before the public-key operation.
   */
  pos = signature_hashed_len;

  if (signature_body_len - pos < 2) {
    return -1;
  }

  unhashed_len = openpgp_read_be16(signature_body + pos);
  pos += 2;

  if (unhashed_len > signature_body_len - pos) {
    return -1;
  }

  pos += unhashed_len;

  if (signature_body_len - pos < 2) {
    return -1;
  }

  if (signature_body[pos] != digest[0] ||
      signature_body[pos + 1] != digest[1]) {
    return -1;
  }

  pos += 2;

  if (openpgp_read_mpi_fixed(signature_body, signature_body_len,
                             &pos, signature, 32) != 0) {
    return -1;
  }

  if (openpgp_read_mpi_fixed(signature_body, signature_body_len,
                             &pos, signature + 32, 32) != 0) {
    return -1;
  }

  if (pos != signature_body_len) {
    return -1;
  }

  /* raw_pub expects bare X||Y without the 0x04 prefix. */
  if (ecdsa_verify_raw_pub(&secp256k1, &point[1], signature, digest) != 0) {
    return -1;
  }

  return 0;
}
