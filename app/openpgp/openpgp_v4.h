#ifndef OPENPGP_V4_H
#define OPENPGP_V4_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_SHA256_LEN 32
#define OPENPGP_V4_FINGERPRINT_LEN 20
#define OPENPGP_V4_SIG_FIELDS_LEN 35
#define OPENPGP_RAW_ECDSA_LEN 64

int openpgp_v4_build_sig_fields(
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    uint32_t creation_time,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int openpgp_v4_build_sig_fields_for_type(
    uint8_t signature_type,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    uint32_t creation_time,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int openpgp_v4_build_certification_data(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t *user_id,
    size_t user_id_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int openpgp_v4_primary_key_fingerprint(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

int openpgp_v4_digest(const uint8_t *signed_data,
                      size_t signed_data_len,
                      const uint8_t *sig_fields,
                      size_t sig_fields_len,
                      uint8_t digest[OPENPGP_SHA256_LEN]);

int openpgp_v4_build_signature_packet(
    const uint8_t *sig_fields,
    size_t sig_fields_len,
    const uint8_t digest[OPENPGP_SHA256_LEN],
    const uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN],
    const uint8_t issuer_key_id[8],
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);


int openpgp_v4_verify_uid_self_cert(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t *user_id,
    size_t user_id_len,
    const uint8_t *signature_body,
    size_t signature_body_len);

#endif
