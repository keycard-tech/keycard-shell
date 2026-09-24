#ifndef CORE_OPENPGP_H
#define CORE_OPENPGP_H

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "openpgp/openpgp_v4.h"

app_err_t core_openpgp_prepare_primary_key(
    uint8_t *path,
    uint16_t path_len,
    uint32_t creation_time,
    uint8_t *primary_key_body,
    size_t primary_key_body_capacity,
    size_t *primary_key_body_len,
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

typedef struct {
    uint8_t sig_fields[OPENPGP_V4_SIG_FIELDS_LEN];
    uint8_t digest[OPENPGP_SHA256_LEN];
} core_openpgp_uid_certification_t;

app_err_t core_openpgp_prepare_uid_certification(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    const uint8_t *uid,
    size_t uid_len,
    uint32_t creation_time,
    core_openpgp_uid_certification_t *certification);

app_err_t core_openpgp_confirm_identity(
    const uint8_t *uid,
    size_t uid_len,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

app_err_t core_openpgp_certify_uid(
    uint8_t *path,
    uint16_t path_len,
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    const uint8_t *uid,
    size_t uid_len,
    uint32_t creation_time,
    core_openpgp_uid_certification_t *certification,
    uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN]);

#endif
