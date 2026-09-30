#ifndef CORE_OPENPGP_H
#define CORE_OPENPGP_H

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "openpgp/openpgp_v4.h"

#define CORE_OPENPGP_SIGNATURE_PACKET_MAX_LEN 119
#define CORE_OPENPGP_IDENTITY_MAX_LEN 458

app_err_t core_openpgp_prepare_primary_key(uint8_t *path, uint16_t path_len, uint32_t creation_time, uint8_t *primary_key_body, size_t primary_key_body_capacity, size_t *primary_key_body_len, uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

typedef struct {
    uint8_t sig_fields[OPENPGP_V4_SIG_FIELDS_LEN];
    uint8_t digest[OPENPGP_SHA256_LEN];
} core_openpgp_uid_certification_t;

app_err_t core_openpgp_prepare_uid_certification(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], const uint8_t *uid, size_t uid_len, uint32_t creation_time, core_openpgp_uid_certification_t *certification);

app_err_t core_openpgp_confirm_identity(const uint8_t *uid, size_t uid_len, uint32_t creation_time, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

app_err_t core_openpgp_certify_uid(uint8_t *path, uint16_t path_len, const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], const uint8_t *uid, size_t uid_len, uint32_t creation_time, core_openpgp_uid_certification_t *certification, uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN]);

app_err_t core_openpgp_build_uid_certification_packet(const core_openpgp_uid_certification_t *certification, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], const uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN], uint8_t *out, size_t out_capacity, size_t *out_len);

app_err_t core_openpgp_assemble_and_verify_identity(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t *uid, size_t uid_len, const uint8_t *certification_packet, size_t certification_packet_len, uint8_t *out, size_t out_capacity, size_t *out_len);

/*
 * Internal orchestration primitive.
 *
 * path must be selected by trusted Shell policy, never supplied by the
 * untrusted OpenPGP request.
 */
app_err_t core_openpgp_create_identity_at_path(uint8_t *path, uint16_t path_len, const uint8_t *uid, size_t uid_len, uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

/*
 * Scan a versioned OpenPGP request from UR:BYTES, create the identity using a
 * trusted Shell-selected path, and display the verified certificate as
 * UR:BYTES.
 */
app_err_t core_openpgp_qr_run(uint8_t *path, uint16_t path_len);

/*
 * Run the dedicated OpenPGP flow using the Shell-owned derivation policy.
 *
 * The host/request does not select the Keycard derivation path.
 */
app_err_t core_openpgp_run(void);

#endif
