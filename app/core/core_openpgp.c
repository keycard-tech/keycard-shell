#include "core_openpgp.h"

#include "core.h"
#include "crypto/bip32.h"
#include "openpgp/openpgp_protocol.h"

app_err_t core_openpgp_prepare_primary_key(
    uint8_t *path,
    uint16_t path_len,
    uint32_t creation_time,
    uint8_t *primary_key_body,
    size_t primary_key_body_capacity,
    size_t *primary_key_body_len,
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN])
{
    uint8_t point[BIP32_PUBKEY_LEN];

    if (path == NULL ||
        path_len == 0 ||
        (path_len % sizeof(uint32_t)) != 0 ||
        path_len > UINT8_MAX ||
        creation_time == 0 ||
        primary_key_body == NULL ||
        primary_key_body_len == NULL ||
        fingerprint == NULL) {
        return ERR_DATA;
    }

    app_err_t err = core_export_key(
        &g_core.keycard,
        path,
        path_len,
        point,
        NULL);

    if (err != ERR_OK) {
        return err;
    }

    if (openpgp_v4_build_public_key_body(
            point,
            sizeof(point),
            creation_time,
            primary_key_body,
            primary_key_body_capacity,
            primary_key_body_len) != 0) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_primary_key_fingerprint(
            primary_key_body,
            *primary_key_body_len,
            fingerprint) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}

app_err_t core_openpgp_prepare_uid_certification(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    const uint8_t *uid,
    size_t uid_len,
    uint32_t creation_time,
    core_openpgp_uid_certification_t *certification)
{
    uint8_t signed_data[
        3 +
        OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN +
        5 +
        OPENPGP_UID_MAX_LEN];
    size_t signed_data_len;
    size_t sig_fields_len;

    if (primary_key_body == NULL ||
        primary_key_body_len != OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN ||
        fingerprint == NULL ||
        uid == NULL ||
        uid_len == 0 ||
        uid_len > OPENPGP_UID_MAX_LEN ||
        creation_time == 0 ||
        certification == NULL) {
        return ERR_DATA;
    }

    if (openpgp_v4_build_certification_data(
            primary_key_body,
            primary_key_body_len,
            uid,
            uid_len,
            signed_data,
            sizeof(signed_data),
            &signed_data_len) != 0) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_build_sig_fields(
            fingerprint,
            creation_time,
            certification->sig_fields,
            sizeof(certification->sig_fields),
            &sig_fields_len) != 0) {
        return ERR_CRYPTO;
    }

    if (sig_fields_len != OPENPGP_V4_SIG_FIELDS_LEN) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_digest(
            signed_data,
            signed_data_len,
            certification->sig_fields,
            sig_fields_len,
            certification->digest) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}
