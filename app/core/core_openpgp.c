#include "core_openpgp.h"

#include "core.h"
#include "crypto/bip32.h"

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
