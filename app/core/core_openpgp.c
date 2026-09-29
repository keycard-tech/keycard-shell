#include "core_openpgp.h"

#include "core.h"
#include "crypto/bip32.h"
#include "crypto/util.h"
#include "crypto/memzero.h"
#include "keycard/keycard_cmdset.h"
#include "mem.h"
#include "openpgp/openpgp_packet.h"
#include "openpgp/openpgp_protocol.h"
#include "ui/i18n.h"
#include "ui/ui.h"
#include "ur/ur_encode.h"

#define OPENPGP_UID_CERT_SIGNATURE_TYPE 0x13

/*
 * Shell-owned OpenPGP identity path:
 *
 *   m/43'/60'/1581'/5261136'/0
 *
 * 5261136 == 0x504750 == "PGP".
 *
 * Pending final maintainer confirmation, the final non-hardened component
 * is treated as the OpenPGP identity/key index and the initial identity uses
 * index 0. The host never supplies this path.
 */
#define OPENPGP_EIP1581_PATH_LEN 5

static const uint32_t OPENPGP_EIP1581_PATH[OPENPGP_EIP1581_PATH_LEN] = {
    0x8000002b,
    0x8000003c,
    0x8000062d,
    0x80504750,
    0x00000000,
};

#define OPENPGP_UID_CERT_ISSUER_FINGERPRINT_OFFSET 9
#define OPENPGP_UID_CERT_ISSUER_KEY_ID_OFFSET \
    (OPENPGP_V4_SIG_FIELDS_LEN + 4)

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

    if (openpgp_v4_build_sig_fields_for_type(
            OPENPGP_UID_CERT_SIGNATURE_TYPE,
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

app_err_t core_openpgp_confirm_identity(
    const uint8_t *uid,
    size_t uid_len,
    uint32_t creation_time,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN])
{
    char fingerprint_hex[(OPENPGP_V4_FINGERPRINT_LEN * 2) + 1];
    uint8_t creation_time_buf[UINT32_STRING_LEN];
    uint8_t *creation_time_str;
    char *review = (char *) g_mem_heap;
    size_t review_len = 0;
    size_t creation_time_len;
    size_t uid_title_len;
    size_t creation_time_title_len;
    size_t fingerprint_title_len;

    if (uid == NULL ||
        uid_len == 0 ||
        uid_len > OPENPGP_UID_MAX_LEN ||
        creation_time == 0 ||
        fingerprint == NULL) {
        return ERR_DATA;
    }

    /*
     * The certification digest commits to the exact UID bytes.
     * Reject bytes that cannot be unambiguously reviewed by the
     * existing text UI before allowing certification.
     */
    for (size_t i = 0; i < uid_len; i++) {
        if (uid[i] < 0x20 || uid[i] > 0x7e) {
            return ERR_DATA;
        }
    }

    base16_encode(
        fingerprint,
        fingerprint_hex,
        OPENPGP_V4_FINGERPRINT_LEN);

    creation_time_str = u32toa(
        creation_time,
        creation_time_buf,
        sizeof(creation_time_buf));

    creation_time_len = strlen((const char *) creation_time_str);
    uid_title_len = strlen(LSTR(OPENPGP_UID_TITLE));
    creation_time_title_len = strlen(LSTR(OPENPGP_CREATION_TIME_TITLE));
    fingerprint_title_len = strlen(LSTR(OPENPGP_FINGERPRINT_TITLE));

    /*
     * Build one review document in the shared heap. The scanned request UID
     * has already been copied by the caller, so the QR input may be replaced.
     */
    if (uid_title_len + 1 +
        uid_len + 2 +
        creation_time_title_len + 1 +
        creation_time_len + 2 +
        fingerprint_title_len + 1 +
        (OPENPGP_V4_FINGERPRINT_LEN * 2) > MEM_HEAP_SIZE) {
        return ERR_DATA;
    }

    memcpy(&review[review_len], LSTR(OPENPGP_UID_TITLE), uid_title_len);
    review_len += uid_title_len;
    review[review_len++] = '\n';

    memcpy(&review[review_len], uid, uid_len);
    review_len += uid_len;
    review[review_len++] = '\n';
    review[review_len++] = '\n';

    memcpy(
        &review[review_len],
        LSTR(OPENPGP_CREATION_TIME_TITLE),
        creation_time_title_len);
    review_len += creation_time_title_len;
    review[review_len++] = '\n';

    memcpy(
        &review[review_len],
        creation_time_str,
        creation_time_len);
    review_len += creation_time_len;
    review[review_len++] = '\n';
    review[review_len++] = '\n';

    memcpy(
        &review[review_len],
        LSTR(OPENPGP_FINGERPRINT_TITLE),
        fingerprint_title_len);
    review_len += fingerprint_title_len;
    review[review_len++] = '\n';

    memcpy(
        &review[review_len],
        fingerprint_hex,
        OPENPGP_V4_FINGERPRINT_LEN * 2);
    review_len += OPENPGP_V4_FINGERPRINT_LEN * 2;

    if (ui_display_paged_text(
            LSTR(OPENPGP_APPROVE_TITLE),
            review,
            review_len) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    return ERR_OK;
}

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
    uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN])
{
    uint8_t card_signature[OPENPGP_RAW_ECDSA_LEN + 1];

    if (path == NULL ||
        path_len == 0 ||
        (path_len % sizeof(uint32_t)) != 0 ||
        path_len > UINT8_MAX ||
        certification == NULL ||
        raw_signature == NULL) {
        return ERR_DATA;
    }

    memzero(raw_signature, OPENPGP_RAW_ECDSA_LEN);
    memzero(card_signature, sizeof(card_signature));

    app_err_t err = core_openpgp_prepare_uid_certification(
        primary_key_body,
        primary_key_body_len,
        fingerprint,
        uid,
        uid_len,
        creation_time,
        certification);

    if (err != ERR_OK) {
        return err;
    }

    err = core_openpgp_confirm_identity(
        uid,
        uid_len,
        creation_time,
        fingerprint);

    if (err != ERR_OK) {
        return err;
    }

    keycard_t *kc = &g_core.keycard;

    if (keycard_cmd_sign(
            kc,
            KEYCARD_SIGN_ECDSA_SECP256K1,
            path,
            (uint8_t) path_len,
            certification->digest) != ERR_OK ||
        APDU_SW(&kc->apdu) != 0x9000) {
        return ERR_CRYPTO;
    }

    if (keycard_read_signature(
            APDU_RESP(&kc->apdu),
            kc->apdu.lr,
            certification->digest,
            card_signature) != ERR_OK) {
        memzero(card_signature, sizeof(card_signature));
        return ERR_DATA;
    }

    memcpy(
        raw_signature,
        card_signature,
        OPENPGP_RAW_ECDSA_LEN);

    memzero(card_signature, sizeof(card_signature));

    return ERR_OK;
}

app_err_t core_openpgp_build_uid_certification_packet(
    const core_openpgp_uid_certification_t *certification,
    const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN],
    const uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN],
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t issuer_key_id[8];

    if (certification == NULL ||
        fingerprint == NULL ||
        raw_signature == NULL ||
        out == NULL ||
        out_len == NULL) {
        return ERR_DATA;
    }

    *out_len = 0;

    /*
     * For an OpenPGP v4 key, the key ID is the low 64 bits
     * (final 8 bytes) of the primary-key fingerprint.
     */
    memcpy(
        issuer_key_id,
        &fingerprint[OPENPGP_V4_FINGERPRINT_LEN - sizeof(issuer_key_id)],
        sizeof(issuer_key_id));

    if (openpgp_v4_build_signature_packet(
            certification->sig_fields,
            sizeof(certification->sig_fields),
            certification->digest,
            raw_signature,
            issuer_key_id,
            out,
            out_capacity,
            out_len) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}

static int core_openpgp_append_new_format_packet(
    uint8_t tag,
    const uint8_t *body,
    size_t body_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *offset)
{
    size_t p;
    size_t remaining;
    size_t encoded_len;

    if (tag > 0x3f ||
        body == NULL ||
        body_len == 0 ||
        out == NULL ||
        offset == NULL ||
        *offset > out_capacity) {
        return -1;
    }

    p = *offset;
    remaining = out_capacity - p;

    if (body_len < 192) {
        if (remaining < 2) {
            return -1;
        }

        out[p++] = (uint8_t)(0xc0 | tag);
        out[p++] = (uint8_t)body_len;
    } else if (body_len <= 8383) {
        if (remaining < 3) {
            return -1;
        }

        encoded_len = body_len - 192;

        out[p++] = (uint8_t)(0xc0 | tag);
        out[p++] = (uint8_t)((encoded_len >> 8) + 192);
        out[p++] = (uint8_t)encoded_len;
    } else {
        return -1;
    }

    if (body_len > out_capacity - p) {
        return -1;
    }

    memcpy(&out[p], body, body_len);
    p += body_len;

    *offset = p;
    return 0;
}

static int core_openpgp_validate_identity_binding(
    const openpgp_cert_target_t *target)
{
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN];
    const uint8_t *signature_body;

    if (target == NULL ||
        target->primary_key_body == NULL ||
        target->self_cert_body == NULL) {
        return -1;
    }

    if (openpgp_v4_primary_key_fingerprint(
            target->primary_key_body,
            target->primary_key_body_len,
            fingerprint) != 0) {
        return -1;
    }

    signature_body = target->self_cert_body;

    /*
     * Require the exact certification metadata layout emitted by
     * openpgp_v4_build_sig_fields_for_type() and
     * openpgp_v4_build_signature_packet().
     */
    if (target->self_cert_body_len <
            OPENPGP_UID_CERT_ISSUER_KEY_ID_OFFSET + 8 ||
        signature_body[4] != 0x00 ||
        signature_body[5] != 0x1d ||
        signature_body[6] != 0x16 ||
        signature_body[7] != 0x21 ||
        signature_body[8] != 0x04 ||
        signature_body[OPENPGP_V4_SIG_FIELDS_LEN] != 0x00 ||
        signature_body[OPENPGP_V4_SIG_FIELDS_LEN + 1] != 0x0a ||
        signature_body[OPENPGP_V4_SIG_FIELDS_LEN + 2] != 0x09 ||
        signature_body[OPENPGP_V4_SIG_FIELDS_LEN + 3] != 0x10) {
        return -1;
    }

    if (memcmp(
            &signature_body[OPENPGP_UID_CERT_ISSUER_FINGERPRINT_OFFSET],
            fingerprint,
            OPENPGP_V4_FINGERPRINT_LEN) != 0) {
        return -1;
    }

    if (memcmp(
            &signature_body[OPENPGP_UID_CERT_ISSUER_KEY_ID_OFFSET],
            &fingerprint[OPENPGP_V4_FINGERPRINT_LEN - 8],
            8) != 0) {
        return -1;
    }

    return 0;
}

app_err_t core_openpgp_assemble_and_verify_identity(
    const uint8_t *primary_key_body,
    size_t primary_key_body_len,
    const uint8_t *uid,
    size_t uid_len,
    const uint8_t *certification_packet,
    size_t certification_packet_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    openpgp_cert_target_t target;
    size_t p = 0;

    if (primary_key_body == NULL ||
        primary_key_body_len != OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN ||
        uid == NULL ||
        uid_len == 0 ||
        uid_len > OPENPGP_UID_MAX_LEN ||
        certification_packet == NULL ||
        certification_packet_len == 0 ||
        out == NULL ||
        out_len == NULL) {
        return ERR_DATA;
    }

    *out_len = 0;

    if (core_openpgp_append_new_format_packet(
            6,
            primary_key_body,
            primary_key_body_len,
            out,
            out_capacity,
            &p) != 0) {
        return ERR_DATA;
    }

    if (core_openpgp_append_new_format_packet(
            13,
            uid,
            uid_len,
            out,
            out_capacity,
            &p) != 0) {
        return ERR_DATA;
    }

    if (certification_packet_len > out_capacity - p) {
        return ERR_DATA;
    }

    memcpy(
        &out[p],
        certification_packet,
        certification_packet_len);
    p += certification_packet_len;

    /*
     * Parse the exact bytes we are about to return. This checks packet
     * framing, ordering, signature type and rejection of trailing data.
     */
    if (openpgp_parse_cert_target(
            out,
            p,
            &target) != 0) {
        return ERR_DATA;
    }

    /*
     * Make sure parsing recovered exactly the objects supplied to this
     * assembly step before performing the cryptographic self-check.
     */
    if (target.primary_key_body_len != primary_key_body_len ||
        memcmp(
            target.primary_key_body,
            primary_key_body,
            primary_key_body_len) != 0 ||
        target.user_id_len != uid_len ||
        memcmp(
            target.user_id,
            uid,
            uid_len) != 0 ||
        target.self_cert_packet_len != certification_packet_len ||
        memcmp(
            target.self_cert_packet,
            certification_packet,
            certification_packet_len) != 0 ||
        target.self_cert_type != OPENPGP_UID_CERT_SIGNATURE_TYPE) {
        return ERR_DATA;
    }

    if (core_openpgp_validate_identity_binding(&target) != 0) {
        return ERR_DATA;
    }

    if (openpgp_v4_verify_uid_self_cert(
            target.primary_key_body,
            target.primary_key_body_len,
            target.user_id,
            target.user_id_len,
            target.self_cert_body,
            target.self_cert_body_len) != 0) {
        return ERR_CRYPTO;
    }

    *out_len = p;
    return ERR_OK;
}

app_err_t core_openpgp_create_identity_at_path(
    uint8_t *path,
    uint16_t path_len,
    const uint8_t *uid,
    size_t uid_len,
    uint32_t creation_time,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t primary_key_body[
        OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN];
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN];
    uint8_t uid_copy[OPENPGP_UID_MAX_LEN];
    core_openpgp_uid_certification_t certification;
    uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN];
    uint8_t certification_packet[
        CORE_OPENPGP_SIGNATURE_PACKET_MAX_LEN];

    size_t primary_key_body_len = 0;
    size_t certification_packet_len = 0;
    app_err_t err;

    if (path == NULL ||
        path_len == 0 ||
        uid == NULL ||
        uid_len == 0 ||
        uid_len > OPENPGP_UID_MAX_LEN ||
        creation_time == 0 ||
        out == NULL ||
        out_len == NULL) {
        return ERR_DATA;
    }

    *out_len = 0;

    /*
     * Keep the reviewed UID stable for the entire operation and permit the
     * caller's input and output storage to alias safely.
     */
    memcpy(uid_copy, uid, uid_len);

    err = core_openpgp_prepare_primary_key(
        path,
        path_len,
        creation_time,
        primary_key_body,
        sizeof(primary_key_body),
        &primary_key_body_len,
        fingerprint);

    if (err != ERR_OK) {
        return err;
    }

    err = core_openpgp_certify_uid(
        path,
        path_len,
        primary_key_body,
        primary_key_body_len,
        fingerprint,
        uid_copy,
        uid_len,
        creation_time,
        &certification,
        raw_signature);

    if (err != ERR_OK) {
        memzero(raw_signature, sizeof(raw_signature));
        return err;
    }

    err = core_openpgp_build_uid_certification_packet(
        &certification,
        fingerprint,
        raw_signature,
        certification_packet,
        sizeof(certification_packet),
        &certification_packet_len);

    memzero(raw_signature, sizeof(raw_signature));

    if (err != ERR_OK) {
        return err;
    }

    return core_openpgp_assemble_and_verify_identity(
        primary_key_body,
        primary_key_body_len,
        uid_copy,
        uid_len,
        certification_packet,
        certification_packet_len,
        out,
        out_capacity,
        out_len);
}

app_err_t core_openpgp_qr_run(
    uint8_t *path,
    uint16_t path_len)
{
    struct zcbor_string qr_request;
    struct zcbor_string qr_response;
    openpgp_request_t request;

    uint8_t *identity = g_mem_heap;
    uint8_t *encoded =
        &g_mem_heap[CORE_OPENPGP_IDENTITY_MAX_LEN];

    size_t identity_len = 0;
    size_t encoded_len = 0;
    app_err_t err;

    if (path == NULL ||
        path_len == 0) {
        return ERR_DATA;
    }

    /*
     * OpenPGP has a dedicated UR:BYTES entry point. Do not widen
     * UR_ANY_TX to accept arbitrary BYTES payloads.
     */
    if (ui_qrscan(BYTES, &qr_request) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    if (openpgp_protocol_parse_request(
            qr_request.value,
            qr_request.len,
            &request) != 0) {
        return ERR_DATA;
    }

    if (request.operation != OPENPGP_OP_CREATE_IDENTITY) {
        return ERR_DATA;
    }

    /*
     * qr_request points into g_mem_heap. create_identity_at_path() snapshots
     * the UID before writing identity output, so the scanned request may be
     * safely replaced here.
     */
    err = core_openpgp_create_identity_at_path(
        path,
        path_len,
        request.uid,
        request.uid_len,
        request.creation_time,
        identity,
        CORE_OPENPGP_IDENTITY_MAX_LEN,
        &identity_len);

    if (err != ERR_OK) {
        return err;
    }

    qr_response.value = identity;
    qr_response.len = identity_len;

    /*
     * Keep the CBOR output separate from the raw certificate input.
     * The raw identity occupies at most [0, 458), so encoding begins at 458.
     */
    if (cbor_encode_psbt(
            encoded,
            MEM_HEAP_SIZE - CORE_OPENPGP_IDENTITY_MAX_LEN,
            &qr_response,
            &encoded_len) != ZCBOR_SUCCESS) {
        return ERR_DATA;
    }

    if (ui_display_ur_qr(
            NULL,
            encoded,
            encoded_len,
            BYTES) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    return ERR_OK;
}

app_err_t core_openpgp_run(void)
{
    uint8_t path[OPENPGP_EIP1581_PATH_LEN * sizeof(uint32_t)];

    for (size_t i = 0; i < OPENPGP_EIP1581_PATH_LEN; i++) {
        uint32_t v = OPENPGP_EIP1581_PATH[i];

        path[i * 4] = (uint8_t)(v >> 24);
        path[i * 4 + 1] = (uint8_t)(v >> 16);
        path[i * 4 + 2] = (uint8_t)(v >> 8);
        path[i * 4 + 3] = (uint8_t)v;
    }

    return core_openpgp_qr_run(path, (uint16_t)sizeof(path));
}
