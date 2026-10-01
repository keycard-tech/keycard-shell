#include "core_openpgp.h"

#include <stddef.h>
#include <stdint.h>

#include "core.h"
#include "crypto/bip32.h"
#include "crypto/util.h"
#include "crypto/memzero.h"
#include "keycard/keycard_cmdset.h"
#include "mem.h"
#include "openpgp/openpgp_packet.h"
#include "openpgp/openpgp_protocol.h"
#include "openpgp/openpgp_v4.h"
#include "ui/i18n.h"
#include "ui/ui.h"
#include "ur/ur_encode.h"

#define OPENPGP_UID_CERT_SIGNATURE_TYPE 0x13

#define CORE_OPENPGP_SIGNATURE_PACKET_MAX_LEN 119
#define CORE_OPENPGP_IDENTITY_MAX_LEN 458
#define CORE_OPENPGP_UTC_TIME_LEN 23
#define CORE_OPENPGP_UTC_TIME_BUF_LEN (CORE_OPENPGP_UTC_TIME_LEN + 1)

typedef struct {
    uint8_t sig_fields[OPENPGP_V4_SIG_FIELDS_LEN];
    uint8_t digest[OPENPGP_SHA256_LEN];
} core_openpgp_uid_certification_t;

typedef struct {
    uint8_t *path;
    uint16_t path_len;

    uint8_t uid[OPENPGP_UID_MAX_LEN];
    size_t uid_len;
    uint32_t creation_time;

    uint8_t primary_key_body[OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN];
    size_t primary_key_body_len;
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN];

    core_openpgp_uid_certification_t certification;
    uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN];

    uint8_t certification_packet[CORE_OPENPGP_SIGNATURE_PACKET_MAX_LEN];
    size_t certification_packet_len;
} core_openpgp_identity_t;

/* Shell-owned path: m/43'/60'/1581'/5261136'/0; the host never supplies it. */
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

static app_err_t core_openpgp_prepare_primary_key(core_openpgp_identity_t *identity) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    uint8_t *path = identity->path;
    uint16_t path_len = identity->path_len;
    uint32_t creation_time = identity->creation_time;
    uint8_t *primary_key_body = identity->primary_key_body;
    size_t primary_key_body_capacity = sizeof(identity->primary_key_body);
    size_t *primary_key_body_len = &identity->primary_key_body_len;
    uint8_t *fingerprint = identity->fingerprint;
    uint8_t point[BIP32_PUBKEY_LEN];

    if (path == NULL ||
        path_len == 0 ||
        (path_len % sizeof(uint32_t)) != 0 ||
        path_len > BIP44_MAX_PATH_LEN ||
        creation_time == 0 ||
        primary_key_body == NULL ||
        primary_key_body_len == NULL ||
        fingerprint == NULL) {
        return ERR_DATA;
    }

    memcpy(g_core.bip44_path, path, path_len);
    g_core.bip44_path_len = (uint8_t) path_len;

    app_err_t err = core_export_key(&g_core.keycard, g_core.bip44_path, g_core.bip44_path_len, point, NULL);

    g_core.bip44_path_len = 0;

    if (err != ERR_OK) {
        return err;
    }

    if (openpgp_v4_build_public_key_body(point, sizeof(point), creation_time, primary_key_body, primary_key_body_capacity, primary_key_body_len) != 0) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_primary_key_fingerprint(primary_key_body, *primary_key_body_len, fingerprint) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}

static app_err_t core_openpgp_prepare_uid_certification(core_openpgp_identity_t *identity) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    const uint8_t *primary_key_body = identity->primary_key_body;
    size_t primary_key_body_len = identity->primary_key_body_len;
    const uint8_t *fingerprint = identity->fingerprint;
    const uint8_t *uid = identity->uid;
    size_t uid_len = identity->uid_len;
    uint32_t creation_time = identity->creation_time;
    core_openpgp_uid_certification_t *certification = &identity->certification;

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

    if (openpgp_v4_build_certification_data(primary_key_body, primary_key_body_len, uid, uid_len, signed_data, sizeof(signed_data), &signed_data_len) != 0) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_build_sig_fields_for_type(OPENPGP_UID_CERT_SIGNATURE_TYPE, fingerprint, creation_time, certification->sig_fields, sizeof(certification->sig_fields), &sig_fields_len) != 0) {
        return ERR_CRYPTO;
    }

    if (sig_fields_len != OPENPGP_V4_SIG_FIELDS_LEN) {
        return ERR_CRYPTO;
    }

    if (openpgp_v4_digest(signed_data, signed_data_len, certification->sig_fields, sig_fields_len, certification->digest) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}

static uint8_t core_openpgp_is_leap_year(uint32_t year) {
    return (year % 4U) == 0U && ((year % 100U) != 0U || (year % 400U) == 0U);
}

static void core_openpgp_write_two_digits(char *out, uint32_t value) {
    out[0] = (char) ('0' + ((value / 10U) % 10U));
    out[1] = (char) ('0' + (value % 10U));
}

static void core_openpgp_write_four_digits(char *out, uint32_t value) {
    out[0] = (char) ('0' + ((value / 1000U) % 10U));
    out[1] = (char) ('0' + ((value / 100U) % 10U));
    out[2] = (char) ('0' + ((value / 10U) % 10U));
    out[3] = (char) ('0' + (value % 10U));
}

static int core_openpgp_format_unix_time_utc(uint32_t timestamp, char *out, size_t out_capacity) {
    static const uint8_t month_days[12] = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31,
    };

    uint32_t days = timestamp / 86400U;
    uint32_t seconds_of_day = timestamp % 86400U;
    uint32_t year = 1970U;
    uint32_t month = 0U;

    if (out == NULL || out_capacity < CORE_OPENPGP_UTC_TIME_BUF_LEN) {
        return -1;
    }

    while (1) {
        uint32_t days_in_year = core_openpgp_is_leap_year(year) ? 366U : 365U;

        if (days < days_in_year) {
            break;
        }

        days -= days_in_year;
        year++;
    }

    while (month < 12U) {
        uint32_t days_in_month = month_days[month];

        if (month == 1U && core_openpgp_is_leap_year(year)) {
            days_in_month++;
        }

        if (days < days_in_month) {
            break;
        }

        days -= days_in_month;
        month++;
    }

    if (month >= 12U) {
        return -1;
    }

    uint32_t day = days + 1U;
    uint32_t hour = seconds_of_day / 3600U;
    uint32_t minute = (seconds_of_day % 3600U) / 60U;
    uint32_t second = seconds_of_day % 60U;

    core_openpgp_write_four_digits(&out[0], year);
    out[4] = '-';
    core_openpgp_write_two_digits(&out[5], month + 1U);
    out[7] = '-';
    core_openpgp_write_two_digits(&out[8], day);
    out[10] = ' ';
    core_openpgp_write_two_digits(&out[11], hour);
    out[13] = ':';
    core_openpgp_write_two_digits(&out[14], minute);
    out[16] = ':';
    core_openpgp_write_two_digits(&out[17], second);
    out[19] = ' ';
    out[20] = 'U';
    out[21] = 'T';
    out[22] = 'C';
    out[23] = '\0';

    return 0;
}

static app_err_t core_openpgp_confirm_identity(const core_openpgp_identity_t *identity) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    const uint8_t *uid = identity->uid;
    size_t uid_len = identity->uid_len;
    uint32_t creation_time = identity->creation_time;
    const uint8_t *fingerprint = identity->fingerprint;

    char fingerprint_hex[(OPENPGP_V4_FINGERPRINT_LEN * 2) + 1];
    char creation_time_utc[CORE_OPENPGP_UTC_TIME_BUF_LEN];
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

    /* Only certify UID bytes that can be reviewed unambiguously. */
    for (size_t i = 0; i < uid_len; i++) {
        if (uid[i] < 0x20 || uid[i] > 0x7e) {
            return ERR_DATA;
        }
    }

    base16_encode(fingerprint, fingerprint_hex, OPENPGP_V4_FINGERPRINT_LEN);

    if (core_openpgp_format_unix_time_utc(creation_time, creation_time_utc, sizeof(creation_time_utc)) != 0) {
        return ERR_DATA;
    }

    creation_time_len = CORE_OPENPGP_UTC_TIME_LEN;
    uid_title_len = strlen(LSTR(OPENPGP_UID_TITLE));
    creation_time_title_len = strlen(LSTR(OPENPGP_CREATION_TIME_TITLE));
    fingerprint_title_len = strlen(LSTR(OPENPGP_FINGERPRINT_TITLE));

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

    memcpy(&review[review_len], LSTR(OPENPGP_CREATION_TIME_TITLE), creation_time_title_len);
    review_len += creation_time_title_len;
    review[review_len++] = '\n';

    memcpy(&review[review_len], creation_time_utc, creation_time_len);
    review_len += creation_time_len;
    review[review_len++] = '\n';
    review[review_len++] = '\n';

    memcpy(&review[review_len], LSTR(OPENPGP_FINGERPRINT_TITLE), fingerprint_title_len);
    review_len += fingerprint_title_len;
    review[review_len++] = '\n';

    memcpy(&review[review_len], fingerprint_hex, OPENPGP_V4_FINGERPRINT_LEN * 2);
    review_len += OPENPGP_V4_FINGERPRINT_LEN * 2;

    if (ui_display_paged_text(LSTR(OPENPGP_APPROVE_TITLE), review, review_len) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    return ERR_OK;
}

static app_err_t core_openpgp_certify_uid(core_openpgp_identity_t *identity) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    uint8_t *path = identity->path;
    uint16_t path_len = identity->path_len;
    core_openpgp_uid_certification_t *certification = &identity->certification;
    uint8_t *raw_signature = identity->raw_signature;

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

    app_err_t err = core_openpgp_prepare_uid_certification(identity);

    if (err != ERR_OK) {
        return err;
    }

    err = core_openpgp_confirm_identity(identity);

    if (err != ERR_OK) {
        return err;
    }

    keycard_t *kc = &g_core.keycard;

    if (keycard_cmd_sign(kc, KEYCARD_SIGN_ECDSA_SECP256K1, path, (uint8_t) path_len, certification->digest) != ERR_OK ||
        APDU_SW(&kc->apdu) != 0x9000) {
        return ERR_CRYPTO;
    }

    if (keycard_read_signature(APDU_RESP(&kc->apdu), kc->apdu.lr, certification->digest, card_signature) != ERR_OK) {
        memzero(card_signature, sizeof(card_signature));
        return ERR_DATA;
    }

    memcpy(raw_signature, card_signature, OPENPGP_RAW_ECDSA_LEN);

    memzero(card_signature, sizeof(card_signature));

    return ERR_OK;
}

static app_err_t core_openpgp_build_uid_certification_packet(core_openpgp_identity_t *identity) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    const core_openpgp_uid_certification_t *certification = &identity->certification;
    const uint8_t *fingerprint = identity->fingerprint;
    const uint8_t *raw_signature = identity->raw_signature;
    uint8_t *out = identity->certification_packet;
    size_t out_capacity = sizeof(identity->certification_packet);
    size_t *out_len = &identity->certification_packet_len;

    uint8_t issuer_key_id[8];

    if (certification == NULL ||
        fingerprint == NULL ||
        raw_signature == NULL ||
        out == NULL ||
        out_len == NULL) {
        return ERR_DATA;
    }

    *out_len = 0;

    /* OpenPGP v4 key ID is the low 64 bits of the fingerprint. */
    memcpy(issuer_key_id, &fingerprint[OPENPGP_V4_FINGERPRINT_LEN - sizeof(issuer_key_id)], sizeof(issuer_key_id));

    if (openpgp_v4_build_signature_packet(certification->sig_fields, sizeof(certification->sig_fields), certification->digest, raw_signature, issuer_key_id, out, out_capacity, out_len) != 0) {
        return ERR_CRYPTO;
    }

    return ERR_OK;
}

static int core_openpgp_append_new_format_packet(uint8_t tag, const uint8_t *body, size_t body_len, uint8_t *out, size_t out_capacity, size_t *offset) {

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

static int core_openpgp_validate_identity_binding(const openpgp_cert_target_t *target) {

    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN];
    const uint8_t *signature_body;

    if (target == NULL ||
        target->primary_key_body == NULL ||
        target->self_cert_body == NULL) {
        return -1;
    }

    if (openpgp_v4_primary_key_fingerprint(target->primary_key_body, target->primary_key_body_len, fingerprint) != 0) {
        return -1;
    }

    signature_body = target->self_cert_body;

    /* Validate the certification metadata layout we emit. */
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

    if (memcmp(&signature_body[OPENPGP_UID_CERT_ISSUER_FINGERPRINT_OFFSET], fingerprint, OPENPGP_V4_FINGERPRINT_LEN) != 0) {
        return -1;
    }

    if (memcmp(&signature_body[OPENPGP_UID_CERT_ISSUER_KEY_ID_OFFSET], &fingerprint[OPENPGP_V4_FINGERPRINT_LEN - 8], 8) != 0) {
        return -1;
    }

    return 0;
}

static app_err_t core_openpgp_assemble_and_verify_identity(const core_openpgp_identity_t *identity, uint8_t *out, size_t out_capacity, size_t *out_len) {

    if (identity == NULL) {
        return ERR_DATA;
    }

    const uint8_t *primary_key_body = identity->primary_key_body;
    size_t primary_key_body_len = identity->primary_key_body_len;
    const uint8_t *uid = identity->uid;
    size_t uid_len = identity->uid_len;
    const uint8_t *certification_packet = identity->certification_packet;
    size_t certification_packet_len = identity->certification_packet_len;

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

    if (core_openpgp_append_new_format_packet(6, primary_key_body, primary_key_body_len, out, out_capacity, &p) != 0) {
        return ERR_DATA;
    }

    if (core_openpgp_append_new_format_packet(13, uid, uid_len, out, out_capacity, &p) != 0) {
        return ERR_DATA;
    }

    if (certification_packet_len > out_capacity - p) {
        return ERR_DATA;
    }

    memcpy(&out[p], certification_packet, certification_packet_len);
    p += certification_packet_len;

    if (openpgp_parse_cert_target(out, p, &target) != 0) {
        return ERR_DATA;
    }

    if (target.primary_key_body_len != primary_key_body_len ||
        memcmp(target.primary_key_body, primary_key_body, primary_key_body_len) != 0 ||
        target.user_id_len != uid_len ||
        memcmp(target.user_id, uid, uid_len) != 0 ||
        target.self_cert_packet_len != certification_packet_len ||
        memcmp(target.self_cert_packet, certification_packet, certification_packet_len) != 0 ||
        target.self_cert_type != OPENPGP_UID_CERT_SIGNATURE_TYPE) {
        return ERR_DATA;
    }

    if (core_openpgp_validate_identity_binding(&target) != 0) {
        return ERR_DATA;
    }

    if (openpgp_v4_verify_uid_self_cert(target.primary_key_body, target.primary_key_body_len, target.user_id, target.user_id_len, target.self_cert_body, target.self_cert_body_len) != 0) {
        return ERR_CRYPTO;
    }

    *out_len = p;
    return ERR_OK;
}

static app_err_t core_openpgp_create_identity_at_path(core_openpgp_identity_t *identity, uint8_t *out, size_t out_capacity, size_t *out_len) {

    app_err_t err;

    if (identity == NULL ||
        identity->path == NULL ||
        identity->path_len == 0 ||
        identity->uid_len == 0 ||
        identity->uid_len > OPENPGP_UID_MAX_LEN ||
        identity->creation_time == 0 ||
        out == NULL ||
        out_len == NULL) {
        return ERR_DATA;
    }

    *out_len = 0;

    err = core_openpgp_prepare_primary_key(identity);

    if (err != ERR_OK) {
        return err;
    }

    err = core_openpgp_certify_uid(identity);

    if (err != ERR_OK) {
        memzero(identity->raw_signature, sizeof(identity->raw_signature));
        return err;
    }

    err = core_openpgp_build_uid_certification_packet(identity);

    memzero(identity->raw_signature, sizeof(identity->raw_signature));

    if (err != ERR_OK) {
        return err;
    }

    return core_openpgp_assemble_and_verify_identity(identity, out, out_capacity, out_len);
}

static app_err_t core_openpgp_qr_run(uint8_t *path, uint16_t path_len) {

    struct zcbor_string qr_request;
    struct zcbor_string qr_response;
    openpgp_request_t request;
    core_openpgp_identity_t identity;

    uint8_t *identity_output = g_mem_heap;
    uint8_t *encoded = &g_mem_heap[CORE_OPENPGP_IDENTITY_MAX_LEN];

    size_t identity_len = 0;
    size_t encoded_len = 0;
    app_err_t err;

    if (path == NULL ||
        path_len == 0) {
        return ERR_DATA;
    }

    /* Keep arbitrary BYTES payloads out of UR_ANY_TX. */
    if (ui_qrscan(BYTES, &qr_request) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    if (openpgp_protocol_parse_request(qr_request.value, qr_request.len, &request) != 0) {
        return ERR_DATA;
    }

    if (request.operation != OPENPGP_OP_CREATE_IDENTITY ||
        request.uid == NULL ||
        request.uid_len == 0 ||
        request.uid_len > OPENPGP_UID_MAX_LEN ||
        request.creation_time == 0) {
        return ERR_DATA;
    }

    /* Snapshot the UID before reusing g_mem_heap for output. */
    memzero(&identity, sizeof(identity));

    identity.path = path;
    identity.path_len = path_len;
    memcpy(identity.uid, request.uid, request.uid_len);
    identity.uid_len = request.uid_len;
    identity.creation_time = request.creation_time;

    err = core_openpgp_create_identity_at_path(&identity, identity_output, CORE_OPENPGP_IDENTITY_MAX_LEN, &identity_len);

    if (err != ERR_OK) {
        return err;
    }

    qr_response.value = identity_output;
    qr_response.len = identity_len;

    /* Encode after the raw certificate region to avoid overlap. */
    if (cbor_encode_psbt(encoded, MEM_HEAP_SIZE - CORE_OPENPGP_IDENTITY_MAX_LEN, &qr_response, &encoded_len) != ZCBOR_SUCCESS) {
        return ERR_DATA;
    }

    if (ui_display_ur_qr(NULL, encoded, encoded_len, BYTES) != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
    }

    return ERR_OK;
}

app_err_t core_openpgp_run(void) {

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
