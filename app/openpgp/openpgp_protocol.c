#include "openpgp/openpgp_protocol.h"

#include "zcbor_decode.h"
#include "zcbor_encode.h"

#define OPENPGP_REQUEST_MAP_ENTRIES 3
#define OPENPGP_REQUEST_KEY_VERSION 1
#define OPENPGP_REQUEST_KEY_OPERATION 2
#define OPENPGP_REQUEST_KEY_UID 3

int openpgp_protocol_parse_request(
    const uint8_t *data,
    size_t data_len,
    openpgp_request_t *request)
{
    zcbor_state_t states[4];
    struct zcbor_string uid;
    uint32_t version;
    uint32_t operation;

    if (data == NULL || request == NULL || data_len == 0) {
        return -1;
    }

    zcbor_new_decode_state(
        states, 4, data, data_len, 1, NULL, 0);

    if (!zcbor_map_start_decode(states) ||
        !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_VERSION) ||
        !zcbor_uint32_decode(states, &version) ||
        !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_OPERATION) ||
        !zcbor_uint32_decode(states, &operation) ||
        !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_UID) ||
        !zcbor_bstr_decode(states, &uid) ||
        !zcbor_map_end_decode(states)) {
        return -1;
    }

    if (states[0].payload != data + data_len) {
        return -1;
    }

    if (version != OPENPGP_PROTOCOL_VERSION ||
        operation != OPENPGP_OP_CREATE_IDENTITY ||
        uid.len == 0 ||
        uid.len > OPENPGP_UID_MAX_LEN) {
        return -1;
    }

    request->operation = (uint8_t)operation;
    request->uid = uid.value;
    request->uid_len = uid.len;

    return 0;
}

int openpgp_protocol_build_request(
    uint8_t operation,
    const uint8_t *uid,
    size_t uid_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    zcbor_state_t states[4];
    struct zcbor_string uid_string;

    if (uid == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    if (operation != OPENPGP_OP_CREATE_IDENTITY ||
        uid_len == 0 ||
        uid_len > OPENPGP_UID_MAX_LEN) {
        return -1;
    }

    uid_string.value = uid;
    uid_string.len = uid_len;

    zcbor_new_encode_state(
        states, 4, out, out_capacity, 1);

    if (!zcbor_map_start_encode(
            states, OPENPGP_REQUEST_MAP_ENTRIES) ||
        !zcbor_uint32_put(states, OPENPGP_REQUEST_KEY_VERSION) ||
        !zcbor_uint32_put(states, OPENPGP_PROTOCOL_VERSION) ||
        !zcbor_uint32_put(states, OPENPGP_REQUEST_KEY_OPERATION) ||
        !zcbor_uint32_put(states, operation) ||
        !zcbor_uint32_put(states, OPENPGP_REQUEST_KEY_UID) ||
        !zcbor_bstr_encode(states, &uid_string)) {
        zcbor_list_map_end_force_encode(states);
        return -1;
    }

    if (!zcbor_map_end_encode(
            states, OPENPGP_REQUEST_MAP_ENTRIES)) {
        return -1;
    }

    *out_len = states[0].payload - out;
    return 0;
}
