#include "openpgp/openpgp_protocol.h"

#include <string.h>

#include "zcbor_decode.h"
#include "zcbor_encode.h"

#define OPENPGP_CREATE_IDENTITY_REQUEST_MAP_ENTRIES 4
#define OPENPGP_SIGN_MESSAGE_REQUEST_MAP_ENTRIES 5

#define OPENPGP_REQUEST_KEY_VERSION 1
#define OPENPGP_REQUEST_KEY_OPERATION 2
#define OPENPGP_REQUEST_KEY_PAYLOAD 3
#define OPENPGP_REQUEST_KEY_CREATION_TIME 4
#define OPENPGP_REQUEST_KEY_SIGNATURE_CREATION_TIME 5

int openpgp_protocol_parse_request(const uint8_t *data, size_t data_len, openpgp_request_t *request) {

    zcbor_state_t states[4];
    struct zcbor_string payload;
    uint32_t version;
    uint32_t operation;

    if (data == NULL || request == NULL || data_len == 0) {
        return -1;
    }

    memset(request, 0, sizeof(*request));

    zcbor_new_decode_state(states, 4, data, data_len, 1, NULL, 0);

    if (!zcbor_map_start_decode(states) ||
        !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_VERSION) ||
        !zcbor_uint32_decode(states, &version) ||
        !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_OPERATION) ||
        !zcbor_uint32_decode(states, &operation)) {
        return -1;
    }

    if (version != OPENPGP_PROTOCOL_VERSION) {
        return -1;
    }

    if (operation == OPENPGP_OP_CREATE_IDENTITY) {
        uint32_t creation_time;

        if (!zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_PAYLOAD) ||
            !zcbor_bstr_decode(states, &payload) ||
            !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_CREATION_TIME) ||
            !zcbor_uint32_decode(states, &creation_time) ||
            !zcbor_map_end_decode(states)) {
            return -1;
        }

        if (payload.len == 0 ||
            payload.len > OPENPGP_UID_MAX_LEN ||
            creation_time == 0) {
            return -1;
        }

        request->operation = (uint8_t) operation;
        request->uid = payload.value;
        request->uid_len = payload.len;
        request->creation_time = creation_time;
    } else if (operation == OPENPGP_OP_SIGN_MESSAGE) {
        uint32_t key_creation_time;
        uint32_t signature_creation_time;

        if (!zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_PAYLOAD) ||
            !zcbor_bstr_decode(states, &payload) ||
            !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_CREATION_TIME) ||
            !zcbor_uint32_decode(states, &key_creation_time) ||
            !zcbor_uint32_expect(states, OPENPGP_REQUEST_KEY_SIGNATURE_CREATION_TIME) ||
            !zcbor_uint32_decode(states, &signature_creation_time) ||
            !zcbor_map_end_decode(states)) {
            return -1;
        }

        if (payload.len == 0 ||
            payload.len > OPENPGP_MESSAGE_MAX_LEN ||
            key_creation_time == 0 ||
            signature_creation_time == 0 ||
            signature_creation_time < key_creation_time) {
            return -1;
        }

        request->operation = (uint8_t) operation;
        request->message = payload.value;
        request->message_len = payload.len;
        request->key_creation_time = key_creation_time;
        request->signature_creation_time = signature_creation_time;
    } else {
        return -1;
    }

    if (states[0].payload != data + data_len) {
        return -1;
    }

    return 0;
}
