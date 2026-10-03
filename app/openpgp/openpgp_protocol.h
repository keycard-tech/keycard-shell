#ifndef OPENPGP_PROTOCOL_H
#define OPENPGP_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_PROTOCOL_VERSION 1

#define OPENPGP_OP_CREATE_IDENTITY 1
#define OPENPGP_OP_SIGN_MESSAGE 2

#define OPENPGP_UID_MAX_LEN 255
#define OPENPGP_MESSAGE_MAX_LEN 104

typedef struct {
    uint8_t operation;

    const uint8_t *uid;
    size_t uid_len;
    uint32_t creation_time;

    const uint8_t *message;
    size_t message_len;
    uint32_t key_creation_time;
    uint32_t signature_creation_time;
} openpgp_request_t;

/*
 * CREATE_IDENTITY:
 *
 * {
 *   1: version,
 *   2: operation,
 *   3: uid,
 *   4: creation_time
 * }
 *
 * SIGN_MESSAGE:
 *
 * {
 *   1: version,
 *   2: operation,
 *   3: message,
 *   4: key_creation_time,
 *   5: signature_creation_time
 * }
 *
 * SIGN_MESSAGE accepts printable ASCII text with LF or CRLF line endings.
 * Canonical text signatures normalize line endings to CRLF before hashing.
 *
 * Requests are carried inside UR:BYTES. OpenPGP timestamps are host-provided
 * metadata. The derivation path and fingerprint are selected or derived by the
 * Shell and are intentionally absent from the request.
 */
int openpgp_protocol_parse_request(const uint8_t *data, size_t data_len, openpgp_request_t *request);

int openpgp_protocol_build_request(uint8_t operation, const uint8_t *uid, size_t uid_len, uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_protocol_build_sign_message_request(const uint8_t *message, size_t message_len, uint32_t key_creation_time, uint32_t signature_creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

#endif
