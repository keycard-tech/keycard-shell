#ifndef OPENPGP_PROTOCOL_H
#define OPENPGP_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_PROTOCOL_VERSION 1
#define OPENPGP_OP_CREATE_IDENTITY 1
#define OPENPGP_UID_MAX_LEN 255

typedef struct {
    uint8_t operation;
    const uint8_t *uid;
    size_t uid_len;
    uint32_t creation_time;
} openpgp_request_t;

/*
 * OpenPGP requests are carried inside UR:BYTES as a CBOR map:
 *
 * {
 *   1: version,
 *   2: operation,
 *   3: uid,
 *   4: creation_time
 * }
 *
 * creation_time is host-provided OpenPGP metadata. The derivation path and
 * trusted cryptographic values are selected or derived by the Shell and are
 * intentionally absent from the request.
 */
int openpgp_protocol_parse_request(const uint8_t *data, size_t data_len, openpgp_request_t *request);

int openpgp_protocol_build_request(uint8_t operation, const uint8_t *uid, size_t uid_len, uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

#endif
