#ifndef OPENPGP_PACKET_H
#define OPENPGP_PACKET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *primary_key_body;
    size_t primary_key_body_len;

    const uint8_t *user_id;
    size_t user_id_len;

    const uint8_t *self_cert_packet;
    size_t self_cert_packet_len;

    const uint8_t *self_cert_body;
    size_t self_cert_body_len;

    uint8_t self_cert_type;
} openpgp_cert_target_t;

/*
 * Parse exactly:
 *
 *   tag 6   Primary Public-Key packet
 *   tag 13  User ID packet
 *   tag 2   self-certification Signature packet
 *
 * Both old- and new-format definite-length packet headers are accepted.
 * Partial and indeterminate lengths are rejected.
 * Trailing packets/bytes are rejected.
 */
int openpgp_parse_cert_target(const uint8_t *packets, size_t packets_len, openpgp_cert_target_t *target);

#endif
