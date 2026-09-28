#include "openpgp/openpgp_packet.h"

#include <string.h>

typedef struct {
    uint8_t tag;

    const uint8_t *packet;
    size_t packet_len;

    const uint8_t *body;
    size_t body_len;
} packet_view_t;

static uint16_t read_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) |
           (uint16_t)p[1];
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int parse_packet(const uint8_t *data,
                        size_t data_len,
                        packet_view_t *packet,
                        size_t *consumed)
{
    uint8_t ctb;
    uint8_t tag;
    size_t pos = 0;
    size_t body_len = 0;

    if (!data || !packet || !consumed || data_len < 2)
        return -1;

    ctb = data[pos++];

    if ((ctb & 0x80) == 0)
        return -1;

    if (ctb & 0x40) {
        /*
         * New-format packet header.
         */
        uint8_t first_len;

        tag = ctb & 0x3f;

        if (pos >= data_len)
            return -1;

        first_len = data[pos++];

        if (first_len < 192) {
            body_len = first_len;
        } else if (first_len <= 223) {
            if (pos >= data_len)
                return -1;

            body_len =
                ((size_t)(first_len - 192) << 8) +
                data[pos++] +
                192;
        } else if (first_len == 255) {
            if (data_len - pos < 4)
                return -1;

            body_len = read_be32(&data[pos]);
            pos += 4;
        } else {
            /*
             * 224..254 are partial-body lengths.
             * This certification operation does not accept them.
             */
            return -1;
        }
    } else {
        /*
         * Old-format packet header.
         */
        uint8_t length_type = ctb & 0x03;

        tag = (ctb >> 2) & 0x0f;

        switch (length_type) {
        case 0:
            if (data_len - pos < 1)
                return -1;

            body_len = data[pos++];
            break;

        case 1:
            if (data_len - pos < 2)
                return -1;

            body_len = read_be16(&data[pos]);
            pos += 2;
            break;

        case 2:
            if (data_len - pos < 4)
                return -1;

            body_len = read_be32(&data[pos]);
            pos += 4;
            break;

        case 3:
        default:
            /*
             * Indeterminate-length old-format packet.
             */
            return -1;
        }
    }

    if (body_len > data_len - pos)
        return -1;

    packet->tag = tag;
    packet->packet = data;
    packet->packet_len = pos + body_len;
    packet->body = data + pos;
    packet->body_len = body_len;

    *consumed = packet->packet_len;
    return 0;
}

int openpgp_parse_cert_target(
    const uint8_t *packets,
    size_t packets_len,
    openpgp_cert_target_t *target)
{
    packet_view_t primary;
    packet_view_t uid;
    packet_view_t self_cert;

    size_t consumed = 0;
    size_t offset = 0;

    if (!packets || packets_len == 0 || !target)
        return -1;

    memset(target, 0, sizeof(*target));

    if (parse_packet(
            packets + offset,
            packets_len - offset,
            &primary,
            &consumed) != 0)
        return -1;

    offset += consumed;

    if (primary.tag != 6 ||
        primary.body_len == 0 ||
        primary.body[0] != 0x04)
        return -1;

    if (offset >= packets_len)
        return -1;

    if (parse_packet(
            packets + offset,
            packets_len - offset,
            &uid,
            &consumed) != 0)
        return -1;

    offset += consumed;

    if (uid.tag != 13 || uid.body_len == 0)
        return -1;

    if (offset >= packets_len)
        return -1;

    if (parse_packet(
            packets + offset,
            packets_len - offset,
            &self_cert,
            &consumed) != 0)
        return -1;

    offset += consumed;

    /*
     * The bundle must contain exactly these three packets.
     */
    if (offset != packets_len)
        return -1;

    /*
     * Minimum v4 signature body:
     *
     * version
     * signature type
     * public-key algorithm
     * hash algorithm
     * hashed-subpacket length (2 bytes)
     */
    if (self_cert.tag != 2 ||
        self_cert.body_len < 6 ||
        self_cert.body[0] != 0x04)
        return -1;

    if (self_cert.body[1] < 0x10 ||
        self_cert.body[1] > 0x13)
        return -1;

    target->primary_key_body = primary.body;
    target->primary_key_body_len = primary.body_len;

    target->user_id = uid.body;
    target->user_id_len = uid.body_len;

    target->self_cert_packet = self_cert.packet;
    target->self_cert_packet_len = self_cert.packet_len;

    target->self_cert_body = self_cert.body;
    target->self_cert_body_len = self_cert.body_len;

    target->self_cert_type = self_cert.body[1];

    return 0;
}
