#ifndef OPENPGP_V4_H
#define OPENPGP_V4_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_VERSION_4 0x04

#define OPENPGP_SIG_TYPE_CANONICAL_TEXT 0x01
#define OPENPGP_SIG_TYPE_GENERIC_CERT 0x10
#define OPENPGP_SIG_TYPE_POSITIVE_CERT 0x13

#define OPENPGP_ALGO_ECDSA 19
#define OPENPGP_HASH_SHA256 8

#define OPENPGP_SUBPACKET_SIG_CREATION_TIME 0x02
#define OPENPGP_SUBPACKET_ISSUER_KEY_ID 0x10
#define OPENPGP_SUBPACKET_KEY_FLAGS 0x1b
#define OPENPGP_SUBPACKET_ISSUER_FINGERPRINT 0x21

#define OPENPGP_SIG_CREATION_TIME_SUBPACKET_LEN 0x05
#define OPENPGP_ISSUER_KEY_ID_SUBPACKET_LEN 0x09
#define OPENPGP_KEY_FLAGS_SUBPACKET_LEN 0x02
#define OPENPGP_ISSUER_FINGERPRINT_SUBPACKET_LEN 0x16

#define OPENPGP_SIG_HASHED_SUBPACKETS_LEN 0x1d
#define OPENPGP_UID_CERT_HASHED_SUBPACKETS_LEN 0x20
#define OPENPGP_SIG_UNHASHED_SUBPACKETS_LEN 0x0a

#define OPENPGP_KEY_FLAGS_CERTIFY_SIGN 0x03

#define OPENPGP_ISSUER_KEY_ID_LEN 8
#define OPENPGP_SECP256K1_POINT_LEN 65
#define OPENPGP_EC_POINT_UNCOMPRESSED 0x04

#define OPENPGP_SHA256_LEN 32
#define OPENPGP_V4_FINGERPRINT_LEN 20
#define OPENPGP_V4_SIG_FIELDS_LEN 35
#define OPENPGP_V4_UID_CERT_SIG_FIELDS_LEN 38
#define OPENPGP_RAW_ECDSA_LEN 64
#define OPENPGP_V4_SECP256K1_PUBLIC_KEY_BODY_LEN 79

int openpgp_v4_build_public_key_body(const uint8_t *point, size_t point_len, uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_build_sig_fields(const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_build_sig_fields_for_type(uint8_t signature_type, const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_build_uid_cert_sig_fields(const uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN], uint32_t creation_time, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_build_certification_data(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t *user_id, size_t user_id_len, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_primary_key_fingerprint(const uint8_t *primary_key_body, size_t primary_key_body_len, uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

int openpgp_v4_canonicalize_text(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_capacity, size_t *out_len);

int openpgp_v4_digest(const uint8_t *signed_data, size_t signed_data_len, const uint8_t *sig_fields, size_t sig_fields_len, uint8_t digest[OPENPGP_SHA256_LEN]);

int openpgp_v4_build_signature_packet(const uint8_t *sig_fields, size_t sig_fields_len, const uint8_t digest[OPENPGP_SHA256_LEN], const uint8_t raw_signature[OPENPGP_RAW_ECDSA_LEN], const uint8_t issuer_key_id[OPENPGP_ISSUER_KEY_ID_LEN], uint8_t *out, size_t out_capacity, size_t *out_len);


int openpgp_v4_verify_uid_self_cert(const uint8_t *primary_key_body, size_t primary_key_body_len, const uint8_t *user_id, size_t user_id_len, const uint8_t *signature_body, size_t signature_body_len);

#endif
