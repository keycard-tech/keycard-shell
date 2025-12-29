/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef UR_DECODE_H__
#define UR_DECODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "ur_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_decode_eth_sign_request(
		const uint8_t *payload, size_t payload_len,
		struct eth_sign_request *result,
		size_t *payload_len_out);


int cbor_decode_eth_signature(
		const uint8_t *payload, size_t payload_len,
		struct eth_signature *result,
		size_t *payload_len_out);


int cbor_decode_hd_key(
		const uint8_t *payload, size_t payload_len,
		struct hd_key *result,
		size_t *payload_len_out);


int cbor_decode_crypto_multi_accounts(
		const uint8_t *payload, size_t payload_len,
		struct crypto_multi_accounts *result,
		size_t *payload_len_out);


int cbor_decode_crypto_account(
		const uint8_t *payload, size_t payload_len,
		struct crypto_account *result,
		size_t *payload_len_out);


int cbor_decode_ur_part(
		const uint8_t *payload, size_t payload_len,
		struct ur_part *result,
		size_t *payload_len_out);


int cbor_decode_dev_auth(
		const uint8_t *payload, size_t payload_len,
		struct dev_auth *result,
		size_t *payload_len_out);


int cbor_decode_psbt(
		const uint8_t *payload, size_t payload_len,
		struct zcbor_string *result,
		size_t *payload_len_out);


int cbor_decode_tagged_psbt(
		const uint8_t *payload, size_t payload_len,
		struct zcbor_string *result,
		size_t *payload_len_out);


int cbor_decode_btc_sign_request(
		const uint8_t *payload, size_t payload_len,
		struct btc_sign_request *result,
		size_t *payload_len_out);


int cbor_decode_btc_signature(
		const uint8_t *payload, size_t payload_len,
		struct btc_signature *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* UR_DECODE_H__ */
