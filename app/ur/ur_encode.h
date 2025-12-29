/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef UR_ENCODE_H__
#define UR_ENCODE_H__

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


int cbor_encode_eth_sign_request(
		uint8_t *payload, size_t payload_len,
		const struct eth_sign_request *input,
		size_t *payload_len_out);


int cbor_encode_eth_signature(
		uint8_t *payload, size_t payload_len,
		const struct eth_signature *input,
		size_t *payload_len_out);


int cbor_encode_hd_key(
		uint8_t *payload, size_t payload_len,
		const struct hd_key *input,
		size_t *payload_len_out);


int cbor_encode_crypto_multi_accounts(
		uint8_t *payload, size_t payload_len,
		const struct crypto_multi_accounts *input,
		size_t *payload_len_out);


int cbor_encode_crypto_account(
		uint8_t *payload, size_t payload_len,
		const struct crypto_account *input,
		size_t *payload_len_out);


int cbor_encode_ur_part(
		uint8_t *payload, size_t payload_len,
		const struct ur_part *input,
		size_t *payload_len_out);


int cbor_encode_dev_auth(
		uint8_t *payload, size_t payload_len,
		const struct dev_auth *input,
		size_t *payload_len_out);


int cbor_encode_psbt(
		uint8_t *payload, size_t payload_len,
		const struct zcbor_string *input,
		size_t *payload_len_out);


int cbor_encode_tagged_psbt(
		uint8_t *payload, size_t payload_len,
		const struct zcbor_string *input,
		size_t *payload_len_out);


int cbor_encode_btc_sign_request(
		uint8_t *payload, size_t payload_len,
		const struct btc_sign_request *input,
		size_t *payload_len_out);


int cbor_encode_btc_signature(
		uint8_t *payload, size_t payload_len,
		const struct btc_signature *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* UR_ENCODE_H__ */
