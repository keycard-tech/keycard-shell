/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "ur_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_uuid(zcbor_state_t *state, const struct zcbor_string *input);
static bool encode_repeated_eth_signature_request_id(zcbor_state_t *state, const struct eth_signature_request_id *input);
static bool encode_repeated_eth_signature_signature_origin(zcbor_state_t *state, const struct eth_signature_signature_origin *input);
static bool encode_dev_auth_step_type(zcbor_state_t *state, const struct dev_auth_step_type_r *input);
static bool encode_repeated_dev_auth_dev_id(zcbor_state_t *state, const struct dev_auth_dev_id *input);
static bool encode_repeated_dev_auth_first_auth(zcbor_state_t *state, const struct dev_auth_first_auth *input);
static bool encode_repeated_dev_auth_auth_time(zcbor_state_t *state, const struct dev_auth_auth_time *input);
static bool encode_repeated_dev_auth_auth_count(zcbor_state_t *state, const struct dev_auth_auth_count *input);
static bool encode_repeated_dev_auth_challenge(zcbor_state_t *state, const struct dev_auth_challenge *input);
static bool encode_repeated_dev_auth_auth_sig(zcbor_state_t *state, const struct dev_auth_auth_sig *input);
static bool encode_repeated_eth_sign_request_request_id(zcbor_state_t *state, const struct eth_sign_request_request_id *input);
static bool encode_sign_data_type(zcbor_state_t *state, const struct sign_data_type_r *input);
static bool encode_repeated_eth_sign_request_chain_id(zcbor_state_t *state, const struct eth_sign_request_chain_id *input);
static bool encode_path_component(zcbor_state_t *state, const struct path_component *input);
static bool encode_repeated_crypto_keypath_source_fingerprint(zcbor_state_t *state, const struct crypto_keypath_source_fingerprint *input);
static bool encode_repeated_crypto_keypath_depth(zcbor_state_t *state, const struct crypto_keypath_depth *input);
static bool encode_crypto_keypath(zcbor_state_t *state, const struct crypto_keypath *input);
static bool encode_repeated_eth_sign_request_address(zcbor_state_t *state, const struct eth_sign_request_address *input);
static bool encode_repeated_eth_sign_request_request_origin(zcbor_state_t *state, const struct eth_sign_request_request_origin *input);
static bool encode_coininfo(zcbor_state_t *state, const struct coininfo *input);
static bool encode_repeated_hd_key_use_info(zcbor_state_t *state, const struct hd_key_use_info *input);
static bool encode_repeated_hd_key_source(zcbor_state_t *state, const struct hd_key_source *input);
static bool encode_repeated_btc_sign_request_btc_addresses(zcbor_state_t *state, const struct btc_sign_request_btc_addresses_r *input);
static bool encode_repeated_btc_sign_request_btc_origin(zcbor_state_t *state, const struct btc_sign_request_btc_origin *input);
static bool encode_tagged_hd_key(zcbor_state_t *state, const struct hd_key *input);
static bool encode_repeated_crypto_multi_accounts_device(zcbor_state_t *state, const struct crypto_multi_accounts_device *input);
static bool encode_repeated_crypto_multi_accounts_device_id(zcbor_state_t *state, const struct crypto_multi_accounts_device_id *input);
static bool encode_repeated_crypto_multi_accounts_version(zcbor_state_t *state, const struct crypto_multi_accounts_version *input);
static bool encode_key_exp(zcbor_state_t *state, const struct hd_key *input);
static bool encode_script_hash(zcbor_state_t *state, const struct hd_key *input);
static bool encode_witness_public_key_hash(zcbor_state_t *state, const struct hd_key *input);
static bool encode_script_hash_wpkh(zcbor_state_t *state, const struct hd_key *input);
static bool encode_witness_script_hash(zcbor_state_t *state, const struct hd_key *input);
static bool encode_script_hash_wsh(zcbor_state_t *state, const struct hd_key *input);
static bool encode_public_key_hash(zcbor_state_t *state, const struct hd_key *input);
static bool encode_taproot(zcbor_state_t *state, const struct hd_key *input);
static bool encode_crypto_output(zcbor_state_t *state, const struct crypto_output_r *input);
static bool encode_btc_signature(zcbor_state_t *state, const struct btc_signature *input);
static bool encode_btc_sign_request(zcbor_state_t *state, const struct btc_sign_request *input);
static bool encode_psbt(zcbor_state_t *state, const struct zcbor_string *input);
static bool encode_dev_auth(zcbor_state_t *state, const struct dev_auth *input);
static bool encode_ur_part(zcbor_state_t *state, const struct ur_part *input);
static bool encode_crypto_account(zcbor_state_t *state, const struct crypto_account *input);
static bool encode_crypto_multi_accounts(zcbor_state_t *state, const struct crypto_multi_accounts *input);
static bool encode_hd_key(zcbor_state_t *state, const struct hd_key *input);
static bool encode_eth_signature(zcbor_state_t *state, const struct eth_signature *input);
static bool encode_eth_sign_request(zcbor_state_t *state, const struct eth_sign_request *input);


static bool encode_uuid(
		zcbor_state_t *state, const struct zcbor_string *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 37)
	&& (zcbor_bstr_encode(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_signature_request_id(
		zcbor_state_t *state, const struct eth_signature_request_id *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (1))))
	&& (encode_uuid(state, (&(*input).eth_signature_request_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_signature_signature_origin(
		zcbor_state_t *state, const struct eth_signature_signature_origin *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (3))))
	&& (zcbor_tstr_encode(state, (&(*input).eth_signature_signature_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_dev_auth_step_type(
		zcbor_state_t *state, const struct dev_auth_step_type_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_init_m_c) ? ((zcbor_uint32_put(state, (1))))
	: (((*input).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_device_m_c) ? ((zcbor_uint32_put(state, (2))))
	: (((*input).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_server_m_c) ? ((zcbor_uint32_put(state, (3))))
	: false)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_dev_id(
		zcbor_state_t *state, const struct dev_auth_dev_id *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (2))))
	&& (encode_uuid(state, (&(*input).dev_auth_dev_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_first_auth(
		zcbor_state_t *state, const struct dev_auth_first_auth *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (3))))
	&& ((((((*input).dev_auth_first_auth <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).dev_auth_first_auth)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_auth_time(
		zcbor_state_t *state, const struct dev_auth_auth_time *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& ((((((*input).dev_auth_auth_time <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).dev_auth_auth_time)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_auth_count(
		zcbor_state_t *state, const struct dev_auth_auth_count *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (5))))
	&& ((((((*input).dev_auth_auth_count <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).dev_auth_auth_count)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_challenge(
		zcbor_state_t *state, const struct dev_auth_challenge *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (6))))
	&& ((((*input).dev_auth_challenge.len >= 32)
	&& ((*input).dev_auth_challenge.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).dev_auth_challenge)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_dev_auth_auth_sig(
		zcbor_state_t *state, const struct dev_auth_auth_sig *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (7))))
	&& ((((*input).dev_auth_auth_sig.len >= 64)
	&& ((*input).dev_auth_auth_sig.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).dev_auth_auth_sig)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_sign_request_request_id(
		zcbor_state_t *state, const struct eth_sign_request_request_id *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (1))))
	&& (encode_uuid(state, (&(*input).eth_sign_request_request_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_sign_data_type(
		zcbor_state_t *state, const struct sign_data_type_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).sign_data_type_choice == sign_data_type_eth_transaction_data_m_c) ? ((zcbor_uint32_put(state, (1))))
	: (((*input).sign_data_type_choice == sign_data_type_eth_typed_data_m_c) ? ((zcbor_uint32_put(state, (2))))
	: (((*input).sign_data_type_choice == sign_data_type_eth_raw_bytes_m_c) ? ((zcbor_uint32_put(state, (3))))
	: (((*input).sign_data_type_choice == sign_data_type_eth_typed_transaction_m_c) ? ((zcbor_uint32_put(state, (4))))
	: false))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_sign_request_chain_id(
		zcbor_state_t *state, const struct eth_sign_request_chain_id *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (zcbor_int32_encode(state, (&(*input).eth_sign_request_chain_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_path_component(
		zcbor_state_t *state, const struct path_component *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((((((((((((*input).path_component_child_index_m <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).path_component_child_index_m))))
	&& ((zcbor_bool_encode(state, (&(*input).path_component_is_hardened_m)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_crypto_keypath_source_fingerprint(
		zcbor_state_t *state, const struct crypto_keypath_source_fingerprint *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (2))))
	&& ((((((*input).crypto_keypath_source_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).crypto_keypath_source_fingerprint)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_crypto_keypath_depth(
		zcbor_state_t *state, const struct crypto_keypath_depth *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (3))))
	&& ((((((*input).crypto_keypath_depth <= UINT8_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).crypto_keypath_depth)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_crypto_keypath(
		zcbor_state_t *state, const struct crypto_keypath *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((((zcbor_uint32_put(state, (1))))
	&& (zcbor_list_start_encode(state, 20) && ((zcbor_multi_encode_minmax(0, 10, &(*input).crypto_keypath_components_path_component_m_count, (zcbor_encoder_t *)encode_path_component, state, (&(*input).crypto_keypath_components_path_component_m), sizeof(struct path_component))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 20)))
	&& (!(*input).crypto_keypath_source_fingerprint_present || encode_repeated_crypto_keypath_source_fingerprint(state, (&(*input).crypto_keypath_source_fingerprint)))
	&& (!(*input).crypto_keypath_depth_present || encode_repeated_crypto_keypath_depth(state, (&(*input).crypto_keypath_depth)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_sign_request_address(
		zcbor_state_t *state, const struct eth_sign_request_address *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (6))))
	&& ((((((*input).eth_sign_request_address.len >= 20)
	&& ((*input).eth_sign_request_address.len <= 20)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).eth_sign_request_address)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_eth_sign_request_request_origin(
		zcbor_state_t *state, const struct eth_sign_request_request_origin *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (7))))
	&& (zcbor_tstr_encode(state, (&(*input).eth_sign_request_request_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_coininfo(
		zcbor_state_t *state, const struct coininfo *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 2) && (((((zcbor_uint32_put(state, (1))))
	&& ((((((((*input).coininfo_coin_type <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).coininfo_coin_type))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_int32_encode(state, (&(*input).coininfo_network))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_hd_key_use_info(
		zcbor_state_t *state, const struct hd_key_use_info *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (5))))
	&& zcbor_tag_put(state, 305)
	&& (encode_coininfo(state, (&(*input).hd_key_use_info)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_hd_key_source(
		zcbor_state_t *state, const struct hd_key_source *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (10))))
	&& (zcbor_tstr_encode(state, (&(*input).hd_key_source)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_btc_sign_request_btc_addresses(
		zcbor_state_t *state, const struct btc_sign_request_btc_addresses_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (5))))
	&& (zcbor_list_start_encode(state, 1) && (((!(*input).btc_sign_request_btc_addresses_btc_address_m_present || zcbor_tstr_encode(state, (&(*input).btc_sign_request_btc_addresses_btc_address_m)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_btc_sign_request_btc_origin(
		zcbor_state_t *state, const struct btc_sign_request_btc_origin *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (6))))
	&& (zcbor_tstr_encode(state, (&(*input).btc_sign_request_btc_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_tagged_hd_key(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 303)
	&& (encode_hd_key(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_crypto_multi_accounts_device(
		zcbor_state_t *state, const struct crypto_multi_accounts_device *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (3))))
	&& (zcbor_tstr_encode(state, (&(*input).crypto_multi_accounts_device)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_crypto_multi_accounts_device_id(
		zcbor_state_t *state, const struct crypto_multi_accounts_device_id *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (zcbor_tstr_encode(state, (&(*input).crypto_multi_accounts_device_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_crypto_multi_accounts_version(
		zcbor_state_t *state, const struct crypto_multi_accounts_version *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (5))))
	&& (zcbor_tstr_encode(state, (&(*input).crypto_multi_accounts_version)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_key_exp(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 303)
	&& (encode_hd_key(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_script_hash(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 400)
	&& (encode_key_exp(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_witness_public_key_hash(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 404)
	&& (encode_key_exp(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_script_hash_wpkh(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 400)
	&& (encode_witness_public_key_hash(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_witness_script_hash(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 401)
	&& (encode_key_exp(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_script_hash_wsh(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 400)
	&& (encode_witness_script_hash(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_public_key_hash(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 403)
	&& (encode_key_exp(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_taproot(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_put(state, 409)
	&& (encode_key_exp(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_crypto_output(
		zcbor_state_t *state, const struct crypto_output_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).crypto_output_choice == crypto_output_script_hash_m_c) ? ((encode_script_hash(state, (&(*input).crypto_output_script_hash_m))))
	: (((*input).crypto_output_choice == crypto_output_script_hash_wpkh_m_c) ? ((encode_script_hash_wpkh(state, (&(*input).crypto_output_script_hash_wpkh_m))))
	: (((*input).crypto_output_choice == crypto_output_script_hash_wsh_m_c) ? ((encode_script_hash_wsh(state, (&(*input).crypto_output_script_hash_wsh_m))))
	: (((*input).crypto_output_choice == crypto_output_witness_script_hash_m_c) ? ((encode_witness_script_hash(state, (&(*input).crypto_output_witness_script_hash_m))))
	: (((*input).crypto_output_choice == crypto_output_public_key_hash_m_c) ? ((encode_public_key_hash(state, (&(*input).crypto_output_public_key_hash_m))))
	: (((*input).crypto_output_choice == crypto_output_witness_public_key_hash_m_c) ? ((encode_witness_public_key_hash(state, (&(*input).crypto_output_witness_public_key_hash_m))))
	: (((*input).crypto_output_choice == crypto_output_taproot_m_c) ? ((encode_taproot(state, (&(*input).crypto_output_taproot_m))))
	: false)))))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_btc_signature(
		zcbor_state_t *state, const struct btc_signature *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((((zcbor_uint32_put(state, (1))))
	&& (encode_uuid(state, (&(*input).btc_signature_request_id))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_bstr_encode(state, (&(*input).btc_signature_signature))))
	&& (((zcbor_uint32_put(state, (3))))
	&& (zcbor_bstr_encode(state, (&(*input).btc_signature_public_key))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_btc_sign_request(
		zcbor_state_t *state, const struct btc_sign_request *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 6) && (((((zcbor_uint32_put(state, (1))))
	&& (encode_uuid(state, (&(*input).btc_sign_request_request_id))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_bstr_encode(state, (&(*input).btc_sign_request_sign_data))))
	&& (((zcbor_uint32_put(state, (3))))
	&& (zcbor_uint32_put(state, (1))))
	&& (((zcbor_uint32_put(state, (4))))
	&& (zcbor_list_start_encode(state, 1) && (((!(*input).btc_sign_request_btc_derivation_paths_crypto_keypath_m_present || encode_crypto_keypath(state, (&(*input).btc_sign_request_btc_derivation_paths_crypto_keypath_m)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1)))
	&& (!(*input).btc_sign_request_btc_addresses_present || encode_repeated_btc_sign_request_btc_addresses(state, (&(*input).btc_sign_request_btc_addresses)))
	&& (!(*input).btc_sign_request_btc_origin_present || encode_repeated_btc_sign_request_btc_origin(state, (&(*input).btc_sign_request_btc_origin)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 6))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_psbt(
		zcbor_state_t *state, const struct zcbor_string *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_bstr_encode(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_dev_auth(
		zcbor_state_t *state, const struct dev_auth *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 7) && (((((zcbor_uint32_put(state, (1))))
	&& (encode_dev_auth_step_type(state, (&(*input).dev_auth_step))))
	&& (!(*input).dev_auth_dev_id_present || encode_repeated_dev_auth_dev_id(state, (&(*input).dev_auth_dev_id)))
	&& (!(*input).dev_auth_first_auth_present || encode_repeated_dev_auth_first_auth(state, (&(*input).dev_auth_first_auth)))
	&& (!(*input).dev_auth_auth_time_present || encode_repeated_dev_auth_auth_time(state, (&(*input).dev_auth_auth_time)))
	&& (!(*input).dev_auth_auth_count_present || encode_repeated_dev_auth_auth_count(state, (&(*input).dev_auth_auth_count)))
	&& (!(*input).dev_auth_challenge_present || encode_repeated_dev_auth_challenge(state, (&(*input).dev_auth_challenge)))
	&& (!(*input).dev_auth_auth_sig_present || encode_repeated_dev_auth_auth_sig(state, (&(*input).dev_auth_auth_sig)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 7))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_ur_part(
		zcbor_state_t *state, const struct ur_part *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 5) && (((((((((*input).ur_part_seqNum <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).ur_part_seqNum))))
	&& ((zcbor_uint32_encode(state, (&(*input).ur_part_seqLen))))
	&& ((zcbor_uint32_encode(state, (&(*input).ur_part_messageLen))))
	&& (((((((*input).ur_part_checksum <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).ur_part_checksum))))
	&& ((zcbor_bstr_encode(state, (&(*input).ur_part_data))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 5))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_crypto_account(
		zcbor_state_t *state, const struct crypto_account *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 2) && (((((zcbor_uint32_put(state, (1))))
	&& ((((((*input).crypto_account_master_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).crypto_account_master_fingerprint))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_list_start_encode(state, 10) && ((zcbor_multi_encode_minmax(0, 10, &(*input).crypto_account_output_descriptors_crypto_output_m_count, (zcbor_encoder_t *)encode_crypto_output, state, (&(*input).crypto_account_output_descriptors_crypto_output_m), sizeof(struct crypto_output_r))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 10)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_crypto_multi_accounts(
		zcbor_state_t *state, const struct crypto_multi_accounts *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 5) && (((((zcbor_uint32_put(state, (1))))
	&& ((((((*input).crypto_multi_accounts_master_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).crypto_multi_accounts_master_fingerprint))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_list_start_encode(state, 10) && ((zcbor_multi_encode_minmax(0, 10, &(*input).crypto_multi_accounts_keys_tagged_hd_key_m_count, (zcbor_encoder_t *)encode_tagged_hd_key, state, (&(*input).crypto_multi_accounts_keys_tagged_hd_key_m), sizeof(struct hd_key))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 10)))
	&& (!(*input).crypto_multi_accounts_device_present || encode_repeated_crypto_multi_accounts_device(state, (&(*input).crypto_multi_accounts_device)))
	&& (!(*input).crypto_multi_accounts_device_id_present || encode_repeated_crypto_multi_accounts_device_id(state, (&(*input).crypto_multi_accounts_device_id)))
	&& (!(*input).crypto_multi_accounts_version_present || encode_repeated_crypto_multi_accounts_version(state, (&(*input).crypto_multi_accounts_version)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 5))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_hd_key(
		zcbor_state_t *state, const struct hd_key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 8) && (((((zcbor_uint32_put(state, (2))))
	&& (zcbor_bool_encode(state, (&(*input).hd_key_is_private))))
	&& (((zcbor_uint32_put(state, (3))))
	&& ((((((*input).hd_key_key_data.len >= 33)
	&& ((*input).hd_key_key_data.len <= 33)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).hd_key_key_data))))
	&& (((zcbor_uint32_put(state, (4))))
	&& ((((((*input).hd_key_chain_code.len >= 32)
	&& ((*input).hd_key_chain_code.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).hd_key_chain_code))))
	&& (!(*input).hd_key_use_info_present || encode_repeated_hd_key_use_info(state, (&(*input).hd_key_use_info)))
	&& (((zcbor_uint32_put(state, (6))))
	&& zcbor_tag_put(state, 304)
	&& (encode_crypto_keypath(state, (&(*input).hd_key_origin))))
	&& (((zcbor_uint32_put(state, (8))))
	&& ((((((*input).hd_key_parent_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).hd_key_parent_fingerprint))))
	&& (((zcbor_uint32_put(state, (9))))
	&& (zcbor_tstr_encode(state, (&(*input).hd_key_name))))
	&& (!(*input).hd_key_source_present || encode_repeated_hd_key_source(state, (&(*input).hd_key_source)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 8))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_eth_signature(
		zcbor_state_t *state, const struct eth_signature *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((!(*input).eth_signature_request_id_present || encode_repeated_eth_signature_request_id(state, (&(*input).eth_signature_request_id)))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_bstr_encode(state, (&(*input).eth_signature_signature))))
	&& (!(*input).eth_signature_signature_origin_present || encode_repeated_eth_signature_signature_origin(state, (&(*input).eth_signature_signature_origin)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_eth_sign_request(
		zcbor_state_t *state, const struct eth_sign_request *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 7) && (((!(*input).eth_sign_request_request_id_present || encode_repeated_eth_sign_request_request_id(state, (&(*input).eth_sign_request_request_id)))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_bstr_encode(state, (&(*input).eth_sign_request_sign_data))))
	&& (((zcbor_uint32_put(state, (3))))
	&& (encode_sign_data_type(state, (&(*input).eth_sign_request_data_type))))
	&& (!(*input).eth_sign_request_chain_id_present || encode_repeated_eth_sign_request_chain_id(state, (&(*input).eth_sign_request_chain_id)))
	&& (((zcbor_uint32_put(state, (5))))
	&& zcbor_tag_put(state, 304)
	&& (encode_crypto_keypath(state, (&(*input).eth_sign_request_derivation_path))))
	&& (!(*input).eth_sign_request_address_present || encode_repeated_eth_sign_request_address(state, (&(*input).eth_sign_request_address)))
	&& (!(*input).eth_sign_request_request_origin_present || encode_repeated_eth_sign_request_request_origin(state, (&(*input).eth_sign_request_request_origin)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 7))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_eth_sign_request(
		uint8_t *payload, size_t payload_len,
		const struct eth_sign_request *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_eth_sign_request, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_eth_signature(
		uint8_t *payload, size_t payload_len,
		const struct eth_signature *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_eth_signature, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_hd_key(
		uint8_t *payload, size_t payload_len,
		const struct hd_key *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_hd_key, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_crypto_multi_accounts(
		uint8_t *payload, size_t payload_len,
		const struct crypto_multi_accounts *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[7];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_crypto_multi_accounts, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_crypto_account(
		uint8_t *payload, size_t payload_len,
		const struct crypto_account *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[8];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_crypto_account, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_ur_part(
		uint8_t *payload, size_t payload_len,
		const struct ur_part *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ur_part, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_dev_auth(
		uint8_t *payload, size_t payload_len,
		const struct dev_auth *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_dev_auth, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_psbt(
		uint8_t *payload, size_t payload_len,
		const struct zcbor_string *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_psbt, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_btc_sign_request(
		uint8_t *payload, size_t payload_len,
		const struct btc_sign_request *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_btc_sign_request, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_btc_signature(
		uint8_t *payload, size_t payload_len,
		const struct btc_signature *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_btc_signature, sizeof(states) / sizeof(zcbor_state_t), 1);
}
