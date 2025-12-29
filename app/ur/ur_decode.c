/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "ur_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_uuid(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_repeated_eth_signature_request_id(zcbor_state_t *state, struct eth_signature_request_id *result);
static bool decode_repeated_eth_signature_signature_origin(zcbor_state_t *state, struct eth_signature_signature_origin *result);
static bool decode_dev_auth_step_type(zcbor_state_t *state, struct dev_auth_step_type_r *result);
static bool decode_repeated_dev_auth_dev_id(zcbor_state_t *state, struct dev_auth_dev_id *result);
static bool decode_repeated_dev_auth_first_auth(zcbor_state_t *state, struct dev_auth_first_auth *result);
static bool decode_repeated_dev_auth_auth_time(zcbor_state_t *state, struct dev_auth_auth_time *result);
static bool decode_repeated_dev_auth_auth_count(zcbor_state_t *state, struct dev_auth_auth_count *result);
static bool decode_repeated_dev_auth_challenge(zcbor_state_t *state, struct dev_auth_challenge *result);
static bool decode_repeated_dev_auth_auth_sig(zcbor_state_t *state, struct dev_auth_auth_sig *result);
static bool decode_repeated_eth_sign_request_request_id(zcbor_state_t *state, struct eth_sign_request_request_id *result);
static bool decode_sign_data_type(zcbor_state_t *state, struct sign_data_type_r *result);
static bool decode_repeated_eth_sign_request_chain_id(zcbor_state_t *state, struct eth_sign_request_chain_id *result);
static bool decode_path_component(zcbor_state_t *state, struct path_component *result);
static bool decode_repeated_crypto_keypath_source_fingerprint(zcbor_state_t *state, struct crypto_keypath_source_fingerprint *result);
static bool decode_repeated_crypto_keypath_depth(zcbor_state_t *state, struct crypto_keypath_depth *result);
static bool decode_crypto_keypath(zcbor_state_t *state, struct crypto_keypath *result);
static bool decode_repeated_eth_sign_request_address(zcbor_state_t *state, struct eth_sign_request_address *result);
static bool decode_repeated_eth_sign_request_request_origin(zcbor_state_t *state, struct eth_sign_request_request_origin *result);
static bool decode_coininfo(zcbor_state_t *state, struct coininfo *result);
static bool decode_repeated_hd_key_use_info(zcbor_state_t *state, struct hd_key_use_info *result);
static bool decode_repeated_hd_key_source(zcbor_state_t *state, struct hd_key_source *result);
static bool decode_repeated_btc_sign_request_btc_addresses(zcbor_state_t *state, struct btc_sign_request_btc_addresses_r *result);
static bool decode_repeated_btc_sign_request_btc_origin(zcbor_state_t *state, struct btc_sign_request_btc_origin *result);
static bool decode_tagged_hd_key(zcbor_state_t *state, struct hd_key *result);
static bool decode_repeated_crypto_multi_accounts_device(zcbor_state_t *state, struct crypto_multi_accounts_device *result);
static bool decode_repeated_crypto_multi_accounts_device_id(zcbor_state_t *state, struct crypto_multi_accounts_device_id *result);
static bool decode_repeated_crypto_multi_accounts_version(zcbor_state_t *state, struct crypto_multi_accounts_version *result);
static bool decode_key_exp(zcbor_state_t *state, struct hd_key *result);
static bool decode_script_hash(zcbor_state_t *state, struct hd_key *result);
static bool decode_witness_public_key_hash(zcbor_state_t *state, struct hd_key *result);
static bool decode_script_hash_wpkh(zcbor_state_t *state, struct hd_key *result);
static bool decode_witness_script_hash(zcbor_state_t *state, struct hd_key *result);
static bool decode_script_hash_wsh(zcbor_state_t *state, struct hd_key *result);
static bool decode_public_key_hash(zcbor_state_t *state, struct hd_key *result);
static bool decode_taproot(zcbor_state_t *state, struct hd_key *result);
static bool decode_crypto_output(zcbor_state_t *state, struct crypto_output_r *result);
static bool decode_btc_signature(zcbor_state_t *state, struct btc_signature *result);
static bool decode_btc_sign_request(zcbor_state_t *state, struct btc_sign_request *result);
static bool decode_tagged_psbt(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_psbt(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_dev_auth(zcbor_state_t *state, struct dev_auth *result);
static bool decode_ur_part(zcbor_state_t *state, struct ur_part *result);
static bool decode_crypto_account(zcbor_state_t *state, struct crypto_account *result);
static bool decode_crypto_multi_accounts(zcbor_state_t *state, struct crypto_multi_accounts *result);
static bool decode_hd_key(zcbor_state_t *state, struct hd_key *result);
static bool decode_eth_signature(zcbor_state_t *state, struct eth_signature *result);
static bool decode_eth_sign_request(zcbor_state_t *state, struct eth_sign_request *result);


static bool decode_uuid(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 37)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_signature_request_id(
		zcbor_state_t *state, struct eth_signature_request_id *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (1))))
	&& (decode_uuid(state, (&(*result).eth_signature_request_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_signature_signature_origin(
		zcbor_state_t *state, struct eth_signature_signature_origin *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (3))))
	&& (zcbor_tstr_decode(state, (&(*result).eth_signature_signature_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_dev_auth_step_type(
		zcbor_state_t *state, struct dev_auth_step_type_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_uint_decode(state, &(*result).dev_auth_step_type_choice, sizeof((*result).dev_auth_step_type_choice)))) && ((((((*result).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_init_m_c) && ((1)))
	|| (((*result).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_device_m_c) && ((1)))
	|| (((*result).dev_auth_step_type_choice == dev_auth_step_type_dev_auth_server_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_dev_id(
		zcbor_state_t *state, struct dev_auth_dev_id *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (2))))
	&& (decode_uuid(state, (&(*result).dev_auth_dev_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_first_auth(
		zcbor_state_t *state, struct dev_auth_first_auth *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (3))))
	&& (zcbor_uint32_decode(state, (&(*result).dev_auth_first_auth)))
	&& ((((((*result).dev_auth_first_auth <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_auth_time(
		zcbor_state_t *state, struct dev_auth_auth_time *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_uint32_decode(state, (&(*result).dev_auth_auth_time)))
	&& ((((((*result).dev_auth_auth_time <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_auth_count(
		zcbor_state_t *state, struct dev_auth_auth_count *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (5))))
	&& (zcbor_uint32_decode(state, (&(*result).dev_auth_auth_count)))
	&& ((((((*result).dev_auth_auth_count <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_challenge(
		zcbor_state_t *state, struct dev_auth_challenge *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (6))))
	&& (zcbor_bstr_decode(state, (&(*result).dev_auth_challenge)))
	&& ((((*result).dev_auth_challenge.len >= 32)
	&& ((*result).dev_auth_challenge.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_dev_auth_auth_sig(
		zcbor_state_t *state, struct dev_auth_auth_sig *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (7))))
	&& (zcbor_bstr_decode(state, (&(*result).dev_auth_auth_sig)))
	&& ((((*result).dev_auth_auth_sig.len >= 64)
	&& ((*result).dev_auth_auth_sig.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_sign_request_request_id(
		zcbor_state_t *state, struct eth_sign_request_request_id *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (1))))
	&& (decode_uuid(state, (&(*result).eth_sign_request_request_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_sign_data_type(
		zcbor_state_t *state, struct sign_data_type_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_uint_decode(state, &(*result).sign_data_type_choice, sizeof((*result).sign_data_type_choice)))) && ((((((*result).sign_data_type_choice == sign_data_type_eth_transaction_data_m_c) && ((1)))
	|| (((*result).sign_data_type_choice == sign_data_type_eth_typed_data_m_c) && ((1)))
	|| (((*result).sign_data_type_choice == sign_data_type_eth_raw_bytes_m_c) && ((1)))
	|| (((*result).sign_data_type_choice == sign_data_type_eth_typed_transaction_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_sign_request_chain_id(
		zcbor_state_t *state, struct eth_sign_request_chain_id *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_int32_decode(state, (&(*result).eth_sign_request_chain_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_path_component(
		zcbor_state_t *state, struct path_component *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_uint32_decode(state, (&(*result).path_component_child_index_m)))
	&& ((((((((((*result).path_component_child_index_m <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((zcbor_bool_decode(state, (&(*result).path_component_is_hardened_m)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_crypto_keypath_source_fingerprint(
		zcbor_state_t *state, struct crypto_keypath_source_fingerprint *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (2))))
	&& (zcbor_uint32_decode(state, (&(*result).crypto_keypath_source_fingerprint)))
	&& ((((((*result).crypto_keypath_source_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_crypto_keypath_depth(
		zcbor_state_t *state, struct crypto_keypath_depth *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (3))))
	&& (zcbor_uint32_decode(state, (&(*result).crypto_keypath_depth)))
	&& ((((((*result).crypto_keypath_depth <= UINT8_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_crypto_keypath(
		zcbor_state_t *state, struct crypto_keypath *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(0, 10, &(*result).crypto_keypath_components_path_component_m_count, (zcbor_decoder_t *)decode_path_component, state, (&(*result).crypto_keypath_components_path_component_m), sizeof(struct path_component))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))
	&& zcbor_present_decode(&((*result).crypto_keypath_source_fingerprint_present), (zcbor_decoder_t *)decode_repeated_crypto_keypath_source_fingerprint, state, (&(*result).crypto_keypath_source_fingerprint))
	&& zcbor_present_decode(&((*result).crypto_keypath_depth_present), (zcbor_decoder_t *)decode_repeated_crypto_keypath_depth, state, (&(*result).crypto_keypath_depth))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_sign_request_address(
		zcbor_state_t *state, struct eth_sign_request_address *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (6))))
	&& (zcbor_bstr_decode(state, (&(*result).eth_sign_request_address)))
	&& ((((((*result).eth_sign_request_address.len >= 20)
	&& ((*result).eth_sign_request_address.len <= 20)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_eth_sign_request_request_origin(
		zcbor_state_t *state, struct eth_sign_request_request_origin *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (7))))
	&& (zcbor_tstr_decode(state, (&(*result).eth_sign_request_request_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_coininfo(
		zcbor_state_t *state, struct coininfo *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (zcbor_uint32_decode(state, (&(*result).coininfo_coin_type)))
	&& ((((((((*result).coininfo_coin_type <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_int32_decode(state, (&(*result).coininfo_network))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_hd_key_use_info(
		zcbor_state_t *state, struct hd_key_use_info *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (5))))
	&& zcbor_tag_expect(state, 305)
	&& (decode_coininfo(state, (&(*result).hd_key_use_info)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_hd_key_source(
		zcbor_state_t *state, struct hd_key_source *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (10))))
	&& (zcbor_tstr_decode(state, (&(*result).hd_key_source)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_btc_sign_request_btc_addresses(
		zcbor_state_t *state, struct btc_sign_request_btc_addresses_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (5))))
	&& (zcbor_list_start_decode(state) && ((((*result).btc_sign_request_btc_addresses_btc_address_m_present = ((zcbor_tstr_decode(state, (&(*result).btc_sign_request_btc_addresses_btc_address_m)))), 1)) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_btc_sign_request_btc_origin(
		zcbor_state_t *state, struct btc_sign_request_btc_origin *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (6))))
	&& (zcbor_tstr_decode(state, (&(*result).btc_sign_request_btc_origin)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_tagged_hd_key(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 303)
	&& (decode_hd_key(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_crypto_multi_accounts_device(
		zcbor_state_t *state, struct crypto_multi_accounts_device *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (3))))
	&& (zcbor_tstr_decode(state, (&(*result).crypto_multi_accounts_device)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_crypto_multi_accounts_device_id(
		zcbor_state_t *state, struct crypto_multi_accounts_device_id *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_tstr_decode(state, (&(*result).crypto_multi_accounts_device_id)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_crypto_multi_accounts_version(
		zcbor_state_t *state, struct crypto_multi_accounts_version *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (5))))
	&& (zcbor_tstr_decode(state, (&(*result).crypto_multi_accounts_version)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_key_exp(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 303)
	&& (decode_hd_key(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_script_hash(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 400)
	&& (decode_key_exp(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_witness_public_key_hash(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 404)
	&& (decode_key_exp(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_script_hash_wpkh(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 400)
	&& (decode_witness_public_key_hash(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_witness_script_hash(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 401)
	&& (decode_key_exp(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_script_hash_wsh(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 400)
	&& (decode_witness_script_hash(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_public_key_hash(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 403)
	&& (decode_key_exp(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_taproot(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 409)
	&& (decode_key_exp(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_crypto_output(
		zcbor_state_t *state, struct crypto_output_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((decode_script_hash(state, (&(*result).crypto_output_script_hash_m)))) && (((*result).crypto_output_choice = crypto_output_script_hash_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_script_hash_wpkh(state, (&(*result).crypto_output_script_hash_wpkh_m)))) && (((*result).crypto_output_choice = crypto_output_script_hash_wpkh_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_script_hash_wsh(state, (&(*result).crypto_output_script_hash_wsh_m)))) && (((*result).crypto_output_choice = crypto_output_script_hash_wsh_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_witness_script_hash(state, (&(*result).crypto_output_witness_script_hash_m)))) && (((*result).crypto_output_choice = crypto_output_witness_script_hash_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_public_key_hash(state, (&(*result).crypto_output_public_key_hash_m)))) && (((*result).crypto_output_choice = crypto_output_public_key_hash_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_witness_public_key_hash(state, (&(*result).crypto_output_witness_public_key_hash_m)))) && (((*result).crypto_output_choice = crypto_output_witness_public_key_hash_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_taproot(state, (&(*result).crypto_output_taproot_m)))) && (((*result).crypto_output_choice = crypto_output_taproot_m_c), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_btc_signature(
		zcbor_state_t *state, struct btc_signature *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (decode_uuid(state, (&(*result).btc_signature_request_id))))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_bstr_decode(state, (&(*result).btc_signature_signature))))
	&& (((zcbor_uint32_expect(state, (3))))
	&& (zcbor_bstr_decode(state, (&(*result).btc_signature_public_key))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_btc_sign_request(
		zcbor_state_t *state, struct btc_sign_request *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (decode_uuid(state, (&(*result).btc_sign_request_request_id))))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_bstr_decode(state, (&(*result).btc_sign_request_sign_data))))
	&& (((zcbor_uint32_expect(state, (3))))
	&& (zcbor_uint32_expect(state, (1))))
	&& (((zcbor_uint32_expect(state, (4))))
	&& (zcbor_list_start_decode(state) && ((((*result).btc_sign_request_btc_derivation_paths_crypto_keypath_m_present = (zcbor_tag_expect(state, 304)
	&& (decode_crypto_keypath(state, (&(*result).btc_sign_request_btc_derivation_paths_crypto_keypath_m)))), 1)) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))
	&& zcbor_present_decode(&((*result).btc_sign_request_btc_addresses_present), (zcbor_decoder_t *)decode_repeated_btc_sign_request_btc_addresses, state, (&(*result).btc_sign_request_btc_addresses))
	&& zcbor_present_decode(&((*result).btc_sign_request_btc_origin_present), (zcbor_decoder_t *)decode_repeated_btc_sign_request_btc_origin, state, (&(*result).btc_sign_request_btc_origin))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_tagged_psbt(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((zcbor_tag_expect(state, 310)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_psbt(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_bstr_decode(state, (&(*result))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_dev_auth(
		zcbor_state_t *state, struct dev_auth *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (decode_dev_auth_step_type(state, (&(*result).dev_auth_step))))
	&& zcbor_present_decode(&((*result).dev_auth_dev_id_present), (zcbor_decoder_t *)decode_repeated_dev_auth_dev_id, state, (&(*result).dev_auth_dev_id))
	&& zcbor_present_decode(&((*result).dev_auth_first_auth_present), (zcbor_decoder_t *)decode_repeated_dev_auth_first_auth, state, (&(*result).dev_auth_first_auth))
	&& zcbor_present_decode(&((*result).dev_auth_auth_time_present), (zcbor_decoder_t *)decode_repeated_dev_auth_auth_time, state, (&(*result).dev_auth_auth_time))
	&& zcbor_present_decode(&((*result).dev_auth_auth_count_present), (zcbor_decoder_t *)decode_repeated_dev_auth_auth_count, state, (&(*result).dev_auth_auth_count))
	&& zcbor_present_decode(&((*result).dev_auth_challenge_present), (zcbor_decoder_t *)decode_repeated_dev_auth_challenge, state, (&(*result).dev_auth_challenge))
	&& zcbor_present_decode(&((*result).dev_auth_auth_sig_present), (zcbor_decoder_t *)decode_repeated_dev_auth_auth_sig, state, (&(*result).dev_auth_auth_sig))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_ur_part(
		zcbor_state_t *state, struct ur_part *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_decode(state, (&(*result).ur_part_seqNum)))
	&& ((((((*result).ur_part_seqNum <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((zcbor_uint32_decode(state, (&(*result).ur_part_seqLen))))
	&& ((zcbor_uint32_decode(state, (&(*result).ur_part_messageLen))))
	&& ((zcbor_uint32_decode(state, (&(*result).ur_part_checksum)))
	&& ((((((*result).ur_part_checksum <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((zcbor_bstr_decode(state, (&(*result).ur_part_data))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_crypto_account(
		zcbor_state_t *state, struct crypto_account *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (zcbor_uint32_decode(state, (&(*result).crypto_account_master_fingerprint)))
	&& ((((((*result).crypto_account_master_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(0, 10, &(*result).crypto_account_output_descriptors_crypto_output_m_count, (zcbor_decoder_t *)decode_crypto_output, state, (&(*result).crypto_account_output_descriptors_crypto_output_m), sizeof(struct crypto_output_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_crypto_multi_accounts(
		zcbor_state_t *state, struct crypto_multi_accounts *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (1))))
	&& (zcbor_uint32_decode(state, (&(*result).crypto_multi_accounts_master_fingerprint)))
	&& ((((((*result).crypto_multi_accounts_master_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(0, 10, &(*result).crypto_multi_accounts_keys_tagged_hd_key_m_count, (zcbor_decoder_t *)decode_tagged_hd_key, state, (&(*result).crypto_multi_accounts_keys_tagged_hd_key_m), sizeof(struct hd_key))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))
	&& zcbor_present_decode(&((*result).crypto_multi_accounts_device_present), (zcbor_decoder_t *)decode_repeated_crypto_multi_accounts_device, state, (&(*result).crypto_multi_accounts_device))
	&& zcbor_present_decode(&((*result).crypto_multi_accounts_device_id_present), (zcbor_decoder_t *)decode_repeated_crypto_multi_accounts_device_id, state, (&(*result).crypto_multi_accounts_device_id))
	&& zcbor_present_decode(&((*result).crypto_multi_accounts_version_present), (zcbor_decoder_t *)decode_repeated_crypto_multi_accounts_version, state, (&(*result).crypto_multi_accounts_version))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_hd_key(
		zcbor_state_t *state, struct hd_key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && (((((zcbor_uint32_expect(state, (2))))
	&& (zcbor_bool_decode(state, (&(*result).hd_key_is_private))))
	&& (((zcbor_uint32_expect(state, (3))))
	&& (zcbor_bstr_decode(state, (&(*result).hd_key_key_data)))
	&& ((((((*result).hd_key_key_data.len >= 33)
	&& ((*result).hd_key_key_data.len <= 33)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_uint32_expect(state, (4))))
	&& (zcbor_bstr_decode(state, (&(*result).hd_key_chain_code)))
	&& ((((((*result).hd_key_chain_code.len >= 32)
	&& ((*result).hd_key_chain_code.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& zcbor_present_decode(&((*result).hd_key_use_info_present), (zcbor_decoder_t *)decode_repeated_hd_key_use_info, state, (&(*result).hd_key_use_info))
	&& (((zcbor_uint32_expect(state, (6))))
	&& zcbor_tag_expect(state, 304)
	&& (decode_crypto_keypath(state, (&(*result).hd_key_origin))))
	&& (((zcbor_uint32_expect(state, (8))))
	&& (zcbor_uint32_decode(state, (&(*result).hd_key_parent_fingerprint)))
	&& ((((((*result).hd_key_parent_fingerprint <= UINT32_MAX)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_uint32_expect(state, (9))))
	&& (zcbor_tstr_decode(state, (&(*result).hd_key_name))))
	&& zcbor_present_decode(&((*result).hd_key_source_present), (zcbor_decoder_t *)decode_repeated_hd_key_source, state, (&(*result).hd_key_source))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_eth_signature(
		zcbor_state_t *state, struct eth_signature *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result).eth_signature_request_id_present), (zcbor_decoder_t *)decode_repeated_eth_signature_request_id, state, (&(*result).eth_signature_request_id))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_bstr_decode(state, (&(*result).eth_signature_signature))))
	&& zcbor_present_decode(&((*result).eth_signature_signature_origin_present), (zcbor_decoder_t *)decode_repeated_eth_signature_signature_origin, state, (&(*result).eth_signature_signature_origin))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_eth_sign_request(
		zcbor_state_t *state, struct eth_sign_request *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result).eth_sign_request_request_id_present), (zcbor_decoder_t *)decode_repeated_eth_sign_request_request_id, state, (&(*result).eth_sign_request_request_id))
	&& (((zcbor_uint32_expect(state, (2))))
	&& (zcbor_bstr_decode(state, (&(*result).eth_sign_request_sign_data))))
	&& (((zcbor_uint32_expect(state, (3))))
	&& (decode_sign_data_type(state, (&(*result).eth_sign_request_data_type))))
	&& zcbor_present_decode(&((*result).eth_sign_request_chain_id_present), (zcbor_decoder_t *)decode_repeated_eth_sign_request_chain_id, state, (&(*result).eth_sign_request_chain_id))
	&& (((zcbor_uint32_expect(state, (5))))
	&& zcbor_tag_expect(state, 304)
	&& (decode_crypto_keypath(state, (&(*result).eth_sign_request_derivation_path))))
	&& zcbor_present_decode(&((*result).eth_sign_request_address_present), (zcbor_decoder_t *)decode_repeated_eth_sign_request_address, state, (&(*result).eth_sign_request_address))
	&& zcbor_present_decode(&((*result).eth_sign_request_request_origin_present), (zcbor_decoder_t *)decode_repeated_eth_sign_request_request_origin, state, (&(*result).eth_sign_request_request_origin))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_eth_sign_request(
		const uint8_t *payload, size_t payload_len,
		struct eth_sign_request *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_eth_sign_request, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_eth_signature(
		const uint8_t *payload, size_t payload_len,
		struct eth_signature *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_eth_signature, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_hd_key(
		const uint8_t *payload, size_t payload_len,
		struct hd_key *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_hd_key, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_crypto_multi_accounts(
		const uint8_t *payload, size_t payload_len,
		struct crypto_multi_accounts *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[7];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_crypto_multi_accounts, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_crypto_account(
		const uint8_t *payload, size_t payload_len,
		struct crypto_account *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[8];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_crypto_account, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_ur_part(
		const uint8_t *payload, size_t payload_len,
		struct ur_part *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ur_part, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_dev_auth(
		const uint8_t *payload, size_t payload_len,
		struct dev_auth *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_dev_auth, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_psbt(
		const uint8_t *payload, size_t payload_len,
		struct zcbor_string *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_psbt, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_tagged_psbt(
		const uint8_t *payload, size_t payload_len,
		struct zcbor_string *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_tagged_psbt, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_btc_sign_request(
		const uint8_t *payload, size_t payload_len,
		struct btc_sign_request *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_btc_sign_request, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_btc_signature(
		const uint8_t *payload, size_t payload_len,
		struct btc_signature *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_btc_signature, sizeof(states) / sizeof(zcbor_state_t), 1);
}
