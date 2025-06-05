/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef UR_TYPES_H__
#define UR_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct eth_signature_request_id {
	struct zcbor_string eth_signature_request_id;
};

struct eth_signature_signature_origin {
	struct zcbor_string eth_signature_signature_origin;
};

struct eth_signature {
	struct eth_signature_request_id eth_signature_request_id;
	bool eth_signature_request_id_present;
	struct zcbor_string eth_signature_signature;
	struct eth_signature_signature_origin eth_signature_signature_origin;
	bool eth_signature_signature_origin_present;
};

struct ur_part {
	uint32_t ur_part_seqNum;
	uint32_t ur_part_seqLen;
	uint32_t ur_part_messageLen;
	uint32_t ur_part_checksum;
	struct zcbor_string ur_part_data;
};

struct btc_signature {
	struct zcbor_string btc_signature_request_id;
	struct zcbor_string btc_signature_signature;
	struct zcbor_string btc_signature_public_key;
};

struct dev_auth_step_type_r {
	enum {
		dev_auth_step_type_dev_auth_init_m_c = 1,
		dev_auth_step_type_dev_auth_device_m_c = 2,
		dev_auth_step_type_dev_auth_server_m_c = 3,
	} dev_auth_step_type_choice;
};

struct dev_auth_dev_id {
	struct zcbor_string dev_auth_dev_id;
};

struct dev_auth_first_auth {
	uint32_t dev_auth_first_auth;
};

struct dev_auth_auth_time {
	uint32_t dev_auth_auth_time;
};

struct dev_auth_auth_count {
	uint32_t dev_auth_auth_count;
};

struct dev_auth_challenge {
	struct zcbor_string dev_auth_challenge;
};

struct dev_auth_auth_sig {
	struct zcbor_string dev_auth_auth_sig;
};

struct dev_auth {
	struct dev_auth_step_type_r dev_auth_step;
	struct dev_auth_dev_id dev_auth_dev_id;
	bool dev_auth_dev_id_present;
	struct dev_auth_first_auth dev_auth_first_auth;
	bool dev_auth_first_auth_present;
	struct dev_auth_auth_time dev_auth_auth_time;
	bool dev_auth_auth_time_present;
	struct dev_auth_auth_count dev_auth_auth_count;
	bool dev_auth_auth_count_present;
	struct dev_auth_challenge dev_auth_challenge;
	bool dev_auth_challenge_present;
	struct dev_auth_auth_sig dev_auth_auth_sig;
	bool dev_auth_auth_sig_present;
};

struct eth_sign_request_request_id {
	struct zcbor_string eth_sign_request_request_id;
};

struct sign_data_type_r {
	enum {
		sign_data_type_eth_transaction_data_m_c = 1,
		sign_data_type_eth_typed_data_m_c = 2,
		sign_data_type_eth_raw_bytes_m_c = 3,
		sign_data_type_eth_typed_transaction_m_c = 4,
	} sign_data_type_choice;
};

struct eth_sign_request_chain_id {
	int32_t eth_sign_request_chain_id;
};

struct path_component {
	uint32_t path_component_child_index_m;
	bool path_component_is_hardened_m;
};

struct crypto_keypath_source_fingerprint {
	uint32_t crypto_keypath_source_fingerprint;
};

struct crypto_keypath_depth {
	uint32_t crypto_keypath_depth;
};

struct crypto_keypath {
	struct path_component crypto_keypath_components_path_component_m[10];
	size_t crypto_keypath_components_path_component_m_count;
	struct crypto_keypath_source_fingerprint crypto_keypath_source_fingerprint;
	bool crypto_keypath_source_fingerprint_present;
	struct crypto_keypath_depth crypto_keypath_depth;
	bool crypto_keypath_depth_present;
};

struct eth_sign_request_address {
	struct zcbor_string eth_sign_request_address;
};

struct eth_sign_request_request_origin {
	struct zcbor_string eth_sign_request_request_origin;
};

struct eth_sign_request {
	struct eth_sign_request_request_id eth_sign_request_request_id;
	bool eth_sign_request_request_id_present;
	struct zcbor_string eth_sign_request_sign_data;
	struct sign_data_type_r eth_sign_request_data_type;
	struct eth_sign_request_chain_id eth_sign_request_chain_id;
	bool eth_sign_request_chain_id_present;
	struct crypto_keypath eth_sign_request_derivation_path;
	struct eth_sign_request_address eth_sign_request_address;
	bool eth_sign_request_address_present;
	struct eth_sign_request_request_origin eth_sign_request_request_origin;
	bool eth_sign_request_request_origin_present;
};

struct coininfo {
	uint32_t coininfo_coin_type;
	int32_t coininfo_network;
};

struct hd_key_use_info {
	struct coininfo hd_key_use_info;
};

struct hd_key_source {
	struct zcbor_string hd_key_source;
};

struct hd_key {
	bool hd_key_is_private;
	struct zcbor_string hd_key_key_data;
	struct zcbor_string hd_key_chain_code;
	struct hd_key_use_info hd_key_use_info;
	bool hd_key_use_info_present;
	struct crypto_keypath hd_key_origin;
	uint32_t hd_key_parent_fingerprint;
	struct zcbor_string hd_key_name;
	struct hd_key_source hd_key_source;
	bool hd_key_source_present;
};

struct btc_sign_request_btc_addresses_r {
	struct zcbor_string btc_sign_request_btc_addresses_btc_address_m;
	bool btc_sign_request_btc_addresses_btc_address_m_present;
};

struct btc_sign_request_btc_origin {
	struct zcbor_string btc_sign_request_btc_origin;
};

struct btc_sign_request {
	struct zcbor_string btc_sign_request_request_id;
	struct zcbor_string btc_sign_request_sign_data;
	struct crypto_keypath btc_sign_request_btc_derivation_paths_crypto_keypath_m;
	bool btc_sign_request_btc_derivation_paths_crypto_keypath_m_present;
	struct btc_sign_request_btc_addresses_r btc_sign_request_btc_addresses;
	bool btc_sign_request_btc_addresses_present;
	struct btc_sign_request_btc_origin btc_sign_request_btc_origin;
	bool btc_sign_request_btc_origin_present;
};

struct crypto_multi_accounts_device {
	struct zcbor_string crypto_multi_accounts_device;
};

struct crypto_multi_accounts_device_id {
	struct zcbor_string crypto_multi_accounts_device_id;
};

struct crypto_multi_accounts_version {
	struct zcbor_string crypto_multi_accounts_version;
};

struct crypto_multi_accounts {
	uint32_t crypto_multi_accounts_master_fingerprint;
	struct hd_key crypto_multi_accounts_keys_tagged_hd_key_m[10];
	size_t crypto_multi_accounts_keys_tagged_hd_key_m_count;
	struct crypto_multi_accounts_device crypto_multi_accounts_device;
	bool crypto_multi_accounts_device_present;
	struct crypto_multi_accounts_device_id crypto_multi_accounts_device_id;
	bool crypto_multi_accounts_device_id_present;
	struct crypto_multi_accounts_version crypto_multi_accounts_version;
	bool crypto_multi_accounts_version_present;
};

struct crypto_output_r {
	union {
		struct hd_key crypto_output_script_hash_m;
		struct hd_key crypto_output_script_hash_wpkh_m;
		struct hd_key crypto_output_script_hash_wsh_m;
		struct hd_key crypto_output_witness_script_hash_m;
		struct hd_key crypto_output_public_key_hash_m;
		struct hd_key crypto_output_witness_public_key_hash_m;
		struct hd_key crypto_output_taproot_m;
	};
	enum {
		crypto_output_script_hash_m_c,
		crypto_output_script_hash_wpkh_m_c,
		crypto_output_script_hash_wsh_m_c,
		crypto_output_witness_script_hash_m_c,
		crypto_output_public_key_hash_m_c,
		crypto_output_witness_public_key_hash_m_c,
		crypto_output_taproot_m_c,
	} crypto_output_choice;
};

struct crypto_account {
	uint32_t crypto_account_master_fingerprint;
	struct crypto_output_r crypto_account_output_descriptors_crypto_output_m[10];
	size_t crypto_account_output_descriptors_crypto_output_m_count;
};

#ifdef __cplusplus
}
#endif

#endif /* UR_TYPES_H__ */
