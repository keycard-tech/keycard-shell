#include "app_tasks.h"
#include "core.h"
#include "crypto/address.h"
#include "crypto/sha2.h"
#include "crypto/ripemd160.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "ethereum/eth_db.h"
#include "mem.h"
#include "keycard/keycard_cmdset.h"
#include "settings.h"
#include "storage/keys.h"
#include "ui/ui_internal.h"
#include "util/tlv.h"
#include "ur/ur_encode.h"

#define BIP44_ACCOUNT_IDX 2
#define CRYPTO_MULTIACCOUNT_SN_LEN 40

#define USB_MORE_DATA_TIMEOUT 100

typedef void (*core_addr_encoder_t)(const uint8_t* key, char* addr);

const uint32_t ETH_PURPOSE = 0x8000002c;
const uint32_t ETH_COIN = 0x8000003c;

const uint32_t BTC_LEGACY_PURPOSE = 0x8000002c;
const uint32_t BTC_NESTED_SEGWIT_PURPOSE = 0x80000031;
const uint32_t BTC_NATIVE_SEGWIT_PURPOSE = 0x80000054;
const uint32_t BTC_TAPROOT_PURPOSE = 0x80000056;
const uint32_t BTC_LEGACY_MULTISIG_PURPOSE = 0x8000002d;
const uint32_t BTC_MULTISIG_PURPOSE = 0x80000030;

const uint32_t BTC_MAINNET_COIN = 0x80000000;
const uint32_t BTC_TESTNET_COIN = 0x80000001;

const uint32_t BIP44_ETH_PATH[] = { ETH_PURPOSE, ETH_COIN, 0x80000000 };

const uint32_t BIP44_BTC_LEGACY_PATH[] = { BTC_LEGACY_PURPOSE, BTC_MAINNET_COIN, 0x80000000 };
const uint32_t BIP44_BTC_NESTED_SEGWIT_PATH[] = { BTC_NESTED_SEGWIT_PURPOSE, BTC_MAINNET_COIN, 0x80000000 };
const uint32_t BIP44_BTC_NATIVE_SEGWIT_PATH[] = { BTC_NATIVE_SEGWIT_PURPOSE, BTC_MAINNET_COIN, 0x80000000 };

const uint32_t BIP44_BTC_TESTNET_LEGACY_PATH[] = { BTC_LEGACY_PURPOSE, BTC_TESTNET_COIN, 0x80000000 };
const uint32_t BIP44_BTC_TESTNET_NESTED_SEGWIT_PATH[] = { BTC_NESTED_SEGWIT_PURPOSE, BTC_TESTNET_COIN, 0x80000000 };
const uint32_t BIP44_BTC_TESTNET_NATIVE_SEGWIT_PATH[] = { BTC_NATIVE_SEGWIT_PURPOSE, BTC_TESTNET_COIN, 0x80000000 };

const uint32_t BIP44_BTC_MULTISIG_P2WSH_PATH[] = { BTC_MULTISIG_PURPOSE, BTC_MAINNET_COIN, 0x80000000, 0x80000002 };
const uint32_t BIP44_BTC_MULTISIG_P2WSH_P2SH_PATH[] = { BTC_MULTISIG_PURPOSE, BTC_MAINNET_COIN, 0x80000000, 0x80000001 };
const uint32_t BIP44_BTC_MULTISIG_P2SH_PATH[] = { BTC_LEGACY_MULTISIG_PURPOSE };

const char *const EIP4527_NAME = "Keycard Shell";

const char *const EIP4527_STANDARD = "account.standard";
const char *const EIP4527_LEDGER_LIVE = "account.ledger_live";
const char *const EIP4527_LEDGER_LEGACY = "account.ledger_legacy";

core_ctx_t g_core;

union qr_tx_data {
  struct eth_sign_request eth_sign_request;
  struct zcbor_string crypto_psbt;
  struct btc_sign_request btc_sign_request;
};

app_err_t core_export_key(keycard_t* kc, uint8_t* path, uint16_t len, uint8_t* out_pub, uint8_t* out_chain) {
  uint8_t export_type;

  if (out_chain) {
    export_type = 2;
  } else {
    export_type = 1;
  }

  if ((keycard_cmd_export_key(kc, export_type, path, len) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
    return ERR_CRYPTO;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);

  uint16_t tag;
  uint16_t off = tlv_read_tag(data, &tag);
  if (tag != 0xa1) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);
  len = tlv_read_fixed_primitive(0x80, PUBKEY_LEN, &data[off], out_pub);
  if (len == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  if (out_chain) {
    if (tlv_read_fixed_primitive(0x82, CHAINCODE_LEN, &data[off], out_chain) == TLV_INVALID) {
      return ERR_DATA;
    }
  }

  return ERR_OK;
}

app_err_t core_get_fingerprint(uint8_t* path, size_t len, uint32_t* fingerprint) {
  if (len == 0 && g_core.master_fingerprint != 0) {
    *fingerprint = g_core.master_fingerprint;
    return ERR_OK;
  }

  app_err_t err = core_export_key(&g_core.keycard, path, len, g_core.data.key.pub, NULL);

  if (err != ERR_OK) {
    return err;
  }

  g_core.data.key.pub[0] = 0x02 | (g_core.data.key.pub[PUBKEY_LEN - 1] & 1);

  hash160(g_core.data.key.pub, PUBKEY_COMPRESSED_LEN, g_core.data.key.pub);

  *fingerprint = (g_core.data.key.pub[0] << 24) | (g_core.data.key.pub[1] << 16) | (g_core.data.key.pub[2] << 8) | g_core.data.key.pub[3];

  if (len == 0)  {
    g_core.master_fingerprint = *fingerprint;
  }

  return ERR_OK;
}

app_err_t core_export_public(uint8_t* pub, uint8_t* chain, uint32_t* fingerprint, uint32_t* parent_fingerprint) {
  SC_BUF(path, BIP44_MAX_PATH_LEN);
  app_err_t err;

  if (fingerprint) {
    err = core_get_fingerprint(path, 0, fingerprint);
    if (err != ERR_OK) {
      return err;
    }
  }

  if (parent_fingerprint) {
    memcpy(path, g_core.bip44_path, (g_core.bip44_path_len - 4));
    err = core_get_fingerprint(path, (g_core.bip44_path_len - 4), parent_fingerprint);
    if (err != ERR_OK) {
      return err;
    }
  }

  memcpy(path, g_core.bip44_path, g_core.bip44_path_len);
  err = core_export_key(&g_core.keycard, path, g_core.bip44_path_len, pub, chain);

  if (err != ERR_OK) {
    return err;
  }

  pub[0] = 0x02 | (pub[PUBKEY_LEN - 1] & 1);

  return ERR_OK;
}

app_err_t core_set_derivation_path(struct crypto_keypath* derivation_path) {
  g_core.bip44_path_len = derivation_path->crypto_keypath_components_path_component_m_count * 4;

  if (g_core.bip44_path_len > BIP44_MAX_PATH_LEN) {
    g_core.bip44_path_len = 0;
    return ERR_DATA;
  }

  for (int i = 0; i < derivation_path->crypto_keypath_components_path_component_m_count; i++) {
    uint32_t idx = derivation_path->crypto_keypath_components_path_component_m[i].path_component_child_index_m;
    if (derivation_path->crypto_keypath_components_path_component_m[i].path_component_is_hardened_m) {
      idx |= 0x80000000;
    }

    g_core.bip44_path[(i * 4)] = idx >> 24;
    g_core.bip44_path[(i * 4) + 1] = (idx >> 16) & 0xff;
    g_core.bip44_path[(i * 4) + 2] = (idx >> 8) & 0xff;
    g_core.bip44_path[(i * 4) + 3] = idx & 0xff;
  }

  return ERR_OK;
}

static app_err_t core_usb_get_public(keycard_t* kc, apdu_t* cmd) {
  uint8_t* data = APDU_DATA(cmd);
  uint16_t len = data[0] * 4;
  if (len > BIP44_MAX_PATH_LEN) {
    core_usb_err_sw(cmd, 0x6a, 0x80);
    return ERR_DATA;
  }

  uint8_t* out = APDU_RESP(cmd);
  uint8_t extended = APDU_P2(cmd) == 1;

  if (ui_confirm_export_key() != CORE_EVT_UI_OK) {
    core_usb_err_sw(cmd, 0x69, 0x82);
    return ERR_CANCEL;
  }

  SC_BUF(path, BIP44_MAX_PATH_LEN);

  uint32_t mfp;
  app_err_t err = core_get_fingerprint(path, 0, &mfp);

  if (err == ERR_OK) {
    mfp = rev32(mfp);

    memcpy(path, &data[1], len);
    err = core_export_key(kc, path, len, &out[6], (extended ? &out[72] : NULL));
  }

  switch (err) {
  case ERR_OK:
    break;
  case ERR_CRYPTO:
    core_usb_err_sw(cmd, 0x69, 0x82);
    return ERR_DATA;
  default:
    core_usb_err_sw(cmd, 0x6f, 0x00);
    return ERR_DATA;
  }

  out[0] = 4;
  memcpy(&out[1], &mfp, 4);

  out[5] = 65;

  if (extended) {
    out[71] = 32;
    len = 104;
  } else {
    out[71] = 0;
    len = 72;
  }

  out[len++] = 0x90;
  out[len++] = 0x00;

  cmd->lr = len;

  return ERR_OK;
}

TEST_APP_ACCESSIBLE app_err_t core_usb_get_app_config(apdu_t* cmd) {
  uint8_t* data = APDU_RESP(cmd);
  data[0] = FW_VERSION[0];
  data[1] = FW_VERSION[1];
  data[2] = FW_VERSION[2];

  uint32_t db_version = 0;
  eth_db_lookup_version(&db_version);

  data[3] = db_version >> 24;
  data[4] = (db_version >> 16) & 0xff;
  data[5] = (db_version >> 8) & 0xff;
  data[6] = db_version & 0xff;

  hal_device_uid(&data[7]);

  uint8_t key[32];
  key_read_private(DEV_AUTH_PRIV_KEY, key);
  ecdsa_get_public_key33(&secp256k1, key, &data[7 + HAL_DEVICE_UID_LEN]);
  memset(key, 0, 32);

  data[7 + HAL_DEVICE_UID_LEN + 33] = 0x90;
  data[8 + HAL_DEVICE_UID_LEN + 33] = 0x00;
  cmd->lr = 9 + HAL_DEVICE_UID_LEN + 33;

  return ERR_OK;
}

app_err_t core_usb_get_response(command_t* cmd) {
  if (cmd->extra_data == NULL) {
    core_usb_err_sw(&cmd->apdu, 0x69, 0x85);
    return ERR_OK;
  }

  apdu_t* apdu = &cmd->apdu;
  uint8_t* apdu_out = APDU_RESP(apdu);

  uint16_t sent_len = APP_MIN(USB_CMD_MAX_PAYLOAD, cmd->extra_len);
  memcpy(apdu_out, cmd->extra_data, sent_len);
  apdu->lr = sent_len + 2;

  cmd->extra_len -= sent_len;
  cmd->extra_data += sent_len;

  if (cmd->extra_len > 0) {
    apdu_out[sent_len] = 0x61;
    apdu_out[sent_len + 1] = cmd->extra_len > USB_CMD_MAX_PAYLOAD ?  0x00 : (cmd->extra_len + 2);
    return ERR_NEED_MORE_DATA;
  } else {
    apdu_out[sent_len] = 0x90;
    apdu_out[sent_len + 1] = 0x00;
    return ERR_OK;
  }
}

static app_err_t core_usb_command(keycard_t* kc, command_t* cmd) {
  apdu_t* apdu = &cmd->apdu;

  app_err_t err;

  if (APDU_CLA(apdu) == 0xe0) {
    switch(APDU_INS(apdu)) {
      case INS_GET_PUBLIC:
        err = core_usb_get_public(kc, apdu);
        break;
      case INS_SIGN_ETH_TX:
        err = core_eth_usb_sign_tx(kc, apdu);
        break;
      case INS_SIGN_ETH_MSG:
        err = core_eth_usb_sign_message(kc, apdu);
        break;
      case INS_GET_APP_CONF:
        err = core_usb_get_app_config(apdu);
        break;
      case INS_SIGN_EIP_712:
        err = core_eth_usb_sign_eip712(kc, apdu);
        break;
      case INS_SIGN_PSBT:
        err = core_btc_usb_sign_psbt(kc, cmd);
        break;
      case INS_GET_RESPONSE:
        err = core_usb_get_response(cmd);
        break;
      case INS_FW_UPGRADE:
        err = updater_usb_fw_upgrade(cmd, apdu);
        break;
      case INS_ERC20_UPGRADE:
        err = updater_usb_db_upgrade(apdu);
        break;
      default:
        err = ERR_CANCEL;
        core_usb_err_sw(apdu, 0x6d, 0x00);
        break;
    }
  } else {
    err = ERR_CANCEL;
    core_usb_err_sw(apdu, 0x6e, 0x00);
  }

  command_init_send(cmd);
  return err;
}

static void core_usb_cancel() {
  core_usb_err_sw(&g_core.usb_command.apdu, 0x69, 0x82);
  command_init_send(&g_core.usb_command);
}

void core_usb_run() {
  while(1) {
    if (core_usb_command(&g_core.keycard, &g_core.usb_command) == ERR_NEED_MORE_DATA) {
      if (core_wait_event(USB_MORE_DATA_TIMEOUT, 1) != CORE_EVT_USB_CMD) {
        break;
      }
    } else {
      break;
    }
  }

  g_core.usb_command.extra_data = NULL;
  g_core.usb_command.extra_len = 0;
}

void core_qr_run() {
  union qr_tx_data qr_request;
  ur_type_t tx_type;

  if (ui_qrscan_tx(&tx_type, &qr_request) != CORE_EVT_UI_OK) {
    return;
  }

  switch(tx_type) {
  case ETH_SIGN_REQUEST:
    core_eth_eip4527_run(&qr_request.eth_sign_request);
    break;
  case CRYPTO_PSBT:
    core_btc_psbt_qr_run(&qr_request.crypto_psbt);
    break;
  case BTC_SIGN_REQUEST:
    core_btc_sign_msg_qr_run(&qr_request.btc_sign_request);
    break;
  default:
    break;
  }
}

static inline void set_device_name(struct zcbor_string* card_name) {
  const char* name = core_get_device_name();
  card_name->value = (const uint8_t*) name;
  card_name->len = strlen(name);
}

static app_err_t get_hd_key(struct hd_key* key, uint8_t* pub, uint8_t* chain, const uint32_t* path, uint32_t path_len, uint32_t account, const char* source) {
  key->hd_key_is_private = 0;
  key->hd_key_key_data.len = PUBKEY_COMPRESSED_LEN;
  key->hd_key_key_data.value = pub;
  key->hd_key_chain_code.len = CHAINCODE_LEN;
  key->hd_key_chain_code.value = chain;
  key->hd_key_use_info_present = 0;
  key->hd_key_origin.crypto_keypath_depth_present = 1;
  key->hd_key_origin.crypto_keypath_depth.crypto_keypath_depth = path_len;
  key->hd_key_origin.crypto_keypath_source_fingerprint_present = 1;
  key->hd_key_origin.crypto_keypath_components_path_component_m_count = path_len;

  set_device_name(&key->hd_key_name);

  if (source != NULL) {
    if (source == EIP4527_LEDGER_LEGACY) {
      key->hd_key_children_present = 1;
      key->hd_key_children.hd_key_children.crypto_keypath_depth_present = 0;
      key->hd_key_children.hd_key_children.crypto_keypath_source_fingerprint_present = 0;
      key->hd_key_children.hd_key_children.crypto_keypath_components_path_component_m_count = 1;
      key->hd_key_children.hd_key_children.crypto_keypath_components_path_component_m[0].path_component_child_index_m_present = 0;
      key->hd_key_children.hd_key_children.crypto_keypath_components_path_component_m[0].path_component_is_hardened_m = 0;
    } else {
      key->hd_key_children_present = 0;
    }

    key->hd_key_source_present = 1;
    key->hd_key_source.hd_key_source.len = strlen(source);
    key->hd_key_source.hd_key_source.value = (const uint8_t*) source;
  } else {
    key->hd_key_children_present = 0;
    key->hd_key_source_present = 0;
  }

  g_core.bip44_path_len = 0;

  for (int i = 0; i < path_len; i++) {
    uint32_t path_elem;

    key->hd_key_origin.crypto_keypath_components_path_component_m[i].path_component_child_index_m_present = 1;

    if (i == BIP44_ACCOUNT_IDX) {
      key->hd_key_origin.crypto_keypath_components_path_component_m[i].path_component_child_index_m = account;
      key->hd_key_origin.crypto_keypath_components_path_component_m[i].path_component_is_hardened_m = 1;
      path_elem = rev32((0x80000000 | account));
    } else {
      key->hd_key_origin.crypto_keypath_components_path_component_m[i].path_component_child_index_m = path[i] & 0x7fffffff;
      key->hd_key_origin.crypto_keypath_components_path_component_m[i].path_component_is_hardened_m = ((path[i] & 0x80000000) >> 31);
      path_elem = rev32(path[i]);
    }

    memcpy(&g_core.bip44_path[i * sizeof(uint32_t)], &path_elem, sizeof(uint32_t));
    g_core.bip44_path_len += sizeof(uint32_t);
  }

  if (core_export_public(pub, chain, &key->hd_key_origin.crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint, &key->hd_key_parent_fingerprint) != ERR_OK) {
    return ERR_HW;
  }

  return ERR_OK;
}

static void core_display_public_eip4527(uint32_t account, const char* account_type) {
  struct hd_key key;

  if (get_hd_key(&key, g_core.data.key.pub, g_core.data.key.chain, BIP44_ETH_PATH, (sizeof(BIP44_ETH_PATH)/sizeof(uint32_t)), account, account_type) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  cbor_encode_hd_key(g_core.data.key.cbor_key, CBOR_KEY_MAX_LEN, &key, &g_core.data.key.cbor_len);
  ui_display_ur_qr(NULL, g_core.data.key.cbor_key, g_core.data.key.cbor_len, CRYPTO_HDKEY);
}

// this macro can only be used in core_display_public_bitcoin_*()
#define CORE_BITCOIN_EXPORT(__NUM__, __TYPE__, __PATH__, __PATH_LEN__, __ACCOUNT__) \
  if (get_hd_key(&account.crypto_account_output_descriptors_crypto_output_m[__NUM__].crypto_output_public_key_hash_m, &g_mem_heap[keys_off], &g_mem_heap[keys_off + PUBKEY_LEN], __PATH__, __PATH_LEN__, __ACCOUNT__, NULL) != ERR_OK) { \
    ui_card_transport_error(); \
    return; \
  } \
  account.crypto_account_output_descriptors_crypto_output_m[__NUM__].crypto_output_choice =  __TYPE__; \
  keys_off += PUBKEY_LEN + CHAINCODE_LEN
static void core_display_public_bitcoin(const uint32_t* segwit, const uint32_t* nested_segwit, const uint32_t* legacy, uint32_t account_idx) {
  struct crypto_account account;

  size_t keys_off = 0;

  CORE_BITCOIN_EXPORT(0, crypto_output_witness_public_key_hash_m_c, segwit, 3, account_idx);
  CORE_BITCOIN_EXPORT(1, crypto_output_script_hash_wpkh_m_c, nested_segwit, 3, account_idx);
  CORE_BITCOIN_EXPORT(2, crypto_output_public_key_hash_m_c, legacy, 3, account_idx);

  account.crypto_account_output_descriptors_crypto_output_m_count = 3;
  account.crypto_account_master_fingerprint = g_core.master_fingerprint;
  cbor_encode_crypto_account(&g_mem_heap[keys_off], MEM_HEAP_SIZE, &account, &g_core.data.key.cbor_len);
  ui_display_ur_qr(NULL, &g_mem_heap[keys_off], g_core.data.key.cbor_len, CRYPTO_ACCOUNT);
}

static void core_display_public_bitcoin_multisig(uint32_t account_idx) {
  struct crypto_account account;

  size_t keys_off = 0;

  CORE_BITCOIN_EXPORT(0, crypto_output_witness_script_hash_m_c, BIP44_BTC_MULTISIG_P2WSH_PATH, 4, account_idx);
  CORE_BITCOIN_EXPORT(1, crypto_output_script_hash_wsh_m_c, BIP44_BTC_MULTISIG_P2WSH_P2SH_PATH, 4, account_idx);
  CORE_BITCOIN_EXPORT(2, crypto_output_script_hash_m_c, BIP44_BTC_MULTISIG_P2SH_PATH, 1, account_idx);

  account.crypto_account_output_descriptors_crypto_output_m_count = 3;
  account.crypto_account_master_fingerprint = g_core.master_fingerprint;
  cbor_encode_crypto_account(&g_mem_heap[keys_off], MEM_HEAP_SIZE, &account, &g_core.data.key.cbor_len);
  ui_display_ur_qr(NULL, &g_mem_heap[keys_off], g_core.data.key.cbor_len, CRYPTO_ACCOUNT);
}

// this macro can only be used in core_display_public_multicoin()
#define CORE_MULTICOIN_EXPORT(__NUM__, __PATH__, __ACCOUNT__, __SOURCE__) \
  if (get_hd_key(&accounts.crypto_multi_accounts_keys_tagged_hd_key_m[__NUM__], &g_mem_heap[keys_off], &g_mem_heap[keys_off + PUBKEY_LEN], __PATH__, (sizeof(__PATH__)/sizeof(uint32_t)), __ACCOUNT__, __SOURCE__) != ERR_OK) { \
    ui_card_transport_error(); \
    return; \
  } \
  keys_off += PUBKEY_LEN + CHAINCODE_LEN

void core_display_public_multicoin() {
  struct crypto_multi_accounts accounts;

  set_device_name(&accounts.crypto_multi_accounts_device.crypto_multi_accounts_device);
  accounts.crypto_multi_accounts_device_present = 1;

  uint8_t uid[CRYPTO_MULTIACCOUNT_SN_LEN/2];
  memset(uid, 0, sizeof(uid));
  hal_device_uid(uid);
  uint8_t sn[CRYPTO_MULTIACCOUNT_SN_LEN];
  base16_encode(uid, (char*) sn, (CRYPTO_MULTIACCOUNT_SN_LEN/2));

  accounts.crypto_multi_accounts_device_id.crypto_multi_accounts_device_id.len = CRYPTO_MULTIACCOUNT_SN_LEN;
  accounts.crypto_multi_accounts_device_id.crypto_multi_accounts_device_id.value = sn;
  accounts.crypto_multi_accounts_device_id_present = 1;

  accounts.crypto_multi_accounts_version_present = 0;

  size_t keys_off = 0;

  CORE_MULTICOIN_EXPORT(0, BIP44_BTC_LEGACY_PATH, 0, NULL);
  CORE_MULTICOIN_EXPORT(1, BIP44_BTC_NESTED_SEGWIT_PATH, 0, NULL);
  CORE_MULTICOIN_EXPORT(2, BIP44_BTC_NATIVE_SEGWIT_PATH, 0, NULL);
  CORE_MULTICOIN_EXPORT(3, BIP44_ETH_PATH, 0, EIP4527_STANDARD);

  accounts.crypto_multi_accounts_keys_tagged_hd_key_m_count = 4;
  accounts.crypto_multi_accounts_master_fingerprint = g_core.master_fingerprint;

  cbor_encode_crypto_multi_accounts(&g_mem_heap[keys_off], MEM_HEAP_SIZE, &accounts, &g_core.data.key.cbor_len);
  ui_display_ur_qr(NULL, &g_mem_heap[keys_off], g_core.data.key.cbor_len, CRYPTO_MULTI_ACCOUNTS);
}

static void core_addresses(const char* title, uint32_t purpose, uint32_t coin, core_addr_encoder_t encoder) {
  uint32_t index = 0;

  purpose = rev32(purpose);
  coin = rev32(coin);
  memcpy(g_core.bip44_path, &purpose, 4);
  memcpy(&g_core.bip44_path[4], &coin, 4);
  memset(&g_core.bip44_path[8], 0, 8);
  g_core.bip44_path[8] = 0x80;

  g_core.bip44_path_len = 20;

  do {
    uint32_t tmp = rev32(index);
    memcpy(&g_core.bip44_path[16], &tmp, 4);

    if (core_export_public(g_core.data.key.pub, NULL, NULL, NULL) != ERR_OK) {
      ui_card_transport_error();
    }

    encoder(g_core.data.key.pub, (char*) g_mem_heap);
    ui_display_address_qr(title, (char*) g_mem_heap, &index);
  } while(index != UINT32_MAX);
}

static void core_eth_addr_encoder(const uint8_t* key, char* addr) {
  addr[0] = '0';
  addr[1] = 'x';
  ethereum_address(key, g_core.address);
  ethereum_address_checksum(g_core.address, &addr[2]);
}

static void core_btc_addr_encoder(const uint8_t* key, char* addr) {
  hash160(key, PUBKEY_COMPRESSED_LEN, g_core.address);
  bitcoin_segwit_address(g_core.address, RIPEMD160_DIGEST_LENGTH, addr);
}

void core_addresses_ethereum() {
  core_addresses(LSTR(QR_ADDRESS_ETH_TITLE), ETH_PURPOSE, ETH_COIN, core_eth_addr_encoder);
}

void core_addresses_bitcoin() {
  core_addresses(LSTR(QR_ADDRESS_BTC_TITLE), BTC_NATIVE_SEGWIT_PURPOSE, BTC_MAINNET_COIN, core_btc_addr_encoder);
}

core_evt_t core_wait_event(uint32_t timeout, uint8_t accept_usb) {
  uint32_t events;

  BaseType_t res = pdFAIL;
  res = xTaskNotifyWaitIndexed(CORE_EVENT_IDX, 0, UINT32_MAX, &events, timeout);

  if (res != pdPASS) {
    return CORE_EVT_NONE;
  }

  if (events & CORE_USB_EVT) {
    if (accept_usb) {
      return CORE_EVT_USB_CMD;
    } else {
      core_usb_cancel();
    }
  }

  if (events & CORE_UI_EVT) {
    return g_ui_cmd.result == ERR_OK ? CORE_EVT_UI_OK : CORE_EVT_UI_CANCELLED;
  }

  return core_wait_event(timeout, accept_usb);
}


void core_connect_wallet() {
  if (!g_settings.skip_help && (ui_prompt(LSTR(CONNECT_HOWTO), LSTR(CONNECT_HOWTO_PROMPT), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK)) {
    return;
  }

  i18n_str_id_t selected = MENU_CONNECT_EIP4527;

  while (ui_menu(LSTR(MENU_CONNECT), &menu_connect, &selected, -1, 0, UI_MENU_NOCANCEL, 0, 0) == CORE_EVT_UI_OK) {
    uint32_t account = 0;

    if ((selected == MENU_CONNECT_LEDGER_LIVE) ||
        (selected == MENU_CONNECT_BITCOIN_ALT) ||
        (selected == MENU_CONNECT_BITCOIN_MULTISIG_ALT) ||
        (selected == MENU_CONNECT_BITCOIN_TESTNET)) {
      if (ui_read_number(LSTR(MENU_CONNECT_SELECT_ACCOUNT), 0, INT32_MAX, &account, false) != CORE_EVT_UI_OK) {
        continue;
      }
    }

    switch(selected) {
    case MENU_CONNECT_LEDGER_LIVE:
      core_display_public_eip4527(account, EIP4527_LEDGER_LIVE);
      break;
    case MENU_CONNECT_LEDGER_LEGACY:
      core_display_public_eip4527(account, EIP4527_LEDGER_LEGACY);
      break;
    case MENU_CONNECT_EIP4527:
      core_display_public_eip4527(account, EIP4527_STANDARD);
      break;
    case MENU_CONNECT_BITCOIN_ALT:
    case MENU_CONNECT_BITCOIN:
      core_display_public_bitcoin(BIP44_BTC_NATIVE_SEGWIT_PATH, BIP44_BTC_NESTED_SEGWIT_PATH, BIP44_BTC_LEGACY_PATH, account);
      break;
    case MENU_CONNECT_BITCOIN_MULTISIG_ALT:
    case MENU_CONNECT_BITCOIN_MULTISIG:
      core_display_public_bitcoin_multisig(account);
      break;
    case MENU_CONNECT_BITCOIN_TESTNET:
      core_display_public_bitcoin(BIP44_BTC_TESTNET_NATIVE_SEGWIT_PATH, BIP44_BTC_TESTNET_NESTED_SEGWIT_PATH, BIP44_BTC_TESTNET_LEGACY_PATH, account);
      break;
    case MENU_CONNECT_MULTICOIN:
      core_display_public_multicoin();
      break;
    default:
      break;
    }
  }
}
