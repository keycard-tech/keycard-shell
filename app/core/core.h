#ifndef _CORE_H_
#define _CORE_H_

#include "FreeRTOS.h"
#include "task.h"

#include "app_tasks.h"
#include "crypto/sha3.h"
#include "ethereum/ethUstream.h"
#include "ethereum/eip712.h"
#include "ethereum/ethUtils.h"
#include "keycard/keycard.h"
#include "iso7816/smartcard.h"
#include "ui/ui.h"
#include "ur/ur_types.h"

#define BIP44_MAX_PATH_LEN 40

#define SIGNATURE_LEN 64
#define PUBKEY_LEN 65
#define PUBKEY_COMPRESSED_LEN 33
#define CHAINCODE_LEN 32
#define CBOR_SIG_MAX_LEN 192
#define CBOR_KEY_MAX_LEN 192

typedef struct {
  txContext_t ctx;
  txContent_t content;
} core_eth_tx_t;

typedef struct {
  uint32_t received;
  uint32_t len;
  uint8_t* content;
} core_msg_t;

typedef struct {
  uint8_t plain_sig[SIGNATURE_LEN + 4];
  uint8_t cbor_sig[CBOR_SIG_MAX_LEN];
  size_t cbor_len;
} core_sig_t;

typedef struct {
  uint8_t pub[PUBKEY_LEN];
  uint8_t chain[CHAINCODE_LEN];
  uint8_t cbor_key[CBOR_KEY_MAX_LEN];
  size_t cbor_len;
} core_key_t;

typedef union {
  core_eth_tx_t eth_tx;
  core_msg_t msg;
  eip712_ctx_t eip712;
  core_sig_t sig;
  core_key_t key;
} core_data_t;

typedef struct {
  bool ready;
  keycard_t keycard;
  command_t usb_command;
  uint32_t master_fingerprint;

  uint8_t address[ADDRESS_LENGTH];
  uint8_t bip44_path[BIP44_MAX_PATH_LEN];
  uint8_t bip44_path_len;
  SHA3_CTX hash_ctx;
  core_data_t data;
} core_ctx_t;

extern core_ctx_t g_core;
extern const char *const EIP4527_NAME;

app_err_t core_export_key(keycard_t* kc, uint8_t* path, uint16_t len, uint8_t* out_pub, uint8_t* out_chain);
app_err_t core_get_fingerprint(uint8_t* path, size_t len, uint32_t* fingerprint);
app_err_t core_export_public(uint8_t* pub, uint8_t* chain, uint32_t* fingerprint, uint32_t* parent_fingerprint);
app_err_t core_set_derivation_path(struct crypto_keypath* derivation_path);

core_evt_t core_wait_event(uint32_t timeout, uint8_t accept_usb);

void core_usb_run();
app_err_t core_usb_get_response(command_t* cmd);
app_err_t core_eth_usb_get_address(keycard_t* kc, apdu_t* cmd);
app_err_t core_eth_usb_sign_tx(keycard_t* kc, apdu_t* cmd);
app_err_t core_eth_usb_sign_message(keycard_t* kc, apdu_t* cmd);
app_err_t core_eth_usb_sign_eip712(keycard_t* kc, apdu_t* cmd);
app_err_t core_btc_usb_sign_psbt(keycard_t* kc, command_t* cmd);

void core_eth_eip4527_run(struct eth_sign_request* qr_request);
void core_btc_psbt_qr_run(struct zcbor_string* qr_request);
void core_btc_sign_msg_qr_run(struct btc_sign_request* qr_request);

void core_qr_run();
void core_display_public_eip4527();
void core_display_public_bitcoin_mainnet();
void core_display_public_bitcoin_testnet();
void core_display_public_bitcoin_multisig();
void core_display_public_multicoin();
void core_addresses_ethereum();
void core_addresses_bitcoin();
void updater_database_run();
void device_auth_run();
void device_info();
void device_help();

app_err_t updater_usb_fw_upgrade(command_t* cmd, apdu_t* apdu);
app_err_t updater_usb_db_upgrade(apdu_t* apdu);

static inline const char* core_get_device_name() {
  return g_core.keycard.name[0] ? g_core.keycard.name : EIP4527_NAME;
}

static inline void core_usb_err_sw(apdu_t* cmd, uint8_t sw1, uint8_t sw2) {
  uint8_t* data = APDU_RESP(cmd);
  data[0] = sw1;
  data[1] = sw2;
  cmd->lr = 2;
}

#endif
