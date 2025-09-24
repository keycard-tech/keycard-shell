#include "core.h"
#include "crypto/address.h"
#include "crypto/sha3.h"
#include "crypto/util.h"
#include "keycard/keycard_cmdset.h"
#include "mem.h"
#include "ur/ur_encode.h"

#define ETH_MSG_MAGIC_LEN 26
#define ETH_EIP712_MAGIC_LEN 2

const uint8_t *const ETH_MSG_MAGIC = (uint8_t *) "\031Ethereum Signed Message:\n";
const uint8_t ETH_EIP712_MAGIC[] = { 0x19, 0x01 };

static inline app_err_t core_eth_init_sign(uint32_t* fingerprint) {
  keccak_256_Init(&g_core.hash_ctx);

  if (core_export_public(g_core.data.key.pub, g_core.data.key.chain, fingerprint, NULL) != ERR_OK) {
    return ERR_HW;
  }

  ethereum_address(g_core.data.key.pub, g_core.address);

  return ERR_OK;
}

static inline uint32_t core_eth_get_tx_v_base() {
  uint32_t v_base;
  if (g_core.data.eth_tx.ctx.txType == EIP1559 || g_core.data.eth_tx.ctx.txType == EIP2930) {
    v_base = 0;
  } else {
    if (g_core.data.eth_tx.content.v == V_NONE) {
      v_base = 27;
    } else {
      v_base = (g_core.data.eth_tx.content.v * 2) + 35;
    }
  }

  return v_base;
}

static inline void core_eth_set_is_message() {
  g_core.data.eth_tx.ctx.txType = LEGACY;
  g_core.data.eth_tx.content.v = V_NONE;
}

static app_err_t core_eth_sign(keycard_t* kc, uint8_t* out) {
  uint8_t digest[SHA3_256_DIGEST_LENGTH];
  keccak_Final(&g_core.hash_ctx, digest);

  if ((keycard_cmd_sign(kc, g_core.bip44_path, g_core.bip44_path_len, digest) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
    return ERR_CRYPTO;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);

  if (keycard_read_signature(data, digest, out) != ERR_OK) {
    return ERR_DATA;
  }

  return ERR_OK;
}

static inline app_err_t core_eth_wait_tx_confirmation() {
  return ui_display_eth_tx(g_core.address, &g_core.data.eth_tx.content) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}

static inline app_err_t core_eth_wait_msg_confirmation(const uint8_t* msg, size_t msg_len) {
  return ui_display_msg(ADDR_ETH, g_core.address, msg, msg_len) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}

static app_err_t core_eth_process_tx(const uint8_t* data, uint32_t len, uint8_t first_segment) {
  if (first_segment) {
    // EIP 2718: TransactionType might be present before the TransactionPayload.
    uint8_t txType = data[0];

    initTx(&g_core.data.eth_tx.ctx, &g_core.hash_ctx, &g_core.data.eth_tx.content);

    if (txType >= MIN_TX_TYPE && txType <= MAX_TX_TYPE) {
      // Enumerate through all supported txTypes here...
      if (txType == EIP2930 || txType == EIP1559) {
        keccak_Update(&g_core.hash_ctx, data, 1);
        g_core.data.eth_tx.ctx.txType = txType;
        data++;
        len--;
      } else {
        return ERR_UNSUPPORTED;
      }
    } else {
      g_core.data.eth_tx.ctx.txType = LEGACY;
    }
  }

  if (g_core.data.eth_tx.ctx.currentField == RLP_NONE) {
    return ERR_DATA;
  }

  parserStatus_e res = processTx(&g_core.data.eth_tx.ctx, data, len);
  switch (res) {
    case USTREAM_FINISHED:
      return core_eth_wait_tx_confirmation();
    case USTREAM_PROCESSING:
      return ERR_NEED_MORE_DATA;
    case USTREAM_FAULT:
    default:
      return ERR_DATA;
  }
}

static app_err_t core_eth_process_msg(const uint8_t* data, uint32_t len, uint8_t first_segment) {
  if (first_segment) {
    core_eth_set_is_message();
    g_core.data.msg.received = 0;
    keccak_Update(&g_core.hash_ctx, ETH_MSG_MAGIC, ETH_MSG_MAGIC_LEN);
    uint8_t tmp[11];
    uint8_t* ascii_len = u32toa(g_core.data.msg.len, tmp, 11);
    keccak_Update(&g_core.hash_ctx, ascii_len, 10 - (size_t)(ascii_len - tmp));
  }

  if ((g_core.data.msg.received + len) > g_core.data.msg.len) {
    return ERR_DATA;
  }

  keccak_Update(&g_core.hash_ctx, data, len);
  g_core.data.msg.received += len;

  if (g_core.data.msg.received == g_core.data.msg.len) {
    return core_eth_wait_msg_confirmation(g_core.data.msg.content, g_core.data.msg.len);
  } else {
    return ERR_NEED_MORE_DATA;
  }
}

static app_err_t core_eth_process_eip712(const uint8_t* data, uint32_t len) {
  core_eth_set_is_message();

  uint8_t* heap = (uint8_t*) &data[len];
  size_t heap_size = MEM_HEAP_SIZE - ((size_t) (heap - g_mem_heap));
  app_err_t err;

  keccak_Update(&g_core.hash_ctx, ETH_EIP712_MAGIC, ETH_EIP712_MAGIC_LEN);
  memset(&g_core.data.eip712, 0, sizeof(eip712_ctx_t));
  err = eip712_hash(&g_core.data.eip712, &g_core.hash_ctx, heap, heap_size, (const char*) data, len);

  if (err != ERR_OK) {
    return err;
  }

  SHA3_CTX tmp;
  memcpy(&tmp, &g_core.hash_ctx, sizeof(SHA3_CTX));
  keccak_Final(&tmp, g_core.data.eip712.hash);
  return ui_display_eip712(g_core.address, &g_core.data.eip712) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}

static app_err_t core_eth_usb_init_sign(uint8_t* data) {
  g_core.bip44_path_len = data[0] * 4;

  if (g_core.bip44_path_len > BIP44_MAX_PATH_LEN) {
    g_core.bip44_path_len = 0;
    return ERR_DATA;
  }

  memcpy(g_core.bip44_path, &data[1], g_core.bip44_path_len);

  return core_eth_init_sign(NULL);
}

static void core_eth_usb_sign(keycard_t* kc, apdu_t* cmd) {
  uint8_t* out = APDU_RESP(cmd);

  switch (core_eth_sign(kc, &out[1])) {
  case ERR_OK:
    out[0] = core_eth_get_tx_v_base() + out[65];
    out[65] = 0x90;
    out[66] = 0x00;
    cmd->lr = 67;
    break;
  case ERR_CRYPTO:
    core_usb_err_sw(cmd, 0x69, 0x82);
    break;
  default:
    core_usb_err_sw(cmd, 0x6f, 0x00);
    break;
  }
}

app_err_t core_eth_usb_sign_tx(keycard_t* kc, apdu_t* cmd) {
  cmd->has_lc = 1;
  uint8_t* data = APDU_DATA(cmd);
  uint32_t len = APDU_LC(cmd);
  uint8_t first = APDU_P1(cmd) == 0;

  if (first) {
    if (core_eth_usb_init_sign(data) != ERR_OK) {
      core_usb_err_sw(cmd, 0x6a, 0x80);
      return ERR_DATA;
    }

    data = &data[1+g_core.bip44_path_len];
    len -= g_core.bip44_path_len + 1;

    if (len < 1) {
      core_usb_err_sw(cmd, 0x6a, 0x80);
      return ERR_DATA;
    }

    g_core.data.eth_tx.content.data = g_mem_heap;
    g_core.data.eth_tx.content.chainID = 1;
  }

  app_err_t err = core_eth_process_tx(data, len, first);

  switch(err) {
  case ERR_OK:
    core_eth_usb_sign(kc, cmd);
    break;
  case ERR_NEED_MORE_DATA:
    core_usb_err_sw(cmd, 0x90, 0x00);
    break;
  case ERR_DATA:
    core_usb_err_sw(cmd, 0x6a, 0x80);
    break;
  case ERR_CANCEL:
    core_usb_err_sw(cmd, 0x69, 0x82);
    break;
  case ERR_UNSUPPORTED:
    core_usb_err_sw(cmd, 0x65, 0x01);
    break;
  default:
    core_usb_err_sw(cmd, 0x6f, 0x00);
    break;
  }

  return err;
}

static app_err_t core_eth_usb_message_reassemble(keycard_t* kc, apdu_t* cmd, uint8_t** segment, uint32_t* len, uint8_t* first_segment) {
  cmd->has_lc = 1;
  uint8_t* data = APDU_DATA(cmd);
  *len = APDU_LC(cmd);
  *first_segment = APDU_P1(cmd) == 0;
  if (*first_segment) {
    if (core_eth_usb_init_sign(data) != ERR_OK) {
      return ERR_DATA;
    }

    g_core.data.msg.len = (data[1+g_core.bip44_path_len] << 24) | (data[2+g_core.bip44_path_len] << 16) | (data[3+g_core.bip44_path_len] << 8) | data[4+g_core.bip44_path_len];

    if (g_core.data.msg.len > MEM_HEAP_SIZE) {
      return ERR_DATA;
    }

    g_core.data.msg.received = 0;
    *len -= g_core.bip44_path_len + 5;
    data = &data[g_core.bip44_path_len + 5];
  }

  if ((g_core.data.msg.received + *len) > MEM_HEAP_SIZE) {
    return ERR_DATA;
  }

  g_core.data.msg.content = g_mem_heap;
  *segment = &g_core.data.msg.content[g_core.data.msg.received];
  memcpy(*segment, data, *len);
  return ERR_OK;
}

app_err_t core_eth_usb_sign_message(keycard_t* kc, apdu_t* cmd) {
  uint8_t* segment;
  uint32_t len;
  uint8_t first_segment;
  app_err_t err = core_eth_usb_message_reassemble(kc, cmd, &segment, &len, &first_segment);

  if (err == ERR_OK) {
    err = core_eth_process_msg(segment, len, first_segment);
  }

  switch(err) {
    case ERR_OK:
      core_eth_usb_sign(kc, cmd);
      break;
    case ERR_NEED_MORE_DATA:
      core_usb_err_sw(cmd, 0x90, 0x00);
      break;
    case ERR_DATA:
      core_usb_err_sw(cmd, 0x6a, 0x80);
      break;
    case ERR_CANCEL:
      core_usb_err_sw(cmd, 0x69, 0x82);
      break;
    default:
      core_usb_err_sw(cmd, 0x6f, 0x00);
      break;
  }

  return err;
}

app_err_t core_eth_usb_sign_eip712(keycard_t* kc, apdu_t* cmd) {
  uint8_t* segment;
  uint32_t len;
  uint8_t first_segment;
  app_err_t err = core_eth_usb_message_reassemble(kc, cmd, &segment, &len, &first_segment);

  if ((err != ERR_OK) || ((g_core.data.msg.received + len) > g_core.data.msg.len)) {
    core_usb_err_sw(cmd, 0x6a, 0x80);
    return ERR_DATA;
  }

  g_core.data.msg.received += len;

  core_eth_set_is_message();

  if (g_core.data.msg.received == g_core.data.msg.len) {
    if (core_eth_process_eip712(g_core.data.msg.content, g_core.data.msg.len) == ERR_OK) {
      core_eth_usb_sign(kc, cmd);
      return ERR_OK;
    } else {
      core_usb_err_sw(cmd, 0x69, 0x82);
      return ERR_CANCEL;
    }
  } else {
    core_usb_err_sw(cmd, 0x90, 0x00);
    return ERR_NEED_MORE_DATA;
  }

}

static app_err_t core_eth_eip4527_init_sign(struct eth_sign_request *qr_request) {
  app_err_t err = core_set_derivation_path(&qr_request->eth_sign_request_derivation_path);

  if (err != ERR_OK) {
    return err;
  }

  uint32_t fingerprint;
  err = core_eth_init_sign(&fingerprint);

  if (err != ERR_OK) {
    return err;
  }

  if (!(qr_request->eth_sign_request_derivation_path.crypto_keypath_source_fingerprint_present &&
      (qr_request->eth_sign_request_derivation_path.crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint == fingerprint))) {
    return ERR_MISMATCH;
  }

  ethereum_address(g_core.data.key.pub, g_core.address);

  return ERR_OK;
}

void core_eth_eip4527_run(struct eth_sign_request* qr_request) {
  if (core_eth_eip4527_init_sign(qr_request) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_WRONG_CARD_MSG), LSTR(INFO_WRONG_CARD_SUB), 0);
    return;
  }

  app_err_t err;

  switch(qr_request->eth_sign_request_data_type.sign_data_type_choice) {
    case sign_data_type_eth_transaction_data_m_c:
    case sign_data_type_eth_typed_transaction_m_c:
      g_core.data.eth_tx.content.data = NULL;
      g_core.data.eth_tx.content.chainID = qr_request->eth_sign_request_chain_id_present ? (uint32_t) qr_request->eth_sign_request_chain_id.eth_sign_request_chain_id : 1;
      err = core_eth_process_tx(qr_request->eth_sign_request_sign_data.value, qr_request->eth_sign_request_sign_data.len, 1);
      break;
    case sign_data_type_eth_raw_bytes_m_c:
      g_core.data.msg.content = (uint8_t*) qr_request->eth_sign_request_sign_data.value;
      g_core.data.msg.len = qr_request->eth_sign_request_sign_data.len;
      err = core_eth_process_msg(qr_request->eth_sign_request_sign_data.value, qr_request->eth_sign_request_sign_data.len, 1);
      break;
    case sign_data_type_eth_typed_data_m_c:
      err = core_eth_process_eip712(qr_request->eth_sign_request_sign_data.value, qr_request->eth_sign_request_sign_data.len);
      break;
    default:
      err = ERR_UNSUPPORTED;
      break;
  }

  switch(err) {
  case ERR_OK:
    break;
  case ERR_CANCEL:
    return;
  default:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return;
  }

  uint32_t v = core_eth_get_tx_v_base();

  if (core_eth_sign(&g_core.keycard, g_core.data.sig.plain_sig) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  struct eth_signature sig = {0};
  sig.eth_signature_request_id_present = qr_request->eth_sign_request_request_id_present;
  if (sig.eth_signature_request_id_present) {
    sig.eth_signature_request_id.eth_signature_request_id.value = qr_request->eth_sign_request_request_id.eth_sign_request_request_id.value;
    sig.eth_signature_request_id.eth_signature_request_id.len = qr_request->eth_sign_request_request_id.eth_sign_request_request_id.len;
  }
  sig.eth_signature_signature.value = g_core.data.sig.plain_sig;
  sig.eth_signature_signature.len = SIGNATURE_LEN;

  v += g_core.data.sig.plain_sig[SIGNATURE_LEN];

  if (v <= 0xff) {
    g_core.data.sig.plain_sig[SIGNATURE_LEN] = v;
    sig.eth_signature_signature.len += 1;
  } else if (v <= 0xffff) {
    g_core.data.sig.plain_sig[SIGNATURE_LEN] = (v >> 8) & 0xff;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 1] = v & 0xff;
    sig.eth_signature_signature.len += 2;
  } else if (v <= 0xffffff) {
    g_core.data.sig.plain_sig[SIGNATURE_LEN] = (v >> 16) & 0xff;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 1] = (v >> 8) & 0xff;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 2] = v & 0xff;
    sig.eth_signature_signature.len += 3;
  } else if (v <= 0xffffffff) {
    g_core.data.sig.plain_sig[SIGNATURE_LEN] = v >> 24;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 1] = (v >> 16) & 0xff;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 2] = (v >> 8) & 0xff;
    g_core.data.sig.plain_sig[SIGNATURE_LEN + 3] = v & 0xff;
    sig.eth_signature_signature.len += 4;
  }

  cbor_encode_eth_signature(g_core.data.sig.cbor_sig, CBOR_SIG_MAX_LEN, &sig, &g_core.data.sig.cbor_len);
  ui_display_ur_qr(LSTR(QR_SCAN_WALLET_TITLE), g_core.data.sig.cbor_sig, g_core.data.sig.cbor_len, ETH_SIGNATURE);
}
