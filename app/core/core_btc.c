#include "common.h"
#include "core.h"
#include "mem.h"
#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/compactsize.h"
#include "bitcoin/psbt_ctx.h"
#include "bitcoin/sighash.h"
#include "bitcoin/taproot.h"
#include "crypto/script.h"
#include "crypto/sha2_soft.h"
#include "crypto/util.h"
#include "keycard/keycard_cmdset.h"
#include "core/core_btc_sig.h"
#include "ur/ur_encode.h"
#include "util/tlv.h"

#define BTC_MSG_MAGIC_LEN 25
#define BTC_MSG_SIG_LEN 65

#define BTC_MESSAGE_SIG_HEADER (27 + 4)

const uint8_t *const BTC_MSG_MAGIC = (uint8_t *) "\030Bitcoin Signed Message:\n";

static app_err_t core_btc_set_path(uint8_t* btc_bip32_path, uint32_t btc_bip32_path_len) {
  if ((btc_bip32_path_len > BIP44_MAX_PATH_LEN) || ((btc_bip32_path_len % 4) != 0)) {
    return ERR_DATA;
  }

  for (int i = 0; i < btc_bip32_path_len; i += 4) {
    g_core.bip44_path[i + 3] = btc_bip32_path[i];
    g_core.bip44_path[i + 2] = btc_bip32_path[i + 1];
    g_core.bip44_path[i + 1] = btc_bip32_path[i + 2];
    g_core.bip44_path[i] = btc_bip32_path[i + 3];
  }

  g_core.bip44_path_len = btc_bip32_path_len;
  return ERR_OK;
}

static app_err_t core_btc_sign_input(btc_tx_ctx_t* tx_ctx, size_t index) {
  if (!tx_ctx->input_data[index].can_sign) {
    return ERR_OK;
  }

  app_err_t err;
  uint8_t digest[SHA256_DIGEST_LENGTH];

  switch(tx_ctx->input_data[index].input_type) {
  case BTC_INPUT_TYPE_LEGACY:
  case BTC_INPUT_TYPE_LEGACY_WITH_REDEEM:
    err = btc_sighash_legacy(tx_ctx, index, digest);
    break;
  case BTC_INPUT_TYPE_P2WPKH:
  case BTC_INPUT_TYPE_P2WSH:
    err = btc_sighash_segwit(tx_ctx, index, digest);
    break;
  case BTC_INPUT_TYPE_P2TR:
    err = btc_sighash_taproot(tx_ctx, index, digest);
    break;
  default:
    err = ERR_DATA;
    break;
  }

  if (err != ERR_OK) {
    return err == ERR_UNSUPPORTED ? ERR_OK : err;
  }

  keycard_t *kc = &g_core.keycard;

  if (core_btc_set_path(tx_ctx->input_data[index].bip32_path, tx_ctx->input_data[index].bip32_path_len) != ERR_OK) {
    return ERR_DATA;
  }

  psbt_record_t signature;
  uint8_t sig_val[DER_ECDSA_MAX_SIGNATURE_LEN + 1];

  if (tx_ctx->input_data[index].input_type == BTC_INPUT_TYPE_P2TR) {
    if (!tx_ctx->input_data[index].has_taproot_internal_key) {
      return ERR_DATA;
    }

    uint8_t tag_hash[SHA256_DIGEST_LENGTH];
    sha256_Raw((uint8_t*) "TapTweak", 8, tag_hash);

    SHA256_CTX sha256;
    sha256_Init(&sha256);
    sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
    sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
    sha256_Update(&sha256, tx_ctx->input_data[index].taproot_internal_key, BTC_TAPROOT_WITPROG_LEN);
    if (tx_ctx->input_data[index].has_taproot_merkle_root) {
      sha256_Update(&sha256, tx_ctx->input_data[index].taproot_merkle_root, SHA256_DIGEST_LENGTH);
    }

    uint8_t hash_tweak[2 * SHA256_DIGEST_LENGTH];
    memcpy(hash_tweak, digest, SHA256_DIGEST_LENGTH);
    sha256_Final(&sha256, &hash_tweak[SHA256_DIGEST_LENGTH]);

    if ((keycard_cmd_sign(kc, KEYCARD_SIGN_BIP340_SCHNORR, g_core.bip44_path, g_core.bip44_path_len, hash_tweak) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
      return ERR_CRYPTO;
    }

    uint8_t* data = APDU_RESP(&kc->apdu);
    if (core_btc_read_schnorr_signature(data, APDU_RESP_LEN(&kc->apdu), &signature) != ERR_OK) {
      return ERR_DATA;
    }
  } else {
    if ((keycard_cmd_sign(kc, KEYCARD_SIGN_ECDSA_SECP256K1, g_core.bip44_path, g_core.bip44_path_len, digest) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
      return ERR_CRYPTO;
    }

    uint8_t* data = APDU_RESP(&kc->apdu);
    if (core_btc_read_signature(data, APDU_RESP_LEN(&kc->apdu), tx_ctx->input_data[index].sighash_flag, sig_val, &signature) != ERR_OK) {
      return ERR_DATA;
    }
  }

  psbt_write_input_record(&tx_ctx->psbt_out, &signature);

  return ERR_OK;
}

static void core_btc_sign_handler(psbt_elem_t* rec) {
  btc_tx_ctx_t* tx_ctx = (btc_tx_ctx_t*) rec->user_data;

  if ((rec->type == PSBT_ELEM_TXELEM) || tx_ctx->error != ERR_OK) {
    return;
  }

  switch(rec->elem.rec->scope) {
  case PSBT_SCOPE_GLOBAL:
    psbt_write_global_record(&tx_ctx->psbt_out, rec->elem.rec);
    break;
  case PSBT_SCOPE_INPUTS:
    if (tx_ctx->index_in < rec->index) {
      psbt_new_input_record_set(&tx_ctx->psbt_out);
      tx_ctx->index_in++;
      tx_ctx->error = core_btc_sign_input(tx_ctx, tx_ctx->index_in);
    }

    psbt_write_input_record(&tx_ctx->psbt_out, rec->elem.rec);
    break;
  case PSBT_SCOPE_OUTPUTS:
    while (tx_ctx->index_out < rec->index) {
      psbt_new_output_record_set(&tx_ctx->psbt_out);
      tx_ctx->index_out++;
    }

    psbt_write_output_record(&tx_ctx->psbt_out, rec->elem.rec);
    break;
  }
}

static bool core_btc_pubkey_matches_output(const uint8_t* pubkey, const psbt_txout_t* out) {
  uint8_t off;

  if (script_is_p2pkh(out->script, out->script_len)) {
    off = 3;
  } else if (script_is_p2wpkh(out->script, out->script_len)) {
    off = 2;
  } else {
    off = 0;
  }

  if (script_is_p2tr(out->script, out->script_len)) {
    uint8_t output_key[BTC_TAPROOT_WITPROG_LEN];

    if (!bitcoin_taproot_output_key(pubkey, output_key)) {
      return false;
    }

    return memcmp(output_key, &out->script[2], BTC_TAPROOT_WITPROG_LEN) == 0;
  }

  uint8_t tmp[RIPEMD160_DIGEST_LENGTH];
  hash160(pubkey, PUBKEY_COMPRESSED_LEN, tmp);

  return memcmp(tmp, &out->script[off], RIPEMD160_DIGEST_LENGTH) == 0;
}

static app_err_t core_btc_validate(btc_tx_ctx_t* tx_ctx) {
  if (btc_psbt_validate_inputs(tx_ctx) != ERR_OK) {
    return ERR_DATA;
  }

  for (int i = 0; i < tx_ctx->output_count; i++) {
    if (tx_ctx->output_data[i].master_fingerprint == tx_ctx->mfp) {
      uint8_t pub[PUBKEY_LEN];
      if (core_btc_set_path(tx_ctx->output_data[i].bip32_path, tx_ctx->output_data[i].bip32_path_len) != ERR_OK) {
        return ERR_DATA;
      }

      if (core_export_public(pub, NULL, NULL, NULL) != ERR_OK) {
        return ERR_HW;
      }

      tx_ctx->output_data[i].change = core_btc_pubkey_matches_output(pub, &tx_ctx->outputs[i]);
    }
  }

  return btc_psbt_any_can_sign(tx_ctx) ? ERR_OK : ERR_MISMATCH;
}

static inline app_err_t core_btc_confirm(btc_tx_ctx_t* tx_ctx) {
  return ui_display_btc_tx(tx_ctx) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}

static app_err_t core_btc_psbt_run(const uint8_t* psbt_in, size_t psbt_len, uint8_t** psbt_out, size_t* out_len) {
  btc_tx_ctx_t* tx_ctx = (btc_tx_ctx_t*) g_camera_fb[1];
  memset(tx_ctx, 0, sizeof(btc_tx_ctx_t));
  *psbt_out = &g_camera_fb[1][(sizeof(btc_tx_ctx_t) + 3) & ~0x3];
  size_t psbt_out_len = CAMERA_FB_SIZE - ((sizeof(btc_tx_ctx_t) + 3) & ~0x3);

  uint32_t mfp;

  if (core_get_fingerprint(g_core.bip44_path, 0, &mfp) != ERR_OK) {
    return ERR_CRYPTO;
  }

  tx_ctx->mfp = rev32(mfp);

  psbt_t psbt;
  psbt_init(&psbt, (uint8_t*) psbt_in, psbt_len);
  psbt_read(psbt_in, psbt_len, &psbt, btc_psbt_element, tx_ctx);

  if (tx_ctx->error != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return tx_ctx->error;
  }

  tx_ctx->error = core_btc_validate(tx_ctx);

  switch(tx_ctx->error) {
  case ERR_OK:
    break;
  case ERR_MISMATCH:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_CANNOT_SIGN), LSTR(INFO_CANNOT_SIGN_SUB), 0);
    return ERR_MISMATCH;
  case ERR_DATA:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return ERR_DATA;
  default:
    ui_card_transport_error();
    return ERR_CRYPTO;
  }

  if (core_btc_confirm(tx_ctx) != ERR_OK) {
    return ERR_CANCEL;
  }

  btc_sighash_common_hashes(tx_ctx);

  psbt_init(&psbt, (uint8_t*) psbt_in, psbt_len);
  psbt_init(&tx_ctx->psbt_out, *psbt_out, psbt_out_len);

  tx_ctx->index_in = -1;
  tx_ctx->index_out = -1;

  if (psbt_read(psbt_in, psbt_len, &psbt, core_btc_sign_handler, tx_ctx) != PSBT_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return ERR_DATA;
  }

  switch(tx_ctx->error) {
  case ERR_OK:
    break;
  case ERR_DATA:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return ERR_DATA;
  default:
    ui_card_transport_error();
    return ERR_CRYPTO;
  }

  while(++tx_ctx->index_out < tx_ctx->output_count) {
    psbt_new_output_record_set(&tx_ctx->psbt_out);
  }

  psbt_finalize(&tx_ctx->psbt_out);
  *out_len = psbt_size(&tx_ctx->psbt_out);

  return ERR_OK;
}

void core_btc_psbt_qr_run(struct zcbor_string* qr_request) {
  uint8_t* psbt_out;
  size_t out_len;

  if (core_btc_psbt_run(qr_request->value, qr_request->len, &psbt_out, &out_len) != ERR_OK) {
    return;
  }

  struct zcbor_string qr_out;
  qr_out.value = psbt_out;
  qr_out.len = out_len;

  cbor_encode_psbt(g_mem_heap, MEM_HEAP_SIZE, &qr_out, &out_len);
  ui_display_ur_qr(NULL, g_mem_heap, out_len, CRYPTO_PSBT);
}

app_err_t core_btc_sign_msg_run(const uint8_t* msg, size_t msg_len, uint32_t expected_mfp, uint8_t* out, uint8_t* pubkey) {
  uint32_t mfp;
  app_err_t err = core_export_public(pubkey, NULL, &mfp, NULL);

  if (err != ERR_OK) {
    ui_card_transport_error();
    return err;
  }

  if (mfp != expected_mfp) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_WRONG_CARD_MSG), LSTR(INFO_WRONG_CARD_SUB), 0);
    return ERR_MISMATCH;
  }

  hash160(pubkey, PUBKEY_COMPRESSED_LEN, g_core.address);

  if (ui_display_msg(ADDR_BTC_SEGWIT, g_core.address, msg, msg_len) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  SHA256_CTX sha256;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Init(&sha256);
  sha256_Update(&sha256, BTC_MSG_MAGIC, BTC_MSG_MAGIC_LEN);
  compactsize_write(digest, msg_len);
  sha256_Update(&sha256, digest, compactsize_length(msg_len));
  sha256_Update(&sha256, msg, msg_len);
  sha256_Final(&sha256, digest);
  sha256_Raw(digest, SHA256_DIGEST_LENGTH, digest);

  keycard_t *kc = &g_core.keycard;

  if ((keycard_cmd_sign(kc, KEYCARD_SIGN_ECDSA_SECP256K1, g_core.bip44_path, g_core.bip44_path_len, digest) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
    ui_card_transport_error();
    return ERR_CRYPTO;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);

  if (keycard_read_signature(data, APDU_RESP_LEN(&kc->apdu), digest, &out[1]) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return ERR_DATA;
  }

  out[0] = BTC_MESSAGE_SIG_HEADER + out[65];

  return ERR_OK;
}

void core_btc_sign_msg_qr_run(struct btc_sign_request* qr_request) {
  if (!qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m_present ||
      !qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m.crypto_keypath_source_fingerprint_present ||
      (core_set_derivation_path(&qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m) != ERR_OK)) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return;
  }

  uint8_t pubkey[PUBKEY_LEN];

  if (core_btc_sign_msg_run(qr_request->btc_sign_request_sign_data.value, qr_request->btc_sign_request_sign_data.len, qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m.crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint, g_core.data.sig.plain_sig, pubkey) != ERR_OK) {
    return;
  }

  struct btc_signature cbor_sig;
  cbor_sig.btc_signature_request_id.value = qr_request->btc_sign_request_request_id.value;
  cbor_sig.btc_signature_request_id.len = qr_request->btc_sign_request_request_id.len;
  cbor_sig.btc_signature_signature.value = g_core.data.sig.plain_sig;
  cbor_sig.btc_signature_signature.len = BTC_MSG_SIG_LEN;
  cbor_sig.btc_signature_public_key.value = pubkey;
  cbor_sig.btc_signature_public_key.len = PUBKEY_COMPRESSED_LEN;

  cbor_encode_btc_signature(g_core.data.sig.cbor_sig, CBOR_SIG_MAX_LEN, &cbor_sig, &g_core.data.sig.cbor_len);
  ui_display_ur_qr(NULL, g_core.data.sig.cbor_sig, g_core.data.sig.cbor_len, BTC_SIGNATURE);
}

app_err_t core_btc_usb_sign_psbt(keycard_t* kc, command_t* cmd) {
  apdu_t* apdu = &cmd->apdu;
  apdu->has_lc = 1;
  uint8_t* data = APDU_DATA(apdu);
  size_t len = APDU_LC(apdu);
  uint8_t first_segment = APDU_P1(apdu) == 0;

  if (first_segment) {
    if (len < 4) {
      core_usb_err_sw(apdu, 0x6a, 0x80);
      return ERR_DATA;
    }

    g_core.data.msg.len = ((uint32_t) data[0] << 24) | ((uint32_t) data[1] << 16) | ((uint32_t) data[2] << 8) | data[3];
    g_core.data.msg.received = 0;
    data += 4;
    len -= 4;
  }

  if ((g_core.data.msg.received + len) > MEM_HEAP_SIZE) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  }

  memcpy(&g_mem_heap[g_core.data.msg.received], data, len);

  g_core.data.msg.received += len;

  if (g_core.data.msg.received > g_core.data.msg.len) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  } else if (g_core.data.msg.received == g_core.data.msg.len) {
    uint8_t* psbt_out;
    size_t out_len;

    if (core_btc_psbt_run(g_mem_heap, g_core.data.msg.len, &psbt_out, &out_len) != ERR_OK) {
      core_usb_err_sw(apdu, 0x6a, 0x80);
      return ERR_DATA;
    } else {
      cmd->extra_len = out_len;
      cmd->extra_data = psbt_out;
      return core_usb_get_response(cmd);
    }
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
  return ERR_NEED_MORE_DATA;
}
