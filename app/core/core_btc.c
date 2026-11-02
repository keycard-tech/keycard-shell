#include "common.h"
#include "core.h"
#include "mem.h"
#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/compactsize.h"
#include "bitcoin/psbt_ctx.h"
#include "crypto/script.h"
#include "crypto/sha2_soft.h"
#include "crypto/util.h"
#include "keycard/keycard_cmdset.h"
#include "ur/ur_encode.h"
#include "util/tlv.h"

#define BTC_TXID_LEN 32
#define BTC_MSG_MAGIC_LEN 25
#define BTC_MSG_SIG_LEN 65

#define BTC_MESSAGE_SIG_HEADER (27 + 4)

static const uint8_t P2PKH_SCRIPT_PRE[4] = { 0x19, 0x76, 0xa9, 0x14 };
static const uint8_t P2PKH_SCRIPT_POST[2] = { 0x88, 0xac };

const uint8_t *const BTC_MSG_MAGIC = (uint8_t *) "\030Bitcoin Signed Message:\n";

static app_err_t core_btc_hash_legacy(btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & SIGHASH_MASK;
  uint8_t anyonecanpay = tx_ctx->input_data[index].sighash_flag & SIGHASH_ANYONECANPAY;

  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  uint8_t* script;
  size_t script_len;

  if (tx_ctx->input_data[index].input_type == BTC_INPUT_TYPE_LEGACY_WITH_REDEEM) {
    script = tx_ctx->input_data[index].redeem_script;
    script_len = tx_ctx->input_data[index].redeem_script_len;
  } else {
    script = tx_ctx->input_data[index].script_pubkey;
    script_len = tx_ctx->input_data[index].script_pubkey_len;
  }

  uint8_t cscript_len[sizeof(uint64_t)];
  uint8_t csize_len = compactsize_length(script_len);
  compactsize_write(cscript_len, script_len);

  if (anyonecanpay) {
    uint8_t tmp = 1;
    sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
    sha256_Update(&sha256, tx_ctx->inputs[index].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));
    sha256_Update(&sha256, cscript_len, csize_len);
    sha256_Update(&sha256, script, script_len);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));
  } else{
    for (int i = 0; i < tx_ctx->input_count; i++) {
      sha256_Update(&sha256, (uint8_t*) &tx_ctx->input_count, sizeof(uint8_t));
      sha256_Update(&sha256, tx_ctx->inputs[i].txid, BTC_TXID_LEN);
      sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].index, sizeof(uint32_t));

      if (i == index) {
        sha256_Update(&sha256, cscript_len, csize_len);
        sha256_Update(&sha256, script, script_len);
      } else {
        uint8_t tmp = 0;
        sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
      }

      if ((sighash == SIGHASH_ALL) || (i == index)) {
        sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].sequence_number, sizeof(uint32_t));
      } else {
        uint32_t tmp = 0;
        sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint32_t));
      }
    }
  }

  if (sighash == SIGHASH_NONE) {
    uint8_t tmp = 0;
    sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
  } else {
    uint8_t out_count = sighash == SIGHASH_SINGLE ? (index + 1) : tx_ctx->output_count;
    sha256_Update(&sha256, (uint8_t*) &out_count, sizeof(uint8_t));
    for (int i = 0; i < out_count; i++) {
      if ((sighash == SIGHASH_ALL) || (i == index)) {
        size_t len = ((uint32_t) tx_ctx->outputs[i].script - (uint32_t) tx_ctx->outputs[i].amount) + tx_ctx->outputs[i].script_len;
        sha256_Update(&sha256, tx_ctx->outputs[i].amount, len);
      } else {
        int64_t amount = -1;
        uint8_t tmp = 0;
        sha256_Update(&sha256, (uint8_t*) &amount, sizeof(uint64_t));
        sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
      }
    }
  }

  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->input_data[index].sighash_flag, sizeof(uint32_t));

  sha256_Final(&sha256, digest);
  sha256_Raw(digest, SHA256_DIGEST_LENGTH, digest);

  return ERR_OK;
}

static app_err_t core_btc_hash_segwit(btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  uint8_t hprev[SHA256_DIGEST_LENGTH];
  uint8_t hseq[SHA256_DIGEST_LENGTH];
  uint8_t hout[SHA256_DIGEST_LENGTH];
  sha256_Raw(tx_ctx->hash_prevouts, SHA256_DIGEST_LENGTH, hprev);
  sha256_Raw(tx_ctx->hash_sequence, SHA256_DIGEST_LENGTH, hseq);
  sha256_Raw(tx_ctx->hash_outputs, SHA256_DIGEST_LENGTH, hout);

  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & SIGHASH_MASK;
  uint8_t anyonecanpay = tx_ctx->input_data[index].sighash_flag & SIGHASH_ANYONECANPAY;

  SHA256_CTX sha256;
  sha256_Init(&sha256);
  
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  if (anyonecanpay) {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, hprev, SHA256_DIGEST_LENGTH);
  }

  if (anyonecanpay || (sighash != SIGHASH_ALL)) {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, hseq, SHA256_DIGEST_LENGTH);
  }

  sha256_Update(&sha256, tx_ctx->inputs[index].txid, BTC_TXID_LEN);
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));

  if (tx_ctx->input_data[index].input_type == BTC_INPUT_TYPE_P2WPKH) {
    sha256_Update(&sha256, P2PKH_SCRIPT_PRE, sizeof(P2PKH_SCRIPT_PRE));
    if (tx_ctx->input_data[index].redeem_script) {
      sha256_Update(&sha256, &tx_ctx->input_data[index].redeem_script[2], BTC_PUBKEY_HASH_LEN);
    } else {
      sha256_Update(&sha256, &tx_ctx->input_data[index].script_pubkey[2], BTC_PUBKEY_HASH_LEN);
    }
    sha256_Update(&sha256, P2PKH_SCRIPT_POST, sizeof(P2PKH_SCRIPT_POST));
  } else {
    uint8_t csize[sizeof(uint64_t)];
    compactsize_write(csize, tx_ctx->input_data[index].witness_script_len);
    sha256_Update(&sha256, csize, compactsize_length(tx_ctx->input_data[index].witness_script_len));
    sha256_Update(&sha256, tx_ctx->input_data[index].witness_script, tx_ctx->input_data[index].witness_script_len);
  }

  sha256_Update(&sha256, tx_ctx->input_data[index].amount, sizeof(uint64_t));
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));

  if (sighash == SIGHASH_ALL) {
    sha256_Update(&sha256, hout, SHA256_DIGEST_LENGTH);
  } else if ((sighash == SIGHASH_SINGLE) && (index < tx_ctx->output_count)) {
    SOFT_SHA256_CTX inner_sha256;
    uint8_t inner_digest[SHA256_DIGEST_LENGTH];
    soft_sha256_Init(&inner_sha256);
    size_t output_len = ((uint32_t) tx_ctx->outputs[index].script - (uint32_t) tx_ctx->outputs[index].amount) + tx_ctx->outputs[index].script_len;
    soft_sha256_Update(&inner_sha256, tx_ctx->outputs[index].amount, output_len);
    soft_sha256_Final(&inner_sha256, inner_digest);

    soft_sha256_Init(&inner_sha256);
    soft_sha256_Update(&inner_sha256, inner_digest, SHA256_DIGEST_LENGTH);
    soft_sha256_Final(&inner_sha256, inner_digest);

    sha256_Update(&sha256, inner_digest, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  }

  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->input_data[index].sighash_flag, sizeof(uint32_t));

  sha256_Final(&sha256, digest);
  sha256_Raw(digest, SHA256_DIGEST_LENGTH, digest);
  return ERR_OK;
}

static app_err_t core_btc_hash_taproot(btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & 0xff;
  uint8_t base_type = sighash & SIGHASH_MASK;
  bool anyonecanpay = sighash & SIGHASH_ANYONECANPAY;

  // SIGHASH_DEFAULT (0x00) signs over the whole transaction like SIGHASH_ALL
  if (base_type == SIGHASH_DEFAULT) {
    base_type = SIGHASH_ALL;
  }

  // only defined hash_type values are allowed (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83)
  switch (sighash) {
  case SIGHASH_DEFAULT:
  case SIGHASH_ALL:
  case SIGHASH_NONE:
  case SIGHASH_SINGLE:
  case (SIGHASH_ALL | SIGHASH_ANYONECANPAY):
  case (SIGHASH_NONE | SIGHASH_ANYONECANPAY):
  case (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY):
    break;
  default:
    return ERR_DATA;
  }

  // hash_TapSighash(0x00 || SigMsg): tagged hash with a single SHA256 over the
  // tag prefix, the sighash epoch byte 0x00 and the signature message.
  uint8_t tag_hash[SHA256_DIGEST_LENGTH];
  sha256_Raw((uint8_t*) "TapSighash", 10, tag_hash);

  SHA256_CTX sha256;
  sha256_Init(&sha256);
  sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
  sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
  uint8_t epoch = 0;
  sha256_Update(&sha256, &epoch, 1);

  // hash_type
  sha256_Update(&sha256, &sighash, 1);

  // nVersion
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  // nLockTime
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));

  // Transaction level data
  if (!anyonecanpay) {
    sha256_Update(&sha256, tx_ctx->hash_prevouts, SHA256_DIGEST_LENGTH);
    sha256_Update(&sha256, tx_ctx->hash_amounts, SHA256_DIGEST_LENGTH);
    sha256_Update(&sha256, tx_ctx->hash_scriptpubkeys, SHA256_DIGEST_LENGTH);
    sha256_Update(&sha256, tx_ctx->hash_sequence, SHA256_DIGEST_LENGTH);
  }

  if ((base_type != SIGHASH_NONE) && (base_type != SIGHASH_SINGLE)) {
    sha256_Update(&sha256, tx_ctx->hash_outputs, SHA256_DIGEST_LENGTH);
  }

  // spend_type = (ext_flag * 2) + annex_present = 0 (no BIP342 extension, no annex)
  uint8_t spend_type = 0;
  sha256_Update(&sha256, &spend_type, 1);

  if (anyonecanpay) {
    // outpoint (32-byte txid + 4-byte index)
    sha256_Update(&sha256, tx_ctx->inputs[index].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));
    // amount
    sha256_Update(&sha256, tx_ctx->input_data[index].amount, sizeof(uint64_t));
    // scriptPubKey serialized as script inside CTxOut (compact size length prefix)
    uint8_t csize[sizeof(uint64_t)];
    compactsize_write(csize, tx_ctx->input_data[index].script_pubkey_len);
    sha256_Update(&sha256, csize, compactsize_length(tx_ctx->input_data[index].script_pubkey_len));
    sha256_Update(&sha256, tx_ctx->input_data[index].script_pubkey, tx_ctx->input_data[index].script_pubkey_len);
    // nSequence
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));
  } else {
    // input_index
    uint32_t idx = index;
    sha256_Update(&sha256, (uint8_t*) &idx, sizeof(uint32_t));
  }

  if (base_type == SIGHASH_SINGLE) {
    if (index >= tx_ctx->output_count) {
      return ERR_DATA; // SIGHASH_SINGLE without a corresponding output
    }

    // sha_single_output: single SHA256 of the corresponding output in CTxOut format
    SHA256_CTX inner;
    uint8_t inner_digest[SHA256_DIGEST_LENGTH];
    size_t output_len = ((uint32_t) tx_ctx->outputs[index].script - (uint32_t) tx_ctx->outputs[index].amount) + tx_ctx->outputs[index].script_len;
    sha256_Init(&inner);
    sha256_Update(&inner, tx_ctx->outputs[index].amount, output_len);
    sha256_Final(&inner, inner_digest);

    sha256_Update(&sha256, inner_digest, SHA256_DIGEST_LENGTH);
  }

  sha256_Final(&sha256, digest);
  return ERR_OK;
}

static app_err_t core_btc_read_signature(uint8_t* data, uint8_t sighash, psbt_record_t* rec) {
  uint16_t len;
  uint16_t tag;
  uint16_t off = tlv_read_tag(data, &tag);

  if (tag != 0xa0) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);

  off += tlv_read_tag(&data[off], &tag);
  if (tag != 0x80) {
    return ERR_DATA;
  }
  off += tlv_read_length(&data[off], &len);

  rec->scope = PSBT_SCOPE_INPUTS;
  rec->type = PSBT_IN_PARTIAL_SIG;

  rec->key = &data[off];
  rec->key_size = PUBKEY_COMPRESSED_LEN;
  rec->key[0] = 0x02 | (rec->key[64] & 1);

  rec->val = &rec->key[len];

  if (rec->val[0] != 0x30) {
    return ERR_DATA;
  }

  if (rec->val[1] > DER_ECDSA_MAX_SIGNATURE_LEN) {
    return ERR_DATA;
  }

  rec->val_size = 3 + rec->val[1];
  rec->val[rec->val_size - 1] = sighash;

  return ERR_OK;
}

static app_err_t core_btc_read_schnorr_signature(uint8_t* data, psbt_record_t* rec) {
  uint16_t len;
  uint16_t tag;
  uint16_t off = tlv_read_tag(data, &tag);

  if (tag != 0xa0) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);

  off += tlv_read_tag(&data[off], &tag);
  if (tag != 0x80) {
    return ERR_DATA;
  }
  off += tlv_read_length(&data[off], &len);
  off += len;

  off += tlv_read_tag(&data[off], &tag);
  if (tag != 0x88) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);
  if (len != 64) {
    return ERR_DATA;
  }

  rec->scope = PSBT_SCOPE_INPUTS;
  rec->type = PSBT_IN_TAP_KEY_SIG;
  rec->key = NULL;
  rec->key_size = 0;
  rec->val = &data[off];
  rec->val_size = 64;

  return ERR_OK;
}

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
    err = core_btc_hash_legacy(tx_ctx, index, digest);
    break;
  case BTC_INPUT_TYPE_P2WPKH:
  case BTC_INPUT_TYPE_P2WSH:
    err = core_btc_hash_segwit(tx_ctx, index, digest);
    break;
  case BTC_INPUT_TYPE_P2TR:
    err = core_btc_hash_taproot(tx_ctx, index, digest);
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
    if (core_btc_read_schnorr_signature(data, &signature) != ERR_OK) {
      return ERR_DATA;
    }
  } else {
    if ((keycard_cmd_sign(kc, KEYCARD_SIGN_ECDSA_SECP256K1, g_core.bip44_path, g_core.bip44_path_len, digest) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
      return ERR_CRYPTO;
    }

    uint8_t* data = APDU_RESP(&kc->apdu);
    if (core_btc_read_signature(data, tx_ctx->input_data[index].sighash_flag, &signature) != ERR_OK) {
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
    return memcmp(&pubkey[1], &out->script[2], 32) == 0;
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

static void core_btc_common_hashes(btc_tx_ctx_t* tx_ctx) {
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, tx_ctx->inputs[i].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].index, sizeof(uint32_t));
  }

  sha256_Final(&sha256, tx_ctx->hash_prevouts);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].sequence_number, sizeof(uint32_t));
  }

  sha256_Final(&sha256, tx_ctx->hash_sequence);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, tx_ctx->input_data[i].amount, sizeof(uint64_t));
  }

  sha256_Final(&sha256, tx_ctx->hash_amounts);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    uint8_t csize[sizeof(uint64_t)];
    compactsize_write(csize, tx_ctx->input_data[i].script_pubkey_len);
    sha256_Update(&sha256, csize, compactsize_length(tx_ctx->input_data[i].script_pubkey_len));
    sha256_Update(&sha256, tx_ctx->input_data[i].script_pubkey, tx_ctx->input_data[i].script_pubkey_len);
  }

  sha256_Final(&sha256, tx_ctx->hash_scriptpubkeys);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->output_count; i++) {
    size_t len = ((uint32_t) tx_ctx->outputs[i].script - (uint32_t) tx_ctx->outputs[i].amount) + tx_ctx->outputs[i].script_len;
    sha256_Update(&sha256, tx_ctx->outputs[i].amount, len);
  }

  sha256_Final(&sha256, tx_ctx->hash_outputs);
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

  core_btc_common_hashes(tx_ctx);

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

  if (keycard_read_signature(data, kc->apdu.lr, digest, &out[1]) != ERR_OK) {
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

    g_core.data.msg.len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
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
