#include "core.h"
#include "mem.h"
#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/compactsize.h"
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

struct btc_utxo_ctx {
  btc_tx_ctx_t* tx_ctx;
  uint32_t output_count;
  uint32_t input_index;
};

static void core_btc_utxo_handler(psbt_txelem_t* elem) {
  if (elem->elem_type != PSBT_TXELEM_TXOUT) {
    return;
  }

  struct btc_utxo_ctx* utxo_ctx = (struct btc_utxo_ctx*) elem->user_data;

  if (utxo_ctx->tx_ctx->inputs[utxo_ctx->input_index].index != utxo_ctx->output_count++) {
    return;
  }

  psbt_txout_t* tx_out = elem->elem.txout;
  utxo_ctx->tx_ctx->input_data[utxo_ctx->input_index].amount = tx_out->amount;
  utxo_ctx->tx_ctx->input_data[utxo_ctx->input_index].script_pubkey = tx_out->script;
  utxo_ctx->tx_ctx->input_data[utxo_ctx->input_index].script_pubkey_len = tx_out->script_len;
}

static void core_btc_psbt_rec_handler(btc_tx_ctx_t* tx_ctx, size_t index, psbt_record_t* rec) {
  if (rec->scope != PSBT_SCOPE_INPUTS) {
    return;
  } else if (index >= tx_ctx->input_count) {
    tx_ctx->error = ERR_DATA;
    return;
  }

  struct btc_utxo_ctx utxo_ctx;

  switch (rec->type) {
  case PSBT_IN_NON_WITNESS_UTXO:
    utxo_ctx.tx_ctx = tx_ctx;
    utxo_ctx.output_count = 0;
    utxo_ctx.input_index = index;
    tx_ctx->input_data[index].nonwitness_utxo = rec->val;
    tx_ctx->input_data[index].nonwitness_utxo_len = rec->val_size;
    if (psbt_btc_tx_parse(rec->val, rec->val_size, &utxo_ctx, core_btc_utxo_handler) != PSBT_OK) {
      tx_ctx->error = ERR_DECODE;
    }
    break;
  case PSBT_IN_REDEEM_SCRIPT:
    tx_ctx->input_data[index].redeem_script = rec->val;
    tx_ctx->input_data[index].redeem_script_len = rec->val_size;
    break;
  case PSBT_IN_WITNESS_SCRIPT:
    tx_ctx->input_data[index].witness_script = rec->val;
    tx_ctx->input_data[index].witness_script_len = rec->val_size;
    break;
  case PSBT_IN_WITNESS_UTXO:
    if (rec->val[8] >= 253) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    tx_ctx->input_data[index].amount = rec->val;
    tx_ctx->input_data[index].script_pubkey = &rec->val[9];
    tx_ctx->input_data[index].script_pubkey_len = rec->val_size - 9;
    tx_ctx->input_data[index].witness = true;
    break;
  case PSBT_IN_BIP32_DERIVATION:
    memcpy(&tx_ctx->input_data[index].master_fingerprint, rec->val, sizeof(uint32_t));
    tx_ctx->input_data[index].bip32_path = &rec->val[4];
    tx_ctx->input_data[index].bip32_path_len = rec->val_size - 4;
    break;
  case PSBT_IN_SIGHASH_TYPE:
    memcpy(&tx_ctx->input_data[index].sighash_flag, rec->val, sizeof(uint32_t));
    break;
  }
}

static void core_btc_txelem_handler(btc_tx_ctx_t* tx_ctx, psbt_txelem_t* elem) {
  switch (elem->elem_type) {
  case PSBT_TXELEM_TX:
    memcpy(&tx_ctx->tx, elem->elem.tx, sizeof(psbt_tx_t));
    break;
  case PSBT_TXELEM_TXIN:
    if (tx_ctx->input_count < BTC_MAX_INPUTS) {
      memcpy(&tx_ctx->inputs[tx_ctx->input_count++], elem->elem.txin, sizeof(psbt_txin_t));
    } else {
      tx_ctx->error = ERR_FULL;
    }
    break;
  case PSBT_TXELEM_TXOUT:
    if (tx_ctx->output_count < BTC_MAX_OUTPUTS) {
      memcpy(&tx_ctx->outputs[tx_ctx->output_count++], elem->elem.txout, sizeof(psbt_txout_t));
    } else {
      tx_ctx->error = ERR_FULL;
    }
    break;
  default:
    break;
  }
}

static void core_btc_parser_cb(psbt_elem_t* rec) {
  btc_tx_ctx_t* tx_ctx = (btc_tx_ctx_t*) rec->user_data;

  if (rec->type == PSBT_ELEM_RECORD) {
    core_btc_psbt_rec_handler(tx_ctx, rec->index, rec->elem.rec);
  } else if (rec->type == PSBT_ELEM_TXELEM) {
    core_btc_txelem_handler(tx_ctx, rec->elem.txelem);
  }
}

static app_err_t core_btc_hash_legacy(btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & SIGHASH_MASK;
  uint8_t anyonecanpay = tx_ctx->input_data[index].sighash_flag & SIGHASH_ANYONECANPAY;

  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  uint8_t* script;
  uint8_t script_len;

  if (tx_ctx->input_data[index].input_type == BTC_INPUT_TYPE_LEGACY_WITH_REDEEM) {
    script = tx_ctx->input_data[index].redeem_script;
    script_len = tx_ctx->input_data[index].redeem_script_len;
  } else {
    script = tx_ctx->input_data[index].script_pubkey;
    script_len = tx_ctx->input_data[index].script_pubkey_len;
  }

  if (anyonecanpay) {
    uint8_t tmp = 1;
    sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
    sha256_Update(&sha256, tx_ctx->inputs[index].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));
    sha256_Update(&sha256, &script_len, sizeof(uint8_t));
    sha256_Update(&sha256, script, script_len);
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));
  } else{
    for (int i = 0; i < tx_ctx->input_count; i++) {
      sha256_Update(&sha256, (uint8_t*) &tx_ctx->input_count, sizeof(uint8_t));
      sha256_Update(&sha256, tx_ctx->inputs[i].txid, BTC_TXID_LEN);
      sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].index, sizeof(uint32_t));

      if (i == index) {
        sha256_Update(&sha256, (uint8_t*) &script_len, sizeof(uint8_t));
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
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & SIGHASH_MASK;
  uint8_t anyonecanpay = tx_ctx->input_data[index].sighash_flag & SIGHASH_ANYONECANPAY;

  sha256_Update(&sha256, (uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  if (anyonecanpay) {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, tx_ctx->hash_prevouts, SHA256_DIGEST_LENGTH);
  }

  if (anyonecanpay || (sighash != SIGHASH_ALL)) {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, tx_ctx->hash_sequence, SHA256_DIGEST_LENGTH);
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
    sha256_Update(&sha256, tx_ctx->input_data[index].witness_script, tx_ctx->input_data[index].witness_script_len);
  }

  sha256_Update(&sha256, tx_ctx->input_data[index].amount, sizeof(uint64_t));
  sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));

  if (sighash == SIGHASH_ALL) {
    sha256_Update(&sha256, tx_ctx->hash_outputs, SHA256_DIGEST_LENGTH);
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

  rec->val_size = 3 + rec->val[1];
  rec->val[rec->val_size - 1] = sighash;

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
  default:
    err = ERR_DATA;
    break;
  }

  if (err != ERR_OK) {
    return err == ERR_UNSUPPORTED ? ERR_OK : err;
  }

  keycard_t *kc = &g_core.keycard;

  for (int i = 0; i < tx_ctx->input_data[index].bip32_path_len; i += 4) {
    g_core.bip44_path[i + 3] = tx_ctx->input_data[index].bip32_path[i];
    g_core.bip44_path[i + 2] = tx_ctx->input_data[index].bip32_path[i + 1];
    g_core.bip44_path[i + 1] = tx_ctx->input_data[index].bip32_path[i + 2];
    g_core.bip44_path[i] = tx_ctx->input_data[index].bip32_path[i + 3];
  }

  g_core.bip44_path_len = tx_ctx->input_data[index].bip32_path_len;

  if ((keycard_cmd_sign(kc, g_core.bip44_path, g_core.bip44_path_len, digest, 0) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
    return ERR_CRYPTO;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);
  psbt_record_t signature;

  if (core_btc_read_signature(data, tx_ctx->input_data[index].sighash_flag, &signature) != ERR_OK) {
    return ERR_DATA;
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
    if (rec->index != tx_ctx->index_in) {
      psbt_new_input_record_set(&tx_ctx->psbt_out);
      tx_ctx->index_in = rec->index;
      tx_ctx->error = core_btc_sign_input(tx_ctx, rec->index);
    }

    psbt_write_input_record(&tx_ctx->psbt_out, rec->elem.rec);
    break;
  case PSBT_SCOPE_OUTPUTS:
    if (rec->index != tx_ctx->index_out) {
      psbt_new_output_record_set(&tx_ctx->psbt_out);
      tx_ctx->index_out = rec->index;
    }

    psbt_write_output_record(&tx_ctx->psbt_out, rec->elem.rec);
    break;
  }
}

static inline bool core_btc_is_valid_script(uint8_t* hash, uint8_t* redeem_script, size_t redeem_script_len) {
  uint8_t digest[RIPEMD160_DIGEST_LENGTH];
  hash160(redeem_script, redeem_script_len, digest);

  return memcmp(digest, hash, RIPEMD160_DIGEST_LENGTH) == 0;
}

static inline bool core_btc_is_valid_redeem_script(uint8_t* script, size_t script_len, uint8_t* redeem_script, size_t redeem_script_len) {
  return script_is_p2sh(script, script_len) &&
         core_btc_is_valid_script(&script[2], redeem_script, redeem_script_len);
}

static inline bool core_btc_is_valid_witness_script(uint8_t* script, size_t script_len, uint8_t* witness_script, size_t witness_script_len) {
  return script_is_p2wsh(script, script_len) &&
         (witness_script != NULL) &&
         core_btc_is_valid_script(&script[2], witness_script, witness_script_len);
}

static inline bool btc_is_segwit(uint8_t* tx) {
  return tx[4] == 0;
}

static void btc_generate_txid(uint8_t* tx, size_t tx_len, uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  if (btc_is_segwit(tx)) {
    uint8_t* p = tx;
    // this tx has been parsed before so we know it is correctly formatted, we won't repeat the same checks
    sha256_Update(&ctx, p, sizeof(uint32_t));
    p += sizeof(uint32_t) + sizeof(uint16_t);

    uint32_t count = compactsize_read(p, NULL);
    uint32_t lenlen = compactsize_peek_length(*p);
    sha256_Update(&ctx, p, lenlen);
    p += lenlen;

    for(int i = 0; i < count; i++) {
      sha256_Update(&ctx, p, SHA256_DIGEST_LENGTH + sizeof(uint32_t));
      p += SHA256_DIGEST_LENGTH + sizeof(uint32_t);
      uint32_t scriptlen = compactsize_read(p, NULL);
      lenlen = compactsize_peek_length(*p);
      sha256_Update(&ctx, p, lenlen + scriptlen + sizeof(uint32_t));
      p += lenlen + scriptlen + sizeof(uint32_t);
    }

    count = compactsize_read(p, NULL);
    lenlen = compactsize_peek_length(*p);
    sha256_Update(&ctx, p, lenlen);
    p += lenlen;

    for(int i = 0; i < count; i++) {
      sha256_Update(&ctx, p, sizeof(uint64_t));
      p += sizeof(uint64_t);
      uint32_t scriptlen = compactsize_read(p, NULL);
      lenlen = compactsize_peek_length(*p);
      sha256_Update(&ctx, p, lenlen + scriptlen);
      p += lenlen + scriptlen;
    }

    sha256_Update(&ctx, &tx[tx_len - 4], sizeof(uint32_t));
  } else {
    sha256_Update(&ctx, tx, tx_len);
  }

  sha256_Final(&ctx, out);
  sha256_Raw(out, SHA256_DIGEST_LENGTH, out);
}

static inline bool btc_validate_tx_hash(uint8_t* tx, size_t tx_len, uint8_t expected_hash[SHA256_DIGEST_LENGTH]) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  btc_generate_txid(tx, tx_len, digest);
  return memcmp(expected_hash, digest, SHA256_DIGEST_LENGTH) == 0;
}

static app_err_t core_btc_validate(btc_tx_ctx_t* tx_ctx) {
  uint32_t mfp;

  if (core_get_fingerprint(g_core.bip44_path, 0, &mfp) != ERR_OK) {
    return ERR_CRYPTO;
  }

  mfp = rev32(mfp);

  bool can_sign_something = false;

  for (int i = 0; i < tx_ctx->input_count; i++) {
    if (tx_ctx->input_data[i].master_fingerprint == mfp) {
      tx_ctx->input_data[i].can_sign = true;
      can_sign_something = true;
    } else {
      continue;
    }

    if (tx_ctx->input_data[i].sighash_flag == SIGHASH_DEFAULT) {
      tx_ctx->input_data[i].sighash_flag = SIGHASH_ALL;
    }

    if (tx_ctx->input_data[i].nonwitness_utxo && !btc_validate_tx_hash(tx_ctx->input_data[i].nonwitness_utxo, tx_ctx->input_data[i].nonwitness_utxo_len, tx_ctx->inputs[i].txid)) {
      return ERR_DATA;
    }

    if (tx_ctx->input_data[i].witness) {
      uint8_t *script;
      size_t script_len;

      if (tx_ctx->input_data[i].redeem_script) {
        if (!core_btc_is_valid_redeem_script(tx_ctx->input_data[i].script_pubkey, tx_ctx->input_data[i].script_pubkey_len, tx_ctx->input_data[i].redeem_script, tx_ctx->input_data[i].redeem_script_len)) {
          return ERR_DATA;
        }

        script = tx_ctx->input_data[i].redeem_script;
        script_len = tx_ctx->input_data[i].redeem_script_len;
      } else {
        script = tx_ctx->input_data[i].script_pubkey;
        script_len = tx_ctx->input_data[i].script_pubkey_len;
      }

      if (script_is_p2wpkh(script, script_len)) {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_P2WPKH;
      } else if (core_btc_is_valid_witness_script(script, script_len, tx_ctx->input_data[i].witness_script, tx_ctx->input_data[i].witness_script_len)) {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_P2WSH;
      } else {
        return ERR_DATA;
      }
    } else if (tx_ctx->input_data[i].script_pubkey) {
      if (tx_ctx->input_data[i].redeem_script) {
        if (!core_btc_is_valid_redeem_script(tx_ctx->input_data[i].script_pubkey, tx_ctx->input_data[i].script_pubkey_len, tx_ctx->input_data[i].redeem_script, tx_ctx->input_data[i].redeem_script_len)) {
          return ERR_DATA;
        }

        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_LEGACY_WITH_REDEEM;
      } else {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_LEGACY;
      }
    } else {
      return ERR_DATA;
    }
  }

  for (int i = 0; i < tx_ctx->output_count; i++) {
    for (int j = 0; j < tx_ctx->input_count; j++) {
      if (tx_ctx->input_data[j].can_sign &&
          (tx_ctx->input_data[j].script_pubkey_len == tx_ctx->outputs[i].script_len) &&
          !memcmp(tx_ctx->input_data[j].script_pubkey, tx_ctx->outputs[i].script, tx_ctx->outputs[i].script_len)) {
        tx_ctx->output_is_change[i] = true;
        break;
      }
    }
  }

  return can_sign_something ? ERR_OK : ERR_MISMATCH;
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
  sha256_Raw(tx_ctx->hash_prevouts, SHA256_DIGEST_LENGTH, tx_ctx->hash_prevouts);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, (uint8_t*) &tx_ctx->inputs[i].sequence_number, sizeof(uint32_t));
  }

  sha256_Final(&sha256, tx_ctx->hash_sequence);
  sha256_Raw(tx_ctx->hash_sequence, SHA256_DIGEST_LENGTH, tx_ctx->hash_sequence);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->output_count; i++) {
    size_t len = ((uint32_t) tx_ctx->outputs[i].script - (uint32_t) tx_ctx->outputs[i].amount) + tx_ctx->outputs[i].script_len;
    sha256_Update(&sha256, tx_ctx->outputs[i].amount, len);
  }

  sha256_Final(&sha256, tx_ctx->hash_outputs);
  sha256_Raw(tx_ctx->hash_outputs, SHA256_DIGEST_LENGTH, tx_ctx->hash_outputs);
}

static app_err_t core_btc_psbt_run(const uint8_t* psbt_in, size_t psbt_len, uint8_t** psbt_out, size_t* out_len) {
  btc_tx_ctx_t* tx_ctx = (btc_tx_ctx_t*) g_camera_fb[1];
  memset(tx_ctx, 0, sizeof(btc_tx_ctx_t));
  *psbt_out = &g_camera_fb[1][(sizeof(btc_tx_ctx_t) + 3) & ~0x3];
  size_t psbt_out_len = CAMERA_FB_SIZE - ((sizeof(btc_tx_ctx_t) + 3) & ~0x3);

  psbt_t psbt;
  psbt_init(&psbt, (uint8_t*) psbt_in, psbt_len);
  psbt_read(psbt_in, psbt_len, &psbt, core_btc_parser_cb, tx_ctx);

  if (tx_ctx->error != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
    return tx_ctx->error;
  }

  tx_ctx->error = core_btc_validate(tx_ctx);

  switch(tx_ctx->error) {
  case ERR_OK:
    break;
  case ERR_MISMATCH:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_WRONG_CARD), NULL, 0);
    return ERR_MISMATCH;
  case ERR_DATA:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
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

  tx_ctx->index_in = UINT32_MAX;
  tx_ctx->index_out = UINT32_MAX;

  if (psbt_read(psbt_in, psbt_len, &psbt, core_btc_sign_handler, tx_ctx) != PSBT_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
    return ERR_DATA;
  }

  switch(tx_ctx->error) {
  case ERR_OK:
    break;
  case ERR_DATA:
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
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

  //TODO: this can be optimized by simply prepending the cbor header to the psbt
  cbor_encode_psbt(g_mem_heap, MEM_HEAP_SIZE, &qr_out, &out_len);
  ui_display_ur_qr(LSTR(QR_SCAN_WALLET_TITLE), g_mem_heap, out_len, CRYPTO_PSBT);
}

app_err_t core_btc_sign_msg_run(const uint8_t* msg, size_t msg_len, uint32_t expected_mfp, uint8_t* out, uint8_t* pubkey) {
  uint32_t mfp;
  app_err_t err = core_export_public(pubkey, NULL, &mfp, NULL);

  if (err != ERR_OK) {
    ui_card_transport_error();
    return err;
  }

  if (mfp != expected_mfp) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_WRONG_CARD), NULL, 0);
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

  if ((keycard_cmd_sign(kc, g_core.bip44_path, g_core.bip44_path_len, digest, 1) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
    ui_card_transport_error();
    return ERR_CRYPTO;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);

  if (keycard_read_signature(data, digest, &out[1]) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
    return ERR_DATA;
  }

  out[0] = BTC_MESSAGE_SIG_HEADER + out[65];

  return ERR_OK;
}

void core_btc_sign_msg_qr_run(struct btc_sign_request* qr_request) {
  if (!qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m_present ||
      !qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m.crypto_keypath_source_fingerprint_present ||
      (core_set_derivation_path(&qr_request->btc_sign_request_btc_derivation_paths_crypto_keypath_m) != ERR_OK)) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA), NULL, 0);
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
  ui_display_ur_qr(LSTR(QR_SCAN_WALLET_TITLE), g_core.data.sig.cbor_sig, g_core.data.sig.cbor_len, BTC_SIGNATURE);
}
