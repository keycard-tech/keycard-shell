#include <string.h>

#include "bitcoin/psbt_ctx.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_tx.h"
#include "bitcoin/tx.h"
#include "crypto/script.h"
#include "crypto/sha2.h"
#include "crypto/util.h"

struct btc_utxo_ctx {
  btc_tx_ctx_t* tx_ctx;
  uint32_t output_count;
  uint32_t input_index;
};

void btc_psbt_prevtx_output(psbt_txelem_t* elem) {
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

void btc_psbt_input_record(btc_tx_ctx_t* tx_ctx, size_t index, psbt_record_t* rec) {
  if (index >= tx_ctx->input_count) {
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
    if (psbt_btc_tx_parse(rec->val, rec->val_size, &utxo_ctx, btc_psbt_prevtx_output) != PSBT_OK) {
      tx_ctx->error = ERR_DECODE;
      break;
    }

    if (tx_ctx->inputs[index].index >= utxo_ctx.output_count) {
      tx_ctx->error = ERR_DATA;
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
    if (rec->val_size < 9) {
        tx_ctx->error = ERR_DECODE;
        return;
    }
    if (rec->val[8] >= 253) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    if ((size_t)rec->val[8] + 9 != rec->val_size) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    tx_ctx->input_data[index].witness = true;

    if (tx_ctx->input_data[index].nonwitness_utxo) {
      break;
    }
    tx_ctx->input_data[index].amount = rec->val;
    tx_ctx->input_data[index].script_pubkey = &rec->val[9];
    tx_ctx->input_data[index].script_pubkey_len = rec->val[8];
    break;
  case PSBT_IN_BIP32_DERIVATION:
    if (rec->val_size < 4) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    if (tx_ctx->input_data[index].master_fingerprint != tx_ctx->mfp) {
      memcpy(&tx_ctx->input_data[index].master_fingerprint, rec->val, sizeof(uint32_t));
      tx_ctx->input_data[index].bip32_path = &rec->val[4];
      tx_ctx->input_data[index].bip32_path_len = rec->val_size - 4;
    }
    break;
  case PSBT_IN_SIGHASH_TYPE:
    if (rec->val_size < sizeof(uint32_t)) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    memcpy(&tx_ctx->input_data[index].sighash_flag, rec->val, sizeof(uint32_t));
    break;
  case PSBT_IN_TAP_INTERNAL_KEY:
    if (rec->val_size != 32) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    tx_ctx->input_data[index].taproot_internal_key = rec->val;
    tx_ctx->input_data[index].has_taproot_internal_key = true;
    break;
  case PSBT_IN_TAP_MERKLE_ROOT:
    if (rec->val_size != 32) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    tx_ctx->input_data[index].taproot_merkle_root = rec->val;
    tx_ctx->input_data[index].has_taproot_merkle_root = true;
    break;
  case PSBT_IN_TAP_BIP32_DERIVATION:
    if (rec->val_size < 5) {
      tx_ctx->error = ERR_DECODE;
      return;
    }
    if (tx_ctx->input_data[index].master_fingerprint != tx_ctx->mfp) {
      memcpy(&tx_ctx->input_data[index].master_fingerprint, &rec->val[1], sizeof(uint32_t));
      tx_ctx->input_data[index].bip32_path = &rec->val[5];
      tx_ctx->input_data[index].bip32_path_len = rec->val_size - 5;
    }
    break;
  }
}

void btc_psbt_output_record(btc_tx_ctx_t* tx_ctx, size_t index, psbt_record_t* rec) {
  if (index >= tx_ctx->output_count) {
    tx_ctx->error = ERR_DATA;
    return;
  }

  if (rec->type == PSBT_OUT_BIP32_DERIVATION) {
    if (rec->val_size < 4) {
      tx_ctx->error = ERR_DECODE;
      return;
    }

    if (tx_ctx->output_data[index].master_fingerprint != tx_ctx->mfp) {
      memcpy(&tx_ctx->output_data[index].master_fingerprint, rec->val, sizeof(uint32_t));
      tx_ctx->output_data[index].bip32_path = &rec->val[4];
      tx_ctx->output_data[index].bip32_path_len = rec->val_size - 4;
    }
  }
}

void btc_psbt_tx_element(btc_tx_ctx_t* tx_ctx, psbt_txelem_t* elem) {
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

void btc_psbt_element(psbt_elem_t* rec) {
  btc_tx_ctx_t* tx_ctx = (btc_tx_ctx_t*) rec->user_data;

  if (rec->type == PSBT_ELEM_RECORD) {
    switch (rec->elem.rec->scope) {
    case PSBT_SCOPE_INPUTS:
      btc_psbt_input_record(tx_ctx, rec->index, rec->elem.rec);
      break;
    case PSBT_SCOPE_OUTPUTS:
      btc_psbt_output_record(tx_ctx, rec->index, rec->elem.rec);
      break;
    default:
      break;
    }
  } else if (rec->type == PSBT_ELEM_TXELEM) {
    btc_psbt_tx_element(tx_ctx, rec->elem.txelem);
  }
}


bool btc_redeem_script_matches(const uint8_t* script, size_t script_len,
                               const uint8_t* redeem_script, size_t redeem_script_len) {
  if (script_is_p2sh(script, script_len)) {
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];
    hash160(redeem_script, redeem_script_len, digest);

    return memcmp(digest, &script[2], RIPEMD160_DIGEST_LENGTH) == 0;
  }

  return false;
}

bool btc_witness_script_matches(const uint8_t* script, size_t script_len,
                                const uint8_t* witness_script, size_t witness_script_len) {
  if (script_is_p2wsh(script, script_len) && (witness_script != NULL)) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(witness_script, witness_script_len, digest);

    return memcmp(digest, &script[2], SHA256_DIGEST_LENGTH) == 0;
  }

  return false;
}


app_err_t btc_psbt_validate_inputs(btc_tx_ctx_t* tx_ctx) {
  for (int i = 0; i < tx_ctx->input_count; i++) {
    if (tx_ctx->input_data[i].master_fingerprint == tx_ctx->mfp) {
      tx_ctx->input_data[i].can_sign = true;
    } else {
      continue;
    }

    if (tx_ctx->input_data[i].nonwitness_utxo && !btc_validate_tx_hash(tx_ctx->input_data[i].nonwitness_utxo, tx_ctx->input_data[i].nonwitness_utxo_len, tx_ctx->inputs[i].txid)) {
      return ERR_DATA;
    }

    if (tx_ctx->input_data[i].witness) {
      uint8_t *script;
      size_t script_len;

      if (tx_ctx->input_data[i].redeem_script) {
        if (!btc_redeem_script_matches(tx_ctx->input_data[i].script_pubkey, tx_ctx->input_data[i].script_pubkey_len, tx_ctx->input_data[i].redeem_script, tx_ctx->input_data[i].redeem_script_len)) {
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
      } else if (script_is_p2tr(script, script_len)) {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_P2TR;
      } else if (btc_witness_script_matches(script, script_len, tx_ctx->input_data[i].witness_script, tx_ctx->input_data[i].witness_script_len)) {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_P2WSH;
      } else {
        return ERR_DATA;
      }
    } else if (tx_ctx->input_data[i].script_pubkey) {
      if (tx_ctx->input_data[i].redeem_script) {
        if (!btc_redeem_script_matches(tx_ctx->input_data[i].script_pubkey, tx_ctx->input_data[i].script_pubkey_len, tx_ctx->input_data[i].redeem_script, tx_ctx->input_data[i].redeem_script_len)) {
          return ERR_DATA;
        }

        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_LEGACY_WITH_REDEEM;
      } else {
        tx_ctx->input_data[i].input_type = BTC_INPUT_TYPE_LEGACY;
      }
    } else {
      return ERR_DATA;
    }

    if ((tx_ctx->input_data[i].sighash_flag == SIGHASH_DEFAULT) && (tx_ctx->input_data[i].input_type != BTC_INPUT_TYPE_P2TR)) {
      tx_ctx->input_data[i].sighash_flag = SIGHASH_ALL;
    }
  }

  return ERR_OK;
}

bool btc_psbt_any_can_sign(const btc_tx_ctx_t* tx_ctx) {
  for (size_t i = 0; i < tx_ctx->input_count; i++) {
    if (tx_ctx->input_data[i].can_sign) {
      return true;
    }
  }

  return false;
}
