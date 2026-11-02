#include <string.h>

#include "bitcoin/sighash.h"
#include "bitcoin/compactsize.h"
#include "bitcoin/psbt_tx.h"
#include "crypto/script.h"
#include "crypto/sha2.h"

static const uint8_t P2PKH_SCRIPT_PRE[4] = { 0x19, 0x76, 0xa9, 0x14 };
static const uint8_t P2PKH_SCRIPT_POST[2] = { 0x88, 0xac };

app_err_t btc_sighash_legacy(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  uint8_t sighash = tx_ctx->input_data[index].sighash_flag & SIGHASH_MASK;
  uint8_t anyonecanpay = tx_ctx->input_data[index].sighash_flag & SIGHASH_ANYONECANPAY;

  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  const uint8_t* script;
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
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));
    sha256_Update(&sha256, cscript_len, csize_len);
    sha256_Update(&sha256, script, script_len);
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));
  } else {
    const uint8_t input_count = tx_ctx->input_count;
    sha256_Update(&sha256, &input_count, sizeof(input_count));
    for (int i = 0; i < tx_ctx->input_count; i++) {
      sha256_Update(&sha256, tx_ctx->inputs[i].txid, BTC_TXID_LEN);
      sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[i].index, sizeof(uint32_t));

      if (i == index) {
        sha256_Update(&sha256, cscript_len, csize_len);
        sha256_Update(&sha256, script, script_len);
      } else {
        uint8_t tmp = 0;
        sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
      }

      if ((sighash == SIGHASH_ALL) || (i == index)) {
        sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[i].sequence_number, sizeof(uint32_t));
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
        size_t len = btc_txout_len(&tx_ctx->outputs[i]);
        sha256_Update(&sha256, tx_ctx->outputs[i].amount, len);
      } else {
        int64_t amount = -1;
        uint8_t tmp = 0;
        sha256_Update(&sha256, (uint8_t*) &amount, sizeof(uint64_t));
        sha256_Update(&sha256, (uint8_t*) &tmp, sizeof(uint8_t));
      }
    }
  }

  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));
  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->input_data[index].sighash_flag, sizeof(uint32_t));

  sha256_Final(&sha256, digest);
  sha256_Raw(digest, SHA256_DIGEST_LENGTH, digest);

  return ERR_OK;
}

app_err_t btc_sighash_segwit(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
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
  
  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

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
  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));

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
  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));

  if (sighash == SIGHASH_ALL) {
    sha256_Update(&sha256, hout, SHA256_DIGEST_LENGTH);
  } else if ((sighash == SIGHASH_SINGLE) && (index < tx_ctx->output_count)) {
    SOFT_SHA256_CTX inner_sha256;
    uint8_t inner_digest[SHA256_DIGEST_LENGTH];
    soft_sha256_Init(&inner_sha256);
    size_t output_len = btc_txout_len(&tx_ctx->outputs[index]);
    soft_sha256_Update(&inner_sha256, tx_ctx->outputs[index].amount, output_len);
    soft_sha256_Final(&inner_sha256, inner_digest);

    soft_sha256_Init(&inner_sha256);
    soft_sha256_Update(&inner_sha256, inner_digest, SHA256_DIGEST_LENGTH);
    soft_sha256_Final(&inner_sha256, inner_digest);

    sha256_Update(&sha256, inner_digest, SHA256_DIGEST_LENGTH);
  } else {
    sha256_Update(&sha256, ZERO32, SHA256_DIGEST_LENGTH);
  }

  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));
  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->input_data[index].sighash_flag, sizeof(uint32_t));

  sha256_Final(&sha256, digest);
  sha256_Raw(digest, SHA256_DIGEST_LENGTH, digest);
  return ERR_OK;
}

app_err_t btc_sighash_taproot(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
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

  uint8_t tag_hash[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t*) "TapSighash", 10, tag_hash);

  SHA256_CTX sha256;
  sha256_Init(&sha256);
  sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
  sha256_Update(&sha256, tag_hash, SHA256_DIGEST_LENGTH);
  uint8_t epoch = 0;
  sha256_Update(&sha256, &epoch, 1);

  sha256_Update(&sha256, &sighash, 1);

  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.version, sizeof(uint32_t));

  sha256_Update(&sha256, (const uint8_t*) &tx_ctx->tx.lock_time, sizeof(uint32_t));

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

  uint8_t spend_type = 0;
  sha256_Update(&sha256, &spend_type, 1);

  if (anyonecanpay) {
    sha256_Update(&sha256, tx_ctx->inputs[index].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].index, sizeof(uint32_t));
    sha256_Update(&sha256, tx_ctx->input_data[index].amount, sizeof(uint64_t));
    uint8_t csize[sizeof(uint64_t)];
    compactsize_write(csize, tx_ctx->input_data[index].script_pubkey_len);
    sha256_Update(&sha256, csize, compactsize_length(tx_ctx->input_data[index].script_pubkey_len));
    sha256_Update(&sha256, tx_ctx->input_data[index].script_pubkey, tx_ctx->input_data[index].script_pubkey_len);
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[index].sequence_number, sizeof(uint32_t));
  } else {
    uint32_t idx = index;
    sha256_Update(&sha256, (uint8_t*) &idx, sizeof(uint32_t));
  }

  if (base_type == SIGHASH_SINGLE) {
    if (index >= tx_ctx->output_count) {
      return ERR_DATA; // SIGHASH_SINGLE without a corresponding output
    }

    SHA256_CTX inner;
    uint8_t inner_digest[SHA256_DIGEST_LENGTH];
    size_t output_len = btc_txout_len(&tx_ctx->outputs[index]);
    sha256_Init(&inner);
    sha256_Update(&inner, tx_ctx->outputs[index].amount, output_len);
    sha256_Final(&inner, inner_digest);

    sha256_Update(&sha256, inner_digest, SHA256_DIGEST_LENGTH);
  }

  sha256_Final(&sha256, digest);
  return ERR_OK;
}

void btc_sighash_common_hashes(btc_tx_ctx_t* tx_ctx) {
  SHA256_CTX sha256;
  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, tx_ctx->inputs[i].txid, BTC_TXID_LEN);
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[i].index, sizeof(uint32_t));
  }

  sha256_Final(&sha256, tx_ctx->hash_prevouts);

  sha256_Init(&sha256);

  for(int i = 0; i < tx_ctx->input_count; i++) {
    sha256_Update(&sha256, (const uint8_t*) &tx_ctx->inputs[i].sequence_number, sizeof(uint32_t));
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
    size_t len = btc_txout_len(&tx_ctx->outputs[i]);
    sha256_Update(&sha256, tx_ctx->outputs[i].amount, len);
  }

  sha256_Final(&sha256, tx_ctx->hash_outputs);
}

