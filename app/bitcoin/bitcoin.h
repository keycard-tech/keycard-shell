#ifndef __BITCOIN__
#define __BITCOIN__

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "mem.h"
#include "bitcoin/psbt.h"

#define BTC_MAX_INPUTS 20
#define BTC_MAX_OUTPUTS 20

#define SIGHASH_MASK 0x1f

typedef enum {
  BTC_INPUT_TYPE_LEGACY,
  BTC_INPUT_TYPE_LEGACY_WITH_REDEEM,
  BTC_INPUT_TYPE_P2WPKH,
  BTC_INPUT_TYPE_P2WSH,
} btc_input_type_t;

typedef enum {
  SIGHASH_DEFAULT = 0x00,
  SIGHASH_ALL = 0x01,
  SIGHASH_NONE = 0x02,
  SIGHASH_SINGLE = 0x03,
  SIGHASH_ANYONECANPAY = 0x80
} btc_sighash_flag_t;

typedef struct {
  uint8_t* script_pubkey;
  size_t script_pubkey_len;
  uint8_t* redeem_script;
  size_t redeem_script_len;
  uint8_t* witness_script;
  size_t witness_script_len;
  uint8_t* nonwitness_utxo;
  size_t nonwitness_utxo_len;
  uint8_t* amount;
  uint8_t* bip32_path;
  uint32_t bip32_path_len;
  uint32_t master_fingerprint;
  uint32_t sighash_flag;
  btc_input_type_t input_type;
  bool witness;
  bool can_sign;
} psbt_input_data_t;

typedef struct {
  psbt_tx_t tx;
  psbt_txin_t inputs[BTC_MAX_INPUTS];
  psbt_txout_t outputs[BTC_MAX_OUTPUTS];
  psbt_input_data_t input_data[BTC_MAX_INPUTS];
  bool output_is_change[BTC_MAX_OUTPUTS];
  size_t input_count;
  size_t output_count;

  psbt_t psbt_out;
  size_t index_in;
  size_t index_out;
  uint8_t hash_prevouts[SHA256_DIGEST_LENGTH];
  uint8_t hash_sequence[SHA256_DIGEST_LENGTH];
  uint8_t hash_outputs[SHA256_DIGEST_LENGTH];

  uint32_t mfp;
  app_err_t error;
} btc_tx_ctx_t;

static inline bool btc_is_bip322(const btc_tx_ctx_t* tx) {
  return (tx->input_count == 1) &&
      (tx->output_count == 1) &&
      (tx->inputs[0].sequence_number == 0) &&
      (tx->inputs[0].index == 0) &&
      !memcmp(tx->input_data[0].amount, ZERO32, sizeof(uint64_t)) &&
      !memcmp(tx->outputs[0].amount, ZERO32, sizeof(uint64_t));
}

#endif
