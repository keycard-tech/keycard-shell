#ifndef PSBT_H
#define PSBT_H

#include <stddef.h>
#include <stdio.h>
#include "psbt_tx.h"

enum psbt_global_type {
  PSBT_GLOBAL_UNSIGNED_TX = 0
};

enum psbt_input_type {
  PSBT_IN_NON_WITNESS_UTXO    = 0,
  PSBT_IN_WITNESS_UTXO        = 1,
  PSBT_IN_PARTIAL_SIG         = 2,
  PSBT_IN_SIGHASH_TYPE        = 3,
  PSBT_IN_REDEEM_SCRIPT       = 4,
  PSBT_IN_WITNESS_SCRIPT      = 5,
  PSBT_IN_BIP32_DERIVATION    = 6,
  PSBT_IN_FINAL_SCRIPTSIG     = 7,
  PSBT_IN_FINAL_SCRIPTWITNESS = 8,
  // BIP371 Taproot fields
  PSBT_IN_TAP_KEY_SIG         = 0x13,
  PSBT_IN_TAP_SCRIPT_SIG      = 0x14,
  PSBT_IN_TAP_LEAF_SCRIPT     = 0x15,
  PSBT_IN_TAP_BIP32_DERIVATION = 0x16,
  PSBT_IN_TAP_INTERNAL_KEY    = 0x17,
  PSBT_IN_TAP_MERKLE_ROOT     = 0x18,
};

enum psbt_output_type {
  PSBT_OUT_REDEEM_SCRIPT      = 0,
  PSBT_OUT_WITNESS_SCRIPT     = 1,
  PSBT_OUT_BIP32_DERIVATION   = 2,
  // BIP371 Taproot fields
  PSBT_OUT_TAP_INTERNAL_KEY   = 5,
  PSBT_OUT_TAP_TREE           = 6,
  PSBT_OUT_TAP_BIP32_DERIVATION = 7,
};

enum psbt_scope {
  PSBT_SCOPE_GLOBAL,
  PSBT_SCOPE_INPUTS,
  PSBT_SCOPE_OUTPUTS,
};

enum psbt_state {
  PSBT_ST_INIT = 2,
  PSBT_ST_GLOBAL,
  PSBT_ST_INPUTS,
  PSBT_ST_INPUTS_NEW,
  PSBT_ST_OUTPUTS,
  PSBT_ST_OUTPUTS_NEW,
  PSBT_ST_FINALIZED,
};

typedef struct {
  enum psbt_state state;
  uint8_t *data;
  uint8_t *write_pos;
  size_t data_capacity;
} psbt_t;

typedef struct {
  uint8_t type;
  uint8_t *key;
  size_t key_size;
  uint8_t *val;
  size_t val_size;
  enum psbt_scope scope;
} psbt_record_t;

enum psbt_elem_type {
  PSBT_ELEM_RECORD,
  PSBT_ELEM_TXELEM,
};

typedef struct {
  enum psbt_elem_type type;
  void *user_data;
  int index;
  union {
    psbt_txelem_t *txelem;
    psbt_record_t *rec;
  } elem;
} psbt_elem_t;

typedef void (psbt_elem_handler_t)(psbt_elem_t *rec);

typedef struct {
  int inputs;
  int outputs;
  void *user_data;
  psbt_elem_handler_t *handler;
} psbt_tx_counter_t;


size_t psbt_size(psbt_t *tx);
psbt_result_t psbt_read(const uint8_t *src, size_t src_size, psbt_t *psbt, psbt_elem_handler_t *elem_handler, void* user_data);

psbt_result_t psbt_write_global_record(psbt_t *tx, psbt_record_t *rec);
psbt_result_t psbt_write_input_record(psbt_t *tx, psbt_record_t *rec);
psbt_result_t psbt_write_output_record(psbt_t *tx, psbt_record_t *rec);
psbt_result_t psbt_new_input_record_set(psbt_t *tx);
psbt_result_t psbt_new_output_record_set(psbt_t *tx);

psbt_result_t psbt_init(psbt_t *tx, uint8_t *dest, size_t dest_size);
psbt_result_t psbt_finalize(psbt_t *tx);

#endif /* PSBT_H */
