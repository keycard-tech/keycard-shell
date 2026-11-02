#ifndef BITCOIN_PSBT_CTX_H
#define BITCOIN_PSBT_CTX_H

#include <stdbool.h>

#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"

void btc_psbt_input_record(btc_tx_ctx_t* tx_ctx, size_t index, psbt_record_t* rec);
void btc_psbt_output_record(btc_tx_ctx_t* tx_ctx, size_t index, psbt_record_t* rec);
void btc_psbt_tx_element(btc_tx_ctx_t* tx_ctx, psbt_txelem_t* elem);
void btc_psbt_prevtx_output(psbt_txelem_t* elem);

void btc_psbt_element(psbt_elem_t* rec);


app_err_t btc_psbt_validate_inputs(btc_tx_ctx_t* tx_ctx);

bool btc_psbt_any_can_sign(const btc_tx_ctx_t* tx_ctx);

bool btc_redeem_script_matches(const uint8_t* script, size_t script_len,
                               const uint8_t* redeem_script, size_t redeem_script_len);
bool btc_witness_script_matches(const uint8_t* script, size_t script_len,
                                const uint8_t* witness_script, size_t witness_script_len);

#endif /* BITCOIN_PSBT_CTX_H */
