#ifndef BITCOIN_SIGHASH_H
#define BITCOIN_SIGHASH_H

#include <stddef.h>
#include <stdint.h>

#include "bitcoin/bitcoin.h"

app_err_t btc_sighash_legacy(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]);
app_err_t btc_sighash_segwit(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]);

app_err_t btc_sighash_taproot(const btc_tx_ctx_t* tx_ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]);

void btc_sighash_common_hashes(btc_tx_ctx_t* tx_ctx);

#endif /* BITCOIN_SIGHASH_H */
