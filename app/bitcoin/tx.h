#ifndef BITCOIN_TX_H
#define BITCOIN_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto/sha2.h"

bool btc_validate_tx_hash(const uint8_t* tx, size_t tx_len, const uint8_t expected_hash[SHA256_DIGEST_LENGTH]);

#endif /* BITCOIN_TX_H */
