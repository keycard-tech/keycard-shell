#ifndef RAILGUN_POSEIDON_T6_H
#define RAILGUN_POSEIDON_T6_H

#include <stdbool.h>
#include <stdint.h>

#include "hal.h"

/*
 * RAILGUN-compatible five-input Poseidon over BN254 Fr.
 * Inputs and output use 32-byte big-endian encoding.
 * Inputs are reduced modulo Fr, matching kohaku_crypto.
 *
 * Experimental public-data implementation; not a signing API.
 */
hal_err_t railgun_poseidon_t6_hash(
    const uint8_t inputs[5][32], uint8_t out[32]);

/* Public-data diagnostics only; callback runs between rounds. */
hal_err_t railgun_poseidon_t6_hash_with_checkpoint(
    const uint8_t inputs[5][32], uint8_t out[32],
    bool (*checkpoint)(void*), void* context);

#endif
