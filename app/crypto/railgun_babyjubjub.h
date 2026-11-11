#ifndef RAILGUN_BABYJUBJUB_H
#define RAILGUN_BABYJUBJUB_H

#include <stdbool.h>
#include <stdint.h>

#include "hal.h"

/*
 * Experimental public-data arithmetic over BN254 Fr.
 *
 * Full-width, big-endian scalar and coordinate encodings.
 * Input coordinates must be canonical field elements.
 *
 * Variable-time. Does not enforce subgroup membership.
 * NOT suitable for private spending scalars.
 *
 * Inputs and outputs must not overlap.
 */
hal_err_t railgun_babyjubjub_public_mul(
    const uint8_t x[32],
    const uint8_t y[32],
    const uint8_t scalar[32],
    uint8_t out_x[32],
    uint8_t out_y[32]);

/* Public-scalar diagnostics only; callback runs between scalar bytes. */
hal_err_t railgun_babyjubjub_public_mul_with_checkpoint(
    const uint8_t x[32], const uint8_t y[32],
    const uint8_t scalar[32],
    uint8_t out_x[32], uint8_t out_y[32],
    bool (*checkpoint)(void*), void* context);

#endif
