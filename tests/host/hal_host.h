#ifndef HAL_HOST_H
#define HAL_HOST_H

#include <stdint.h>
#include <stddef.h>

/*
 * Controls for the host implementation of the hal_ interface. Tests that reach a function
 * which needs silicon abort with the function's name instead of returning a value that
 * would look like a pass.
 */

/* Seed for the deterministic byte source behind hal_rng_next(). Set before the code under
 * test draws random bytes; two runs with the same seed must take the same path. */
void hal_host_rng_seed(uint64_t seed);

/* Bytes drawn so far, so a test can assert that a code path consumed randomness at all. */
size_t hal_host_rng_count(void);

#endif
