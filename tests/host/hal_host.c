#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "hal.h"
#include "hal_host.h"

/*
 * Host implementation of the hal_ interface. Only what a test actually needs is here; a
 * function that needs silicon is not stubbed at all, so pulling it into a test produces a
 * link error naming the function. Add a stub here only when a test can drive it meaningfully.
 */

static uint64_t rng_state;
static size_t rng_drawn;

void hal_host_rng_seed(uint64_t seed) {
  rng_state = seed;
  rng_drawn = 0;
}

size_t hal_host_rng_count(void) {
  return rng_drawn;
}

/* splitmix64: reproducible across compilers and platforms, unlike rand(). */
static uint64_t splitmix64(void) {
  uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

hal_err_t hal_rng_next(uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(splitmix64() >> 24);
  }
  rng_drawn += len;
  return HAL_SUCCESS;
}
