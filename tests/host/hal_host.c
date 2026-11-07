#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "hal.h"
#include "hal_host.h"

/*
 * Host implementation of the hal_ interface. Only what a test actually needs is here; a
 * function that needs silicon is not stubbed at all, so pulling it into a test produces a
 * link error naming the function. Add a stub here only when a test can drive it meaningfully.
 *
 * One exception, at the bottom of the file: a test that wants a function living in the same
 * translation unit as silicon does need the object to link at all. Those stubs abort and name
 * themselves, so the boundary still shows up as a failure rather than as a value.
 */

static uint64_t rng_state;
static size_t rng_drawn;
static bool rng_refuse_next;

void hal_host_rng_seed(uint64_t seed) {
  rng_state = seed;
  rng_drawn = 0;
  rng_refuse_next = false;
}

void hal_host_rng_refuse_next(void) {
  rng_refuse_next = true;
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
  if (rng_refuse_next) {
    rng_refuse_next = false;
    return HAL_FAIL;
  }
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(splitmix64() >> 24);
  }
  rng_drawn += len;
  return HAL_SUCCESS;
}

/* hal_pka_host.c supplies the public key accelerator's five curve operations and the bignum
 * helpers app/ uses. What is left here aborts: the Montgomery-specific trio, which app/ never
 * calls, and which nothing should answer for without silicon to say what it does. */
static void pka_absent(const char* fn) {
  fprintf(stderr, "%s: the public key accelerator is not reachable from a host test\n", fn);
  abort();
}

#define PKA_ABSENT_MOD(op, args)                                        \
  hal_err_t hal_bn_##op args {                                          \
    pka_absent(__func__);                                               \
    return HAL_FAIL;                                                    \
  }

PKA_ABSENT_MOD(mul_r2, (const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(mul_mont, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                          const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(mul, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]))
