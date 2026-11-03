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

/* The public-key accelerator and the bignum unit behind it live on the device, and
 * app/crypto/ecdsa.c calls them from every function except the DER reader. They are declared here so
 * that a test of that reader links. Anything that actually reaches one of them stops with this
 * message rather than answering with a value no hardware produced. */
static void pka_absent(const char* fn) {
  fprintf(stderr, "%s: the public key accelerator is not reachable from a host test\n", fn);
  abort();
}

hal_err_t hal_ecdsa_sign(const ecdsa_curve* curve, const uint8_t* priv_key, const uint8_t* digest,
                         const uint8_t* k, uint8_t* sig_out) {
  (void)curve; (void)priv_key; (void)digest; (void)k; (void)sig_out;
  pka_absent(__func__);
  return HAL_FAIL;
}

hal_err_t hal_ecdsa_verify(const ecdsa_curve* curve, const uint8_t* pub_key, const uint8_t* sig,
                           const uint8_t* digest) {
  (void)curve; (void)pub_key; (void)sig; (void)digest;
  pka_absent(__func__);
  return HAL_FAIL;
}

hal_err_t hal_ec_point_multiply(const ecdsa_curve* curve, const uint8_t* scalar,
                                const uint8_t* point, uint8_t* point_out) {
  (void)curve; (void)scalar; (void)point; (void)point_out;
  pka_absent(__func__);
  return HAL_FAIL;
}

hal_err_t hal_ec_double_ladder(const ecdsa_curve* curve, const uint8_t* s1, const uint8_t* p1,
                               const uint8_t* s2, const uint8_t* p2, uint8_t* point_out) {
  (void)curve; (void)s1; (void)p1; (void)s2; (void)p2; (void)point_out;
  pka_absent(__func__);
  return HAL_FAIL;
}

hal_err_t hal_ec_point_check(const ecdsa_curve* curve, const uint8_t* point) {
  (void)curve; (void)point;
  pka_absent(__func__);
  return HAL_FAIL;
}

#define PKA_ABSENT_MOD(op, args)                                        \
  hal_err_t hal_bn_##op args {                                          \
    pka_absent(__func__);                                               \
    return HAL_FAIL;                                                    \
  }

PKA_ABSENT_MOD(mul_r2, (const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(mul_mont, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                          const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(mul_mod, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(add_mod, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(sub_mod, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(exp_mod, (const uint8_t a[BN_SIZE], const uint8_t e[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(inv_mod, (const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(mul, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(add, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]))
PKA_ABSENT_MOD(sub, (const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]))

int hal_bn_cmp(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE]) {
  (void)a; (void)b;
  pka_absent(__func__);
  return 0;
}
