#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hal.h"
#include "hal_host.h"
#include "pwr.h"

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

/* The device serial. Fixed, because a reply that carries it is only checkable against a known value;
 * hal_host_device_uid_set() is for the rare test that needs two devices to differ. */
static uint8_t device_uid[HAL_DEVICE_UID_LEN] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

void hal_host_device_uid_set(const uint8_t uid[HAL_DEVICE_UID_LEN]) {
  memcpy(device_uid, uid, HAL_DEVICE_UID_LEN);
}

hal_err_t hal_device_uid(uint8_t out[HAL_DEVICE_UID_LEN]) {
  memcpy(out, device_uid, HAL_DEVICE_UID_LEN);
  return HAL_SUCCESS;
}

/* Counted, not performed: a firmware upgrade's whole promise to the other bank is that it asks for the
 * switch and then reboots, so both halves have to be observable. */
static unsigned reboots;

unsigned hal_host_reboots(void) {
  return reboots;
}

void hal_host_reboots_clear(void) {
  reboots = 0;
}

void pwr_reboot(void) {
  reboots++;
}
