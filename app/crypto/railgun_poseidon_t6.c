#include "crypto/railgun_poseidon_t6.h"

#include <string.h>

#include "crypto/railgun_poseidon_t6_constants.h"

#define POSEIDON_T6_WIDTH 6
#define POSEIDON_T6_ROUNDS 68

static const uint8_t poseidon_t6_fr[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
};

/* Public field inputs only. BN254 Fr needs at most five subtractions. */
static void reduce_input(
    const uint8_t input[32], uint8_t output[32]) {
  memcpy(output, input, 32);

  while (memcmp(output, poseidon_t6_fr, 32) >= 0) {
    unsigned borrow = 0;

    for (int i = 31; i >= 0; i--) {
      unsigned lhs = output[i];
      unsigned rhs = (unsigned)poseidon_t6_fr[i] + borrow;
      output[i] = (uint8_t)(lhs - rhs);
      borrow = lhs < rhs;
    }
  }
}

/* Use separate outputs; never depend on HAL input/output aliasing. */
static hal_err_t add_into(
    uint8_t accumulator[32], const uint8_t other[32]) {
  uint8_t next[32];

  if (hal_bn_add_mod(
          accumulator, other, poseidon_t6_fr, next) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  memcpy(accumulator, next, 32);
  return HAL_SUCCESS;
}

static hal_err_t sbox5(uint8_t value[32]) {
  uint8_t square[32], fourth[32], fifth[32];

  if (hal_bn_mul_mod(
          value, value, poseidon_t6_fr, square) != HAL_SUCCESS ||
      hal_bn_mul_mod(
          square, square, poseidon_t6_fr, fourth) != HAL_SUCCESS ||
      hal_bn_mul_mod(
          fourth, value, poseidon_t6_fr, fifth) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  memcpy(value, fifth, 32);
  return HAL_SUCCESS;
}

hal_err_t railgun_poseidon_t6_hash_with_checkpoint(
    const uint8_t inputs[5][32], uint8_t out[32],
    bool (*checkpoint)(void*), void* context) {
  if (inputs == NULL || out == NULL) {
    return HAL_FAIL;
  }

  uint8_t state[POSEIDON_T6_WIDTH][32] = {{0}};
  uint8_t mixed[POSEIDON_T6_WIDTH][32];
  uint8_t product[32];

  for (unsigned i = 0; i < 5; i++) {
    reduce_input(inputs[i], state[i + 1]);
  }

  for (unsigned round = 0; round < POSEIDON_T6_ROUNDS; round++) {
    if (checkpoint && !checkpoint(context)) {
      return HAL_FAIL;
    }
    for (unsigned i = 0; i < POSEIDON_T6_WIDTH; i++) {
      if (add_into(state[i], poseidon_t6_rc[round][i]) != HAL_SUCCESS) {
        return HAL_FAIL;
      }
    }

    /* First four and last four rounds apply the S-box to all lanes. */
    const bool full_round = round < 4 || round >= 64;

    for (unsigned i = 0;
         i < (full_round ? POSEIDON_T6_WIDTH : 1); i++) {
      if (sbox5(state[i]) != HAL_SUCCESS) {
        return HAL_FAIL;
      }
    }

    memset(mixed, 0, sizeof(mixed));

    for (unsigned row = 0; row < POSEIDON_T6_WIDTH; row++) {
      for (unsigned col = 0; col < POSEIDON_T6_WIDTH; col++) {
        if (hal_bn_mul_mod(
                poseidon_t6_mds[row][col],
                state[col], poseidon_t6_fr, product) != HAL_SUCCESS ||
            add_into(mixed[row], product) != HAL_SUCCESS) {
          return HAL_FAIL;
        }
      }
    }

    memcpy(state, mixed, sizeof(state));
  }

  memcpy(out, state[0], 32);
  return HAL_SUCCESS;
}

hal_err_t railgun_poseidon_t6_hash(
    const uint8_t inputs[5][32], uint8_t out[32]) {
  return railgun_poseidon_t6_hash_with_checkpoint(
      inputs, out, NULL, NULL);
}
