//
//  Contains code from:
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "slip39.h"
#include "pbkdf2.h"
#include "shamir.h"

#include <string.h>

#define FEISTEL_BASE_ITERATION_COUNT 2500
#define FEISTEL_ROUND_COUNT 4

static const uint32_t RS1024_GEN[] = {
  0x00E0E040,
  0x01C1C080,
  0x03838100,
  0x07070200,
  0x0E0E0009,
  0x1C0C2412,
  0x38086C24,
  0x3090FC48,
  0x21B1F890,
  0x03F3F120,
};

static const uint8_t SLIP39_CUSTOMIZATION[] = {
    's', 'h', 'a', 'm', 'i', 'r', '_', 'e', 'x', 't', 'e', 'n', 'd', 'a', 'b', 'l', 'e'
};

#define CUSTOMIZATION_NON_EXTENDABLE_LEN 6
#define CUSTOMIZATION_EXTENDABLE_LEN 17

static uint32_t rs1024_polymod(uint8_t ext, const uint16_t *values, uint32_t values_length) {
  uint32_t chk = 1;

  uint8_t customization_len = ext ? CUSTOMIZATION_EXTENDABLE_LEN : CUSTOMIZATION_NON_EXTENDABLE_LEN;

  for (uint32_t i = 0; i < customization_len; ++i) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10 ) ^ SLIP39_CUSTOMIZATION[i];
    for(unsigned int j=0; j<10; ++j, b>>=1) {
      chk ^= RS1024_GEN[j] * (b&1);
    }
  }

  for (uint32_t i=0; i < values_length; ++i) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10 ) ^ values[i];
    for(unsigned int j=0; j<10; ++j, b>>=1) {
      chk ^= RS1024_GEN[j] * (b&1);
    }
  }

  return chk;
}

static void rs1024_create_checksum(uint8_t ext, uint16_t *values, uint32_t n) {
  values[n-3] = 0;
  values[n-2] = 0;
  values[n-1] = 0;

  uint32_t polymod = rs1024_polymod(ext, values, n) ^ 1;

  values[n-3] = (polymod >> 20) & 1023;
  values[n-2] = (polymod >> 10) & 1023;
  values[n-1] = (polymod) & 1023;
}


static uint8_t rs1024_verify_checksum(uint8_t ext, const uint16_t *values, uint32_t n) {
  return rs1024_polymod(ext, values, n) == 1;
}

static int32_t _get_salt(uint16_t identifier, uint8_t *result, uint32_t result_length) {
  if(result_length < 8) {
      return -1;
  }

  for(unsigned int i=0; i<6; ++i) {
      result[i] = SLIP39_CUSTOMIZATION[i];
  }

  result[6] = identifier >> 8;
  result[7] = identifier & 0xff;
  return 8;
}

static void round_function(uint8_t i, const char *passphrase, uint8_t exp, const uint8_t *salt, uint32_t salt_length, const uint8_t *r, uint32_t r_length, uint8_t *dest, uint32_t dest_length) {
  size_t pass_length = strlen(passphrase) + 1;
  uint8_t pass[pass_length];
  memcpy(&pass[1], passphrase, (pass_length - 1));
  pass[0] = i;

  uint32_t iterations = FEISTEL_BASE_ITERATION_COUNT << exp;
  uint8_t saltr[salt_length + r_length];

  memcpy(saltr, salt, salt_length);
  memcpy(saltr + salt_length, r, r_length);

  pbkdf2_hmac_sha256(pass, pass_length, saltr, salt_length + r_length, iterations, dest, dest_length);
}

static void feistel(uint8_t forward, const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  uint32_t half_length = input_length / 2;
  uint8_t *l, *r, *t, f[half_length];
  uint8_t salt[8];

  memcpy(output, input + half_length, half_length);
  memcpy(output + half_length, input, half_length);

  r = output;
  l = output+half_length;

  if (!ext) {
    _get_salt(identifier, salt, 8);
  }

  for (uint8_t i = 0; i < FEISTEL_ROUND_COUNT; ++i) {
    uint8_t index;

    if (forward) {
      index = i;
    } else {
      index = FEISTEL_ROUND_COUNT - 1 - i;
    }

    round_function(index, passphrase, iteration_exponent, salt, ext ? 0 : 8, r, half_length, f, half_length);

    t = l;
    l = r;
    r = t;

    for(uint32_t j = 0; j < half_length; ++j) {
      r[j] = r[j] ^ f[j];
    }
  }
}

void slip39_encrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  feistel(1, input, input_length, passphrase, ext, iteration_exponent, identifier, output);
}

void slip39_decrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  feistel(0, input, input_length, passphrase, ext, iteration_exponent, identifier, output);
}
