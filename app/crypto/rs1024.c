//
//  rs1024.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "rs1024.h"

//////////////////////////////////////////////////
// rs1024 checksum functions

static const uint32_t generator[] = {
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

static const uint8_t customization[] = {
    's', 'h', 'a', 'm', 'i', 'r', '_', 'e', 'x', 't', 'e', 'n', 'd', 'a', 'b', 'l', 'e'
};

#define CUSTOMIZATION_NON_EXTENDABLE_LEN 6
#define CUSTOMIZATION_EXTENDABLE_LEN 17

uint32_t rs1024_polymod(uint8_t ext, const uint16_t *values, uint32_t values_length) {
  // there are a bunch of hard coded magic numbers in this
  // that would have to be changed if the value of CHECKSUM_LENGTH_WORDS
  // were to change.

  // unsigned ints are assumed to be 32 bits, which is enough to hold
  // CHECKSUM_LENGTH_WORDS * RADIX_BITS
  uint32_t chk = 1;

  uint8_t customization_len = ext ? CUSTOMIZATION_EXTENDABLE_LEN : CUSTOMIZATION_NON_EXTENDABLE_LEN;

  // initialize with the customization string
  for(uint32_t i = 0; i < customization_len; ++i) {
    // 20 = (CHESUM_LENGTH_WORDS - 1) * RADIX_BITS
    uint32_t b = chk >> 20;
    // 0xFFFFF = (1 << ((CHECKSUM_LENGTH_WORDS-1)*RADIX_BITS)) - 1
    // 10 = RADIX_BITS
    chk = ((chk & 0xFFFFF) << 10 ) ^ customization[i];
    for(unsigned int j=0; j<10; ++j, b>>=1) {
      chk ^= generator[j] * (b&1);
    }
  }

  // continue with the values
  for(uint32_t i=0; i < values_length; ++i) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10 ) ^ values[i];
    for(unsigned int j=0; j<10; ++j, b>>=1) {
      chk ^= generator[j] * (b&1);
    }
  }

  return chk;
}

void rs1024_create_checksum(uint8_t ext, uint16_t *values, uint32_t n) {
  // Set the last three words to zero
  values[n-3] = 0;
  values[n-2] = 0;
  values[n-1] = 0;

  // compute the checkum
  uint32_t polymod = rs1024_polymod(ext, values, n) ^ 1;

  // fix up the last three words to make the checksum come out to the right number
  values[n-3] = (polymod >> 20) & 1023;
  values[n-2] = (polymod >> 10) & 1023;
  values[n-1] = (polymod) & 1023;
}


uint8_t rs1024_verify_checksum(uint8_t ext, const uint16_t *values, uint32_t n) {
  return rs1024_polymod(ext, values, n) == 1;
}
