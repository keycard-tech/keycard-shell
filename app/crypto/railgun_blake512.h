#ifndef RAILGUN_BLAKE512_H
#define RAILGUN_BLAKE512_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Original BLAKE-512, not BLAKE2b or SHA-512.
 * Output is 64 bytes. The input may be NULL only when length is zero.
 */
bool railgun_blake512(
    const uint8_t *input, size_t length, uint8_t output[64]);

#endif
