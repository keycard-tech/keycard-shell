/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __BIP39_H__
#define __BIP39_H__

#include <stdbool.h>
#include <stdint.h>

#include "options.h"

#define BIP39_MAX_MNEMONIC_LEN 24
#define BIP39_WORD_COUNT 2048
#define BIP39_PBKDF2_ROUNDS 2048

extern const char *const BIP39_WORDLIST_ENGLISH[BIP39_WORD_COUNT];

bool mnemonic_from_data(uint16_t* mnemonic, uint32_t* out_len, const uint8_t *data, int len);
bool mnemonic_from_string(uint16_t* indexes, uint32_t* out_len, const char *mnemonic);

void mnemonic_from_indexes( char* mnemo, const uint16_t *indexes, int len);

int mnemonic_check(const uint16_t *mnemonic, int len);
int mnemonic_to_bits(const uint16_t *mnemonic, int n, uint8_t *bits);
bool mnemonic_from_seedqr_standard(uint16_t* mnemonic, uint32_t* out_len, const char* digits, int len);

// passphrase must be at most 256 characters otherwise it would be truncated
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[512 / 8]);

#endif
