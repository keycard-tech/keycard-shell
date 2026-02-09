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

#include <stdbool.h>
#include <string.h>

#include "bip39.h"
#include "hmac.h"
#include "memzero.h"
#include "options.h"
#include "pbkdf2.h"
#include "rand.h"
#include "sha2.h"
#include "util.h"

bool mnemonic_from_data(uint16_t* mnemonic, uint32_t* out_len, const uint8_t* data, int len) {
  if ((len != 16) && (len != 32)) {
    return false;
  }

  uint8_t bits[32 + 1] = {0};

  sha256_Raw(data, len, bits);
  // checksum
  bits[len] = bits[0];
  // data
  memcpy(bits, data, len);

  *out_len = len * 3 / 4;

  int i = 0, j = 0, idx = 0;

  for (i = 0; i < *out_len; i++) {
    idx = 0;
    for (j = 0; j < 11; j++) {
      idx <<= 1;
      idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
    }

    mnemonic[i] = idx;
  }

  memzero(bits, sizeof(bits));

  return true;
}

void mnemonic_from_indexes(char* mnemo, const uint16_t* indexes, int len) {
  char *p = mnemo;
  for (int i = 0; i < len; i++) {
    uint16_t idx = indexes[i];
    strcpy(p, BIP39_WORDLIST_ENGLISH[idx]);
    p += strlen(BIP39_WORDLIST_ENGLISH[idx]);
    *(p++) = ' ';
  }

  *(--p) = '\0';
}

bool mnemonic_from_seedqr_standard(uint16_t* mnemonic, uint32_t* out_len, const char* digits, int len) {
  if ((len != 48) && (len != 96)) {
    return false;
  }

  *out_len = len / 4;

  for (int i = 0; i < len; i += 4) {
    mnemonic[i / 4] = ((digits[i] - '0') * 1000) + ((digits[i + 1] - '0') * 100) + ((digits[i + 2] - '0') * 10) + (digits[i + 3] - '0');

    if (mnemonic[i / 4] >= BIP39_WORD_COUNT) {
      return false;
    }
  }

  return true;
}

int mnemonic_to_bits(const uint16_t *mnemonic, int n, uint8_t *bits) {
  // check that number of words is valid for BIP-39:
  // (a) between 128 and 256 bits of initial entropy (12 - 24 words)
  // (b) number of bits divisible by 33 (1 checksum bit per 32 input bits)
  //     - that is, (n * 11) % 33 == 0, so n % 3 == 0
  if (n < 12 || n > 24 || (n % 3)) {
    return 0;
  }

  uint32_t bi = 0;
  uint8_t result[32 + 1] = {0};
  memzero(result, sizeof(result));

  for (int i = 0; i < n; i++) {
    int k = mnemonic[i];

    for (int ki = 0; ki < 11; ki++) {
      if (k & (1 << (10 - ki))) {
        result[bi / 8] |= 1 << (7 - (bi % 8));
      }
      bi++;
    }
  }

  if (bi != n * 11) {
    return 0;
  }

  memcpy(bits, result, sizeof(result));
  memzero(result, sizeof(result));

  // returns amount of entropy + checksum BITS
  return n * 11;
}

static bool mnemonic_check_bits(uint8_t* bits, int words) {
  uint8_t checksum = bits[words * 4 / 3];
  sha256_Raw(bits, words * 4 / 3, bits);
  if (words == 12) {
    return (bits[0] & 0xF0) == (checksum & 0xF0);  // compare first 4 bits
  } else if (words == 18) {
    return (bits[0] & 0xFC) == (checksum & 0xFC);  // compare first 6 bits
  } else if (words == 24) {
    return bits[0] == checksum;  // compare 8 bits
  }
  return 0;
}

int mnemonic_check(const uint16_t *mnemonic, int len) {
  uint8_t bits[32 + 1] = {0};
  int mnemonic_bits_len = mnemonic_to_bits(mnemonic, len, bits);
  if (mnemonic_bits_len != (12 * 11) && mnemonic_bits_len != (18 * 11) &&
      mnemonic_bits_len != (24 * 11)) {
    return 0;
  }

  int words = mnemonic_bits_len / 11;

  return mnemonic_check_bits(bits, words);
}

// passphrase must be at most 256 characters otherwise it would be truncated
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[512 / 8]) {
  int mnemoniclen = strlen(mnemonic);
  int passphraselen = strnlen(passphrase, 256);

  uint8_t salt[8 + 256] = {0};
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase, passphraselen);
  PBKDF2_HMAC_SHA512_CTX pctx;
  pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)mnemonic, mnemoniclen, salt, passphraselen + 8, 1);

  for (int i = 0; i < 16; i++) {
    pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 16);
  }

  pbkdf2_hmac_sha512_Final(&pctx, seed);
  memzero(salt, sizeof(salt));
}

bool mnemonic_from_string(uint16_t* indexes, uint32_t* out_len, const char *mnemonic) {
  if (!mnemonic) {
    return 0;
  }

  uint32_t i = 0, n = 0;

  while (mnemonic[i]) {
    if (mnemonic[i] == ' ') {
      n++;
    }
    i++;
  }

  n++;

  // check number of words
  if (n != 12 && n != 24) {
    return false;
  }

  *out_len = 0;

  char current_word[10];
  uint32_t j, k;

  i = 0;

  while (mnemonic[i]) {
    j = 0;

    while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
      if (j >= sizeof(current_word) - 1) {
        return false;
      }
      current_word[j] = mnemonic[i];
      i++;
      j++;
    }

    current_word[j] = 0;

    if (mnemonic[i] != 0) {
      i++;
    }

    k = 0;

    for (;;) {
      if (k >= BIP39_WORD_COUNT) {
        return false;
      }

      if (strcmp(current_word, BIP39_WORDLIST_ENGLISH[k]) == 0) {
        indexes[(*out_len)++] = k;
        break;
      }

      k++;
    }
  }

  return true;
}

