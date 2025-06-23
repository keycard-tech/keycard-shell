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

bool mnemonic_generate(char* mnemo, int strength) {
  if (strength % 32 || strength < 128 || strength > 256) {
    return false;
  }
  uint8_t data[32] = {0};
  random_buffer(data, 32);
  if (!mnemonic_from_data(mnemo, data, strength / 8)) {
    return false;
  }

  memzero(data, sizeof(data));
  return true;
}

bool mnemonic_from_data(char* mnemo, const uint8_t *data, int len) {
  if (len % 4 || len < 16 || len > 32) {
    return false;
  }

  uint8_t bits[32 + 1] = {0};

  sha256_Raw(data, len, bits);
  // checksum
  bits[len] = bits[0];
  // data
  memcpy(bits, data, len);

  int mlen = len * 3 / 4;

  int i = 0, j = 0, idx = 0;
  char *p = mnemo;
  for (i = 0; i < mlen; i++) {
    idx = 0;
    for (j = 0; j < 11; j++) {
      idx <<= 1;
      idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
    }
    strcpy(p, BIP39_WORDLIST_ENGLISH[idx]);
    p += strlen(BIP39_WORDLIST_ENGLISH[idx]);
    *p = (i < mlen - 1) ? ' ' : 0;
    p++;
  }
  memzero(bits, sizeof(bits));

  return true;
}

void mnemonic_from_indexes(char* mnemo, const uint16_t *indexes, int len) {
  char *p = mnemo;
  for (int i = 0; i < len; i++) {
    uint16_t idx = indexes[i];
    strcpy(p, BIP39_WORDLIST_ENGLISH[idx]);
    p += strlen(BIP39_WORDLIST_ENGLISH[idx]);
    *(p++) = ' ';
  }

  *(--p) = '\0';
}

bool mnemonic_from_seedqr_standard(char* mnemo, char* digits, int len) {
  if (len % 4 || len < 48 || len > 96) {
    return false;
  }

  uint16_t idxs[len / 4];

  for (int i = 0; i < len; i += 4) {
    idxs[i / 4] = ((digits[i] - '0') * 1000) + ((digits[i + 1] - '0') * 100) + ((digits[i + 2] - '0') * 10) + (digits[i + 3] - '0');

    if (idxs[i / 4] >= BIP39_WORD_COUNT) {
      return false;
    }
  }

  if (!mnemonic_check(idxs, len / 4)) {
    return false;
  }

  mnemonic_from_indexes(mnemo, idxs, len / 4);
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

static int mnemonic_check_bits(uint8_t* bits, int words) {
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

int mnemonic_check_string(const char *mnemonic) {
  uint8_t bits[32 + 1];
  int seed_len = mnemonic_to_entropy(mnemonic, bits);
  if (seed_len != (12 * 11) && seed_len != (18 * 11) && seed_len != (24 * 11)) {
    return 0;
  }
  int words = seed_len / 11;

  return mnemonic_check_bits(bits, words);
}

// passphrase must be at most 256 characters otherwise it would be truncated
void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total)) {
  int mnemoniclen = strlen(mnemonic);
  int passphraselen = strnlen(passphrase, 256);

  uint8_t salt[8 + 256] = {0};
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase, passphraselen);
  static CONFIDENTIAL PBKDF2_HMAC_SHA512_CTX pctx;
  pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)mnemonic, mnemoniclen, salt,
                          passphraselen + 8, 1);
  if (progress_callback) {
    progress_callback(0, BIP39_PBKDF2_ROUNDS);
  }
  for (int i = 0; i < 16; i++) {
    pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 16);
    if (progress_callback) {
      progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 16,
                        BIP39_PBKDF2_ROUNDS);
    }
  }

  pbkdf2_hmac_sha512_Final(&pctx, seed);
  memzero(salt, sizeof(salt));
}

int mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy) {
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
  if (n != 12 && n != 18 && n != 24) {
    return 0;
  }

  char current_word[10];
  uint32_t j, k, ki, bi = 0;
  uint8_t bits[32 + 1];

  memzero(bits, sizeof(bits));
  i = 0;
  while (mnemonic[i]) {
    j = 0;
    while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
      if (j >= sizeof(current_word) - 1) {
        return 0;
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
      if (!BIP39_WORDLIST_ENGLISH[k]) {  // word not found
        return 0;
      }
      if (strcmp(current_word, BIP39_WORDLIST_ENGLISH[k]) == 0) {  // word found on index k
        for (ki = 0; ki < 11; ki++) {
          if (k & (1 << (10 - ki))) {
            bits[bi / 8] |= 1 << (7 - (bi % 8));
          }
          bi++;
        }
        break;
      }
      k++;
    }
  }
  if (bi != n * 11) {
    return 0;
  }
  memcpy(entropy, bits, sizeof(bits));
  return n * 11;
}

