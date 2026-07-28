/**
 * Copyright (c) 2016 Pavol Rusnak
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

#ifndef __SCRIPT_H__
#define __SCRIPT_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "address.h"
#include "ripemd160.h"

#define BTC_PUBKEY_HASH_LEN 20
#define BTC_WITNESS_LEN 32
#define BTC_P2PKH_LEN 25
#define BTC_P2SH_LEN 23
#define BTC_P2TR_LEN 34
#define OP_1 0x51

static inline bool script_is_p2wpkh(const uint8_t* script, size_t script_len) {
  return (script_len == BTC_PUBKEY_HASH_LEN + 2) &&
         (script[0] == 0) &&
         (script[1] == BTC_PUBKEY_HASH_LEN);
}

static inline bool script_is_p2wsh(const uint8_t* script, size_t script_len) {
  return (script_len == BTC_WITNESS_LEN + 2) &&
         (script[0] == 0) &&
         (script[1] == BTC_WITNESS_LEN);
}

static inline bool script_is_p2pkh(const uint8_t* script, size_t script_len) {
  return (script_len == BTC_P2PKH_LEN) &&
         (script[0] == 0x76) &&
         (script[1] == 0xa9) &&
         (script[2] == RIPEMD160_DIGEST_LENGTH) &&
         (script[23] == 0x88) &&
         (script[24] == 0xac);
}

static inline bool script_is_p2sh(const uint8_t* script, size_t script_len) {
  return (script_len == BTC_P2SH_LEN) &&
         (script[0] == 0xa9) &&
         (script[1] == RIPEMD160_DIGEST_LENGTH) &&
         (script[22] == 0x87);
}

static inline bool script_is_p2tr(const uint8_t* script, size_t script_len) {
  return (script_len == BTC_P2TR_LEN) &&
         (script[0] == OP_1) &&
         (script[1] == BTC_TAPROOT_WITPROG_LEN);
}

int script_output_to_address(const uint8_t *script, int script_len, char addr[MAX_ADDR_LEN]);

#endif
