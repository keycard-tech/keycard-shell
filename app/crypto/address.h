/**
 * Copyright (c) 2016 Daira Hopwood
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

#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ripemd160.h"
#include "segwit_addr.h"

#define MAX_ADDR_LEN 91

#define BTC_P2PKH_ADDR_PREFIX 0
#define BTC_P2SH_ADDR_PREFIX 5

typedef enum {
  ADDR_ETH,
  ADDR_BTC_LEGACY,
  ADDR_BTC_NESTED_SEGWIT,
  ADDR_BTC_SEGWIT,
  ADDR_BTC_TAPROOT
} addr_type_t;

size_t address_prefix_bytes_len(uint32_t address_type);
void address_write_prefix_bytes(uint32_t address_type, uint8_t *out);
bool address_check_prefix(const uint8_t *addr, uint32_t address_type);

int address_format(addr_type_t addr_type, const uint8_t* data, char out[MAX_ADDR_LEN]);
size_t bitcoin_legacy_address(const uint8_t data[RIPEMD160_DIGEST_LENGTH], uint8_t prefix, char out[MAX_ADDR_LEN]);

static inline size_t bitcoin_segwit_address(const uint8_t* data, size_t data_len, int witver, char out[MAX_ADDR_LEN]) {
  return segwit_addr_encode(out, BTC_BECH32_HRP, witver, data, data_len);
}

void ethereum_address(const uint8_t* pub_key, uint8_t* addr);
void ethereum_address_checksum(const uint8_t *addr, char *address);

#endif
