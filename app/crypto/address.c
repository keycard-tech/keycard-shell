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

#include <string.h>
#include "address.h"
#include "sha3.h"
#include "base58.h"
#include "util.h"

size_t address_prefix_bytes_len(uint32_t address_type) {
  if (address_type <= 0xFF) return 1;
  if (address_type <= 0xFFFF) return 2;
  if (address_type <= 0xFFFFFF) return 3;
  return 4;
}

void address_write_prefix_bytes(uint32_t address_type, uint8_t *out) {
  if (address_type > 0xFFFFFF) *(out++) = address_type >> 24;
  if (address_type > 0xFFFF) *(out++) = (address_type >> 16) & 0xFF;
  if (address_type > 0xFF) *(out++) = (address_type >> 8) & 0xFF;
  *(out++) = address_type & 0xFF;
}

bool address_check_prefix(const uint8_t *addr, uint32_t address_type) {
  if (address_type <= 0xFF) {
    return address_type == (uint32_t)(addr[0]);
  }
  if (address_type <= 0xFFFF) {
    return address_type == (((uint32_t)addr[0] << 8) | ((uint32_t)addr[1]));
  }
  if (address_type <= 0xFFFFFF) {
    return address_type == (((uint32_t)addr[0] << 16) |
                            ((uint32_t)addr[1] << 8) | ((uint32_t)addr[2]));
  }
  return address_type ==
         (((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) |
          ((uint32_t)addr[2] << 8) | ((uint32_t)addr[3]));
}

void address_format(addr_type_t addr_type, const uint8_t data[RIPEMD160_DIGEST_LENGTH], char out[MAX_ADDR_LEN]) {
  switch(addr_type) {
  case ADDR_ETH:
    out[0] = '0';
    out[1] = 'x';
    ethereum_address_checksum(data, &out[2]);
    return;
  case ADDR_BTC_LEGACY:
    bitcoin_legacy_address(data, BTC_P2PKH_ADDR_PREFIX, out);
    return;
  case ADDR_BTC_NESTED_SEGWIT:
    bitcoin_legacy_address(data, BTC_P2SH_ADDR_PREFIX, out);
    return;
  case ADDR_BTC_SEGWIT:
    bitcoin_segwit_address(data, RIPEMD160_DIGEST_LENGTH, out);
    return;
  }
}

size_t bitcoin_legacy_address(const uint8_t data[RIPEMD160_DIGEST_LENGTH], uint8_t prefix, char out[MAX_ADDR_LEN]) {
  uint8_t raw[RIPEMD160_DIGEST_LENGTH + 1];

  raw[0] = prefix;
  memcpy(&raw[1], data, RIPEMD160_DIGEST_LENGTH);
  return base58_encode_check(raw, RIPEMD160_DIGEST_LENGTH + 1, out, MAX_ADDR_LEN);
}

void ethereum_address(const uint8_t* pub_key, uint8_t* addr) {
  uint8_t buf[32];
  keccak_256(&pub_key[1], 64, buf);
  memcpy(addr, &buf[12], 20);
}

void ethereum_address_checksum(const uint8_t *addr, char *address) {
  base16_encode(addr, address, 20);

  uint8_t hash[32];
  keccak_256((const uint8_t *)(address), 40, hash);

  for (int i = 0; i < 20; i++) {
    if ((hash[i] & 0x80) && address[i * 2] >= 'a' && address[i * 2] <= 'f') {
      address[i * 2] -= 0x20;
    }
    if ((hash[i] & 0x08) && address[i * 2 + 1] >= 'a' && address[i * 2 + 1] <= 'f') {
      address[i * 2 + 1] -= 0x20;
    }
  }
}
