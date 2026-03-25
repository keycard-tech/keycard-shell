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

#include "script.h"
#include "address.h"
#include "sha2.h"

int script_output_to_address(const uint8_t *script, int script_len, char addr[MAX_ADDR_LEN]) {
  if (script_is_p2wpkh(script, script_len)) {
    return bitcoin_segwit_address(&script[2], RIPEMD160_DIGEST_LENGTH, addr);
  } else if (script_is_p2wsh(script, script_len)) {
    return bitcoin_segwit_address(&script[2], SHA256_DIGEST_LENGTH, addr);
  } else if (script_is_p2pkh(script, script_len)) {
    return bitcoin_legacy_address(&script[3], BTC_P2PKH_ADDR_PREFIX, addr);
  } else if (script_is_p2sh(script, script_len)) {
    return bitcoin_legacy_address(&script[2], BTC_P2SH_ADDR_PREFIX, addr);
  }

  return 0;
}
