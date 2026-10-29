#ifndef __TAPROOT_H__
#define __TAPROOT_H__

#include <stdbool.h>
#include <stdint.h>

#include "crypto/bip32.h"
#include "crypto/segwit_addr.h"

/**
 * BIP86 P2TR output key (the 32-byte witness program) for a BIP32 leaf public
 * key stored in the bip32_ctx_t.leaf_pub layout: byte 0 holds the SEC1
 * compression prefix while x || y follow, so the buffer is neither a compressed
 * nor an uncompressed key on its own.
 */
bool bitcoin_taproot_output_key(const uint8_t pub[BIP32_PUBKEY_LEN], uint8_t out[BTC_TAPROOT_WITPROG_LEN]);

#endif
