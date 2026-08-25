#ifndef __BIP32_H__
#define __BIP32_H__

#include <stdint.h>
#include <stddef.h>

#define BIP32_PUBKEY_LEN 65     /* uncompressed (0x04 || x || y) */
#define BIP32_CHAINCODE_LEN 32

/**
 * Derive a non-hardened child from a parent extended public key (CKDpub).
 *
 * BIP32 public derivation only works for non-hardened child indices; hardened
 * derivation requires the private key and must always go through the card.
 *
 * @param pub65     65-byte uncompressed parent public key (0x04 || x || y)
 * @param chain     32-byte parent chain code
 * @param index     non-hardened child index (hardened bit must be clear)
 * @param out_pub65 65-byte uncompressed child public key
 * @param out_chain 32-byte child chain code
 * @return 0 on success, non-zero on failure
 */
int bip32_ckd_pub(const uint8_t* pub65, const uint8_t* chain, uint32_t index, uint8_t* out_pub65, uint8_t* out_chain);

#endif /* __BIP32_H__ */
