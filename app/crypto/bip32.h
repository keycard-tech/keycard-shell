#ifndef __BIP32_H__
#define __BIP32_H__

#include <stdint.h>
#include <stddef.h>
#include "crypto/ripemd160.h"

#define BIP32_PUBKEY_LEN 65     /* uncompressed (0x04 || x || y) */
#define BIP32_CHAINCODE_LEN 32

/*
 * Derivation context for a BIP32 account. It holds the account-level extended
 * public key (purpose' / coin' / account'), the cached change-level keys, and a
 * scratch buffer for the derived leaf public key. The account key must be
 * exported from the card (hardened derivation); all further derivation is done
 * on device via public key derivation.
 */
typedef struct {
  uint32_t purpose;
  uint32_t coin;
  uint32_t account;
  uint8_t account_pub[BIP32_PUBKEY_LEN];
  uint8_t account_chain[BIP32_CHAINCODE_LEN];
  uint8_t change_pub[BIP32_PUBKEY_LEN];
  uint8_t change_chain[BIP32_CHAINCODE_LEN];
  uint8_t leaf_pub[BIP32_PUBKEY_LEN];
} bip32_ctx_t;

typedef void (*bip32_addr_hash_t)(const uint8_t* pub, uint8_t out[RIPEMD160_DIGEST_LENGTH]);

/**
 * Initialise a derivation context from an already exported account extended
 * public key (purpose' / coin' / account'). The hardened steps must have been
 * performed on the card.
 */
void bip32_ctx_setup(bip32_ctx_t* ctx, uint32_t purpose, uint32_t coin, uint32_t account, const uint8_t account_pub[BIP32_PUBKEY_LEN], const uint8_t account_chain[BIP32_CHAINCODE_LEN]);

/**
 * Derive the non-hardened change-level extended key (change = 0 or 1) and cache
 * it in the context.
 * @return 0 on success, non-zero on failure
 */
int bip32_ctx_derive_change(bip32_ctx_t* ctx, uint32_t change);

/**
 * Derive a leaf public key at the given index from the currently cached change
 * level. The result is stored (compressed) in ctx->leaf_pub.
 * @return 0 on success, non-zero on failure
 */
int bip32_ctx_derive_leaf(bip32_ctx_t* ctx, uint32_t index);

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
