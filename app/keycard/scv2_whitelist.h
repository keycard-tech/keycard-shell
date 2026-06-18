#ifndef __SCV2_WHITELIST_H
#define __SCV2_WHITELIST_H

#include <stdint.h>
#include "error.h"

#define SCV2_WHITELIST_PUBKEY_LEN 33

/**
 * Check if a device public key is in the accepted whitelist.
 *
 * @param pubkey  33-byte compressed secp256k1 public key from the card certificate
 * @return ERR_OK if the key is whitelisted, ERR_DATA if not found
 */
app_err_t scv2_whitelist_check(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]);

/**
 * Add a device public key to the accepted whitelist.
 *
 * @param pubkey  33-byte compressed secp256k1 public key from the card certificate
 * @return ERR_OK on success, ERR_DATA if slot limit reached or write failed
 */
app_err_t scv2_whitelist_add(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]);

/**
 * Remove a device public key from the whitelist.
 *
 * @param pubkey  33-byte compressed secp256k1 public key
 * @return ERR_OK on success, ERR_DATA if not found
 */
app_err_t scv2_whitelist_remove(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]);

#endif
