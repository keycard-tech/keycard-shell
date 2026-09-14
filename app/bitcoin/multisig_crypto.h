#ifndef __MULTISIG_CRYPTO_H
#define __MULTISIG_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "error.h"
#include "crypto/aes.h"

#define MULTISIG_ROOT_LEN 32
#define MULTISIG_FP_BLOB_LEN 4

/*
 * EIP-1581 identity key used as the card-bound secret for multisig
 * encryption. The 32-byte private scalar at this path is exported from the
 * card (EXPORT, P2=0x00) and must be wiped with multisig_crypto_wipe() once
 * the session ends.
 */
extern const uint32_t MULTISIG_EIP1581_PATH[];
#define MULTISIG_EIP1581_PATH_LEN 5

/*
 * Per-card multisig key material. All fields are secret / derived and must
 * never be persisted; re-derive them each session from the card.
 *
 *   root     = EIP1581 private scalar (from the card)
 *   enc_key  = HKDF(root, info="multisig-enc")  -> AES-128-CCM key
 *   blob     = truncate4( HMAC( fp_key, master_fp ) )
 *              where fp_key = HKDF(root, info="multisig-fp")
 *
 * blob is the deterministic, keyed-hash search field shared by all
 * descriptors of this card.
 */
typedef struct {
  uint8_t root[MULTISIG_ROOT_LEN];
  uint8_t enc_key[AES_128_KEY_SIZE];
  uint8_t blob[MULTISIG_FP_BLOB_LEN];
} multisig_crypto_t;

/* Derive enc_key and blob from the EIP1581 root + the card master fingerprint. */
void multisig_crypto_init(multisig_crypto_t* m,
                          const uint8_t root[MULTISIG_ROOT_LEN],
                          uint32_t master_fingerprint);

/* AES-128-CCM encrypt/decrypt an opaque payload with the per-card key.
 * The nonce must be unique per entry (never reused under this key). */
app_err_t multisig_crypto_encrypt(const multisig_crypto_t* m,
                                  const uint8_t nonce[CCM_NONCE_SIZE],
                                  const uint8_t* plaintext, size_t len,
                                  uint8_t* out);
app_err_t multisig_crypto_decrypt(const multisig_crypto_t* m,
                                  const uint8_t nonce[CCM_NONCE_SIZE],
                                  const uint8_t* ciphertext, size_t len,
                                  uint8_t* out);

/* Wipe all key material. Always call on session end / card removal. */
void multisig_crypto_wipe(multisig_crypto_t* m);

#endif
