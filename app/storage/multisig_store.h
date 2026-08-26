#ifndef __MULTISIG_STORE_H
#define __MULTISIG_STORE_H

#include <stdint.h>
#include <stddef.h>

#include "error.h"
#include "storage/fs.h"
#include "bitcoin/multisig_crypto.h"

#define MULTISIG_STORE_MAGIC 0x4d53 /* "MS" */

/*
 * Maximum serialized size of one encrypted descriptor entry (name + body +
 * CCM tag + header). Bounds the internal save scratch buffer.
 */
#define MULTISIG_MAX_ENTRY_SIZE 1536

/*
 * Flash layout of a stored multisig descriptor. Only `blob` is searchable in
 * plaintext; the actual content (name + descriptor body) is AES-128-CCM
 * encrypted into `data` (ciphertext || 8-byte tag).
 */
typedef struct __attribute__((packed)) {
  fs_entry_t _fs_data;
  uint8_t blob[MULTISIG_FP_BLOB_LEN];
  uint8_t nonce[CCM_NONCE_SIZE];
  uint8_t data[];
} multisig_entry_t;

/*
 * Save a new descriptor. `plaintext` is the serialized name + body (produced
 * by the descriptor layer). A fresh random CCM nonce is drawn internally.
 */
app_err_t multisig_store_save(const multisig_crypto_t* m,
                              const uint8_t* plaintext, size_t len);

/*
 * Enumerate all entries belonging to this card (matching the session blob).
 * No decryption is performed. Pointers are into flash and remain valid until
 * the entry is erased or the FS is compacted. Returns the total number of
 * matches; at most `max` are stored into `out`.
 */
size_t multisig_store_list(const multisig_crypto_t* m,
                           multisig_entry_t* out[], size_t max);

/*
 * Decrypt the content of a single entry (from multisig_store_list) into `out`.
 */
app_err_t multisig_store_read(const multisig_crypto_t* m,
                              const multisig_entry_t* entry,
                              uint8_t* out, size_t out_cap, size_t* out_len);

/* Erase a single entry (pointer must come from multisig_store_list). */
app_err_t multisig_store_delete(const multisig_crypto_t* m,
                                const multisig_entry_t* entry);

#endif
