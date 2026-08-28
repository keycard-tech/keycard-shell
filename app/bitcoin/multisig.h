#ifndef __MULTISIG_H
#define __MULTISIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "error.h"
#include "crypto/address.h"

#define MULTISIG_MAX_KEYS 6
#define MULTISIG_MAX_NAME_LEN 33
#define MULTISIG_MAX_PATH_LEN 6
#define MULTISIG_XPUB_LEN 78
#define MULTISIG_FP_LEN 4

typedef enum {
  MULTISIG_FORMAT_P2SH = 0,
  MULTISIG_FORMAT_P2WSH_P2SH = 1,
  MULTISIG_FORMAT_P2WSH = 2,
} multisig_format_t;

/* One cosigner of a multisig descriptor. */
typedef struct {
  uint32_t path[MULTISIG_MAX_PATH_LEN]; /* hardened bit set */
  uint8_t path_len;
  uint8_t fingerprint[MULTISIG_FP_LEN]; /* master fingerprint, big-endian */
  uint8_t xpub[MULTISIG_XPUB_LEN];      /* serialized extended public key */
} multisig_key_t;

typedef struct {
  char name[MULTISIG_MAX_NAME_LEN];
  uint8_t m;
  uint8_t n;
  multisig_format_t format;
  multisig_key_t keys[MULTISIG_MAX_KEYS];
  uint8_t key_count;
} multisig_t;

/* Parse a Coldcard/Sparrow multisig setup text file (from a QR scan). */
app_err_t multisig_parse_text(const char* text, size_t len, multisig_t* out);

/* Compact binary serialization of the descriptor (plaintext for the store). */
app_err_t multisig_serialize(const multisig_t* d, uint8_t* out, size_t cap, size_t* out_len);
app_err_t multisig_deserialize(const uint8_t* data, size_t len, multisig_t* out);

/* Regenerate the Coldcard/Sparrow text for QR export. */
app_err_t multisig_to_text(const multisig_t* d, char* out, size_t cap);

/* True if any key's master fingerprint matches mfp (this card is a cosigner). */
bool multisig_has_fingerprint(const multisig_t* d, uint32_t mfp);

/* Derive the multisig address at change/index for the descriptor's format. */
app_err_t multisig_derive_address(const multisig_t* d, uint32_t change, uint32_t index, char addr[MAX_ADDR_LEN]);

#endif
