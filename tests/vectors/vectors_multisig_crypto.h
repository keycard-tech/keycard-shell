#ifndef VECTORS_MULTISIG_CRYPTO_H
#define VECTORS_MULTISIG_CRYPTO_H

/* spec: https://www.rfc-editor.org/rfc/rfc5869.txt
 * sha256 7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c
 *
 * The labels, the truncation to AES-128 and the little-endian fingerprint are the module's own definitions
 * -- they are what the header documents -- but the bytes below come from RFC 5869 extract-and-expand and
 * FIPS 198-1 HMAC, computed here rather than read back from aes_ccm/hkdf's C. enc_key is the key that
 * keeps a stored descriptor private; blob is the searchable index the store matches on, so it must be the
 * same for every session with the same card and different for every card.
 */

typedef struct {
  const char* root;
  uint32_t master_fingerprint;
  const char* enc_key;
  const char* blob;
} multisig_crypto_kat_t;

static const multisig_crypto_kat_t MULTISIG_CRYPTO_KAT[] = {
  {.root = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", .master_fingerprint = 0x00000000, .enc_key = "9350e07beadafe6d4ee1eaffc24c5d56", .blob = "9e3c33b1"},
  {.root = "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da", .master_fingerprint = 0xDEADBEEF, .enc_key = "269ac521a111b07cb13b83df3d7d87f3", .blob = "fb8d41ae"},
  {.root = "0000000000000000000000000000000000000000000000000000000000000000", .master_fingerprint = 0x12345678, .enc_key = "bb476b666f402dc8b515f767021d1e30", .blob = "7809f8b7"},
  {.root = "3e3e480d904bfad816825847b5752fda6a738bd74b2dbb284972be28ede6390c", .master_fingerprint = 0xAABBCCDD, .enc_key = "67ba8d4319b7c59277b9849633189b3d", .blob = "4d38a92e"}
};

#define MULTISIG_CRYPTO_KAT_COUNT (sizeof(MULTISIG_CRYPTO_KAT) / sizeof(MULTISIG_CRYPTO_KAT[0]))

#endif
