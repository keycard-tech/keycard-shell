#include "multisig_crypto.h"

#include <string.h>

#include "crypto/hkdf.h"
#include "crypto/hmac.h"
#include "crypto/memzero.h"
#include "crypto/sha2.h"

/* m/43'/60'/1581'/0'/0 */
const uint32_t MULTISIG_EIP1581_PATH[MULTISIG_EIP1581_PATH_LEN] = {
  0x8000002b, 0x8000003c, 0x8000062d, 0x80000000, 0x00000000,
};

#define MULTISIG_FP_INFO  "multisig-fp"
#define MULTISIG_ENC_INFO "multisig-enc"

static void _derive_fp_blob(const uint8_t root[MULTISIG_ROOT_LEN],
                            uint32_t master_fingerprint,
                            uint8_t out[MULTISIG_FP_BLOB_LEN]) {
  uint8_t fp_key[SHA256_DIGEST_LENGTH];
  uint8_t mac[SHA256_DIGEST_LENGTH];
  uint8_t fp_le[4];

  fp_le[0] = master_fingerprint & 0xff;
  fp_le[1] = (master_fingerprint >> 8) & 0xff;
  fp_le[2] = (master_fingerprint >> 16) & 0xff;
  fp_le[3] = (master_fingerprint >> 24) & 0xff;

  /* fp_key = HKDF(root, info="multisig-fp") */
  hkdf_sha256(NULL, 0, root, MULTISIG_ROOT_LEN,
              (const uint8_t*) MULTISIG_FP_INFO, sizeof(MULTISIG_FP_INFO) - 1,
              fp_key, sizeof(fp_key));

  /* blob = first 4 bytes of HMAC-SHA256(fp_key, fp_le) */
  hmac_sha256(fp_key, sizeof(fp_key), fp_le, sizeof(fp_le), mac);
  memcpy(out, mac, MULTISIG_FP_BLOB_LEN);

  memzero(fp_key, sizeof(fp_key));
  memzero(mac, sizeof(mac));
  memzero(fp_le, sizeof(fp_le));
}

void multisig_crypto_init(multisig_crypto_t* m,
                          const uint8_t root[MULTISIG_ROOT_LEN],
                          uint32_t master_fingerprint) {
  memcpy(m->root, root, MULTISIG_ROOT_LEN);

  /* enc_key = HKDF(root, info="multisig-enc"), truncated to AES-128 */
  hkdf_sha256(NULL, 0, root, MULTISIG_ROOT_LEN,
              (const uint8_t*) MULTISIG_ENC_INFO, sizeof(MULTISIG_ENC_INFO) - 1,
              m->enc_key, AES_128_KEY_SIZE);

  _derive_fp_blob(root, master_fingerprint, m->blob);
}

app_err_t multisig_crypto_encrypt(const multisig_crypto_t* m,
                                  const uint8_t nonce[CCM_NONCE_SIZE],
                                  const uint8_t* plaintext, size_t len,
                                  uint8_t* out) {
  if (!aes128_ccm_encrypt(m->enc_key, nonce, plaintext, len, out)) {
    return ERR_CRYPTO;
  }
  return ERR_OK;
}

app_err_t multisig_crypto_decrypt(const multisig_crypto_t* m,
                                  const uint8_t nonce[CCM_NONCE_SIZE],
                                  const uint8_t* ciphertext, size_t len,
                                  uint8_t* out) {
  if (!aes128_ccm_decrypt(m->enc_key, nonce, ciphertext, len, out)) {
    return ERR_CRYPTO;
  }
  return ERR_OK;
}

void multisig_crypto_wipe(multisig_crypto_t* m) {
  memzero(m, sizeof(*m));
}
