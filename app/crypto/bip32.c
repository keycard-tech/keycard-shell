#include <string.h>

#include "bip32.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "hmac.h"
#include "memzero.h"

int bip32_ckd_pub(const uint8_t* pub65, const uint8_t* chain, uint32_t index, uint8_t* out_pub65, uint8_t* out_chain) {
  uint8_t data[1 + 32 + 4];
  uint8_t I[SHA512_DIGEST_LENGTH];
  uint8_t one[ECC256_ELEMENT_SIZE];

  if (index & 0x80000000) {
    return 1; /* hardened derivation not possible from a public key */
  }

  data[0] = 0x02 | (pub65[BIP32_PUBKEY_LEN - 1] & 1);
  memcpy(&data[1], &pub65[1], 32);
  data[33] = (index >> 24) & 0xff;
  data[34] = (index >> 16) & 0xff;
  data[35] = (index >> 8) & 0xff;
  data[36] = index & 0xff;

  /* I = HMAC-SHA512(key = chain code, msg = data); IL = I[0..31], IR = I[32..63] */
  hmac_sha512(chain, BIP32_CHAINCODE_LEN, data, sizeof(data), I);

  memzero(data, sizeof(data));

  /* IL must be < curve order (failure is astronomically rare) */
  if (memcmp(I, secp256k1.order, ECC256_ELEMENT_SIZE) >= 0) {
    memzero(I, sizeof(I));
    return 2;
  }

  memset(one, 0, ECC256_ELEMENT_SIZE);
  one[ECC256_ELEMENT_SIZE - 1] = 1;

  /* child_point = parent_point + IL*G  (i.e. 1*parent + IL*G) */
  if (hal_ec_double_ladder(&secp256k1, one, &pub65[1], I, secp256k1.G, &out_pub65[1]) != HAL_SUCCESS) {
    memzero(I, sizeof(I));
    return 3;
  }
  out_pub65[0] = 0x04;

  /* child chain code = IR */
  if (out_chain) {
    memcpy(out_chain, I + ECC256_ELEMENT_SIZE, BIP32_CHAINCODE_LEN);
  }

  memzero(I, sizeof(I));
  return 0;
}
