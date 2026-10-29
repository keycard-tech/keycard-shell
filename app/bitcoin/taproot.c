#include <string.h>

#include "taproot.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "crypto/util.h"
#include "hal.h"

#define TAPTWEAK_TAG "TapTweak"

static void _tagged_hash(const char* tag, const uint8_t* data, size_t data_len, uint8_t out[SHA256_DIGEST_LENGTH]) {
  uint8_t tag_hash[SHA256_DIGEST_LENGTH];

  sha256_Raw((const uint8_t*)tag, strlen(tag), tag_hash);

  SHA256_CTX ctx;

  sha256_Init(&ctx);
  sha256_Update(&ctx, tag_hash, sizeof(tag_hash));
  sha256_Update(&ctx, tag_hash, sizeof(tag_hash));
  sha256_Update(&ctx, data, data_len);
  sha256_Final(&ctx, out);
}

bool bitcoin_taproot_output_key(const uint8_t pub[BIP32_PUBKEY_LEN], uint8_t out[BTC_TAPROOT_WITPROG_LEN]) {
  uint8_t tweak[SHA256_DIGEST_LENGTH];
  uint8_t point[ECC256_POINT_SIZE];
  uint8_t multiplier[ECC256_ELEMENT_SIZE];

  _tagged_hash(TAPTWEAK_TAG, &pub[1], ECC256_ELEMENT_SIZE, tweak);

  if (all_zero(tweak, sizeof(tweak)) || (memcmp(tweak, secp256k1.order, ECC256_ELEMENT_SIZE) >= 0)) {
    return false;
  }

  memset(multiplier, 0, sizeof(multiplier));
  multiplier[ECC256_ELEMENT_SIZE - 1] = 1;

  /* BIP86 negates an internal key with odd y; (order-1)*P does it without a field negation */
  if (pub[0] & 1) {
    memcpy(multiplier, secp256k1.order, sizeof(multiplier));

    uint8_t borrow = 1;

    for (int i = ECC256_ELEMENT_SIZE - 1; (i >= 0) && borrow; i--) {
      borrow = (multiplier[i] == 0);
      multiplier[i] -= 1;
    }
  }

  if (hal_ec_double_ladder(&secp256k1, multiplier, &pub[1], tweak, secp256k1.G, point) != HAL_SUCCESS) {
    return false;
  }

  memcpy(out, point, BTC_TAPROOT_WITPROG_LEN);
  return true;
}
