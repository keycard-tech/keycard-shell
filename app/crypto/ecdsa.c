#include <string.h>

#include "ecdsa.h"
#include "hal.h"
#include "memzero.h"
#include "util.h"
#include "util/tlv.h"

static int ec_uncompress_point(const ecdsa_curve *curve, const uint8_t x[ECC256_ELEMENT_SIZE], uint8_t odd, uint8_t out[ECC256_POINT_SIZE]) {
  // y^2 = x^3 + a*x + b
  memcpy(out, x, ECC256_ELEMENT_SIZE);
  uint8_t *y = &out[ECC256_ELEMENT_SIZE];
  hal_bn_mul_mod(x, x, curve->prime, y);

  if (curve->a_sign != A_SIGN_ZERO) {
    hal_bn_add_mod(y, curve->a, curve->prime, y);
  }

  hal_bn_mul_mod(x, y, curve->prime, y);
  hal_bn_add_mod(y, curve->b, curve->prime, y);
  hal_bn_exp_mod(y, curve->sqrt_exp, curve->prime, y);

  if ((odd & 0x1) != (y[ECC256_ELEMENT_SIZE-1] & 1)) {
    hal_bn_sub_mod(curve->prime, y, curve->prime, y);
  }

  return 0;
}

const uint8_t* ec_uncompress_key(const ecdsa_curve *curve, const uint8_t* pub_key, uint8_t out[ECC256_POINT_SIZE]) {
  if (pub_key[0] == 0x04) {
    return &pub_key[1];
  } else {
    return ec_uncompress_point(curve, &pub_key[1], pub_key[0], out) == 0 ? out : NULL;
  }
}

int ecdsa_sign(const ecdsa_curve *curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig) {
  uint8_t k[ECC256_ELEMENT_SIZE];
  hal_rng_next(k, ECC256_ELEMENT_SIZE);
  hal_err_t err = hal_ecdsa_sign(curve, priv_key, digest, k, sig);
  memzero(k, ECC256_ELEMENT_SIZE);
  return err == HAL_SUCCESS ? 0 : 1;
}

int ecdsa_verify(const ecdsa_curve *curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest) {
  uint8_t buf[ECC256_ELEMENT_SIZE * 2];
  pub_key = ec_uncompress_key(curve, pub_key, buf);

  if (pub_key == NULL) {
    return 1;
  }

  return ecdsa_verify_raw_pub(curve, pub_key, sig, digest) == HAL_SUCCESS ? 0 : 1;
}

int ecdsa_verify_raw_pub(const ecdsa_curve *curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest) {
  if (hal_ec_point_check(curve, pub_key) != HAL_SUCCESS) {
    return 1;
  }

  return hal_ecdsa_verify(curve, pub_key, sig, digest) == HAL_SUCCESS ? 0 : 1;
}

int ecdsa_get_public_key65(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t pub_key[ECC256_POINT_SIZE + 1]) {
  if (hal_ec_point_multiply(curve, priv_key, curve->G, &pub_key[1]) != HAL_SUCCESS) {
    return 1;
  }

  pub_key[0] = 0x04;
  return 0;
}

int ecdsa_get_public_key33(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t pub_key[ECC256_POINT_SIZE + 1]) {
  if (ecdsa_get_public_key65(curve, priv_key, pub_key) != 0) {
    return 1;
  }

  pub_key[0] = 0x02 | (pub_key[64] & 1);
  return 0;
}

int ecdsa_recover_pub_from_sig(const ecdsa_curve *curve, uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest, int recid) {
  const uint8_t* r = sig;
  const uint8_t* s = &sig[ECC256_ELEMENT_SIZE];
  uint8_t x[ECC256_ELEMENT_SIZE];

  if ((hal_bn_cmp(r, curve->order) >= 0) || all_zero(r, ECC256_ELEMENT_SIZE)) {
    return 1;
  }

  if ((hal_bn_cmp(s, curve->order) >= 0) || all_zero(s, ECC256_ELEMENT_SIZE)) {
    return 1;
  }

  memcpy(x, r, ECC256_ELEMENT_SIZE);

  if (recid & 2) {
    hal_bn_add(r, curve->order, x);

    if ((hal_bn_cmp(x, r) < 0) || (hal_bn_cmp(x, curve->prime) >= 0)) {
      return 1;
    }
  }

  uint8_t* P = &pub_key[1];
  ec_uncompress_point(curve, x, recid, P);
  if (hal_ec_point_check(curve, P) != HAL_SUCCESS) {
    return 1;
  }

  uint8_t z[ECC256_ELEMENT_SIZE];
  hal_bn_sub(curve->order, digest, z);

  if (hal_ec_double_ladder(curve, s, P, z, curve->G, P) != HAL_SUCCESS) {
    return 1;
  }

  uint8_t r_inv[ECC256_ELEMENT_SIZE];
  hal_bn_inv_mod(r, curve->order, r_inv);
  hal_ec_point_multiply(curve, r_inv, P, P);

  pub_key[0] = 0x04;

  return hal_ec_point_check(curve, P) != HAL_SUCCESS;
}

int ecdh_multiply(const ecdsa_curve *curve, const uint8_t *priv_key, const uint8_t *pub_key, uint8_t *session_key) {
  uint8_t buf[ECC256_POINT_SIZE];
  pub_key = ec_uncompress_key(curve, pub_key, buf);

  if (pub_key == NULL) {
    return 1;
  }

  if (hal_ec_point_check(curve, pub_key) != HAL_SUCCESS) {
    return 1;
  }

  if (hal_ec_point_multiply(curve, priv_key, pub_key, &session_key[1]) != HAL_SUCCESS) {
    return 1;
  }

  session_key[0] = 0x04;
  return 0;
}

// Parse a DER-encoded signature: SEQUENCE of two INTEGERs, right-aligned into sig.
//
// DER requires the minimal length form, which the general TLV reader deliberately accepts, so a
// header of more than two octets is refused here by its length. What is not checked is what was
// not checked before: whether an INTEGER is encoded with the leading zeros DER asks for, which
// leaves one r,s pair with more than one encoding.
int ecdsa_sig_from_der(const uint8_t *der, size_t der_len, uint8_t sig[64]) {
  memzero(sig, 64);

  tlv_t tlv;
  tlv_open(&tlv, der, der_len);

  tlv_t sequence;
  if (!tlv_enter(&tlv, 0x30, &sequence) || (sequence.p - der != 2)) {
    return 1;
  }

  for (int i = 0; i < 2; ++i) {
    const uint8_t *header = sequence.p;
    const uint8_t *integer;
    uint16_t int_len;
    if (!tlv_read_value(&sequence, 0x02, &integer, &int_len) || (integer - header != 2)) {
      return 1;
    }

    // Skip a possible leading zero.
    if (int_len != 0 && integer[0] == 0) {
      integer++;
      int_len--;
    }

    // Copy the integer to the output, making sure it fits.
    if (int_len > 32) {
      return 1;
    }
    memcpy(sig + 32 * (i + 1) - int_len, integer, int_len);
  }

  // Check that there are no trailing elements in the sequence.
  if (sequence.p != sequence.end) {
    return 1;
  }

  return 0;
}
