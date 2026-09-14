#ifndef __ECDSA_H__
#define __ECDSA_H__

#include <stdint.h>
#include <stddef.h>

#define ECC256_ELEMENT_SIZE 32
#define ECC256_POINT_SIZE (ECC256_ELEMENT_SIZE * 2)

#ifndef SOFT_ECDSA
#define A_SIGN_ZERO 0x00
#define A_SIGN_NEGATIVE 0x01
#define A_SIGN_POSITIVE 0x02

typedef struct {
  uint8_t prime[ECC256_ELEMENT_SIZE];
  uint8_t G[ECC256_POINT_SIZE];
  uint8_t order[ECC256_ELEMENT_SIZE];
  uint8_t a[ECC256_ELEMENT_SIZE];
  uint8_t b[ECC256_ELEMENT_SIZE];
  uint8_t sqrt_exp[ECC256_ELEMENT_SIZE];
  uint8_t a_sign;
} ecdsa_curve;
#endif

int ecdsa_sign(const ecdsa_curve *curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig);
int ecdsa_verify(const ecdsa_curve *curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);
int ecdsa_verify_raw_pub(const ecdsa_curve *curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);
int ecdsa_get_public_key65(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t *pub_key);
int ecdsa_get_public_key33(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t *pub_key);
int ecdsa_recover_pub_from_sig(const ecdsa_curve *curve, uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest, int recid);
int ecdsa_sig_to_der(const uint8_t *sig, uint8_t *der);
int ecdsa_sig_from_der(const uint8_t *der, size_t der_len, uint8_t sig[64]);

const uint8_t* ec_uncompress_key(const ecdsa_curve *curve, const uint8_t* pub_key, uint8_t out[ECC256_POINT_SIZE]);

int ecdh_multiply(const ecdsa_curve *curve, const uint8_t *priv_key, const uint8_t *pub_key, uint8_t *session_key);
#endif
