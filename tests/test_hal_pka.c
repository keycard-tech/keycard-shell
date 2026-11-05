/* The host stand-in for the public key accelerator (tests/host/hal_pka_host.c), which is what
 * app/crypto/ecdsa.c, app/crypto/bip32.c and app/bitcoin/taproot.c reach for the curve.
 *
 * Where the answers come from is written into vectors/vectors_pka.h. In short: the deterministic-k
 * model that chose every k was validated against the ten published triples of RFC 6979 appendix
 * A.2.5; every signature row was then compared with a signature libsecp256k1 made over the same
 * private key and digest; the private-key-to-public-key rows are the published pairs of BIP-32
 * test vector 1; the rest is CPython integer arithmetic. Nothing here is read back out of the
 * stand-in.
 *
 * Every buffer is exactly as long as the bytes the call is allowed to write, so a write past the
 * end is a sanitizer failure rather than a read of whatever the neighbouring array was. A refusal
 * is also checked to have written nothing, because a half-filled output is what a caller mistakes
 * for a result. */

#include <stdbool.h>
#include <string.h>

#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "framework/test_util.h"
#include "hal.h"
#include "unity.h"
#include "vectors/vectors_pka.h"

#define EL ECC256_ELEMENT_SIZE
#define PT ECC256_POINT_SIZE

static void assert_untouched(const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, buf[i], "a refused call wrote to its output");
  }
}

void setUp(void) {
}

void tearDown(void) {
}

/* The curve the stand-in is handed is the one the firmware built: reading the struct the way the
 * PKA's own calls read it has to find the generator on the curve. */
static void test_curve_table_is_read_as_built(void) {
  TEST_ASSERT_EQUAL_UINT8(A_SIGN_ZERO, secp256k1.a_sign);
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_ec_point_check(&secp256k1, secp256k1.G));

  /* The generator is not the identity, and negating it is a different point on the curve. */
  uint8_t negated[PT];
  memcpy(negated, secp256k1.G, EL);
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS,
                        hal_bn_sub_mod(secp256k1.prime, &secp256k1.G[EL], secp256k1.prime, &negated[EL]));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_ec_point_check(&secp256k1, negated));
  TEST_ASSERT_TRUE(memcmp(negated, secp256k1.G, PT) != 0);
}

static void test_sign(void) {
  for (size_t i = 0; i < PKA_SIGN_COUNT; i++) {
    const pka_sign_t* row = &PKA_SIGN[i];
    uint8_t priv[EL], digest[EL], k[EL], out[PT];
    TEST_GIVEN(row->priv, priv, EL);
    TEST_GIVEN(row->digest, digest, EL);
    TEST_GIVEN(row->k, k, EL);
    memset(out, 0, sizeof(out));

    TEST_ASSERT_EQUAL_INT_MESSAGE(HAL_SUCCESS, hal_ecdsa_sign(&secp256k1, priv, digest, k, out), row->k);
    TEST_ASSERT_HEX_MESSAGE(out, EL, row->r, row->k);
    TEST_ASSERT_HEX_MESSAGE(&out[EL], EL, row->s, row->k);
  }
}

/* Same inputs, same signature; a different digest, a different signature. Both are stated over a
 * k the row supplies, since the nonce is what the caller of this function chooses. */
static void test_sign_depends_on_the_digest_alone(void) {
  const pka_sign_t* first = &PKA_SIGN[0];
  const pka_sign_t* second = &PKA_SIGN[1];
  TEST_ASSERT_EQUAL_MEMORY(first->priv, second->priv, EL * 2);

  uint8_t priv[EL], digest[EL], k[EL];
  uint8_t out[PT], again[PT], as_row[PT];
  TEST_GIVEN(first->priv, priv, EL);
  TEST_GIVEN(second->digest, digest, EL);
  TEST_GIVEN(second->k, k, EL);
  memset(out, 0, sizeof(out));
  memset(again, 0, sizeof(again));
  memset(as_row, 0, sizeof(as_row));

  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_ecdsa_sign(&secp256k1, priv, digest, k, out));
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_ecdsa_sign(&secp256k1, priv, digest, k, again));
  TEST_ASSERT_EQUAL_MEMORY(out, again, PT);
  TEST_ASSERT_HEX_MESSAGE(out, EL, second->r, second->k);
  TEST_ASSERT_HEX_MESSAGE(&out[EL], EL, second->s, second->k);

  uint8_t first_digest[EL], first_k[EL];
  TEST_GIVEN(first->digest, first_digest, EL);
  TEST_GIVEN(first->k, first_k, EL);
  TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_ecdsa_sign(&secp256k1, priv, first_digest, first_k, as_row));
  TEST_ASSERT_HEX_MESSAGE(as_row, EL, first->r, first->k);
  TEST_ASSERT_HEX_MESSAGE(&as_row[EL], EL, first->s, first->k);
  TEST_ASSERT_TRUE(memcmp(out, as_row, PT) != 0);
}

static void test_verify(void) {
  for (size_t i = 0; i < PKA_VERIFY_COUNT; i++) {
    const pka_verify_t* row = &PKA_VERIFY[i];
    uint8_t sig[PT], digest[EL], point[PT];
    TEST_GIVEN(row->sig, sig, PT);
    TEST_GIVEN(row->digest, digest, EL);
    TEST_GIVEN(row->point, point, PT);

    hal_err_t err = hal_ecdsa_verify(&secp256k1, point, sig, digest);
    TEST_ASSERT_EQUAL_INT_MESSAGE(row->accept ? HAL_SUCCESS : HAL_FAIL, err, row->name);
  }
}

static void test_multiply(void) {
  for (size_t i = 0; i < PKA_MUL_COUNT; i++) {
    const pka_mul_t* row = &PKA_MUL[i];
    uint8_t scalar[EL], point[PT], out[PT];
    TEST_GIVEN(row->scalar, scalar, EL);
    TEST_GIVEN(row->point, point, PT);
    memset(out, 0, sizeof(out));

    hal_err_t err = hal_ec_point_multiply(&secp256k1, scalar, point, out);
    TEST_ASSERT_EQUAL_INT_MESSAGE(row->ok ? HAL_SUCCESS : HAL_FAIL, err, row->scalar);
    if (row->ok) {
      TEST_ASSERT_HEX_MESSAGE(out, PT, row->out, row->scalar);
    } else {
      assert_untouched(out, PT);
    }
  }
}

static void test_double_ladder(void) {
  for (size_t i = 0; i < PKA_LADDER_COUNT; i++) {
    const pka_ladder_t* row = &PKA_LADDER[i];
    uint8_t s1[EL], p1[PT], s2[EL], p2[PT], out[PT];
    TEST_GIVEN(row->s1, s1, EL);
    TEST_GIVEN(row->p1, p1, PT);
    TEST_GIVEN(row->s2, s2, EL);
    TEST_GIVEN(row->p2, p2, PT);
    memset(out, 0, sizeof(out));

    hal_err_t err = hal_ec_double_ladder(&secp256k1, s1, p1, s2, p2, out);
    TEST_ASSERT_EQUAL_INT_MESSAGE(row->ok ? HAL_SUCCESS : HAL_FAIL, err, row->s1);
    if (row->ok) {
      TEST_ASSERT_HEX_MESSAGE(out, PT, row->out, row->s1);
    } else {
      assert_untouched(out, PT);
    }
  }
}

static void test_point_check(void) {
  for (size_t i = 0; i < PKA_CHECK_COUNT; i++) {
    const pka_check_t* row = &PKA_CHECK[i];
    uint8_t point[PT];
    TEST_GIVEN(row->point, point, PT);

    hal_err_t err = hal_ec_point_check(&secp256k1, point);
    TEST_ASSERT_EQUAL_INT_MESSAGE(row->on_curve ? HAL_SUCCESS : HAL_FAIL, err, row->point);
  }
}

static void check_bn(const pka_bn_t* row, hal_err_t (*one)(const uint8_t[], const uint8_t[], uint8_t[])) {
  uint8_t a[BN_SIZE], b[BN_SIZE], out[BN_SIZE];
  TEST_GIVEN(row->a, a, BN_SIZE);
  TEST_GIVEN(row->b, b, BN_SIZE);
  memset(out, 0, sizeof(out));

  TEST_ASSERT_EQUAL_INT_MESSAGE(HAL_SUCCESS, one(a, b, out), row->label);
  TEST_ASSERT_HEX_MESSAGE(out, BN_SIZE, row->out, row->label);
}

static void check_bn_mod(const pka_bn_t* row,
                         hal_err_t (*two)(const uint8_t[], const uint8_t[], const uint8_t[], uint8_t[])) {
  uint8_t a[BN_SIZE], b[BN_SIZE], mod[BN_SIZE], out[BN_SIZE];
  TEST_GIVEN(row->a, a, BN_SIZE);
  TEST_GIVEN(row->b, b, BN_SIZE);
  TEST_GIVEN(row->mod, mod, BN_SIZE);
  memset(out, 0, sizeof(out));

  TEST_ASSERT_EQUAL_INT_MESSAGE(HAL_SUCCESS, two(a, b, mod, out), row->label);
  TEST_ASSERT_HEX_MESSAGE(out, BN_SIZE, row->out, row->label);
}

static void test_bn_add_sub(void) {
  for (size_t i = 0; i < PKA_BN_ADD_COUNT; i++) {
    check_bn(&PKA_BN_ADD[i], hal_bn_add);
  }
  for (size_t i = 0; i < PKA_BN_SUB_COUNT; i++) {
    check_bn(&PKA_BN_SUB[i], hal_bn_sub);
  }
}

static void test_bn_cmp(void) {
  for (size_t i = 0; i < PKA_BN_CMP_COUNT; i++) {
    const pka_bn_t* row = &PKA_BN_CMP[i];
    uint8_t a[BN_SIZE], b[BN_SIZE];
    TEST_GIVEN(row->a, a, BN_SIZE);
    TEST_GIVEN(row->b, b, BN_SIZE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(row->cmp, hal_bn_cmp(a, b), row->label);
  }
}

static void test_bn_modular(void) {
  for (size_t i = 0; i < PKA_BN_ADD_MOD_COUNT; i++) {
    check_bn_mod(&PKA_BN_ADD_MOD[i], hal_bn_add_mod);
  }
  for (size_t i = 0; i < PKA_BN_SUB_MOD_COUNT; i++) {
    check_bn_mod(&PKA_BN_SUB_MOD[i], hal_bn_sub_mod);
  }
  for (size_t i = 0; i < PKA_BN_MUL_MOD_COUNT; i++) {
    check_bn_mod(&PKA_BN_MUL_MOD[i], hal_bn_mul_mod);
  }
  for (size_t i = 0; i < PKA_BN_EXP_MOD_COUNT; i++) {
    check_bn_mod(&PKA_BN_EXP_MOD[i], hal_bn_exp_mod);
  }
}

static void test_bn_inv(void) {
  for (size_t i = 0; i < PKA_BN_INV_MOD_COUNT; i++) {
    const pka_bn_t* row = &PKA_BN_INV_MOD[i];
    uint8_t a[BN_SIZE], mod[BN_SIZE], inverse[BN_SIZE];
    TEST_GIVEN(row->a, a, BN_SIZE);
    TEST_GIVEN(row->mod, mod, BN_SIZE);
    memset(inverse, 0x5A, sizeof(inverse));

    TEST_ASSERT_EQUAL_INT_MESSAGE(HAL_SUCCESS, hal_bn_inv_mod(a, mod, inverse), row->label);
    TEST_ASSERT_HEX_MESSAGE(inverse, BN_SIZE, row->out, row->label);

    /* The answer multiplied back is one. Zero is the one input with no inverse; the row's a is
     * reduced first, because only a multiple of the modulus has no inverse. */
    uint8_t reduced[BN_SIZE], zero[BN_SIZE], product[BN_SIZE], want[BN_SIZE];
    memset(zero, 0, sizeof(zero));
    TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_bn_sub_mod(a, zero, mod, reduced));
    memset(product, 0, sizeof(product));
    TEST_ASSERT_EQUAL_INT(HAL_SUCCESS, hal_bn_mul_mod(a, inverse, mod, product));

    memset(want, 0, sizeof(want));
    want[BN_SIZE - 1] = all_zero(reduced, BN_SIZE) ? 0 : 1;
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, product, BN_SIZE, row->label);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_curve_table_is_read_as_built);
  RUN_TEST(test_sign);
  RUN_TEST(test_sign_depends_on_the_digest_alone);
  RUN_TEST(test_verify);
  RUN_TEST(test_multiply);
  RUN_TEST(test_double_ladder);
  RUN_TEST(test_point_check);
  RUN_TEST(test_bn_add_sub);
  RUN_TEST(test_bn_cmp);
  RUN_TEST(test_bn_modular);
  RUN_TEST(test_bn_inv);
  return UNITY_END();
}
