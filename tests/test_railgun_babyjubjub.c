#include <stdint.h>
#include <string.h>

#include "crypto/bignum.h"
#include "hal.h"
#include "framework/test_util.h"
#include "unity.h"

/*
 * Host-only arithmetic feasibility tests.
 * No signing keys, nonce generation or constant-time claims.
 *
 * BabyJubjub: a*x^2 + y^2 = 1 + d*x^2*y^2 over BN254 Fr.
 * Standard twisted-Edwards coordinates from EIP-2494.
 */

typedef struct {
  bignum256 x;
  bignum256 y;
} babyjub_point_t;

static bignum256 field;
static bignum256 curve_a;
static bignum256 curve_d;

static const char FIELD_FR[] =
    "30644e72e131a029b85045b68181585"
    "d2833e84879b9709143e1f593f0000001";

static const char BASE_X[] =
    "0bb77a6ad63e739b4eacb2e09d6277c1"
    "2ab8d8010534e0b62893f3f6bb957051";
static const char BASE_Y[] =
    "25797203f7a0b24925572e1cd16bf9ed"
    "fce0051fb9e133774b3c257a872d7d8b";

static const char DOUBLE_X[] =
    "162d7e417903fa1c82f2d227e35b846b"
    "1133cfca4f558b5feb9fdcd5f81dd902";
static const char DOUBLE_Y[] =
    "01666cafbf0a30da8b9ebeaf848a1da0"
    "67a892296f1043188e1705402b6d6853";

static const char TRIPLE_X[] =
    "061c1436d1c3008037e887c8234dcf7c3"
    "3c947ad93695b8000fcb4ab70477e3e";
static const char TRIPLE_Y[] =
    "21d66f0e2295ae954494f25889f9319cc"
    "1b4df71eff3f46ba9e4631b43fd7c95";

static void from_hex(const char *hex, bignum256 *out) {
  uint8_t bytes[32];
  TEST_ASSERT_EQUAL_UINT32(32, test_unhex(hex, bytes, sizeof(bytes)));
  bn_read_be(bytes, out);
}

static void load_point(
    babyjub_point_t *point, const char *x, const char *y) {
  from_hex(x, &point->x);
  from_hex(y, &point->y);
}

/*
 * Public-point feasibility arithmetic over BN254 Fr.
 * bignum256 modular operations assume near-256-bit moduli and cannot
 * be used directly with Fr. The HAL accepts a 32-byte modulus.
 */
typedef hal_err_t (*mod_op_t)(
    const uint8_t *, const uint8_t *,
    const uint8_t *, uint8_t *);

static void binary_mod(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out,
    mod_op_t operation) {
  uint8_t lhs[BN_SIZE], rhs[BN_SIZE];
  uint8_t modulus[BN_SIZE], result[BN_SIZE];

  bn_write_be(a, lhs);
  bn_write_be(b, rhs);
  bn_write_be(&field, modulus);

  TEST_ASSERT_EQUAL_INT(
      HAL_SUCCESS, operation(lhs, rhs, modulus, result));

  bn_read_be(result, out);
}

static void add_mod(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  binary_mod(a, b, out, hal_bn_add_mod);
}

static void sub_mod(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  binary_mod(a, b, out, hal_bn_sub_mod);
}

static void mul_mod(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  binary_mod(a, b, out, hal_bn_mul_mod);
}

static void inv_mod(bignum256 *value) {
  uint8_t input[BN_SIZE];
  uint8_t modulus[BN_SIZE];
  uint8_t result[BN_SIZE];

  bn_write_be(value, input);
  bn_write_be(&field, modulus);

  TEST_ASSERT_EQUAL_INT(
      HAL_SUCCESS, hal_bn_inv_mod(input, modulus, result));

  bn_read_be(result, value);
}

static int on_curve(const babyjub_point_t *point) {
  bignum256 x2, y2, lhs, rhs, term, one;

  mul_mod(&point->x, &point->x, &x2);
  mul_mod(&point->y, &point->y, &y2);

  mul_mod(&curve_a, &x2, &term);
  add_mod(&term, &y2, &lhs);

  mul_mod(&x2, &y2, &term);
  mul_mod(&curve_d, &term, &rhs);
  bn_one(&one);
  add_mod(&one, &rhs, &rhs);

  return bn_is_equal(&lhs, &rhs);
}

static int add_points(
    const babyjub_point_t *p,
    const babyjub_point_t *q,
    babyjub_point_t *result) {
  bignum256 xx, yy, product, dxy, one;
  bignum256 numerator_x, numerator_y;
  bignum256 denominator_x, denominator_y;
  bignum256 t1, t2;

  mul_mod(&p->x, &q->x, &xx);
  mul_mod(&p->y, &q->y, &yy);
  mul_mod(&xx, &yy, &product);
  mul_mod(&curve_d, &product, &dxy);

  bn_one(&one);
  add_mod(&one, &dxy, &denominator_x);
  sub_mod(&one, &dxy, &denominator_y);

  if (bn_is_zero(&denominator_x) ||
      bn_is_zero(&denominator_y)) {
    return 0;
  }

  mul_mod(&p->x, &q->y, &t1);
  mul_mod(&p->y, &q->x, &t2);
  add_mod(&t1, &t2, &numerator_x);

  mul_mod(&curve_a, &xx, &t1);
  sub_mod(&yy, &t1, &numerator_y);

  inv_mod(&denominator_x);
  inv_mod(&denominator_y);

  mul_mod(&numerator_x, &denominator_x, &result->x);
  mul_mod(&numerator_y, &denominator_y, &result->y);

  return on_curve(result);
}

static void assert_point(
    const babyjub_point_t *actual,
    const char *expected_x,
    const char *expected_y) {
  babyjub_point_t expected;
  load_point(&expected, expected_x, expected_y);

  TEST_ASSERT_TRUE(bn_is_equal(&actual->x, &expected.x));
  TEST_ASSERT_TRUE(bn_is_equal(&actual->y, &expected.y));
  TEST_ASSERT_TRUE(on_curve(actual));
}

void setUp(void) {
  from_hex(FIELD_FR, &field);
  bn_read_uint32(168700, &curve_a);
  bn_read_uint32(168696, &curve_d);
}

void tearDown(void) {}

static void test_base_point_is_on_curve(void) {
  babyjub_point_t base;
  load_point(&base, BASE_X, BASE_Y);
  TEST_ASSERT_TRUE(on_curve(&base));
}

static void test_base_point_doubling(void) {
  babyjub_point_t base, doubled;
  load_point(&base, BASE_X, BASE_Y);

  TEST_ASSERT_TRUE(add_points(&base, &base, &doubled));
  assert_point(&doubled, DOUBLE_X, DOUBLE_Y);
}

static void test_base_point_tripling(void) {
  babyjub_point_t base, doubled, tripled;
  load_point(&base, BASE_X, BASE_Y);

  TEST_ASSERT_TRUE(add_points(&base, &base, &doubled));
  TEST_ASSERT_TRUE(add_points(&doubled, &base, &tripled));

  assert_point(&tripled, TRIPLE_X, TRIPLE_Y);
}

static void test_additive_identity(void) {
  babyjub_point_t base, identity, result;

  load_point(&base, BASE_X, BASE_Y);
  bn_zero(&identity.x);
  bn_one(&identity.y);

  TEST_ASSERT_TRUE(add_points(&base, &identity, &result));
  assert_point(&result, BASE_X, BASE_Y);
}

static void test_additive_inverse(void) {
  babyjub_point_t base, negated, result;
  bignum256 zero;

  load_point(&base, BASE_X, BASE_Y);
  bn_zero(&zero);
  sub_mod(&zero, &base.x, &negated.x);
  bn_copy(&base.y, &negated.y);

  TEST_ASSERT_TRUE(add_points(&base, &negated, &result));
  TEST_ASSERT_TRUE(bn_is_zero(&result.x));
  TEST_ASSERT_TRUE(bn_is_one(&result.y));
}

static void test_reject_off_curve_coordinates(void) {
  babyjub_point_t invalid;

  load_point(&invalid, BASE_X, BASE_Y);
  bn_addi(&invalid.x, 1);

  TEST_ASSERT_FALSE(on_curve(&invalid));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_base_point_is_on_curve);
  RUN_TEST(test_base_point_doubling);
  RUN_TEST(test_base_point_tripling);
  RUN_TEST(test_additive_identity);
  RUN_TEST(test_additive_inverse);
  RUN_TEST(test_reject_off_curve_coordinates);
  return UNITY_END();
}
