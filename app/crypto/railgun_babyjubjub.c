#include "crypto/railgun_babyjubjub.h"

#include <string.h>

#include "crypto/bignum.h"

typedef struct {
  bignum256 x;
  bignum256 y;
} babyjub_point_t;

typedef struct {
  bignum256 x;
  bignum256 y;
  bignum256 z;
} babyjub_projective_t;

static const uint8_t FIELD_FR[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
};

static const uint8_t CURVE_A[32] = {
    [29] = 0x02, [30] = 0x92, [31] = 0xfc,
};

static const uint8_t CURVE_D[32] = {
    [29] = 0x02, [30] = 0x92, [31] = 0xf8,
};

typedef hal_err_t (*mod_op_t)(
    const uint8_t *, const uint8_t *,
    const uint8_t *, uint8_t *);

#define CHECK_OP(expression) \
  do { \
    if ((expression) != HAL_SUCCESS) return HAL_FAIL; \
  } while (0)

static hal_err_t field_binary(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out,
    mod_op_t operation) {
  uint8_t lhs[BN_SIZE];
  uint8_t rhs[BN_SIZE];
  uint8_t result[BN_SIZE];

  bn_write_be(a, lhs);
  bn_write_be(b, rhs);

  if (operation(lhs, rhs, FIELD_FR, result) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  bn_read_be(result, out);
  return HAL_SUCCESS;
}

static hal_err_t field_add(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  return field_binary(a, b, out, hal_bn_add_mod);
}

static hal_err_t field_sub(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  return field_binary(a, b, out, hal_bn_sub_mod);
}

static hal_err_t field_mul(
    const bignum256 *a,
    const bignum256 *b,
    bignum256 *out) {
  return field_binary(a, b, out, hal_bn_mul_mod);
}

static hal_err_t field_inv(
    const bignum256 *value,
    bignum256 *out) {
  uint8_t input[BN_SIZE];
  uint8_t result[BN_SIZE];

  bn_write_be(value, input);

  if (hal_bn_inv_mod(input, FIELD_FR, result) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  bn_read_be(result, out);
  return HAL_SUCCESS;
}

static hal_err_t point_on_curve(
    const babyjub_point_t *point,
    int *valid) {
  bignum256 a, d, x2, y2, lhs, rhs, term, one;

  bn_read_be(CURVE_A, &a);
  bn_read_be(CURVE_D, &d);

  CHECK_OP(field_mul(&point->x, &point->x, &x2));
  CHECK_OP(field_mul(&point->y, &point->y, &y2));

  CHECK_OP(field_mul(&a, &x2, &term));
  CHECK_OP(field_add(&term, &y2, &lhs));

  CHECK_OP(field_mul(&x2, &y2, &term));
  CHECK_OP(field_mul(&d, &term, &rhs));

  bn_one(&one);
  CHECK_OP(field_add(&one, &rhs, &rhs));

  *valid = bn_is_equal(&lhs, &rhs);
  return HAL_SUCCESS;
}

/*
 * Projective twisted-Edwards addition.
 * Preserves the formula validated by the original native tests.
 */
static hal_err_t projective_add(
    const babyjub_projective_t *p,
    const babyjub_projective_t *q,
    babyjub_projective_t *out) {
  bignum256 curve_a, curve_d;
  bignum256 a, b, c, dxy, e, f, g;
  bignum256 aux, ac, dac, t1, t2;

  bn_read_be(CURVE_A, &curve_a);
  bn_read_be(CURVE_D, &curve_d);

  CHECK_OP(field_mul(&p->z, &q->z, &a));
  CHECK_OP(field_mul(&a, &a, &b));
  CHECK_OP(field_mul(&p->x, &q->x, &c));
  CHECK_OP(field_mul(&p->y, &q->y, &dxy));

  CHECK_OP(field_mul(&curve_d, &c, &e));
  CHECK_OP(field_mul(&e, &dxy, &e));

  CHECK_OP(field_sub(&b, &e, &f));
  CHECK_OP(field_add(&b, &e, &g));

  CHECK_OP(field_add(&p->x, &p->y, &t1));
  CHECK_OP(field_add(&q->x, &q->y, &t2));
  CHECK_OP(field_mul(&t1, &t2, &aux));
  CHECK_OP(field_sub(&aux, &c, &aux));
  CHECK_OP(field_sub(&aux, &dxy, &aux));

  CHECK_OP(field_mul(&a, &f, &t1));
  CHECK_OP(field_mul(&t1, &aux, &out->x));

  CHECK_OP(field_mul(&curve_a, &c, &ac));
  CHECK_OP(field_sub(&dxy, &ac, &dac));

  CHECK_OP(field_mul(&a, &g, &t1));
  CHECK_OP(field_mul(&t1, &dac, &out->y));

  CHECK_OP(field_mul(&f, &g, &out->z));

  return bn_is_zero(&out->z) ? HAL_FAIL : HAL_SUCCESS;
}

static hal_err_t projective_to_affine(
    const babyjub_projective_t *point,
    babyjub_point_t *out) {
  bignum256 inverse;

  if (bn_is_zero(&point->z)) {
    return HAL_FAIL;
  }

  CHECK_OP(field_inv(&point->z, &inverse));
  CHECK_OP(field_mul(&point->x, &inverse, &out->x));
  CHECK_OP(field_mul(&point->y, &inverse, &out->y));

  return HAL_SUCCESS;
}

hal_err_t railgun_babyjubjub_public_mul(
    const uint8_t x[32],
    const uint8_t y[32],
    const uint8_t scalar[32],
    uint8_t out_x[32],
    uint8_t out_y[32]) {
  babyjub_point_t base, result;
  babyjub_projective_t accumulator, point, next;
  int valid;
  int started = 0;

  if (!x || !y || !scalar || !out_x || !out_y) {
    return HAL_FAIL;
  }

  /* Outputs are distinct and non-overlapping by API contract. */
  memset(out_x, 0, 32);
  memset(out_y, 0, 32);

  if (memcmp(x, FIELD_FR, 32) >= 0 ||
      memcmp(y, FIELD_FR, 32) >= 0) {
    return HAL_FAIL;
  }

  bn_read_be(x, &base.x);
  bn_read_be(y, &base.y);

  CHECK_OP(point_on_curve(&base, &valid));

  if (!valid) {
    return HAL_FAIL;
  }

  point.x = base.x;
  point.y = base.y;
  bn_one(&point.z);

  bn_zero(&accumulator.x);
  bn_one(&accumulator.y);
  bn_one(&accumulator.z);

  for (unsigned i = 0; i < 32; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      unsigned set = (scalar[i] >> bit) & 1u;

      if (!started) {
        if (!set) {
          continue;
        }

        accumulator = point;
        started = 1;
        continue;
      }

      CHECK_OP(projective_add(
          &accumulator, &accumulator, &next));
      accumulator = next;

      if (set) {
        CHECK_OP(projective_add(
            &accumulator, &point, &next));
        accumulator = next;
      }
    }
  }

  CHECK_OP(projective_to_affine(&accumulator, &result));
  CHECK_OP(point_on_curve(&result, &valid));

  if (!valid) {
    return HAL_FAIL;
  }

  bn_write_be(&result.x, out_x);
  bn_write_be(&result.y, out_y);

  return HAL_SUCCESS;
}

#undef CHECK_OP
