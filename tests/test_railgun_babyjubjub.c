#include <stdint.h>
#include <string.h>

#include "crypto/bignum.h"
#include "crypto/railgun_blake512.h"
#include "crypto/railgun_poseidon_t6.h"
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


/*
 * Test-only public scalar multiplication.
 * Variable-time double-and-add; NEVER use for secret scalars.
 * Vectors independently calculated using Python integers and EIP-2494.
 */
static int public_mul_u32(
    const babyjub_point_t *base,
    uint32_t scalar,
    babyjub_point_t *out) {
  babyjub_point_t accumulator;
  babyjub_point_t addend = *base;

  if (!on_curve(base)) {
    return 0;
  }

  bn_zero(&accumulator.x);
  bn_one(&accumulator.y);

  while (scalar != 0) {
    babyjub_point_t next;

    if ((scalar & 1u) != 0) {
      if (!add_points(&accumulator, &addend, &next)) {
        return 0;
      }
      accumulator = next;
    }

    scalar >>= 1;

    if (scalar != 0) {
      if (!add_points(&addend, &addend, &next)) {
        return 0;
      }
      addend = next;
    }
  }

  *out = accumulator;
  return 1;
}

static void test_public_scalar_reference_vectors(void) {
  static const struct {
    uint32_t scalar;
    const char *x;
    const char *y;
  } vectors[] = {
    {0,
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000001"},
    {1, BASE_X, BASE_Y},
    {2, DOUBLE_X, DOUBLE_Y},
    {3, TRIPLE_X, TRIPLE_Y},
    {8,
     "10c347ae3592776a678f9fc29ecd029f8297367209a4f28f7cb49b09bffd4145",
     "113f8246f336e8d375c9daab552816825f481c210226f307bc863e017642566c"},
    {16,
     "2d66d2bb7bd385a5e2965d03466bc0579ce96b37ef9541be1aff46d012269648",
     "2f71787edba2b346e45bc228ddf388cf5746118513e6e515e9cd294c5da7c007"},
    {31,
     "1390b1c9d9a82d2159b46c2bb964b4b2f33fce1689896c95545db5582db57f2e",
     "29cec8b61d518c9fb134222a259fb1aac3ef5a0e96ffe08d5f6102a388e5f488"}
  };

  babyjub_point_t base;
  load_point(&base, BASE_X, BASE_Y);

  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    babyjub_point_t result;

    TEST_ASSERT_TRUE(
        public_mul_u32(&base, vectors[i].scalar, &result));

    assert_point(&result, vectors[i].x, vectors[i].y);
  }
}

static void test_public_scalar_rejects_invalid_point(void) {
  babyjub_point_t invalid;
  babyjub_point_t result;

  bn_one(&invalid.x);
  bn_zero(&invalid.y);

  TEST_ASSERT_FALSE(on_curve(&invalid));
  TEST_ASSERT_FALSE(public_mul_u32(&invalid, 8, &result));
}


/*
 * Full-width public-scalar test reference.
 * Uses the projective add-2008-bbjlp formula from kohaku_crypto.
 * Variable-time: NOT suitable for private spending scalars.
 */
typedef struct {
  bignum256 x, y, z;
} babyjub_projective_t;

static int projective_add(
    const babyjub_projective_t *p,
    const babyjub_projective_t *q,
    babyjub_projective_t *out) {
  bignum256 a, b, c, dxy, e, f, g;
  bignum256 aux, ac, dac, t1, t2;

  mul_mod(&p->z, &q->z, &a);
  mul_mod(&a, &a, &b);
  mul_mod(&p->x, &q->x, &c);
  mul_mod(&p->y, &q->y, &dxy);

  mul_mod(&curve_d, &c, &e);
  mul_mod(&e, &dxy, &e);

  sub_mod(&b, &e, &f);
  add_mod(&b, &e, &g);

  add_mod(&p->x, &p->y, &t1);
  add_mod(&q->x, &q->y, &t2);
  mul_mod(&t1, &t2, &aux);
  sub_mod(&aux, &c, &aux);
  sub_mod(&aux, &dxy, &aux);

  mul_mod(&a, &f, &t1);
  mul_mod(&t1, &aux, &out->x);

  mul_mod(&curve_a, &c, &ac);
  sub_mod(&dxy, &ac, &dac);

  mul_mod(&a, &g, &t1);
  mul_mod(&t1, &dac, &out->y);

  mul_mod(&f, &g, &out->z);

  return !bn_is_zero(&out->z);
}

static int projective_to_affine(
    const babyjub_projective_t *p,
    babyjub_point_t *out) {
  bignum256 inverse;

  if (bn_is_zero(&p->z)) {
    return 0;
  }

  inverse = p->z;
  inv_mod(&inverse);

  mul_mod(&p->x, &inverse, &out->x);
  mul_mod(&p->y, &inverse, &out->y);

  return on_curve(out);
}

/*
 * Read the full 256-bit scalar as big-endian.
 * Skip leading zeros, then double-and-add.
 */
static int public_mul_256(
    const babyjub_point_t *base,
    const uint8_t scalar[32],
    babyjub_point_t *out) {
  babyjub_projective_t accumulator, point, next;
  int started = 0;

  if (!on_curve(base)) {
    return 0;
  }

  point.x = base->x;
  point.y = base->y;
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

      if (!projective_add(
              &accumulator, &accumulator, &next)) {
        return 0;
      }
      accumulator = next;

      if (set) {
        if (!projective_add(
                &accumulator, &point, &next)) {
          return 0;
        }
        accumulator = next;
      }
    }
  }

  return projective_to_affine(&accumulator, out);
}

static void test_full_width_scalar_vectors(void) {
  static const struct {
    const char *scalar;
    const char *x;
    const char *y;
  } vectors[] = {
    /* 0 * B8 = identity */
    {
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001"
    },
    /* subgroup_order * B8 = identity */
    {
      "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001"
    },
    /* (subgroup_order + 1) * B8 = B8 */
    {
      "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2",
      BASE_X, BASE_Y
    },
    /* Kohaku synthetic [1u8; 32] key's derived scalar */
    {
      "0ba9f4de43d3c912590c6ab4f8e7f3c0c0229e25c7dd052203b928fcdc87dfba",
      "234056d968baf183fe8d237d496d1c04188220cd33e8f8d14df9b84479736b20",
      "2624393fad9b71c04b3b14d8ac45202dbb4eaff4c2d1350c9453fc08d18651fe"
    },
    /* Kohaku synthetic deterministic nonce: message 0 */
    {
      "031dd101d9c07a84285b4273a397aa286f406d30d7fce36fd3925ab93380abdb",
      "25a426befdcc7918713ea23d9b3f0d87ad843362145d7b92d4cd3f166ad6c8bd",
      "241f9a479cf221163eda6eb3772d36f8b398d9f5d13b5ef3e9223215d57ca2b8"
    },
    /* Message 1 */
    {
      "00df4db54e41e4fc50b13c0e02e0c1414a763b5e0529678277027051579fe8b4",
      "14a052afd7879fe4bf9aea3cb3cf354f75dd677b15103bf401920efe292d00e0",
      "03c3fdc3bb383e8c5f80b41dc3ce512dc8ae33c9e53be80fd1a352232c39e45a"
    },
    /* Message 12345 */
    {
      "0159d924c64d7d42dd0936b68b0948a90a820da1888185125671de372e766215",
      "24ccbdfb612d47b4c41b440eb927f21f34e341f89215932b053ec2b19dc84ce6",
      "171a92a4562a9a063a5d510623bb0537ffba3fb04aa1a16bcc83ea5e881d0651"
    }
  };

  babyjub_point_t base;
  load_point(&base, BASE_X, BASE_Y);

  for (size_t i = 0;
       i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    uint8_t scalar[32];
    babyjub_point_t result;

    TEST_ASSERT_EQUAL_UINT(
        32, test_unhex(vectors[i].scalar, scalar, 32));

    TEST_ASSERT_TRUE(public_mul_256(&base, scalar, &result));
    assert_point(&result, vectors[i].x, vectors[i].y);
  }
}

static void test_full_width_rejects_invalid_base(void) {
  babyjub_point_t invalid, result;
  uint8_t scalar[32] = {0};
  scalar[31] = 1;

  bn_one(&invalid.x);
  bn_zero(&invalid.y);

  TEST_ASSERT_FALSE(
      public_mul_256(&invalid, scalar, &result));
}


/*
 * Native-only synthetic EdDSA-Poseidon compatibility test.
 *
 * The scalar arithmetic below is deliberately simple and variable-time.
 * It MUST NOT be used for real spending keys or firmware signing.
 *
 * Uses the established Kohaku [1u8; 32] reference fixture.
 */
static const uint8_t railgun_subgroup_order[32] = {
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05,
    0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
    0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a,
    0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1
};

/* All values here are 32-byte unsigned, big-endian integers. */
static void subgroup_subtract_order(uint8_t value[32]) {
  unsigned borrow = 0;

  for (int i = 31; i >= 0; i--) {
    unsigned a = value[i];
    unsigned b = (unsigned)railgun_subgroup_order[i] + borrow;

    value[i] = (uint8_t)(a - b);
    borrow = a < b;
  }
}

/* Double a reduced scalar and append one bit. */
static void subgroup_shift_bit(uint8_t value[32], unsigned bit) {
  unsigned carry = bit;

  for (int i = 31; i >= 0; i--) {
    unsigned next = ((unsigned)value[i] << 1) | carry;
    value[i] = (uint8_t)next;
    carry = next >> 8;
  }

  /* Since the subgroup order is 251 bits, carry cannot overflow. */
  if (memcmp(value, railgun_subgroup_order, 32) >= 0) {
    subgroup_subtract_order(value);
  }
}

static void subgroup_add(
    uint8_t accumulator[32], const uint8_t other[32]) {
  unsigned carry = 0;

  for (int i = 31; i >= 0; i--) {
    unsigned sum = (unsigned)accumulator[i] + other[i] + carry;
    accumulator[i] = (uint8_t)sum;
    carry = sum >> 8;
  }

  /* Both operands are reduced, so the sum fits in 252 bits. */
  if (memcmp(accumulator, railgun_subgroup_order, 32) >= 0) {
    subgroup_subtract_order(accumulator);
  }
}

/* Reduce an arbitrary little-endian byte sequence modulo subgroup order. */
static void subgroup_reduce_le(
    const uint8_t *input, size_t length, uint8_t out[32]) {
  memset(out, 0, 32);

  for (size_t i = length; i > 0; i--) {
    for (int bit = 7; bit >= 0; bit--) {
      subgroup_shift_bit(out, (input[i - 1] >> bit) & 1u);
    }
  }
}

/* Reduce an arbitrary big-endian byte sequence modulo subgroup order. */
static void subgroup_reduce_be(
    const uint8_t *input, size_t length, uint8_t out[32]) {
  memset(out, 0, 32);

  for (size_t i = 0; i < length; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      subgroup_shift_bit(out, (input[i] >> bit) & 1u);
    }
  }
}

/* Public test reference: out = factor * reduced_value mod subgroup order. */
static void subgroup_multiply(
    const uint8_t factor[32],
    const uint8_t reduced_value[32],
    uint8_t out[32]) {
  memset(out, 0, 32);

  for (unsigned i = 0; i < 32; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      subgroup_shift_bit(out, 0);

      if ((factor[i] >> bit) & 1u) {
        subgroup_add(out, reduced_value);
      }
    }
  }
}

static void assert_bytes_hex(
    const uint8_t *actual, size_t length, const char *expected_hex) {
  uint8_t expected[64];

  TEST_ASSERT_TRUE(length <= sizeof(expected));
  TEST_ASSERT_EQUAL_UINT(
      length, test_unhex(expected_hex, expected, length));
  TEST_ASSERT_EQUAL_MEMORY(expected, actual, length);
}

static void test_synthetic_eddsa_poseidon_signatures(void) {
  static const struct {
    uint32_t message;
    const char *nonce;
    const char *r8_x;
    const char *r8_y;
    const char *s;
  } vectors[] = {
    {
      0,
      "031dd101d9c07a84285b4273a397aa286f406d30d7fce36fd3925ab93380abdb",
      "25a426befdcc7918713ea23d9b3f0d87ad843362145d7b92d4cd3f166ad6c8bd",
      "241f9a479cf221163eda6eb3772d36f8b398d9f5d13b5ef3e9223215d57ca2b8",
      "013e339699730c7ab62db7474775b241673c3f9c7f4433388f9d33a5dccb1cc1"
    },
    {
      1,
      "00df4db54e41e4fc50b13c0e02e0c1414a763b5e0529678277027051579fe8b4",
      "14a052afd7879fe4bf9aea3cb3cf354f75dd677b15103bf401920efe292d00e0",
      "03c3fdc3bb383e8c5f80b41dc3ce512dc8ae33c9e53be80fd1a352232c39e45a",
      "056c836eb5ac9dd0ce2b39a6322d5046403e359742560d5560a7607b83cfa247"
    },
    {
      12345,
      "0159d924c64d7d42dd0936b68b0948a90a820da1888185125671de372e766215",
      "24ccbdfb612d47b4c41b440eb927f21f34e341f89215932b053ec2b19dc84ce6",
      "171a92a4562a9a063a5d510623bb0537ffba3fb04aa1a16bcc83ea5e881d0651",
      "0496dc182e4598073e8b7d0dd09d555e2e2eddfb99d5af763cf65dac7ec0d944"
    }
  };

  /* Existing public synthetic fixture, not a real spending key. */
  uint8_t synthetic_key[32];
  uint8_t key_digest[64];
  uint8_t pruned[32];
  uint8_t scalar_key_be[32];
  uint8_t pruned_be[32];
  uint8_t reduced_pruned[32];
  uint8_t public_x[32], public_y[32];
  babyjub_point_t base, public_key;

  memset(synthetic_key, 1, sizeof(synthetic_key));
  TEST_ASSERT_TRUE(railgun_blake512(
      synthetic_key, sizeof(synthetic_key), key_digest));

  memcpy(pruned, key_digest, sizeof(pruned));
  pruned[0] &= 0xf8u;
  pruned[31] &= 0x7fu;
  pruned[31] |= 0x40u;

  /* scalar_key = little_endian(pruned) >> 3. */
  for (unsigned i = 0; i < 32; i++) {
    scalar_key_be[31 - i] = (uint8_t)(
        (pruned[i] >> 3) |
        (i + 1 < 32 ? ((unsigned)pruned[i + 1] << 5) : 0));
    pruned_be[31 - i] = pruned[i];
  }

  assert_bytes_hex(
      scalar_key_be, 32,
      "0ba9f4de43d3c912590c6ab4f8e7f3c0c0229e25c7dd052203b928fcdc87dfba");

  subgroup_reduce_be(pruned_be, 32, reduced_pruned);

  load_point(&base, BASE_X, BASE_Y);
  TEST_ASSERT_TRUE(public_mul_256(&base, scalar_key_be, &public_key));

  bn_write_be(&public_key.x, public_x);
  bn_write_be(&public_key.y, public_y);

  assert_bytes_hex(
      public_x, 32,
      "234056d968baf183fe8d237d496d1c04188220cd33e8f8d14df9b84479736b20");
  assert_bytes_hex(
      public_y, 32,
      "2624393fad9b71c04b3b14d8ac45202dbb4eaff4c2d1350c9453fc08d18651fe");

  for (size_t i = 0;
       i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    uint8_t nonce_input[64] = {0};
    uint8_t nonce_digest[64];
    uint8_t nonce[32];
    uint8_t r8_x[32], r8_y[32];
    uint8_t inputs[5][32] = {{0}};
    uint8_t challenge[32];
    uint8_t s[32];
    babyjub_point_t r8;
    uint32_t message = vectors[i].message;

    /* nonce_input = key_hash[32..64] || message_le_32 */
    memcpy(nonce_input, key_digest + 32, 32);
    nonce_input[32] = (uint8_t)message;
    nonce_input[33] = (uint8_t)(message >> 8);
    nonce_input[34] = (uint8_t)(message >> 16);
    nonce_input[35] = (uint8_t)(message >> 24);

    TEST_ASSERT_TRUE(railgun_blake512(
        nonce_input, sizeof(nonce_input), nonce_digest));

    subgroup_reduce_le(nonce_digest, 64, nonce);
    assert_bytes_hex(nonce, 32, vectors[i].nonce);

    TEST_ASSERT_TRUE(public_mul_256(&base, nonce, &r8));
    bn_write_be(&r8.x, r8_x);
    bn_write_be(&r8.y, r8_y);

    assert_bytes_hex(r8_x, 32, vectors[i].r8_x);
    assert_bytes_hex(r8_y, 32, vectors[i].r8_y);

    /* hm = Poseidon(R8.x, R8.y, A.x, A.y, message). */
    memcpy(inputs[0], r8_x, 32);
    memcpy(inputs[1], r8_y, 32);
    memcpy(inputs[2], public_x, 32);
    memcpy(inputs[3], public_y, 32);
    inputs[4][28] = (uint8_t)(message >> 24);
    inputs[4][29] = (uint8_t)(message >> 16);
    inputs[4][30] = (uint8_t)(message >> 8);
    inputs[4][31] = (uint8_t)message;

    TEST_ASSERT_EQUAL_INT(
        HAL_SUCCESS, railgun_poseidon_t6_hash(inputs, challenge));

    /* S = (r + hm * (scalar_key << 3)) mod subgroup order. */
    subgroup_multiply(challenge, reduced_pruned, s);
    subgroup_add(s, nonce);

    assert_bytes_hex(s, 32, vectors[i].s);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_base_point_is_on_curve);
  RUN_TEST(test_base_point_doubling);
  RUN_TEST(test_base_point_tripling);
  RUN_TEST(test_additive_identity);
  RUN_TEST(test_additive_inverse);
  RUN_TEST(test_reject_off_curve_coordinates);
  RUN_TEST(test_public_scalar_reference_vectors);
  RUN_TEST(test_public_scalar_rejects_invalid_point);
  RUN_TEST(test_full_width_scalar_vectors);
  RUN_TEST(test_full_width_rejects_invalid_base);
  RUN_TEST(test_synthetic_eddsa_poseidon_signatures);
  return UNITY_END();
}
