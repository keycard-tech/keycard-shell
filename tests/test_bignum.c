/* app/crypto/bignum.c -- 256-bit arithmetic on nine limbs of 29 bits, the ground under ECDSA and
 * under the amount the user reads before approving.
 *
 * Expectations come from CPython's integers, computed from the representation this module itself
 * documents (value = sum(limb[i] * 2**(29*i))); see vectors/vectors_bignum.h. The oracle shares no
 * limb width, no reduction trick and no code with the module, so the two agreeing means something.
 *
 * Several functions promise only that the answer is *partly* reduced -- anything below 2*prime is
 * within their contract -- and those are range-checked against 2*prime and then reduced with bn_mod
 * before comparison, which is how the elliptic curve code consumes them anyway.
 *
 * The module's own asserts are live in this build, so a vector that broke a documented precondition
 * would abort here rather than pass on garbage. */

#include <string.h>

#include "crypto/bignum.h"
#include "crypto/secp256k1.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_bignum.h"

static bignum256 a, b, prime, result;
static uint8_t raw[64];

void setUp(void) {
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&prime, 0, sizeof(prime));
  memset(&result, 0, sizeof(result));
}

void tearDown(void) {}

static void load(const uint32_t limbs[BN_LIMBS], bignum256* out) {
  memcpy(out->val, limbs, sizeof(out->val));
}

static void load_hex(const char* hex, bignum256* out) {
  size_t len = test_unhex(hex, raw, 32);
  TEST_ASSERT_EQUAL_MESSAGE(strlen(hex) / 2, len, "operand width");
  bn_read_be(raw, out);
}

/* Every function guarantees a normalized answer. A limb at or above 2**29 is a failure by itself:
 * the number it represents silently carries into the limb above, and the sum still looks right. */
static void assert_limbs(const uint32_t expected[BN_LIMBS], const bignum256* got,
                         const char* name) {
  for (int i = 0; i < BN_LIMBS; i++) {
    TEST_ASSERT_LESS_THAN_UINT_MESSAGE(BN_BASE, got->val[i], name);
  }
  TEST_ASSERT_EQUAL_HEX32_ARRAY_MESSAGE(expected, got->val, BN_LIMBS, name);
}

/* For the functions whose contract is only "partly reduced modulo prime". */
static void assert_partly_reduced(const uint32_t expected[BN_LIMBS], const bignum256* got,
                                  const char* name) {
  bignum256 reduced = *got, twice = prime;
  bn_add(&twice, &prime);
  TEST_ASSERT_TRUE_MESSAGE(bn_is_less(&reduced, &twice), name);
  bn_mod(&reduced, &prime);
  assert_limbs(expected, &reduced, name);
}

static int limbs_is_zero(const uint32_t limbs[BN_LIMBS]) {
  uint32_t any = 0;
  for (int i = 0; i < BN_LIMBS; i++) {
    any |= limbs[i];
  }
  return !any;
}

static int limbs_less(const uint32_t* x, const uint32_t* y) {
  for (int i = BN_LIMBS - 1; i >= 0; i--) {
    if (x[i] != y[i]) {
      return x[i] < y[i];
    }
  }
  return 0;
}

static const bn_value_t* value_row(const char* name) {
  for (size_t i = 0; i < VALUES_COUNT; i++) {
    if (strcmp(values[i].name, name) == 0) {
      return &values[i];
    }
  }
  TEST_FAIL_MESSAGE("vector missing");
  return NULL;
}

static void test_read_write(void) {
  for (size_t i = 0; i < VALUES_COUNT; i++) {
    const bn_value_t* v = &values[i];

    load_hex(v->hex, &a);
    assert_limbs(v->limbs, &a, v->name);

    memset(raw, 0xa5, sizeof(raw));
    bn_write_be(&a, raw);
    TEST_ASSERT_HEX_MESSAGE(raw, 32, v->hex, v->name);
    /* Nothing past the 32 bytes is written. */
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, raw[32], v->name);

    size_t le_len = test_unhex(v->le_hex, raw, 32);
    TEST_ASSERT_EQUAL_MESSAGE(32, le_len, v->name);
    bn_read_le(raw, &b);
    assert_limbs(v->limbs, &b, v->name);

    memset(raw, 0xa5, sizeof(raw));
    bn_write_le(&a, raw);
    TEST_ASSERT_HEX_MESSAGE(raw, 32, v->le_hex, v->name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, raw[32], v->name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->bitcount, bn_bitcount(&a), v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->digitcount, bn_digitcount(&a), v->name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(limbs_is_zero(v->limbs), bn_is_zero(&a), v->name);
    uint32_t one[BN_LIMBS] = {1};
    TEST_ASSERT_EQUAL_INT_MESSAGE(!limbs_less(one, v->limbs) && !limbs_less(v->limbs, one),
                                  bn_is_one(&a), v->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE((v->limbs[0] & 1) == 0, bn_is_even(&a), v->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE((v->limbs[0] & 1) == 1, bn_is_odd(&a), v->name);
  }

  bn_zero(&a);
  TEST_ASSERT_TRUE_MESSAGE(bn_is_zero(&a), "bn_zero");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, bn_bitcount(&a), "bn_zero bitcount");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, bn_digitcount(&a), "bn_zero digitcount");
  bn_one(&b);
  TEST_ASSERT_TRUE_MESSAGE(bn_is_one(&b), "bn_one");
  TEST_ASSERT_FALSE_MESSAGE(bn_is_zero(&b), "bn_one is not zero");
}

static void test_read_write_integers(void) {
  for (size_t i = 0; i < VALUES_COUNT; i++) {
    const bn_value_t* v = &values[i];
    /* These two take a machine integer, so only the values small enough for one have a round trip
     * to check. */
    int fits32 = v->limbs[1] < (1u << (32 - BN_BITS_PER_LIMB));
    int fits64 = v->limbs[2] < (1u << (64 - 2 * BN_BITS_PER_LIMB));
    for (int limb = 2; limb < BN_LIMBS; limb++) {
      fits32 = fits32 && v->limbs[limb] == 0;
    }
    for (int limb = 3; limb < BN_LIMBS; limb++) {
      fits64 = fits64 && v->limbs[limb] == 0;
    }
    if (fits32) {
      uint32_t small = v->limbs[0] | (v->limbs[1] << BN_BITS_PER_LIMB);
      bn_read_uint32(small, &a);
      assert_limbs(v->limbs, &a, v->name);
      TEST_ASSERT_EQUAL_HEX32_MESSAGE(small, bn_write_uint32(&a), v->name);
    }
    if (fits64) {
      uint64_t wide = ((uint64_t)v->limbs[2] << (2 * BN_BITS_PER_LIMB)) |
                      ((uint64_t)v->limbs[1] << BN_BITS_PER_LIMB) | v->limbs[0];
      bn_read_uint64(wide, &a);
      assert_limbs(v->limbs, &a, v->name);
      TEST_ASSERT_EQUAL_HEX64_MESSAGE(wide, bn_write_uint64(&a), v->name);
    }
  }
}

static void test_compact_be(void) {
  for (size_t i = 0; i < COMPACT_BE_CASES_COUNT; i++) {
    /* The vector's number written big-endian, of which the last `length` bytes are handed over as
     * the whole of it. */
    load(compact_be_cases[i].in, &a);
    bn_write_be(&a, raw);
    bn_read_compact_be(raw + 32 - compact_be_cases[i].length, compact_be_cases[i].length, &result);
    assert_limbs(compact_be_cases[i].out, &result, compact_be_cases[i].name);
  }
}

static void test_compare(void) {
  for (size_t i = 0; i < VALUES_COUNT; i++) {
    for (size_t j = 0; j < VALUES_COUNT; j++) {
      load(values[i].limbs, &a);
      load(values[j].limbs, &b);
      TEST_ASSERT_EQUAL_INT_MESSAGE(limbs_less(values[i].limbs, values[j].limbs),
                                    bn_is_less(&a, &b), values[i].name);
      TEST_ASSERT_EQUAL_INT_MESSAGE(!limbs_less(values[i].limbs, values[j].limbs) &&
                                      !limbs_less(values[j].limbs, values[i].limbs),
                                    bn_is_equal(&a, &b), values[i].name);
    }
  }
}

static void test_bits(void) {
  static const uint16_t positions[] = {0, 1, 28, 29, 30, 57, 58, 127, 128, 231, 232, 254, 255};

  for (size_t i = 0; i < VALUES_COUNT; i++) {
    for (size_t p = 0; p < sizeof(positions) / sizeof(positions[0]); p++) {
      uint16_t bit = positions[p];
      uint32_t expected = (values[i].limbs[bit / BN_BITS_PER_LIMB] >>
                           (bit % BN_BITS_PER_LIMB)) &
                          1;

      load(values[i].limbs, &a);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected, bn_testbit(&a, bit), values[i].name);

      uint32_t cleared[BN_LIMBS], set[BN_LIMBS];
      memcpy(cleared, values[i].limbs, sizeof(cleared));
      memcpy(set, values[i].limbs, sizeof(set));
      cleared[bit / BN_BITS_PER_LIMB] &= ~(1u << (bit % BN_BITS_PER_LIMB));
      set[bit / BN_BITS_PER_LIMB] |= 1u << (bit % BN_BITS_PER_LIMB);

      bn_clearbit(&a, bit);
      assert_limbs(cleared, &a, values[i].name);
      bn_setbit(&a, bit);
      assert_limbs(set, &a, values[i].name);
    }
  }
}

static void test_cmov_xor(void) {
  for (size_t i = 0; i < VALUES_COUNT; i++) {
    const bn_value_t* other = &values[(i + 1) % VALUES_COUNT];
    load(values[i].limbs, &a);
    load(other->limbs, &b);

    bn_cmov(&result, 1, &a, &b);
    assert_limbs(values[i].limbs, &result, values[i].name);
    bn_cmov(&result, 0, &a, &b);
    assert_limbs(other->limbs, &result, values[i].name);

    /* bn_mod and bn_inverse_fast both pass the same object as the result and as one of the two
     * cases, so those combinations are part of the contract even though the signature forbids
     * nothing else. */
    load(values[i].limbs, &result);
    bn_cmov(&result, 1, &a, &b);
    assert_limbs(values[i].limbs, &result, "cmov res aliases truecase");
    load(other->limbs, &result);
    bn_cmov(&result, 0, &a, &b);
    assert_limbs(other->limbs, &result, "cmov res aliases falsecase");

    uint32_t xored[BN_LIMBS];
    for (int limb = 0; limb < BN_LIMBS; limb++) {
      xored[limb] = values[i].limbs[limb] ^ other->limbs[limb];
    }
    bn_xor(&result, &a, &b);
    assert_limbs(xored, &result, values[i].name);
    load(values[i].limbs, &result);
    bn_xor(&result, &result, &b);
    assert_limbs(xored, &result, "xor res aliases first operand");
  }
}

static void test_normalize_and_shifts(void) {
  for (size_t i = 0; i < NORMALIZE_CASES_COUNT; i++) {
    load(normalize_cases[i].in, &a);
    bn_normalize(&a);
    assert_limbs(normalize_cases[i].out, &a, normalize_cases[i].name);
  }

  for (size_t i = 0; i < LSHIFT_CASES_COUNT; i++) {
    load(lshift_cases[i].in, &a);
    bn_lshift(&a);
    assert_limbs(lshift_cases[i].out, &a, lshift_cases[i].name);
  }

  for (size_t i = 0; i < RSHIFT_CASES_COUNT; i++) {
    load(rshift_cases[i].in, &a);
    bn_rshift(&a);
    assert_limbs(rshift_cases[i].out, &a, rshift_cases[i].name);
  }
}

static void test_fast_mod(void) {
  for (size_t i = 0; i < FAST_MOD_CASES_COUNT; i++) {
    load_hex(fast_mod_cases[i].p_hex, &prime);
    load(fast_mod_cases[i].in, &a);
    bn_fast_mod(&a, &prime);
    assert_limbs(fast_mod_cases[i].out, &a, fast_mod_cases[i].name);
  }
}

static void test_add_subtract(void) {
  for (size_t i = 0; i < ADD_CASES_COUNT; i++) {
    load(add_cases[i].a, &a);
    load(add_cases[i].b, &b);
    bn_add(&a, &b);
    assert_limbs(add_cases[i].out, &a, add_cases[i].name);
  }

  /* x += x is the aliasing case the file calls out, and the way ecdsa_soft.c doubles a point. */
  for (size_t i = 0; i < VALUES_COUNT && i < 8; i++) {
    load(values[i].limbs, &a);
    load(values[i].limbs, &b);
    bn_add(&a, &a);
    uint32_t doubled[BN_LIMBS];
    uint32_t carry = 0;
    for (int limb = 0; limb < BN_LIMBS; limb++) {
      carry += values[i].limbs[limb] * 2u;
      doubled[limb] = carry & (BN_BASE - 1);
      carry >>= BN_BITS_PER_LIMB;
    }
    assert_limbs(doubled, &a, "double");
  }

  for (size_t i = 0; i < ADDMOD_CASES_COUNT; i++) {
    load_hex(addmod_cases[i].p_hex, &prime);
    load(addmod_cases[i].a, &a);
    load(addmod_cases[i].b, &b);
    bn_addmod(&a, &b, &prime);
    assert_partly_reduced(addmod_cases[i].out, &a, addmod_cases[i].name);
  }

  for (size_t i = 0; i < ADDI_CASES_COUNT; i++) {
    load(addi_cases[i].a, &a);
    bn_addi(&a, addi_cases[i].k);
    assert_limbs(addi_cases[i].out, &a, addi_cases[i].name);
  }

  for (size_t i = 0; i < SUBI_CASES_COUNT; i++) {
    load_hex(subi_cases[i].p_hex, &prime);
    load(subi_cases[i].a, &a);
    bn_subi(&a, subi_cases[i].k, &prime);
    assert_limbs(subi_cases[i].out, &a, subi_cases[i].name);
  }

  for (size_t i = 0; i < SUB_CASES_COUNT; i++) {
    load(sub_cases[i].a, &a);
    load(sub_cases[i].b, &b);
    bn_subtract(&a, &b, &result);
    assert_limbs(sub_cases[i].out, &result, sub_cases[i].name);
    /* res may alias either operand. */
    load(sub_cases[i].b, &b);
    bn_subtract(&a, &b, &a);
    assert_limbs(sub_cases[i].out, &a, "subtract res aliases x");
  }

  for (size_t i = 0; i < SUBTRACTMOD_CASES_COUNT; i++) {
    load_hex(subtractmod_cases[i].p_hex, &prime);
    load(subtractmod_cases[i].a, &a);
    load(subtractmod_cases[i].b, &b);
    bn_subtractmod(&a, &b, &result, &prime);
    assert_limbs(subtractmod_cases[i].out, &result, subtractmod_cases[i].name);
  }
}

static void test_modular(void) {
  for (size_t i = 0; i < MULT_K_CASES_COUNT; i++) {
    load_hex(mult_k_cases[i].p_hex, &prime);
    load(mult_k_cases[i].a, &a);
    bn_mult_k(&a, mult_k_cases[i].k, &prime);
    assert_partly_reduced(mult_k_cases[i].out, &a, mult_k_cases[i].name);
  }

  for (size_t i = 0; i < MULT_HALF_CASES_COUNT; i++) {
    load_hex(mult_half_cases[i].p_hex, &prime);
    load(mult_half_cases[i].a, &a);
    bn_mult_half(&a, &prime);
    assert_limbs(mult_half_cases[i].out, &a, mult_half_cases[i].name);
  }

  for (size_t i = 0; i < CNEGATE_CASES_COUNT; i++) {
    load_hex(cnegate_cases[i].p_hex, &prime);
    load(cnegate_cases[i].a, &a);
    bn_cnegate(cnegate_cases[i].k, &a, &prime);
    assert_limbs(cnegate_cases[i].out, &a, cnegate_cases[i].name);
  }

  for (size_t i = 0; i < MOD_CASES_COUNT; i++) {
    load_hex(mod_cases[i].p_hex, &prime);
    load(mod_cases[i].a, &a);
    bn_mod(&a, &prime);
    assert_limbs(mod_cases[i].out, &a, mod_cases[i].name);
  }

  for (size_t i = 0; i < MULTIPLY_CASES_COUNT; i++) {
    load_hex(multiply_cases[i].p_hex, &prime);
    load(multiply_cases[i].a, &a);
    load(multiply_cases[i].b, &b);
    bn_multiply(&a, &b, &prime);
    assert_partly_reduced(multiply_cases[i].out, &b, multiply_cases[i].name);
    /* The rows where the multiplier and the value are the same number are also the rows where they
     * can be the same object, which is how a squaring is done. */
    if (memcmp(multiply_cases[i].a, multiply_cases[i].b, sizeof multiply_cases[i].a) == 0) {
      load(multiply_cases[i].b, &b);
      bn_multiply(&b, &b, &prime);
      assert_partly_reduced(multiply_cases[i].out, &b, "multiply squared in place");
    }
  }

  for (size_t i = 0; i < DIVIDE_BASE_CASES_COUNT; i++) {
    load_hex(divide_base_cases[i].p_hex, &prime);
    load(divide_base_cases[i].a, &a);
    bn_divide_base(&a, &prime);
    assert_limbs(divide_base_cases[i].out, &a, divide_base_cases[i].name);
  }
}

static void test_power_sqrt_inverse(void) {
  for (size_t i = 0; i < POWER_MOD_CASES_COUNT; i++) {
    load_hex(power_mod_cases[i].p_hex, &prime);
    load(power_mod_cases[i].a, &a);
    load(power_mod_cases[i].b, &b);
    bn_power_mod(&a, &b, &prime, &result);
    assert_partly_reduced(power_mod_cases[i].out, &result, power_mod_cases[i].name);
    /* The file states x and res may be the same object, which is how bn_sqrt calls it. */
    load(power_mod_cases[i].a, &a);
    load(power_mod_cases[i].b, &b);
    bn_power_mod(&a, &b, &prime, &a);
    assert_partly_reduced(power_mod_cases[i].out, &a, "power_mod in place");
  }

  for (size_t i = 0; i < SQRT_CASES_COUNT; i++) {
    load_hex(sqrt_cases[i].p_hex, &prime);
    load(sqrt_cases[i].a, &a);
    bn_sqrt(&a, &prime);
    assert_limbs(sqrt_cases[i].out, &a, sqrt_cases[i].name);

    /* And the answer really is a square root: squaring it returns the input. This does not lean on
     * the exponent formula, only on bn_multiply and bn_mod agreeing. */
    bignum256 squared = a;
    bn_multiply(&a, &squared, &prime);
    bn_mod(&squared, &prime);
    bignum256 given;
    load(sqrt_cases[i].a, &given);
    TEST_ASSERT_TRUE_MESSAGE(bn_is_equal(&squared, &given), sqrt_cases[i].name);
  }

  for (size_t i = 0; i < INVERSE_CASES_COUNT; i++) {
    load_hex(inverse_cases[i].p_hex, &prime);
    load(inverse_cases[i].a, &a);
    bn_inverse(&a, &prime);
    assert_limbs(inverse_cases[i].out, &a, inverse_cases[i].name);

    /* x * (1/x) == 1, or 0 for the zero input the file says stays zero. The multiplication is the
     * check; a wrong inverse cannot satisfy it. */
    TEST_ASSERT_TRUE_MESSAGE(bn_is_less(&a, &prime), inverse_cases[i].name);
    if (!limbs_is_zero(inverse_cases[i].out)) {
      bignum256 original, product;
      load(inverse_cases[i].a, &original);
      bn_fast_mod(&original, &prime);
      bn_mod(&original, &prime);
      product = original;
      bn_multiply(&a, &product, &prime);   /* x * (1/x) */
      bn_mod(&product, &prime);
      uint32_t one[BN_LIMBS] = {1};
      assert_limbs(one, &product, inverse_cases[i].name);
    }
  }

  for (size_t i = 0; i < BN_INVERSE_POW2_COUNT; i++) {
    uint32_t a_odd = BN_INVERSE_POW2[i][0], bits = BN_INVERSE_POW2[i][1];
    uint32_t mask = bits == 32 ? 0xFFFFFFFFu : (1u << bits) - 1;
    uint32_t got = inverse_mod_power_two(a_odd, bits);

    /* For n = 1 the iteration (which runs while i < n, from i = 1) never executes, so the
     * accumulator is never masked: the answer is congruent to the inverse but not reduced to n
     * bits. The round trip holds either way and is what the function is for. */
    if (bits == 1) {
      TEST_ASSERT_EQUAL_HEX32_MESSAGE(BN_INVERSE_POW2[i][2], got & mask, "inverse_mod_power_two");
    } else {
      TEST_ASSERT_EQUAL_HEX32_MESSAGE(BN_INVERSE_POW2[i][2], got, "inverse_mod_power_two");
    }
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(1u, (uint32_t)(((uint64_t)got * a_odd) & mask),
                                    "inverse_mod_power_two round trip");
  }
}

static void test_division(void) {
  for (size_t i = 0; i < DIV_CASES_COUNT; i++) {
    uint32_t remainder = 0xdeadbeef;
    load(div_cases[i].a, &a);
    bn_long_division(&a, div_cases[i].k, &result, &remainder);
    assert_limbs(div_cases[i].out, &result, div_cases[i].name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(div_cases[i].extra, remainder, div_cases[i].name);

    /* The two exported wrappers divide in place, which is what bn_digitcount relies on. */
    if (div_cases[i].k == 58 || div_cases[i].k == 1000) {
      uint32_t in_place = 0;
      load(div_cases[i].a, &b);
      if (div_cases[i].k == 58) {
        bn_divmod58(&b, &in_place);
      } else {
        bn_divmod1000(&b, &in_place);
      }
      assert_limbs(div_cases[i].out, &b, div_cases[i].name);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(div_cases[i].extra, in_place, div_cases[i].name);
    }
  }
}

static void test_format(void) {
  /* Filled with a pattern so writing past the promised capacity is visible without waiting for
   * the sanitizer to notice an overrun inside a larger object. */
  static uint8_t buffer[256];

  for (size_t i = 0; i < FORMAT_CASES_COUNT; i++) {
    const bn_format_t* f = &format_cases[i];
    memset(buffer, 0xa5, sizeof(buffer));

    load_hex(f->amount_hex, &a);
    size_t written = bn_format(&a, f->prefix, f->suffix, f->decimals, f->exponent, f->trailing,
                               f->thousands, (char*)buffer, f->capacity);

    TEST_ASSERT_EQUAL_UINT_MESSAGE(strlen(f->expect), written, f->name);
    if (f->expect[0] == '\0') {
      /* Refusing to format writes an empty string, and the module clears the buffer it was given on
       * the way out -- but a zero capacity means it is given nowhere to write. Only what lies beyond
       * the promised capacity belongs to the caller. */
      if (f->capacity > 0) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE('\0', buffer[0], f->name);
      }
    } else {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(f->expect, (const char*)buffer, f->name);
    }
    for (size_t used = f->capacity; used < sizeof(buffer); used++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, buffer[used], "format wrote past capacity");
    }
  }
}

static void test_curve_constants(void) {
  /* The generator derives the prime as 2**256 - 2**32 - 977 the way SEC 2 states it, screens both
   * moduli for primality, and then computes every modular expectation from them -- so this checks
   * the constants the firmware ships against something other than themselves. */
  TEST_ASSERT_HEX(secp256k1.prime, 32, value_row("secp256k1 p")->hex);
  TEST_ASSERT_HEX(secp256k1.order, 32, value_row("secp256k1 n")->hex);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_read_write);
  RUN_TEST(test_read_write_integers);
  RUN_TEST(test_compact_be);
  RUN_TEST(test_compare);
  RUN_TEST(test_bits);
  RUN_TEST(test_cmov_xor);
  RUN_TEST(test_normalize_and_shifts);
  RUN_TEST(test_fast_mod);
  RUN_TEST(test_add_subtract);
  RUN_TEST(test_modular);
  RUN_TEST(test_power_sqrt_inverse);
  RUN_TEST(test_division);
  RUN_TEST(test_format);
  RUN_TEST(test_curve_constants);
  return UNITY_END();
}
