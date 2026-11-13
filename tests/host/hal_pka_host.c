/*
 * A stand-in for the public key accelerator, so the curve code in app/ can be tested against
 * something that computes. The arithmetic is app/crypto/bignum.c, which the suite already pins.
 *
 * The contract is the one in stm32/Core/Src/stm32_crypto.c: curve parameters, a point and a
 * digest go in, and the outcome of the verification equation comes out. This file computes that
 * equation and nothing beside it, which keeps the questions of what to reject beforehand and what
 * to accept afterwards where a test can see them, in app/.
 *
 * A point operation whose answer is the point at infinity -- a zero scalar on its own, a point
 * added to its negation -- returns HAL_FAIL, because 64 bytes cannot hold that answer. A zero
 * scalar beside a nonzero one is a real point and succeeds. hal_ecdsa_sign additionally refuses a
 * zero k, a zero r or a zero s; hal_ecdsa_verify refuses an r or an s outside [1, n-1]. How
 * silicon treats each of these is not recorded anywhere here, so a test that needs to know one is
 * a question for the device rather than for this file.
 *
 * Encoding is the PKA's: 32 bytes big-endian per scalar or field element, 64 per point with x
 * then y and no prefix byte, which is how basePointX and basePointY are read out of the curve
 * struct.
 *
 * Constant time is not modelled: branches follow the scalar's bits and bignum's plain paths are
 * used. It stands in for silicon inside a test, so a test can ask what the curve code does with
 * a point or a signature; timing questions stay where the silicon is.
 */

#include <stdbool.h>
#include <string.h>

#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "hal.h"

#define EL ECC256_ELEMENT_SIZE

typedef struct {
  bignum256 p; /* field prime */
  bignum256 n; /* group order */
  bignum256 a; /* |a|, with the sign kept separately as the curve struct does */
  bignum256 b;
  bool a_neg;
} pcurve_t;

static void pcurve_load(pcurve_t *c, const ecdsa_curve *src) {
  bn_read_be(src->prime, &c->p);
  bn_read_be(src->order, &c->n);
  bn_read_be(src->a, &c->a);
  bn_read_be(src->b, &c->b);
  /* coefSign is a_sign & 1 on the way to the PKA, so the bit set means subtract. */
  c->a_neg = (src->a_sign & 1) != 0;
}

/* bignum's guarantees are all "below 2 * m" at best, and bn_subtractmod hands back
 * x + 2*m - y, which needs more than one conditional subtract to bring below m. Fully reducing
 * here means every helper below can be composed without tracking how reduced its inputs are. */
static void f_reduce(bignum256 *r, const bignum256 *m) {
  while (!bn_is_less(r, m)) {
    bn_subtract(r, m, r);
  }
}


/* All three take the arguments through a temporary, because a caller that writes the answer over
 * one of the inputs has to read it first: with r and y the same object, copying x into r is
 * copying over a multiplicand. */
static void f_mul(bignum256 *r, const bignum256 *x, const bignum256 *y, const bignum256 *m) {
  bignum256 product = *x;
  bn_multiply(y, &product, m);
  f_reduce(&product, m);
  *r = product;
}

static void f_sqr(bignum256 *r, const bignum256 *x, const bignum256 *m) { f_mul(r, x, x, m); }

static void f_add(bignum256 *r, const bignum256 *x, const bignum256 *y, const bignum256 *m) {
  bignum256 sum = *x;
  bn_addmod(&sum, y, m);
  f_reduce(&sum, m);
  *r = sum;
}

static void f_sub(bignum256 *r, const bignum256 *x, const bignum256 *y, const bignum256 *m) {
  bignum256 difference;
  bn_subtractmod(x, y, &difference, m);
  f_reduce(&difference, m);
  *r = difference;
}

static void f_neg(bignum256 *r, const bignum256 *x, const bignum256 *m) {
  bignum256 zero;
  bn_zero(&zero);
  f_sub(r, &zero, x, m);
}

static void f_inv(bignum256 *r, const bignum256 *x, const bignum256 *m) {
  *r = *x;
  bn_inverse(r, m);
}

/* Jacobian coordinates: the affine point (x/z^2, y/z^3). z zero is the point at infinity. */
typedef struct {
  bignum256 x, y, z;
} jpoint_t;

static bool j_infinite(const jpoint_t *q) { return bn_is_zero(&q->z); }

static void j_set_infinite(jpoint_t *q) { bn_zero(&q->z); }

static void j_from_affine(jpoint_t *r, const uint8_t point[ECC256_POINT_SIZE], const pcurve_t *c) {
  bn_read_be(point, &r->x);
  f_reduce(&r->x, &c->p);
  bn_read_be(&point[EL], &r->y);
  f_reduce(&r->y, &c->p);
  bn_one(&r->z);
}

/* False for the point at infinity, which has no affine encoding. */
static bool j_to_affine(uint8_t out[ECC256_POINT_SIZE], const jpoint_t *q, const pcurve_t *c) {
  if (j_infinite(q)) {
    return false;
  }

  bignum256 zi, zi2, x, y;
  f_inv(&zi, &q->z, &c->p);
  f_sqr(&zi2, &zi, &c->p);
  f_mul(&x, &q->x, &zi2, &c->p);
  f_mul(&y, &q->y, &zi, &c->p);
  f_mul(&y, &y, &zi2, &c->p);

  bn_write_be(&x, out);
  bn_write_be(&y, &out[EL]);
  return true;
}

/* dbl-2007-bl and add-2007-bl from hyperelliptic.org's Explicit-Formulas Database, which make
 * no assumption about a. r may alias q or p: the writes are from locals at the end. */
static void j_double(jpoint_t *r, const jpoint_t *q, const pcurve_t *c) {
  const bignum256 *m = &c->p;
  bignum256 xx, yy, yyyy, zz, s, mm, x3, y3, z3, t;

  if (j_infinite(q)) {
    j_set_infinite(r);
    return;
  }

  f_sqr(&xx, &q->x, m);
  f_sqr(&yy, &q->y, m);
  if (bn_is_zero(&yy)) {
    /* The formulas below divide by y. */
    j_set_infinite(r);
    return;
  }
  f_sqr(&yyyy, &yy, m);
  f_sqr(&zz, &q->z, m);

  /* S = 2 * ((X + YY)^2 - XX - YYYY) */
  f_add(&t, &q->x, &yy, m);
  f_sqr(&t, &t, m);
  f_sub(&t, &t, &xx, m);
  f_sub(&t, &t, &yyyy, m);
  f_add(&s, &t, &t, m);

  /* M = 3XX + a*ZZ^2 */
  f_mul(&mm, &zz, &zz, m);
  f_mul(&mm, &mm, &c->a, m);
  if (c->a_neg) {
    f_neg(&mm, &mm, m);
  }
  f_add(&t, &xx, &xx, m);
  f_add(&mm, &mm, &t, m);
  f_add(&mm, &mm, &xx, m);

  /* X3 = M^2 - 2S */
  f_sqr(&x3, &mm, m);
  f_sub(&x3, &x3, &s, m);
  f_sub(&x3, &x3, &s, m);

  /* Y3 = M*(S - X3) - 8*YYYY */
  f_sub(&t, &s, &x3, m);
  f_mul(&y3, &mm, &t, m);
  f_add(&yyyy, &yyyy, &yyyy, m);
  f_add(&yyyy, &yyyy, &yyyy, m);
  f_add(&yyyy, &yyyy, &yyyy, m);
  f_sub(&y3, &y3, &yyyy, m);

  /* Z3 = 2YZ */
  f_add(&z3, &q->y, &q->z, m);
  f_sqr(&z3, &z3, m);
  f_sub(&z3, &z3, &yy, m);
  f_sub(&z3, &z3, &zz, m);

  r->x = x3;
  r->y = y3;
  r->z = z3;
}

static void j_add(jpoint_t *r, const jpoint_t *q, const jpoint_t *p, const pcurve_t *c) {
  const bignum256 *m = &c->p;
  bignum256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, x3, y3, z3;

  if (j_infinite(q)) {
    *r = *p;
    return;
  }
  if (j_infinite(p)) {
    *r = *q;
    return;
  }

  f_sqr(&z1z1, &q->z, m);
  f_sqr(&z2z2, &p->z, m);
  f_mul(&u1, &q->x, &z2z2, m);
  f_mul(&u2, &p->x, &z1z1, m);
  f_mul(&s1, &q->y, &p->z, m);
  f_mul(&s1, &s1, &z2z2, m);
  f_mul(&s2, &p->y, &q->z, m);
  f_mul(&s2, &s2, &z1z1, m);

  f_sub(&h, &u2, &u1, m);
  f_sub(&rr, &s2, &s1, m);

  if (bn_is_zero(&h)) {
    if (bn_is_zero(&rr)) {
      j_double(r, q, c);
      return;
    }
    /* Same x, different y: the sum is the point at infinity. */
    j_set_infinite(r);
    return;
  }

  /* I = (2H)^2, J = H*I, V = U1*I, r = 2*(S2-S1) */
  f_add(&i, &h, &h, m);
  f_sqr(&i, &i, m);
  f_mul(&j, &h, &i, m);
  f_mul(&v, &u1, &i, m);
  f_add(&rr, &rr, &rr, m);

  /* X3 = r^2 - J - 2V */
  f_sqr(&x3, &rr, m);
  f_sub(&x3, &x3, &j, m);
  f_sub(&x3, &x3, &v, m);
  f_sub(&x3, &x3, &v, m);

  /* Y3 = r*(V - X3) - 2*S1*J */
  f_sub(&y3, &v, &x3, m);
  f_mul(&y3, &rr, &y3, m);
  f_mul(&s1, &s1, &j, m);
  f_add(&s1, &s1, &s1, m);
  f_sub(&y3, &y3, &s1, m);

  /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H */
  f_add(&z3, &q->z, &p->z, m);
  f_sqr(&z3, &z3, m);
  f_sub(&z3, &z3, &z1z1, m);
  f_sub(&z3, &z3, &z2z2, m);
  f_mul(&z3, &z3, &h, m);

  r->x = x3;
  r->y = y3;
  r->z = z3;
}

static void j_mul(jpoint_t *r, const bignum256 *k, const jpoint_t *q, const pcurve_t *c) {
  jpoint_t acc;
  j_set_infinite(&acc);

  for (int bit = 255; bit >= 0; bit--) {
    j_double(&acc, &acc, c);
    if (bn_testbit(k, (uint16_t)bit)) {
      j_add(&acc, &acc, q, c);
    }
  }

  *r = acc;
}

/* y^2 == x^3 + a*x + b in the field, with a's sign as the curve struct records it. Arithmetic is
 * modulo p, so a coordinate of p + x denotes the same element as x and is not distinguishable
 * here. */
static bool point_on_curve(const uint8_t point[ECC256_POINT_SIZE], const pcurve_t *c) {
  const bignum256 *m = &c->p;
  bignum256 x, y, lhs, rhs;

  bn_read_be(point, &x);
  f_reduce(&x, m);
  bn_read_be(&point[EL], &y);
  f_reduce(&y, m);

  f_sqr(&lhs, &y, m);

  f_sqr(&rhs, &x, m);
  if (c->a_neg) {
    bignum256 a;
    f_neg(&a, &c->a, m);
    f_add(&rhs, &rhs, &a, m);
  } else {
    f_add(&rhs, &rhs, &c->a, m);
  }
  f_mul(&rhs, &rhs, &x, m);
  f_add(&rhs, &rhs, &c->b, m);

  return bn_is_equal(&lhs, &rhs);
}

hal_err_t hal_ec_point_check(const ecdsa_curve* curve, const uint8_t* point) {
  pcurve_t c;
  pcurve_load(&c, curve);
  return point_on_curve(point, &c) ? HAL_SUCCESS : HAL_FAIL;
}

hal_err_t hal_ec_point_multiply(const ecdsa_curve* curve, const uint8_t* scalar,
                                const uint8_t* point, uint8_t* point_out) {
  pcurve_t c;
  pcurve_load(&c, curve);

  bignum256 k;
  bn_read_be(scalar, &k);
  f_reduce(&k, &c.n);

  jpoint_t q, r;
  j_from_affine(&q, point, &c);
  j_mul(&r, &k, &q, &c);

  return j_to_affine(point_out, &r, &c) ? HAL_SUCCESS : HAL_FAIL;
}

hal_err_t hal_ec_double_ladder(const ecdsa_curve* curve, const uint8_t* s1, const uint8_t* p1,
                               const uint8_t* s2, const uint8_t* p2, uint8_t* point_out) {
  pcurve_t c;
  pcurve_load(&c, curve);

  bignum256 k1, k2;
  bn_read_be(s1, &k1);
  f_reduce(&k1, &c.n);
  bn_read_be(s2, &k2);
  f_reduce(&k2, &c.n);

  jpoint_t q1, q2, r1, r;
  j_from_affine(&q1, p1, &c);
  j_from_affine(&q2, p2, &c);
  j_mul(&r1, &k1, &q1, &c);
  j_mul(&r, &k2, &q2, &c);
  j_add(&r, &r1, &r, &c);

  return j_to_affine(point_out, &r, &c) ? HAL_SUCCESS : HAL_FAIL;
}

/* r = (k*G).x mod n, s = k^-1 * (z + r*d) mod n, z the digest taken modulo n. s comes out of the
 * equation as it comes out. */
hal_err_t hal_ecdsa_sign(const ecdsa_curve* curve, const uint8_t* priv_key, const uint8_t* digest,
                         const uint8_t* k, uint8_t* sig_out) {
  pcurve_t c;
  pcurve_load(&c, curve);

  bignum256 nonce, z, d, r, s, inverse;
  bn_read_be(k, &nonce);
  f_reduce(&nonce, &c.n);
  if (bn_is_zero(&nonce)) {
    return HAL_FAIL;
  }

  bn_read_be(digest, &z);
  f_reduce(&z, &c.n);
  bn_read_be(priv_key, &d);
  f_reduce(&d, &c.n);

  jpoint_t g, point;
  j_from_affine(&g, curve->G, &c);
  j_mul(&point, &nonce, &g, &c);

  uint8_t rx_ry[ECC256_POINT_SIZE];
  if (!j_to_affine(rx_ry, &point, &c)) {
    return HAL_FAIL;
  }

  bn_read_be(rx_ry, &r);
  f_reduce(&r, &c.n);
  if (bn_is_zero(&r)) {
    return HAL_FAIL;
  }

  f_inv(&inverse, &nonce, &c.n);
  f_mul(&s, &r, &d, &c.n);
  f_add(&s, &s, &z, &c.n);
  f_mul(&s, &inverse, &s, &c.n);
  if (bn_is_zero(&s)) {
    return HAL_FAIL;
  }

  bn_write_be(&r, sig_out);
  bn_write_be(&s, &sig_out[EL]);
  return HAL_SUCCESS;
}

/* u1 = z*s^-1, u2 = r*s^-1, accept when (u1*G + u2*Q).x mod n equals r. Both roots of s satisfy
 * it, since s and n - s have inverses that differ only in sign and the x coordinate of a point is
 * unchanged by negating it.
 *
 * r and s outside [1, n-1] are refused rather than reduced: s of zero has no inverse to take, and
 * an r of n or more is not an element of the field the equation is stated in. */
hal_err_t hal_ecdsa_verify(const ecdsa_curve* curve, const uint8_t* pub_key, const uint8_t* sig,
                           const uint8_t* digest) {
  pcurve_t c;
  pcurve_load(&c, curve);

  bignum256 r, s, z, w, u1, u2, x;
  bn_read_be(sig, &r);
  bn_read_be(&sig[EL], &s);
  bn_read_be(digest, &z);
  f_reduce(&z, &c.n);

  if (bn_is_zero(&r) || bn_is_zero(&s) || !bn_is_less(&r, &c.n) || !bn_is_less(&s, &c.n)) {
    return HAL_FAIL;
  }

  f_inv(&w, &s, &c.n);
  f_mul(&u1, &z, &w, &c.n);
  f_mul(&u2, &r, &w, &c.n);

  jpoint_t g, q, r1, sum;
  j_from_affine(&g, curve->G, &c);
  j_from_affine(&q, pub_key, &c);
  j_mul(&r1, &u1, &g, &c);
  j_mul(&sum, &u2, &q, &c);
  j_add(&sum, &r1, &sum, &c);

  uint8_t xy[ECC256_POINT_SIZE];
  if (!j_to_affine(xy, &sum, &c)) {
    return HAL_FAIL;
  }

  bn_read_be(xy, &x);
  f_reduce(&x, &c.n);
  return bn_is_equal(&x, &r) ? HAL_SUCCESS : HAL_FAIL;
}

/* The bignum helpers behind the PKA. Its result is a fixed 256 bits wide, so hal_bn_add and
 * hal_bn_sub discard the carry out of the top byte; bignum's own add and subtract keep it, which
 * is why these two work on the bytes. hal_bn_mul_r2 and hal_bn_mul_mont are Montgomery-specific
 * and stay aborting in hal_host.c. */

hal_err_t hal_bn_add(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]) {
  uint16_t carry = 0;
  for (int i = BN_SIZE - 1; i >= 0; i--) {
    carry += (uint16_t)a[i] + b[i];
    r[i] = (uint8_t)carry;
    carry >>= 8;
  }
  return HAL_SUCCESS;
}

hal_err_t hal_bn_sub(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]) {
  int16_t borrow = 0;
  for (int i = BN_SIZE - 1; i >= 0; i--) {
    int16_t diff = (int16_t)a[i] - b[i] - borrow;
    /* Fixed width: a borrow out of the top byte is discarded. */
    borrow = (diff < 0) ? 1 : 0;
    r[i] = (uint8_t)(diff & 0xff);
  }
  return HAL_SUCCESS;
}

int hal_bn_cmp(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE]) {
  for (int i = 0; i < BN_SIZE; i++) {
    if (a[i] != b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}


/*
 * Host-only BN254 Fr reference arithmetic for the PKA test stand-in.
 *
 * The existing bignum256 modular routines require near-256-bit primes.
 * BN254 Fr violates that precondition. These byte-based functions are
 * deliberately simple, independent of bignum256 reduction, and are NOT
 * suitable for secret-key operations or firmware signing.
 */
static const uint8_t host_fr_modulus[BN_SIZE] = { 0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01 };

static bool host_is_fr(const uint8_t mod[BN_SIZE]) {
  return memcmp(mod, host_fr_modulus, BN_SIZE) == 0;
}

static bool host_fr_valid(const uint8_t a[BN_SIZE]) {
  return memcmp(a, host_fr_modulus, BN_SIZE) < 0;
}

static bool host_fr_zero(const uint8_t a[BN_SIZE]) {
  uint8_t nonzero = 0;
  for (size_t i = 0; i < BN_SIZE; i++) {
    nonzero |= a[i];
  }
  return nonzero == 0;
}

/* x >= y, both 32-byte unsigned big-endian integers. */
static void host_fr_sub_raw(
    const uint8_t x[BN_SIZE], const uint8_t y[BN_SIZE],
    uint8_t out[BN_SIZE]) {
  unsigned borrow = 0;
  for (int i = BN_SIZE - 1; i >= 0; i--) {
    unsigned rhs = (unsigned)y[i] + borrow;
    unsigned lhs = x[i];
    out[i] = (uint8_t)(lhs - rhs);
    borrow = lhs < rhs;
  }
}

/* x,y < Fr. Their sum is less than 2^255, so no 256-bit overflow. */
static void host_fr_add_mod(
    const uint8_t x[BN_SIZE], const uint8_t y[BN_SIZE],
    uint8_t out[BN_SIZE]) {
  uint8_t sum[BN_SIZE];
  unsigned carry = 0;

  for (int i = BN_SIZE - 1; i >= 0; i--) {
    unsigned value = (unsigned)x[i] + y[i] + carry;
    sum[i] = (uint8_t)value;
    carry = value >> 8;
  }

  if (carry != 0) {
    memset(out, 0, BN_SIZE);
    return;
  }

  if (memcmp(sum, host_fr_modulus, BN_SIZE) >= 0) {
    host_fr_sub_raw(sum, host_fr_modulus, out);
  } else {
    memcpy(out, sum, BN_SIZE);
  }
}

static void host_fr_sub_mod(
    const uint8_t x[BN_SIZE], const uint8_t y[BN_SIZE],
    uint8_t out[BN_SIZE]) {
  if (memcmp(x, y, BN_SIZE) >= 0) {
    host_fr_sub_raw(x, y, out);
  } else {
    uint8_t difference[BN_SIZE];
    host_fr_sub_raw(y, x, difference);
    host_fr_sub_raw(host_fr_modulus, difference, out);
  }
}

/* Public-only binary multiplication, intentionally not constant-time. */
static void host_fr_mul_mod(
    const uint8_t x[BN_SIZE], const uint8_t y[BN_SIZE],
    uint8_t out[BN_SIZE]) {
  uint8_t accumulator[BN_SIZE] = {0};
  uint8_t next[BN_SIZE];

  for (size_t i = 0; i < BN_SIZE; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      host_fr_add_mod(accumulator, accumulator, next);
      memcpy(accumulator, next, BN_SIZE);

      if ((x[i] >> bit) & 1) {
        host_fr_add_mod(accumulator, y, next);
        memcpy(accumulator, next, BN_SIZE);
      }
    }
  }

  memcpy(out, accumulator, BN_SIZE);
}

/* Fr is prime; compute x^(Fr-2) for nonzero x. Test-only reference. */
static void host_fr_inv_mod(
    const uint8_t x[BN_SIZE], uint8_t out[BN_SIZE]) {
  uint8_t exponent[BN_SIZE];
  uint8_t accumulator[BN_SIZE] = {0};
  uint8_t next[BN_SIZE];

  memcpy(exponent, host_fr_modulus, BN_SIZE);

  unsigned borrow = 2;
  for (int i = BN_SIZE - 1; i >= 0 && borrow; i--) {
    unsigned value = exponent[i];
    exponent[i] = (uint8_t)(value - borrow);
    borrow = value < borrow;
  }

  accumulator[BN_SIZE - 1] = 1;

  for (size_t i = 0; i < BN_SIZE; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      host_fr_mul_mod(accumulator, accumulator, next);
      memcpy(accumulator, next, BN_SIZE);

      if ((exponent[i] >> bit) & 1) {
        host_fr_mul_mod(accumulator, x, next);
        memcpy(accumulator, next, BN_SIZE);
      }
    }
  }

  memcpy(out, accumulator, BN_SIZE);
}

hal_err_t hal_bn_add_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  if (host_is_fr(mod)) {
    if (!host_fr_valid(a) || !host_fr_valid(b)) return HAL_FAIL;
    host_fr_add_mod(a, b, r);
    return HAL_SUCCESS;
  }

  bignum256 m, x, y;
  bn_read_be(mod, &m);
  bn_read_be(a, &x);
  f_reduce(&x, &m);
  bn_read_be(b, &y);
  f_reduce(&y, &m);
  f_add(&x, &x, &y, &m);
  bn_write_be(&x, r);
  return HAL_SUCCESS;
}

hal_err_t hal_bn_sub_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  if (host_is_fr(mod)) {
    if (!host_fr_valid(a) || !host_fr_valid(b)) return HAL_FAIL;
    host_fr_sub_mod(a, b, r);
    return HAL_SUCCESS;
  }

  bignum256 m, x, y;
  bn_read_be(mod, &m);
  bn_read_be(a, &x);
  f_reduce(&x, &m);
  bn_read_be(b, &y);
  f_reduce(&y, &m);
  f_sub(&x, &x, &y, &m);
  bn_write_be(&x, r);
  return HAL_SUCCESS;
}

hal_err_t hal_bn_mul_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  if (host_is_fr(mod)) {
    if (!host_fr_valid(a) || !host_fr_valid(b)) return HAL_FAIL;
    host_fr_mul_mod(a, b, r);
    return HAL_SUCCESS;
  }

  bignum256 m, x, y;
  bn_read_be(mod, &m);
  bn_read_be(a, &x);
  f_reduce(&x, &m);
  bn_read_be(b, &y);
  f_reduce(&y, &m);
  f_mul(&x, &x, &y, &m);
  bn_write_be(&x, r);
  return HAL_SUCCESS;
}

hal_err_t hal_bn_exp_mod(const uint8_t a[BN_SIZE], const uint8_t e[BN_SIZE],
                         const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  bignum256 m, x, exp, res;
  bn_read_be(mod, &m);
  bn_read_be(a, &x);
  f_reduce(&x, &m);
  bn_read_be(e, &exp);
  bn_power_mod(&x, &exp, &m, &res);
  f_reduce(&res, &m);
  bn_write_be(&res, r);
  return HAL_SUCCESS;
}

/* Zero in, zero out: bn_inverse reaches the answer through Fermat, and 0^(p-2) is 0. */
hal_err_t hal_bn_inv_mod(const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  if (host_is_fr(mod)) {
    if (!host_fr_valid(a) || host_fr_zero(a)) return HAL_FAIL;
    host_fr_inv_mod(a, r);
    return HAL_SUCCESS;
  }

  bignum256 m, x;
  bn_read_be(mod, &m);
  bn_read_be(a, &x);
  f_reduce(&x, &m);
  f_inv(&x, &x, &m);
  bn_write_be(&x, r);
  return HAL_SUCCESS;
}
