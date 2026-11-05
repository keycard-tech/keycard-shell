/* app/crypto/ecdsa.c over the host stand-in for the public key accelerator: the public key of a
 * private key, verification under either SEC1 encoding, ECDH, and recovery.
 *
 * vectors/vectors_ecdsa_curve.h records where each expectation comes from: the published
 * xprv/xpub pairs of BIP-32 test vector 1 for the public keys, the symmetry of the exchange for
 * ECDH, and the standard's own recovery formula for recovery. The signatures are the ones in
 * vectors_pka.h, each compared against libsecp256k1. */

#include <string.h>

#include "crypto/bip32.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "framework/test_util.h"
#include "hal.h"
#include "unity.h"
#include "vectors/vectors_ecdsa_curve.h"
#include "vectors/vectors_pka.h"

#define EL ECC256_ELEMENT_SIZE
#define PT ECC256_POINT_SIZE
#define UNCOMPRESSED (PT + 1)

void setUp(void) {
}

void tearDown(void) {
}

static void test_public_key_of_a_private_key(void) {
  for (size_t i = 0; i < ECDSA_PUBKEY_COUNT; i++) {
    const ecdsa_pubkey_t* row = &ECDSA_PUBKEY[i];
    uint8_t priv[EL], pub[UNCOMPRESSED], compressed[UNCOMPRESSED];
    TEST_GIVEN(row->priv, priv, EL);
    memset(pub, 0xA5, sizeof(pub));
    memset(compressed, 0xA5, sizeof(compressed));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdsa_get_public_key65(&secp256k1, priv, pub), row->priv);
    TEST_ASSERT_HEX_MESSAGE(pub, UNCOMPRESSED, row->pub, row->priv);

    /* The 33-byte form is not a 33-byte write: the function computes the uncompressed point where
     * you hand it and then replaces the 0x04 with the parity byte, so it needs room for 65 and
     * leaves x || y behind the prefix. That is the layout bip32_ctx_t.leaf_pub keeps, and what
     * core.c's caller relies on when it writes its next field over the tail. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdsa_get_public_key33(&secp256k1, priv, compressed), row->priv);
    TEST_ASSERT_HEX_MESSAGE(compressed, PUBKEY_COMPRESSED_LEN, row->compressed, row->priv);
  }
}

/* The three entry points take the key three ways: uncompressed, compressed, and the raw x || y a
 * caller already holds. They are the same point, so they cannot disagree about a signature. */
static void test_verify_takes_either_key_encoding(void) {
  for (size_t i = 0; i < PKA_VERIFY_COUNT; i++) {
    const pka_verify_t* row = &PKA_VERIFY[i];
    uint8_t point[PT], sig[PT], digest[EL];
    TEST_GIVEN(row->point, point, PT);
    TEST_GIVEN(row->sig, sig, PT);
    TEST_GIVEN(row->digest, digest, EL);

    uint8_t uncompressed[UNCOMPRESSED];
    uncompressed[0] = 0x04;
    memcpy(&uncompressed[1], point, PT);

    uint8_t compressed[PUBKEY_COMPRESSED_LEN];
    compressed[0] = 0x02 | (point[PT - 1] & 1);
    memcpy(&compressed[1], point, EL);

    int want = row->accept ? 0 : 1;
    TEST_ASSERT_EQUAL_INT_MESSAGE(want, ecdsa_verify(&secp256k1, uncompressed, sig, digest), row->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(want, ecdsa_verify(&secp256k1, compressed, sig, digest), row->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(want, ecdsa_verify_raw_pub(&secp256k1, point, sig, digest), row->name);
  }
}

/* The nonce is what ecdsa_sign takes off the RNG for itself, so no row can pin the bytes it
 * produces; what a row can pin is that the signature which comes out verifies under the published
 * key of that private key, and that neither a different digest nor a different key accepts it. */
static void test_sign_and_verify(void) {
  for (size_t i = 0; i < ECDSA_PUBKEY_COUNT; i++) {
    const ecdsa_pubkey_t* row = &ECDSA_PUBKEY[i];
    const ecdsa_pubkey_t* other_key = &ECDSA_PUBKEY[(i + 1) % ECDSA_PUBKEY_COUNT];
    uint8_t priv[EL], pub[UNCOMPRESSED], other[UNCOMPRESSED], sig[PT], digest[EL];
    TEST_GIVEN(row->priv, priv, EL);
    TEST_GIVEN(row->pub, pub, UNCOMPRESSED);
    TEST_GIVEN(other_key->pub, other, UNCOMPRESSED);
    TEST_GIVEN(PKA_SIGN[0].digest, digest, EL); /* any digest; the nonce is what varies here */
    memset(sig, 0, sizeof(sig));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdsa_sign(&secp256k1, priv, digest, sig), row->priv);
    TEST_ASSERT_EQUAL_INT(0, ecdsa_verify(&secp256k1, pub, sig, digest));

    digest[0] ^= 1;
    TEST_ASSERT_NOT_EQUAL(0, ecdsa_verify(&secp256k1, pub, sig, digest));
    digest[0] ^= 1;
    TEST_ASSERT_NOT_EQUAL(0, ecdsa_verify(&secp256k1, other, sig, digest));
  }
}

static void test_ecdh_shared_secret(void) {
  for (size_t i = 0; i < ECDSA_ECDH_COUNT; i++) {
    const ecdsa_ecdh_t* row = &ECDSA_ECDH[i];
    uint8_t priv[EL], peer[UNCOMPRESSED], out[UNCOMPRESSED];
    TEST_GIVEN(row->priv, priv, EL);
    TEST_GIVEN(row->peer, peer, UNCOMPRESSED);
    memset(out, 0xA5, sizeof(out));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdh_multiply(&secp256k1, priv, peer, out), row->priv);
    TEST_ASSERT_HEX_MESSAGE(out, UNCOMPRESSED, row->shared, row->priv);
  }
}

static void test_recover_public_key(void) {
  for (size_t i = 0; i < ECDSA_RECOVER_COUNT; i++) {
    const ecdsa_recover_t* row = &ECDSA_RECOVER[i];
    uint8_t sig[PT], digest[EL], out[UNCOMPRESSED];
    TEST_GIVEN(row->sig, sig, PT);
    TEST_GIVEN(row->digest, digest, EL);
    memset(out, 0xA5, sizeof(out));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ecdsa_recover_pub_from_sig(&secp256k1, out, sig, digest, row->recid),
                                  row->name);
    TEST_ASSERT_HEX_MESSAGE(out, UNCOMPRESSED, row->pub, row->name);
  }
}

/* The other bit of a recovery id claims an x of r plus the order. For this curve that sum is past
 * the width of a scalar unless r is under prime - order, a window of 2**32 values, so the sum the
 * code makes wraps and the comparison it then makes against the prime is not the one that bit was
 * meant to trigger. What a caller depends on holds either way, and is what is asserted here: a
 * recovery id that is not the one the signer used does not hand back the signer's key. */
/* The third bit of a recovery id asks for x = r + order, which is a field element only where r is
 * below prime - order -- about 2^129 of the values r can take, and no signature here has an r that
 * small. An id that is not the signer's must not return the signer, refused or otherwise. */
static void test_recovery_id_bit_two_never_yields_the_signer(void) {
  for (size_t i = 0; i < ECDSA_RECOVER_COUNT; i++) {
    const ecdsa_recover_t* row = &ECDSA_RECOVER[i];
    if (strcmp(row->name, "the signer's own key") != 0) {
      continue; /* only a row whose key is the signer's says anything about being mistaken */
    }
    uint8_t sig[PT], digest[EL], out[UNCOMPRESSED], own[UNCOMPRESSED];
    TEST_GIVEN(row->sig, sig, PT);
    TEST_GIVEN(row->digest, digest, EL);
    TEST_GIVEN(row->pub, own, UNCOMPRESSED);
    memset(out, 0xA5, sizeof(out));

    int err = ecdsa_recover_pub_from_sig(&secp256k1, out, sig, digest, row->recid | 2);
    TEST_ASSERT_EQUAL_MESSAGE(1, err, row->sig);
    TEST_ASSERT_EQUAL_UINT8(0xA5, out[0]); /* a refused call writes nothing */
  }
}

/* A public key is a point on the curve: SEC1 v2.0 5.6.2.3.1 step 4 for a verification and 5.7.1
 * step 4 for an exchange. The accelerator computes its equation for any pair of coordinates, so
 * the check is here rather than somewhere hoping the key came from a trusted place -- every caller
 * of these three takes the key from outside. No fixed signature happens to verify against an
 * off-curve point, so this is the rule and not a difference; the points are the ones PKA_CHECK
 * marks as off the curve. */
static void test_off_curve_public_key_is_not_a_key(void) {
  uint8_t sig[PT], digest[EL], priv[EL];
  TEST_GIVEN(PKA_VERIFY[0].sig, sig, PT);
  TEST_GIVEN(PKA_VERIFY[0].digest, digest, EL);
  TEST_GIVEN(ECDSA_ECDH[0].priv, priv, EL);

  size_t checked = 0;
  for (size_t i = 0; i < PKA_CHECK_COUNT; i++) {
    if (PKA_CHECK[i].on_curve) {
      continue;
    }
    uint8_t point[PT], key[UNCOMPRESSED], session[UNCOMPRESSED];
    TEST_GIVEN(PKA_CHECK[i].point, point, PT);
    key[0] = 0x04;
    memcpy(key + 1, point, PT);
    memset(session, 0xA5, sizeof(session));

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, ecdsa_verify(&secp256k1, key, sig, digest), PKA_CHECK[i].point);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, ecdsa_verify_raw_pub(&secp256k1, point, sig, digest),
                                  PKA_CHECK[i].point);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, ecdh_multiply(&secp256k1, priv, key, session),
                                  PKA_CHECK[i].point);
    TEST_ASSERT_EQUAL_UINT8(0xA5, session[0]);
    checked++;
  }
  TEST_ASSERT_TRUE(checked > 0);
}

/* Two numbers outside [1, order-1] are not a signature. The digest is a real one, so a refusal on
 * these rows is the check doing its work rather than something failing behind it. */
static void test_recover_refuses_a_signature_that_is_not_one(void) {
  for (size_t i = 0; i < ECDSA_RECOVER_REJECTED_COUNT; i++) {
    const ecdsa_reject_t* row = &ECDSA_RECOVER_REJECTED[i];
    uint8_t sig[PT], digest[EL], out[UNCOMPRESSED];
    TEST_GIVEN(row->sig, sig, PT);
    TEST_GIVEN(row->digest, digest, EL);
    memset(out, 0xA5, sizeof(out));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(
        0, ecdsa_recover_pub_from_sig(&secp256k1, out, sig, digest, 0), row->name);
    for (size_t byte = 0; byte < UNCOMPRESSED; byte++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xA5, out[byte], "a refused recovery wrote to its output");
    }
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_public_key_of_a_private_key);
  RUN_TEST(test_verify_takes_either_key_encoding);
  RUN_TEST(test_sign_and_verify);
  RUN_TEST(test_ecdh_shared_secret);
  RUN_TEST(test_recover_public_key);
  RUN_TEST(test_recovery_id_bit_two_never_yields_the_signer);
  RUN_TEST(test_recover_refuses_a_signature_that_is_not_one);
  RUN_TEST(test_off_curve_public_key_is_not_a_key);
  return UNITY_END();
}
