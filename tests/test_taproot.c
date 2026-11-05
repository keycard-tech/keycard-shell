/* app/bitcoin/taproot.c: the P2TR output key of a leaf public key. This is the step that runs on
 * the device rather than on the card, and it is one point operation, which is why it is a host
 * test now that the PKA has a stand-in.
 *
 * The expected witness programs are the output keys BIP-86 publishes; vectors/vectors_taproot.h
 * records how the generator satisfied itself that the published account xpub, leaf private key,
 * internal key and output key belong to one derivation. */

#include <string.h>

#include "bitcoin/taproot.h"
#include "crypto/bip32.h"
#include "crypto/secp256k1.h"
#include "framework/test_util.h"
#include "hal.h"
#include "unity.h"
#include "vectors/vectors_taproot.h"

void setUp(void) {
}

void tearDown(void) {
}

static void test_output_key_of_a_published_internal_key(void) {
  for (size_t i = 0; i < TAPROOT_OUTPUT_KEY_COUNT; i++) {
    const taproot_t* row = &TAPROOT_OUTPUT_KEY[i];
    uint8_t internal[BIP32_PUBKEY_LEN], out[BTC_TAPROOT_WITPROG_LEN];
    TEST_GIVEN(row->internal, internal, sizeof(internal));
    memset(out, 0xA5, sizeof(out));

    TEST_ASSERT_TRUE_MESSAGE(bitcoin_taproot_output_key(internal, out), row->path);
    TEST_ASSERT_HEX_MESSAGE(out, BTC_TAPROOT_WITPROG_LEN, row->witprog, row->path);
  }
}

/* An x-only key names a pair of points, and the address must not depend on which of the two the
 * wallet happened to be holding. The other half of each pair is the published key with its prefix
 * flipped and its y replaced by p - y, and it has to give the published output key. */
static void test_output_key_ignores_which_y_the_key_carries(void) {
  for (size_t i = 0; i < TAPROOT_OUTPUT_KEY_COUNT; i++) {
    const taproot_t* row = &TAPROOT_OUTPUT_KEY[i];
    uint8_t flipped[BIP32_PUBKEY_LEN], out[BTC_TAPROOT_WITPROG_LEN];
    TEST_GIVEN(row->internal, flipped, sizeof(flipped));
    flipped[0] ^= 1;
    TEST_ASSERT_EQUAL_INT(
        HAL_SUCCESS,
        hal_bn_sub_mod(secp256k1.prime, &flipped[1 + ECC256_ELEMENT_SIZE], secp256k1.prime,
                       &flipped[1 + ECC256_ELEMENT_SIZE]));
    memset(out, 0xA5, sizeof(out));

    TEST_ASSERT_TRUE_MESSAGE(bitcoin_taproot_output_key(flipped, out), row->path);
    TEST_ASSERT_HEX_MESSAGE(out, BTC_TAPROOT_WITPROG_LEN, row->witprog, row->path);
  }
}

/* The same published output key from the path a device actually takes: the account xpub off the
 * card, the change level and the leaf derived publicly, and the taproot key of the buffer that
 * derivation leaves behind. */
static void test_output_key_of_a_derived_leaf(void) {
  for (size_t i = 0; i < TAPROOT_OUTPUT_KEY_COUNT; i++) {
    const taproot_t* row = &TAPROOT_OUTPUT_KEY[i];
    uint8_t account[BIP32_PUBKEY_LEN], chain[BIP32_CHAINCODE_LEN], internal[BIP32_PUBKEY_LEN];
    TEST_GIVEN(row->account_pub, account, sizeof(account));
    TEST_GIVEN(row->account_chain, chain, sizeof(chain));
    TEST_GIVEN(row->internal, internal, sizeof(internal));

    bip32_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bip32_ctx_setup(&ctx, 86, 0, 0, account, chain);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, bip32_ctx_derive_change(&ctx, row->change), row->path);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, bip32_ctx_derive_leaf(&ctx, row->index), row->path);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(internal, ctx.leaf_pub, PUBKEY_COMPRESSED_LEN, row->path);

    uint8_t out[BTC_TAPROOT_WITPROG_LEN];
    memset(out, 0xA5, sizeof(out));
    TEST_ASSERT_TRUE_MESSAGE(bitcoin_taproot_output_key(ctx.leaf_pub, out), row->path);
    TEST_ASSERT_HEX_MESSAGE(out, BTC_TAPROOT_WITPROG_LEN, row->witprog, row->path);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_output_key_of_a_published_internal_key);
  RUN_TEST(test_output_key_ignores_which_y_the_key_carries);
  RUN_TEST(test_output_key_of_a_derived_leaf);
  return UNITY_END();
}
