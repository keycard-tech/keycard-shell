/* app/crypto/bip32.c: the half of BIP-32 that an account's extended public key can do on its own,
 * which is everything after the card has done the hardened steps.
 *
 * Every expected key and chain code is a published xpub from BIP-32's own test vectors, recorded
 * in vectors/vectors_bip32.h. What the code under test contributes is only the arithmetic those
 * vectors do not publish: the point addition of parent and IL*G, which is the public key
 * accelerator's job and is pinned separately in test_hal_pka.c. */

#include <string.h>

#include "crypto/bip32.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_bip32.h"

#define PUB BIP32_PUBKEY_LEN
#define CC BIP32_CHAINCODE_LEN

void setUp(void) {
}

void tearDown(void) {
}

static void assert_untouched(const uint8_t* buf, size_t len, uint8_t mark) {
  for (size_t i = 0; i < len; i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(mark, buf[i], "a refused derivation wrote to its output");
  }
}

static void test_ckd_pub_matches_the_published_chain(void) {
  for (size_t i = 0; i < BIP32_CKD_COUNT; i++) {
    const bip32_ckd_t* row = &BIP32_CKD[i];
    uint8_t parent[PUB], chain[CC], child[PUB], child_chain[CC];
    TEST_GIVEN(row->parent_pub, parent, PUB);
    TEST_GIVEN(row->parent_chain, chain, CC);
    memset(child, 0xA5, sizeof(child));
    memset(child_chain, 0xA5, sizeof(child_chain));

    int err = bip32_ckd_pub(parent, chain, row->index, child, child_chain);
    if (row->ok) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, err, row->path);
      TEST_ASSERT_HEX_MESSAGE(child, PUB, row->child_pub, row->path);
      TEST_ASSERT_HEX_MESSAGE(child_chain, CC, row->child_chain, row->path);
    } else {
      /* BIP-32 says nothing about the key a hardened step would produce, so the row claims only
       * that this one does not, and writes nothing. */
      TEST_ASSERT_NOT_EQUAL_MESSAGE(0, err, row->path);
      assert_untouched(child, PUB, 0xA5);
      assert_untouched(child_chain, CC, 0xA5);
    }
  }
}

static void test_account_context_walks_the_published_chain(void) {
  for (size_t i = 0; i < BIP32_WALK_COUNT; i++) {
    const bip32_walk_t* row = &BIP32_WALK[i];
    uint8_t account[PUB], account_chain[CC];
    TEST_GIVEN(row->account_pub, account, PUB);
    TEST_GIVEN(row->account_chain, account_chain, CC);

    bip32_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bip32_ctx_setup(&ctx, 84, 0, 0, account, account_chain);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, bip32_ctx_derive_change(&ctx, row->change), row->account_path);
    TEST_ASSERT_HEX_MESSAGE(ctx.change_pub, PUB, row->change_pub, row->account_path);
    TEST_ASSERT_HEX_MESSAGE(ctx.change_chain, CC, row->change_chain, row->account_path);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, bip32_ctx_derive_leaf(&ctx, row->leaf), row->account_path);
    TEST_ASSERT_HEX_MESSAGE(ctx.leaf_pub, PUBKEY_COMPRESSED_LEN, row->leaf_pub, row->account_path);

    /* The leaf is cached in the same 65-byte buffer the uncompressed form would use, with the
     * parity byte in place of the 0x04; the tail past the compressed key is left as derivation
     * wrote it, so anything reading the leaf must read 33 bytes and no more. */
    TEST_ASSERT_TRUE_MESSAGE((ctx.leaf_pub[0] == 0x02) || (ctx.leaf_pub[0] == 0x03),
                             "the leaf is not prefixed the way the encoders read it");

    /* Deriving a leaf does not disturb the cached change level, which every later leaf of the same
     * account is derived from. */
    TEST_ASSERT_HEX_MESSAGE(ctx.change_pub, PUB, row->change_pub, row->account_path);
    TEST_ASSERT_HEX_MESSAGE(ctx.change_chain, CC, row->change_chain, row->account_path);
  }
}

/* A hardened step is refused at every level of the context, which is the whole reason the account
 * key has to come off the card. */
static void test_hardened_steps_are_refused(void) {
  for (size_t i = 0; i < BIP32_WALK_COUNT; i++) {
    const bip32_walk_t* row = &BIP32_WALK[i];
    uint8_t account[PUB], account_chain[CC];
    TEST_GIVEN(row->account_pub, account, PUB);
    TEST_GIVEN(row->account_chain, account_chain, CC);

    bip32_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bip32_ctx_setup(&ctx, 84, 0, 0, account, account_chain);

    TEST_ASSERT_NOT_EQUAL(0, bip32_ctx_derive_change(&ctx, row->change | 0x80000000));
    TEST_ASSERT_EQUAL_UINT8(0, ctx.change_pub[0]);

    TEST_ASSERT_EQUAL_INT(0, bip32_ctx_derive_change(&ctx, row->change));
    TEST_ASSERT_NOT_EQUAL(0, bip32_ctx_derive_leaf(&ctx, row->leaf | 0x80000000));
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ckd_pub_matches_the_published_chain);
  RUN_TEST(test_account_context_walks_the_published_chain);
  RUN_TEST(test_hardened_steps_are_refused);
  return UNITY_END();
}
