/* The digest a signature commits to.
 *
 * Three walkers, one per input type, and all three are pure functions of the parsed transaction, so
 * they can be driven straight from vectors: build the context the way the PSBT parser would, hand it
 * to the walker, compare 32 bytes. The expectations come from mainnet spends whose own signatures
 * verify over them, from the reference that check vouches for, and from BIP-143 -- see the
 * provenance note in vectors/vectors_sighash.h. */

#include <stdio.h>
#include <string.h>

#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_ctx.h"
#include "bitcoin/psbt_tx.h"
#include "bitcoin/sighash.h"
#include "common.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_sighash.h"

void setUp(void) {}

void tearDown(void) {}

/* The transaction the context points into and the script records layered on top of it. One case is
 * live at a time, so each buffer is reused; nothing outlives the assertion that reads it. */
static uint8_t tx_buf[4096];
static uint8_t script_buf[512];
static uint8_t amounts[BTC_MAX_INPUTS][8];

static void collect_tx(psbt_txelem_t* elem) {
  btc_psbt_tx_element((btc_tx_ctx_t*) elem->user_data, elem);
}

/* Decodes a vector's script, bump-allocating from script_buf so that the redeem and witness script
 * of one case can coexist. */
static size_t script_used;

static uint8_t* script(const char* hex, size_t* len) {
  if (hex[0] == '\0') {
    *len = 0;
    return NULL;
  }
  *len = test_unhex(hex, &script_buf[script_used], sizeof(script_buf) - script_used);
  script_used += *len;
  return &script_buf[script_used - *len];
}

static void build(btc_tx_ctx_t* ctx, const sighash_case_t* c) {
  memset(ctx, 0, sizeof(*ctx));
  memset(amounts, 0, sizeof(amounts));
  script_used = 0;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(sizeof(tx_buf), c->tx_len, c->name);
  memcpy(tx_buf, c->tx, c->tx_len);

  /* btc_psbt_tx_element fills the context from the transaction's own elements, which is the state
   * the PSBT parser leaves it in once it has read the unsigned transaction. */
  TEST_ASSERT_EQUAL_MESSAGE(PSBT_OK, psbt_btc_tx_parse(tx_buf, c->tx_len, ctx, collect_tx), c->name);
  TEST_ASSERT_GREATER_THAN_UINT_MESSAGE(0, ctx->input_count, c->name);
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(BTC_MAX_INPUTS, ctx->input_count, c->name);
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(ctx->input_count - 1, c->in, c->name);

  /* The amounts of every input enter hash_amounts, which is what a taproot digest commits to, so
   * every input needs one -- as it does on the device, where validation requires a utxo per input
   * before any hashing happens. */
  for (size_t i = 0; i < ctx->input_count; i++) {
    ctx->input_data[i].amount = amounts[i];
  }

  psbt_input_data_t* in = &ctx->input_data[c->in];
  in->script_pubkey = script(c->script, &in->script_pubkey_len);
  in->redeem_script = script(c->redeem, &in->redeem_script_len);
  in->witness_script = script(c->witness_script, &in->witness_script_len);
  in->input_type = c->input_type;
  in->sighash_flag = c->hash_type;
  in->can_sign = true;

  if (c->amount[0] != '\0') {
    TEST_ASSERT_EQUAL_MESSAGE(8, test_unhex(c->amount, amounts[c->in], 8), c->name);
  }

  btc_sighash_common_hashes(ctx);
}

static app_err_t run(const btc_tx_ctx_t* ctx, size_t index, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  switch (ctx->input_data[index].input_type) {
  case BTC_INPUT_TYPE_LEGACY:
  case BTC_INPUT_TYPE_LEGACY_WITH_REDEEM:
    return btc_sighash_legacy(ctx, index, digest);
  case BTC_INPUT_TYPE_P2WPKH:
  case BTC_INPUT_TYPE_P2WSH:
    return btc_sighash_segwit(ctx, index, digest);
  case BTC_INPUT_TYPE_P2TR:
    return btc_sighash_taproot(ctx, index, digest);
  default:
    return ERR_DATA;
  }
}

/* A table of this size is worth a tally, not one abort: every case is checked, the first few
 * mismatches are shown and the rest counted, so a systematic break is legible at a glance. */
#define SHOWN 5

static void test_sighash_cases(void) {
  size_t failed = 0;
  size_t failed_multi = 0;

  for (size_t i = 0; i < SIGHASH_CASE_COUNT; i++) {
    const sighash_case_t* c = &SIGHASH_CASES[i];
    btc_tx_ctx_t ctx;

    build(&ctx, c);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    if (run(&ctx, c->in, digest) != ERR_OK) {
      printf("%s: walker refused\n", c->name);
      failed++;
      continue;
    }

    uint8_t want[SHA256_DIGEST_LENGTH];
    if (test_unhex(c->digest, want, sizeof(want)) != SHA256_DIGEST_LENGTH) {
      printf("%s: vector digest is not 32 bytes\n", c->name);
      failed++;
      continue;
    }
    if (memcmp(digest, want, sizeof(digest)) == 0) {
      continue;
    }
    if (ctx.input_count > 1) {
      failed_multi++;
    }
    if (failed < SHOWN) {
      printf("%s (in %zu of %zu)\n  got  %s\n  want %s\n", c->name, c->in, ctx.input_count,
             test_hex(digest, sizeof(digest)), c->digest);
    } else {
      printf("%s\n", c->name);
    }
    failed++;
  }

  if (failed) {
    printf("%zu of %zu cases disagree, %zu of them with more than one input\n",
           failed, (size_t)SIGHASH_CASE_COUNT, failed_multi);
    TEST_FAIL_MESSAGE("signature hash differs from the oracle");
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_sighash_cases);
  return UNITY_END();
}
