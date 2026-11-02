/* What the device takes a PSBT input to be.
 *
 * A PSBT describes an input twice over: an amount and a scriptPubKey, plus whatever scripts prove
 * them. Those two decide the signature that gets produced and the number shown on screen, and every
 * byte of them arrives from a wallet. The cases in vectors/vectors_psbt_ctx.h are built from
 * BIP-174's grammar; where two utxo fields describe one input, the precedence they assert -- prevtx
 * over witness_utxo, whichever record was written last -- is Bitcoin Core's (src/psbt.cpp,
 * PSBTInput::GetUTXO), which is also the answer a node verifying the spend would compute. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_ctx.h"
#include "bitcoin/tx.h"
#include "common.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_psbt_ctx.h"

/* The fingerprint the cases carry a derivation for. A PSBT stores it little-endian and the device
 * reads it into a uint32, so it reads as this on any little-endian target. */
#define OUR_FINGERPRINT 0x11223344u

/* Room to decode the expected script of a case; test_unhex reports a refusal by returning this,
 * which the length assert below then catches. */
#define SCRIPT_BUF 64

void setUp(void) {}

void tearDown(void) {}

static uint64_t read_le64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

/* The ingest the device runs on a scanned PSBT: records into the context, then the input
 * validator. Returns whether that flow would take the PSBT at all. */
/* The parser copies a PSBT it is given into the buffer psbt_init() was handed, and keeps pointers
 * into it, which is what the device's own staging buffer is for. */
static uint8_t scratch[2048];

static bool ingest(const psbt_ctx_case_t* c, btc_tx_ctx_t* ctx) {
  psbt_t psbt;

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(sizeof(scratch), c->psbt_len, c->name);

  memset(ctx, 0, sizeof(*ctx));
  ctx->mfp = OUR_FINGERPRINT;
  memcpy(scratch, c->psbt, c->psbt_len);
  psbt_init(&psbt, scratch, sizeof(scratch));

  if (psbt_read(scratch, c->psbt_len, &psbt, btc_psbt_element, ctx) != PSBT_OK) {
    return false;
  }
  if (ctx->error != ERR_OK) {
    return false;
  }
  if (btc_psbt_validate_inputs(ctx) != ERR_OK) {
    return false;
  }

  return btc_psbt_any_can_sign(ctx);
}

static void test_psbt_ctx_cases(void) {
  for (size_t i = 0; i < PSBT_CTX_CASE_COUNT; i++) {
    const psbt_ctx_case_t* c = &PSBT_CTX_CASES[i];
    btc_tx_ctx_t ctx;
    bool accepted = ingest(c, &ctx);

    TEST_ASSERT_EQUAL_MESSAGE(c->accept, accepted, c->name);
    if (!c->accept) {
      continue;
    }

    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, ctx.input_count, c->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(c->input_type, ctx.input_data[0].input_type, c->name);
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx.input_data[0].amount, c->name);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(c->amount, read_le64(ctx.input_data[0].amount), c->name);

    /* Pointer and length are read together downstream, so they have to agree with each other as
     * well as with the expected script. */
    uint8_t want[SCRIPT_BUF];
    size_t want_len = test_unhex(c->script, want, sizeof(want));
    TEST_ASSERT_EQUAL_MESSAGE(want_len, ctx.input_data[0].script_pubkey_len, c->name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, ctx.input_data[0].script_pubkey, want_len, c->name);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_psbt_ctx_cases);
  return UNITY_END();
}
