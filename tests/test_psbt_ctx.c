/* What the device takes a PSBT input to be.
 *
 * A PSBT describes an input twice over: an amount and a scriptPubKey, plus whatever scripts prove
 * them. Those two decide the signature that gets produced and the number shown on screen, and every
 * byte of them arrives from a wallet. The cases in vectors/vectors_psbt_ctx.h are built from
 * BIP-174's grammar; where two utxo fields describe one input, the precedence they assert -- prevtx
 * over witness_utxo, whichever record was written last -- is Bitcoin Core's (src/psbt.cpp,
 * PSBTInput::GetUTXO), which is also the answer a node verifying the spend would compute.
 *
 * The second corpus takes the records one at a time, including the taproot ones BIP-371 defines,
 * because those decide the key a signature comes from: BIP-371 hands the signer the internal key to
 * tweak and the derivation to sign with, and the device hashes both into what it asks the card to
 * sign. A record misread there is a signature made with a key nobody approved. On an output the same
 * records decide what the user is told is their own change and what is somebody else's address. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_ctx.h"
#include "bitcoin/tx.h"
#include "crypto/segwit_addr.h"
#include "crypto/sha2.h"
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
static uint8_t scratch[8192];

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


/* Records taken in one at a time, as the device takes them: parse, records, validation. Reports where
 * it stopped and with what code, so a refusal at the parser is not confused with a refusal by a
 * record handler -- different code paths with different rules. */
static int ingest_records(const psbt_ctx_record_t* c, btc_tx_ctx_t* ctx, app_err_t* err) {
  psbt_t psbt;

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(sizeof(scratch), c->psbt_len, c->name);

  memset(ctx, 0, sizeof(*ctx));
  ctx->mfp = OUR_FINGERPRINT;
  memcpy(scratch, c->psbt, c->psbt_len);
  psbt_init(&psbt, scratch, sizeof(scratch));

  if (psbt_read(scratch, c->psbt_len, &psbt, btc_psbt_element, ctx) != PSBT_OK) {
    *err = ERR_DATA;
    return 0;
  }
  if (ctx->error != ERR_OK) {
    *err = ctx->error;
    return 1;
  }
  app_err_t validated = btc_psbt_validate_inputs(ctx);
  if (validated != ERR_OK) {
    *err = validated;
    return 2;
  }
  *err = ERR_OK;
  return 3;
}

/* A field the case answers is compared byte for byte; NULL means the case says nothing about it,
 * which is a different statement from one that resolved to nothing at all. */
static void expect_field(const uint8_t* got, size_t got_len, const char* want, const char* label) {
  if (want == NULL) {
    return;
  }
  uint8_t expected_[64];
  size_t want_len = strlen(want) / 2;
  TEST_ASSERT_EQUAL_MESSAGE(want_len, test_unhex(want, expected_, sizeof(expected_)), label);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(want_len, got_len, label);
  if (want_len > 0) {
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_, got, want_len, label);
  }
}

static void expect_fingerprint(uint32_t stored, const char* want, const char* label) {
  if (want == NULL) {
    return;
  }
  uint8_t expected_[4];
  TEST_ASSERT_EQUAL_MESSAGE(4, test_unhex(want, expected_, sizeof(expected_)), label);
  /* Compared as the four bytes the record carried rather than as an integer, so the order the
   * context keeps them in is part of what is pinned. */
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_, &stored, 4, label);
}

void test_psbt_ctx_records(void) {
  for (size_t i = 0; i < PSBT_CTX_RECORD_COUNT; i++) {
    const psbt_ctx_record_t* c = &PSBT_CTX_RECORDS[i];
    btc_tx_ctx_t ctx;
    app_err_t err;
    int stage = ingest_records(c, &ctx, &err);

    TEST_ASSERT_EQUAL_INT_MESSAGE(c->stage, stage, c->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(c->err, err, c->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(c->input_count, ctx.input_count, c->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(c->output_count, ctx.output_count, c->name);

    /* Validation classifies only the inputs the device can sign, so a case whose input is not ours
     * says nothing about the type. */
    if ((stage == 3) && (c->input_type >= 0)) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(c->input_type, ctx.input_data[0].input_type, c->name);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(c->sighash, ctx.input_data[0].sighash_flag, c->name);
    }

    /* Whether the flow would sign at all, at every stage: a record refused on the way must not leave
     * the device believing the input is its own. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(c->can_sign, btc_psbt_any_can_sign(&ctx), c->name);

    expect_fingerprint(ctx.input_data[0].master_fingerprint, c->in_mfp, c->name);
    expect_field(ctx.input_data[0].bip32_path, ctx.input_data[0].bip32_path_len, c->in_path, c->name);
    expect_fingerprint(ctx.output_data[0].master_fingerprint, c->out_mfp, c->name);
    expect_field(ctx.output_data[0].bip32_path, ctx.output_data[0].bip32_path_len, c->out_path,
                 c->name);

    /* NULL in the table means the case says nothing; an empty string means it asserts the record is
     * absent, which a row refused partway through cannot claim -- the records before it landed. */
    const uint8_t* internal = ctx.input_data[0].taproot_internal_key;
    if (c->in_internal_key == NULL) {
      /* not answered */
    } else if (c->in_internal_key[0] == '\0') {
      TEST_ASSERT_FALSE_MESSAGE(ctx.input_data[0].has_taproot_internal_key, c->name);
      TEST_ASSERT_NULL_MESSAGE(internal, c->name);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(ctx.input_data[0].has_taproot_internal_key, c->name);
      /* Borrowed from the parsed PSBT rather than copied, so it has to point inside it: the digest
       * the signature is made over reads exactly these bytes. */
      TEST_ASSERT_NOT_NULL_MESSAGE(internal, c->name);
      TEST_ASSERT_TRUE_MESSAGE((internal >= scratch) && (internal < scratch + c->psbt_len), c->name);
      expect_field(internal, BTC_TAPROOT_WITPROG_LEN, c->in_internal_key, c->name);
    }

    if (c->in_merkle_root == NULL) {
      /* not answered */
    } else if (c->in_merkle_root[0] == '\0') {
      TEST_ASSERT_FALSE_MESSAGE(ctx.input_data[0].has_taproot_merkle_root, c->name);
      TEST_ASSERT_NULL_MESSAGE(ctx.input_data[0].taproot_merkle_root, c->name);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(ctx.input_data[0].has_taproot_merkle_root, c->name);
      expect_field(ctx.input_data[0].taproot_merkle_root, SHA256_DIGEST_LENGTH, c->in_merkle_root,
                   c->name);
    }
  }
}

/* An index past the transaction's own counts cannot come from psbt_read, which counts maps against
 * the unsigned transaction, so the guards are driven directly: what has to hold is that a record for
 * an input or output that does not exist is refused without touching the context. */
void test_psbt_record_index_out_of_range(void) {
  static const uint8_t bytes_[] = "0123456789";

  btc_tx_ctx_t ctx;
  psbt_record_t rec;
  memset(&ctx, 0, sizeof(ctx));
  memset(&rec, 0, sizeof(rec));
  rec.scope = PSBT_SCOPE_INPUTS;
  rec.type = PSBT_IN_WITNESS_UTXO;
  rec.val = (uint8_t*)bytes_;
  rec.val_size = sizeof(bytes_);

  ctx.input_count = 1;
  btc_psbt_input_record(&ctx, 1, &rec);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ctx.error);
  TEST_ASSERT_NULL(ctx.input_data[0].amount);
  TEST_ASSERT_EQUAL_UINT(0, ctx.input_data[0].script_pubkey_len);
  TEST_ASSERT_FALSE(ctx.input_data[0].witness);

  memset(&ctx, 0, sizeof(ctx));
  ctx.output_count = 2;
  rec.scope = PSBT_SCOPE_OUTPUTS;
  rec.type = PSBT_OUT_BIP32_DERIVATION;
  btc_psbt_output_record(&ctx, 2, &rec);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ctx.error);
  TEST_ASSERT_EQUAL_UINT(0, ctx.output_data[1].master_fingerprint);
  TEST_ASSERT_EQUAL_UINT(0, ctx.output_data[1].bip32_path_len);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_psbt_ctx_cases);
  RUN_TEST(test_psbt_ctx_records);
  RUN_TEST(test_psbt_record_index_out_of_range);
  return UNITY_END();
}
