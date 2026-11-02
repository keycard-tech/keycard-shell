#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitcoin/tx.h"
#include "crypto/sha2.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_tx.h"

/* Every case is copied to a block of exactly its own length first. The firmware hands these
 * functions a slice of a PSBT inside the message buffer, where reading past the end is invisible;
 * only an allocation the same size as the transaction makes such a read a sanitizer failure. */
void setUp(void) {}

void tearDown(void) {}

static uint8_t* exact(const uint8_t* src, size_t len) {
  uint8_t* copy = malloc(len ? len : 1);
  TEST_ASSERT_NOT_NULL_MESSAGE(copy, "out of memory");
  memcpy(copy, src, len);
  return copy;
}

static void describe(char* out, size_t out_len, const char* name, const char* what, size_t offset) {
  snprintf(out, out_len, "%s: %s at %zu", name, what, offset);
}

static void test_ids_validate(void) {
  for (size_t i = 0; i < TX_ID_VECTOR_COUNT; i++) {
    const tx_id_vector_t* v = &TX_ID_VECTORS[i];
    uint8_t* tx = exact(v->tx, v->tx_len);

    TEST_ASSERT_TRUE_MESSAGE(btc_validate_tx_hash(tx, v->tx_len, v->txid), v->name);

    uint8_t other[SHA256_DIGEST_LENGTH];
    memcpy(other, v->txid, sizeof(other));
    other[0] ^= 0x01;
    TEST_ASSERT_FALSE_MESSAGE(btc_validate_tx_hash(tx, v->tx_len, other), v->name);

    free(tx);
  }
}

/* Changing a byte the id covers has to change the id, and changing one inside the witness stacks
 * must not: the first says the walk is not skipping structure, the second that the stacks really
 * are excluded rather than merely happened to line up. */
static void test_only_the_hashed_range_changes_the_id(void) {
  static const uint8_t probes[] = {0x00, 0xff, 0xaa};
  char message[160];

  for (size_t i = 0; i < TX_ID_VECTOR_COUNT; i++) {
    const tx_id_vector_t* v = &TX_ID_VECTORS[i];
    uint8_t* tx = exact(v->tx, v->tx_len);

    for (size_t off = 0; off < v->tx_len; off++) {
      if (off >= v->witness_start && off < v->witness_end) {
        continue;
      }
      for (size_t p = 0; p < sizeof(probes) / sizeof(probes[0]); p++) {
        if (tx[off] == probes[p]) {
          continue;
        }
        uint8_t saved = tx[off];
        tx[off] = probes[p];
        describe(message, sizeof(message), v->name, "byte changed in the hashed range", off);
        TEST_ASSERT_FALSE_MESSAGE(btc_validate_tx_hash(tx, v->tx_len, v->txid), message);
        tx[off] = saved;
      }
    }

    for (size_t off = v->witness_start; off < v->witness_end; off++) {
      uint8_t saved = tx[off];
      tx[off] = (uint8_t)(saved ^ 0xff);
      describe(message, sizeof(message), v->name, "byte changed in the witness stacks", off);
      TEST_ASSERT_TRUE_MESSAGE(btc_validate_tx_hash(tx, v->tx_len, v->txid), message);
      tx[off] = saved;
    }

    /* Eliding the stacks altogether leaves the id alone as well. */
    if (v->witness_end > v->witness_start) {
      size_t elided_len = v->tx_len - (v->witness_end - v->witness_start);
      uint8_t* elided = malloc(elided_len);
      TEST_ASSERT_NOT_NULL(elided);
      memcpy(elided, v->tx, v->witness_start);
      memcpy(elided + v->witness_start, v->tx + v->witness_end, v->tx_len - v->witness_end);
      TEST_ASSERT_TRUE_MESSAGE(btc_validate_tx_hash(elided, elided_len, v->txid), v->name);
      free(elided);
    }

    free(tx);
  }
}

/* The walk covers the version, the input and output sections and four bytes of locktime taken from
 * the end of the buffer; it never accounts for the witness region. So a prefix that still holds
 * every section, and whose last four bytes carry the locktime's value, holds the id -- which is
 * correct about the id and wrong about the transaction. Completeness is not this function's job:
 * the only caller reaches it from the PSBT ingest, where psbt_btc_tx_parse() has already required
 * the same bytes to end at the locktime. What must not happen is a buffer that lost structure
 * being accepted, so whatever validates has to contain every section and end on the locktime. */
static void test_truncation_accepts_only_what_still_holds_the_id(void) {
  char message[160];
  bool seen_lenient_prefix = false;

  for (size_t i = 0; i < TX_ID_VECTOR_COUNT; i++) {
    const tx_id_vector_t* v = &TX_ID_VECTORS[i];
    for (size_t len = 0; len < v->tx_len; len++) {
      uint8_t* tx = exact(v->tx, len);
      describe(message, sizeof(message), v->name, "truncated to", len);

      if (!btc_validate_tx_hash(tx, len, v->txid)) {
        free(tx);
        continue;
      }

      seen_lenient_prefix = true;
      TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(v->witness_start, len, message);
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->tx + v->tx_len - 4, v->tx + len - 4,
                                       sizeof(uint32_t), message);
      free(tx);
    }
  }

  /* Not a vacuous exception: BIP-143's fifth example has a prefix that validates, which is how the
   * rule above was found. If the corpus changes and none does, this trips and the rule wants
   * re-deriving rather than quietly narrowing. */
  TEST_ASSERT_TRUE_MESSAGE(seen_lenient_prefix, "no prefix of any vector holds its id");
}

static void test_malformed_transactions_are_refused(void) {
  for (size_t i = 0; i < TX_REJECT_VECTOR_COUNT; i++) {
    const tx_reject_vector_t* v = &TX_REJECT_VECTORS[i];
    uint8_t* tx = exact(v->tx, v->tx_len);
    TEST_ASSERT_FALSE_MESSAGE(btc_validate_tx_hash(tx, v->tx_len, v->claimed), v->name);
    free(tx);
  }
}

/* Below the six bytes a serialization cannot start, there is nothing to read; the guard has to
 * come before the marker test, which reads tx[4] and tx[5]. */
static void test_very_short_buffers(void) {
  for (size_t len = 0; len < 6; len++) {
    uint8_t* tx = exact((const uint8_t*) "\x01\x00\x00\x00\x00\x01\x00\x00", len);
    TEST_ASSERT_FALSE_MESSAGE(btc_validate_tx_hash(tx, len, TX_ID_VECTORS[0].txid), "short buffer");
    free(tx);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ids_validate);
  RUN_TEST(test_only_the_hashed_range_changes_the_id);
  RUN_TEST(test_truncation_accepts_only_what_still_holds_the_id);
  RUN_TEST(test_malformed_transactions_are_refused);
  RUN_TEST(test_very_short_buffers);
  return UNITY_END();
}
