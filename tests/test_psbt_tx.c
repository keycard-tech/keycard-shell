#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitcoin/psbt_tx.h"
#include "crypto/sha2.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_psbt_tx.h"

/*
 * psbt_btc_tx_parse() is the cursor walk under the PSBT ingest: it reports the transaction as pointers
 * into the caller's buffer and copies nothing, so the two things worth pinning are which elements come
 * out in which order, and that every pointer it hands over lies inside the buffer it was given. The
 * second one is invisible in the firmware, where the transaction is a slice of a larger message and a
 * read past its end lands on the next record; here each transaction is copied to an allocation of
 * exactly its own length and checked on the way past the handler.
 */

void setUp(void) {}

void tearDown(void) {}

#define SHAPE_BUF 2048
#define ORDER_BUF 512

struct sink {
  const uint8_t* base;
  size_t len;

  SHA256_CTX in;
  SHA256_CTX out;
  SHA256_CTX wit;

  size_t inputs;
  size_t outputs;
  size_t witness_items;
  bool tx_seen;
  uint32_t version;
  uint32_t lock_time;

  char in_shape[SHAPE_BUF];
  char out_shape[SHAPE_BUF];
  char wit_shape[SHAPE_BUF];
  char order[ORDER_BUF];

  size_t stray; /* elements whose slice leaves the buffer */
  size_t spilled; /* shape text that did not fit */
};

static void init_sink(struct sink* sink, const uint8_t* base, size_t len) {
  memset(sink, 0, sizeof(*sink));
  sink->base = base;
  sink->len = len;
  sha256_Init(&sink->in);
  sha256_Init(&sink->out);
  sha256_Init(&sink->wit);
}

static bool inside(const struct sink* sink, const uint8_t* at, size_t len) {
  return at != NULL && at >= sink->base && at + len <= sink->base + sink->len;
}

static void note(struct sink* sink, char* buf, size_t buf_len, const char* prefix, const char* fmt, ...) {
  if (strlen(buf) + 1 >= buf_len) {
    sink->spilled++;
    return;
  }

  va_list args;
  va_start(args, fmt);
  char piece[128];
  vsnprintf(piece, sizeof(piece), fmt, args);
  va_end(args);

  strcat(buf, prefix);
  strcat(buf, piece);
}

static void collect(psbt_txelem_t* elem) {
  struct sink* sink = elem->user_data;
  char* order = sink->order;

  if (strlen(order) + 1 >= sizeof(sink->order)) {
    sink->spilled++;
    return;
  }

  switch (elem->elem_type) {
  case PSBT_TXELEM_TXIN: {
    const psbt_txin_t* in = elem->elem.txin;
    if (!inside(sink, in->txid, 32) || (in->script_len && !inside(sink, in->script, in->script_len))) {
      sink->stray++;
    }

    note(sink, sink->in_shape, sizeof(sink->in_shape), sink->inputs ? ";" : "",
         "%" PRIu32 ":%" PRIu32 ":%zu", in->index, in->sequence_number, in->script_len);
    sha256_Update(&sink->in, in->txid, 32);
    if (in->script_len) {
      sha256_Update(&sink->in, in->script, in->script_len);
    }
    sink->inputs++;
    strcat(order, "I");
    break;
  }
  case PSBT_TXELEM_TXOUT: {
    const psbt_txout_t* out = elem->elem.txout;
    if (!inside(sink, out->amount, 8) || (out->script_len && !inside(sink, out->script, out->script_len))) {
      sink->stray++;
    }

    uint64_t amount = 0;
    for (int i = 7; i >= 0; i--) {
      amount = (amount << 8) | out->amount[i];
    }

    note(sink, sink->out_shape, sizeof(sink->out_shape), sink->outputs ? ";" : "", "%" PRIu64 ":%zu", amount,
         out->script_len);
    sha256_Update(&sink->out, out->amount, 8);
    if (out->script_len) {
      sha256_Update(&sink->out, out->script, out->script_len);
    }
    sink->outputs++;
    strcat(order, "O");
    break;
  }
  case PSBT_TXELEM_WITNESS_ITEM: {
    const psbt_witness_item_t* item = elem->elem.witness_item;
    if (!inside(sink, item->item, item->item_len)) {
      sink->stray++;
    }

    note(sink, sink->wit_shape, sizeof(sink->wit_shape), sink->witness_items ? ";" : "",
         "%" PRIu32 ".%" PRIu32 ":%zu", item->input_index, item->item_index, item->item_len);
    if (item->item_len) {
      sha256_Update(&sink->wit, item->item, item->item_len);
    }
    sink->witness_items++;
    strcat(order, "W");
    break;
  }
  case PSBT_TXELEM_TX: {
    sink->tx_seen = true;
    sink->version = elem->elem.tx->version;
    sink->lock_time = elem->elem.tx->lock_time;
    strcat(order, "T");
    break;
  }
  }
}

static uint8_t* exact(const uint8_t* src, size_t len) {
  uint8_t* copy = malloc(len ? len : 1);
  TEST_ASSERT_NOT_NULL_MESSAGE(copy, "out of memory");
  memcpy(copy, src, len);
  return copy;
}

static uint8_t* widened(const uint8_t* src, size_t len, size_t extra) {
  uint8_t* buf = malloc(len + extra);
  TEST_ASSERT_NOT_NULL_MESSAGE(buf, "out of memory");
  memcpy(buf, src, len);
  memset(buf + len, 0, extra);
  return buf;
}

static void expect_no_stray(const struct sink* sink, const char* what) {
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, sink->spilled, "the trace outgrew this test's buffer");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, sink->stray, what);
}

static void test_every_element_of_the_transaction_is_reported(void) {
  for (size_t i = 0; i < PSBT_TX_VECTOR_COUNT; i++) {
    const psbt_tx_vector_t* v = &PSBT_TX_VECTORS[i];
    uint8_t* buf = exact(v->tx, v->tx_len);
    struct sink sink;
    init_sink(&sink, buf, v->tx_len);

    TEST_ASSERT_EQUAL_MESSAGE(PSBT_OK, psbt_btc_tx_parse(buf, v->tx_len, &sink, collect), v->name);

    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->inputs, sink.inputs, v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->outputs, sink.outputs, v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->witness_items, sink.witness_items, v->name);
    TEST_ASSERT_TRUE_MESSAGE(sink.tx_seen, v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->version, sink.version, v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->locktime, sink.lock_time, v->name);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(v->in_shape, sink.in_shape, v->name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(v->out_shape, sink.out_shape, v->name);

    if (v->wit_shape == NULL) {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", sink.wit_shape, v->name);
    } else {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(v->wit_shape, sink.wit_shape, v->name);
    }

    /* Inputs, then outputs, then the witness stacks, then the transaction itself once the cursor has
     * been shown to have ended where the transaction did. */
    char order[ORDER_BUF] = {0};
    for (size_t n = 0; n < v->inputs; n++) {
      strcat(order, "I");
    }
    for (size_t n = 0; n < v->outputs; n++) {
      strcat(order, "O");
    }
    for (size_t n = 0; n < v->witness_items; n++) {
      strcat(order, "W");
    }
    strcat(order, "T");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(order, sink.order, v->name);

    uint8_t in_digest[SHA256_DIGEST_LENGTH], out_digest[SHA256_DIGEST_LENGTH], wit_digest[SHA256_DIGEST_LENGTH];
    sha256_Final(&sink.in, in_digest);
    sha256_Final(&sink.out, out_digest);
    sha256_Final(&sink.wit, wit_digest);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->in_digest, in_digest, SHA256_DIGEST_LENGTH, v->name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->out_digest, out_digest, SHA256_DIGEST_LENGTH, v->name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->wit_digest, wit_digest, SHA256_DIGEST_LENGTH, v->name);

    expect_no_stray(&sink, v->name);
    free(buf);
  }
}

static void test_no_cut_of_a_transaction_parses(void) {
  for (size_t i = 0; i < PSBT_TX_VECTOR_COUNT; i++) {
    const psbt_tx_vector_t* v = &PSBT_TX_VECTORS[i];

    for (size_t cut = 1; cut < v->tx_len; cut++) {
      uint8_t* buf = exact(v->tx, cut);
      struct sink sink;
      init_sink(&sink, buf, cut);

      char what[SHAPE_BUF];
      snprintf(what, sizeof(what), "%s cut to %zu", v->name, cut);

      TEST_ASSERT_NOT_EQUAL_MESSAGE(PSBT_OK, psbt_btc_tx_parse(buf, cut, &sink, collect), what);
      TEST_ASSERT_FALSE_MESSAGE(sink.tx_seen, what);
      expect_no_stray(&sink, what);
      free(buf);
    }
  }
}

static void test_trailing_bytes_are_refused(void) {
  for (size_t i = 0; i < PSBT_TX_VECTOR_COUNT; i++) {
    const psbt_tx_vector_t* v = &PSBT_TX_VECTORS[i];
    uint8_t* buf = malloc(v->tx_len + 1);
    TEST_ASSERT_NOT_NULL(buf);
    memcpy(buf, v->tx, v->tx_len);
    buf[v->tx_len] = 0x00;
    struct sink sink;
    init_sink(&sink, buf, v->tx_len + 1);

    /* The walk has to end exactly at the locktime: a second transaction in the same record is not
     * one transaction, and the count of inputs and outputs the caller was promised is for the wrong
     * one. */
    TEST_ASSERT_EQUAL_MESSAGE(PSBT_READ_ERROR, psbt_btc_tx_parse(buf, v->tx_len + 1, &sink, collect), v->name);
    expect_no_stray(&sink, v->name);
    free(buf);
  }
}

/*
 * One transaction of the wire format, assembled here so the offset of every length is known: version,
 * marker and flag, one input with an empty scriptSig, one output with a 25-byte scriptPubKey, a
 * witness stack of one 3-byte item, and the locktime.
 */
static const uint8_t probe_tx[] = {
    /* version */ 0x01, 0x00, 0x00, 0x00,
    /* marker */   0x00,
    /* flag */     0x01,
    /* inputs */   0x01,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    /* index */ 0x00, 0x00, 0x00, 0x00,
    /* scriptSig length */ 0x00,
    /* sequence */ 0xff, 0xff, 0xff, 0xff,
    /* outputs */ 0x01,
    /* amount */ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* scriptPubKey length */ 0x19,
    0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x88, 0xac,
    /* witness stack for input 0 */ 0x01,
    /* item length */ 0x03,
    0xaa, 0xbb, 0xcc,
    /* locktime */ 0x00, 0x00, 0x00, 0x00,
};

#define OFF_INPUT_COUNT 6
#define OFF_INPUT_SCRIPT 43
#define OFF_OUTPUT_COUNT 48
#define OFF_OUTPUT_SCRIPT 57
#define OFF_STACK_COUNT 83
#define OFF_ITEM_LENGTH 84

struct site {
  const char* name;
  size_t offset;
  uint64_t value;
};

static const struct site sites[] = {
    {"input count", OFF_INPUT_COUNT, 1},
    {"input scriptSig length", OFF_INPUT_SCRIPT, 0},
    {"output count", OFF_OUTPUT_COUNT, 1},
    {"scriptPubKey length", OFF_OUTPUT_SCRIPT, 25},
    {"witness stack count", OFF_STACK_COUNT, 1},
    {"witness item length", OFF_ITEM_LENGTH, 3},
};

static void splice(uint8_t* buf, const struct site* site, uint8_t flag, size_t width, uint64_t value) {
  /* The site holds a one-byte length; widen it in place, leaving the rest of the transaction where
   * it was, since the walk stops at the length itself. */
  memmove(buf + site->offset + 1 + width, buf + site->offset + 1, sizeof(probe_tx) - site->offset - 1);
  buf[site->offset] = flag;
  for (size_t n = 0; n < width; n++) {
    buf[site->offset + 1 + n] = (uint8_t)(value >> (8 * n));
  }
}

static void test_a_non_canonical_length_is_refused_as_such(void) {
  for (size_t s = 0; s < sizeof(sites) / sizeof(sites[0]); s++) {
    const struct site* site = &sites[s];

    static const struct {
      uint8_t flag;
      size_t width;
    } forms[] = {{0xfd, 2}, {0xfe, 4}, {0xff, 8}};

    for (size_t f = 0; f < sizeof(forms) / sizeof(forms[0]); f++) {
      const size_t len = sizeof(probe_tx) + forms[f].width;
      uint8_t* buf = widened(probe_tx, sizeof(probe_tx), forms[f].width);
      splice(buf, site, forms[f].flag, forms[f].width, site->value);

      struct sink sink;
      init_sink(&sink, buf, len);

      char what[128];
      snprintf(what, sizeof(what), "%s widened to 0x%02x", site->name, forms[f].flag);

      TEST_ASSERT_EQUAL_MESSAGE(PSBT_COMPACT_READ_ERROR, psbt_btc_tx_parse(buf, (uint32_t)len, &sink, collect), what);
      expect_no_stray(&sink, what);
      free(buf);
    }
  }
}

static void test_a_length_beyond_the_buffer_is_refused_before_the_element(void) {
  for (size_t s = 0; s < sizeof(sites) / sizeof(sites[0]); s++) {
    const struct site* site = &sites[s];

    /* Canonical and larger than anything left: the walk must stop rather than hand the caller a
     * slice that runs off the end of the record. */
    uint8_t* buf = widened(probe_tx, sizeof(probe_tx), 2);
    splice(buf, site, 0xfd, 2, 0xffff);

    struct sink sink;
    init_sink(&sink, buf, sizeof(probe_tx) + 2);

    char what[128];
    snprintf(what, sizeof(what), "%s claiming 65535 bytes", site->name);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(PSBT_OK, psbt_btc_tx_parse(buf, (uint32_t)(sizeof(probe_tx) + 2), &sink, collect), what);
    TEST_ASSERT_FALSE_MESSAGE(sink.tx_seen, what);
    expect_no_stray(&sink, what);
    free(buf);
  }
}

static void test_a_length_beyond_the_implementation_limit_is_refused(void) {
  for (size_t s = 0; s < sizeof(sites) / sizeof(sites[0]); s++) {
    const struct site* site = &sites[s];

    uint8_t* buf = widened(probe_tx, sizeof(probe_tx), 4);
    splice(buf, site, 0xfe, 4, 0x02000001); /* MAX_SERIALIZE_SIZE + 1 */

    struct sink sink;
    init_sink(&sink, buf, sizeof(probe_tx) + 4);

    char what[128];
    snprintf(what, sizeof(what), "%s claiming past the limit", site->name);

    TEST_ASSERT_EQUAL_MESSAGE(PSBT_COMPACT_READ_ERROR, psbt_btc_tx_parse(buf, (uint32_t)(sizeof(probe_tx) + 4), &sink, collect), what);
    expect_no_stray(&sink, what);
    free(buf);
  }
}

static void test_an_empty_transaction_parses_as_one(void) {
  /* version, marker, flag, no inputs, no outputs, no witness, locktime: the serialization is not
   * empty even when the transaction is, and the caller still gets its three elements. */
  static const uint8_t bare[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t* buf = exact(bare, sizeof(bare));
  struct sink sink;
  init_sink(&sink, buf, sizeof(bare));

  TEST_ASSERT_EQUAL(PSBT_OK, psbt_btc_tx_parse(buf, sizeof(bare), &sink, collect));
  TEST_ASSERT_EQUAL_UINT(0, sink.inputs);
  TEST_ASSERT_EQUAL_UINT(0, sink.outputs);
  TEST_ASSERT_EQUAL_UINT(0, sink.witness_items);
  TEST_ASSERT_EQUAL_STRING("T", sink.order);
  TEST_ASSERT_EQUAL_UINT(2, sink.version);
  expect_no_stray(&sink, "bare transaction");
  free(buf);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_every_element_of_the_transaction_is_reported);
  RUN_TEST(test_no_cut_of_a_transaction_parses);
  RUN_TEST(test_trailing_bytes_are_refused);
  RUN_TEST(test_a_non_canonical_length_is_refused_as_such);
  RUN_TEST(test_a_length_beyond_the_buffer_is_refused_before_the_element);
  RUN_TEST(test_a_length_beyond_the_implementation_limit_is_refused);
  RUN_TEST(test_an_empty_transaction_parses_as_one);
  return UNITY_END();
}
