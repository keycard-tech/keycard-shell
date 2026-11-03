/* app/ethereum/ethUstream.c and ethUtils.c -- the streaming parser that turns the bytes a wallet
 * sends into the amount, destination and network shown on the screen before approval.
 *
 * The parser is fed by a transport that decides where the chunk boundaries fall (core_eth hands it
 * one APDU at a time), so every transaction is parsed both in one piece and in pieces. A field that
 * arrives split has to parse the same way as one that arrives whole: the hash the device signs is
 * built from the same bytes either way, and a field read at the wrong offset would change the
 * network shown next to the amount the user confirms.
 *
 * Expectations come from an RLP encoder and the EIP-2718 signing-preimage shapes written in
 * vectors/generate.py, which is required to reproduce EIP-155's published example transaction
 * before it emits anything else; see vectors/vectors_ethereum.h. */

#include <stdio.h>
#include <string.h>

#include "crypto/sha3.h"
#include "ethereum/ethUtils.h"
#include "ethereum/ethUstream.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_ethereum.h"

#define DATA_CAPACITY 1024

static txContent_t content;
static txContext_t ctx;
static SHA3_CTX sha3;
static uint8_t payload[2048];
static uint8_t scratch[DATA_CAPACITY];

void setUp(void) {
  memset(&content, 0, sizeof(content));
  memset(payload, 0, sizeof(payload));
  memset(scratch, 0xa5, sizeof(scratch));
}

void tearDown(void) {}

/* What core_eth_process_tx does before the payload is handed over: the type byte is hashed by the
 * caller and stripped, a payload whose first byte is 0xc0 or above is a legacy transaction. */
static size_t begin(int copy_data) {
  content.data = copy_data ? scratch : NULL;
  content.dataCapacity = copy_data ? sizeof(scratch) : 0;
  content.chainID = 1;
  content.v = V_NONE;
  keccak_256_Init(&sha3);
  initTx(&ctx, &sha3, &content);

  if (payload[0] <= MAX_TX_TYPE) {
    keccak_Update(&sha3, payload, 1);
    ctx.txType = payload[0];
    return 1;
  }
  ctx.txType = LEGACY;
  return 0;
}

/* Feeds the transaction in `chunk`-sized pieces, each copied into its own exactly sized buffer so
 * that a read past the end of a piece is a read past the end of an object, which the sanitizers
 * then report. */
static parserStatus_e feed(size_t len, size_t chunk, int copy_data) {
  size_t done = begin(copy_data);
  if (done >= len) {
    return USTREAM_PROCESSING;
  }
  for (;;) {
    size_t left = len - done;
    size_t take = left < chunk ? left : chunk;
    uint8_t piece[take];
    memcpy(piece, payload + done, take);
    parserStatus_e status = processTx(&ctx, piece, (uint32_t)take);
    done += take;
    if (status != USTREAM_PROCESSING || done == len) {
      return status;
    }
  }
}

static void assert_parsed(const eth_tx_t* v, const char* label) {
  uint8_t expected[2048];

  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->chain_id, content.chainID, label);
  if (payload[0] >= 0xc0) {
    // A legacy transaction carries its chain binding in the seventh element, which the parser
    // records in both places; a typed one has no such element and content.v is left as the caller
    // set it, since the signature parity is not read from the preimage at all.
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->chain_id, content.v, label);
  } else {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(V_NONE, content.v, label);
  }

  TEST_ASSERT_EQUAL_UINT_MESSAGE(v->gasprice_len, content.gasprice.length, label);
  TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(v->gasprice, content.gasprice.value, 32, label);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(v->startgas_len, content.startgas.length, label);
  TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(v->startgas, content.startgas.value, 32, label);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(v->value_len, content.value.length, label);
  TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(v->value, content.value.value, 32, label);

  TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(v->destination, content.destination,
                                        sizeof(content.destination), label);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(v->data_len, content.dataLength, label);
  if (v->data_len > 0) {
    TEST_ASSERT_EQUAL_MESSAGE(v->data_len, test_unhex(v->data_hex, expected, sizeof(expected)),
                              label);
    TEST_ASSERT_NOT_NULL_MESSAGE(content.data, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, content.data, v->data_len, label);
  }
}

static void test_transactions_whole(void) {
  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    const eth_tx_t* v = &eth_tx_cases[i];
    size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_MESSAGE(strlen(v->rlp_hex) / 2, len, v->name);

    memset(&content, 0, sizeof(content));
    TEST_ASSERT_EQUAL_MESSAGE(USTREAM_FINISHED, feed(len, len, 1), v->name);
    assert_parsed(v, v->name);

    uint8_t digest[32];
    keccak_Final(&sha3, digest);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(v->hash, digest, 32, v->name);
  }
}

/* Sizes chosen to straddle RLP length prefixes, the 56 byte point where a length moves into a
 * prefix of its own, and the middle of a field's own bytes. */
static const size_t CHUNK_SIZES[] = {1, 2, 3, 5, 7, 13, 55, 56, 57, 100, 251};

static void test_transactions_chunked(void) {
  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    const eth_tx_t* v = &eth_tx_cases[i];
    size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));

    for (size_t c = 0; c < sizeof(CHUNK_SIZES) / sizeof(CHUNK_SIZES[0]); c++) {
      char label[96];
      snprintf(label, sizeof(label), "%s in %u byte pieces", v->name,
               (unsigned)CHUNK_SIZES[c]);

      memset(&content, 0, sizeof(content));
      TEST_ASSERT_EQUAL_MESSAGE(USTREAM_FINISHED, feed(len, CHUNK_SIZES[c], 1), label);
      assert_parsed(v, label);

      uint8_t digest[32];
      keccak_Final(&sha3, digest);
      TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(v->hash, digest, 32, label);
    }
  }
}

/* With no buffer of its own offered, content.data points into the caller's payload instead of a
 * copy of it -- what the caller relies on to show calldata without holding it twice. */
static void test_data_aliased_not_copied(void) {
  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    const eth_tx_t* v = &eth_tx_cases[i];
    if (v->data_len == 0) {
      continue;
    }
    size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));

    memset(&content, 0, sizeof(content));
    size_t skip = begin(0);
    TEST_ASSERT_EQUAL_MESSAGE(USTREAM_FINISHED, processTx(&ctx, payload + skip,
                                                          (uint32_t)(len - skip)),
                              v->name);

    uint8_t expected[2048];
    TEST_ASSERT_EQUAL_MESSAGE(v->data_len, test_unhex(v->data_hex, expected, sizeof(expected)),
                              v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->data_len, content.dataLength, v->name);
    TEST_ASSERT_TRUE_MESSAGE(content.data >= payload && content.data < payload + sizeof(payload),
                             v->name);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, content.data, v->data_len, v->name);
  }
}

/* Every vector is a complete signing preimage, so every proper prefix of one is a transaction the
 * host has not finished sending: the parser must ask for more and nothing else. Faulting here would
 * reject a valid transaction because of where a transport chunk happened to end -- the bug that
 * makes a wallet's APDU size decide whether a payment can be signed. */
static void test_prefix_wants_more_data(void) {
  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    const eth_tx_t* v = &eth_tx_cases[i];
    size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));

    for (size_t cut = 1; cut < len; cut++) {
      char label[96];
      snprintf(label, sizeof(label), "%s cut at %u", v->name, (unsigned)cut);

      memset(&content, 0, sizeof(content));
      TEST_ASSERT_EQUAL_MESSAGE(USTREAM_PROCESSING, feed(cut, 7, 1), label);
    }
  }
}

static void test_rejected(void) {
  for (size_t i = 0; i < ETH_REJECT_CASES_COUNT; i++) {
    const eth_reject_t* v = &eth_reject_cases[i];

    for (size_t c = 0; c < 2; c++) {
      memset(&content, 0, sizeof(content));
      size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));
      size_t done = begin(1);

      char label[160];
      snprintf(label, sizeof(label), "%s (%s)", v->name, c == 0 ? "whole" : "one byte at a time");

      parserStatus_e status = USTREAM_PROCESSING;
      while (status == USTREAM_PROCESSING && done < len) {
        size_t take = c == 0 ? len - done : 1;
        uint8_t piece[take];
        memcpy(piece, payload + done, take);
        status = processTx(&ctx, piece, (uint32_t)take);
        done += take;
      }
      TEST_ASSERT_EQUAL_MESSAGE(USTREAM_FAULT, status, label);
    }
  }
}

/* Calldata longer than the buffer the caller offered is refused rather than written over it. */
static void test_data_capacity_respected(void) {
  const eth_tx_t* v = NULL;
  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    if (eth_tx_cases[i].data_len > 16) {
      v = &eth_tx_cases[i];
      break;
    }
  }
  TEST_ASSERT_NOT_NULL_MESSAGE(v, "need a transaction with calldata");

  size_t len = test_unhex(v->rlp_hex, payload, sizeof(payload));
  size_t skip = begin(1);
  content.dataCapacity = 16;

  TEST_ASSERT_EQUAL_MESSAGE(USTREAM_FAULT, processTx(&ctx, payload + skip, (uint32_t)(len - skip)),
                            v->name);
  for (size_t i = 16; i < sizeof(scratch); i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, scratch[i], "calldata written past the buffer offered");
  }
}

/* ---- ethUtils: the RLP header, taken from the encoding rules ----------------------- */

typedef struct {
  const char* hex;     /* the field's leading bytes */
  int complete;        /* rlpCanDecode could read a header from them */
  int valid;           /* and the header was one the module accepts */
  uint32_t length;     /* payload length, meaningful when valid */
  uint32_t offset;     /* header bytes; 0 means the byte is its own payload */
  int list;
} rlp_head_t;

/* RLP as specified in the Ethereum simple summary: 0x00-0x7f is the byte itself, 0x80-0xb7 a short
 * string, 0xb8-0xbf a long one whose length follows, 0xc0-0xf7 and 0xf8-0xff the same for a list.
 * The module caps a length at 32 bits, so 0xbc and 0xfc answer "invalid" rather than
 * "incomplete". A short length written long (0xb8 0x01) is not canonical RLP and is accepted here;
 * the parser's contract is what a peer can send, not what one should. */
static const rlp_head_t rlp_headers[] = {
    {"00", 1, 1, 1, 0, 0},
    {"7f", 1, 1, 1, 0, 0},
    {"80", 1, 1, 0, 1, 0},
    {"81ff", 1, 1, 1, 1, 0},
    {"82a0a1", 1, 1, 2, 1, 0},
    {"b7aa", 1, 1, 55, 1, 0},
    {"b837", 1, 1, 0x37, 2, 0},
    {"b801ff", 1, 1, 1, 2, 0},
    {"b90100", 1, 1, 0x100, 3, 0},
    {"ba010000", 1, 1, 0x10000, 4, 0},
    {"bb01000000", 1, 1, 0x1000000, 5, 0},
    {"bcffffffff", 0, 0, 0, 0, 0},
    {"bcffffffff00", 1, 0, 0, 0, 0},
    {"bd0100000000", 0, 0, 0, 0, 0},
    {"bd010000000000", 1, 0, 0, 0, 0},
    {"c0", 1, 1, 0, 1, 1},
    {"c180", 1, 1, 1, 1, 1},
    {"f741", 1, 1, 55, 1, 1},
    {"f837", 1, 1, 0x37, 2, 1},
    {"f90100", 1, 1, 0x100, 3, 1},
    {"fa010000", 1, 1, 0x10000, 4, 1},
    {"fb01000000", 1, 1, 0x1000000, 5, 1},
    {"fcffffffff", 0, 0, 0, 0, 0},
    {"fcffffffff00", 1, 0, 0, 0, 0},
    {"b8", 0, 0, 0, 0, 0},
    {"b901", 0, 0, 0, 0, 0},
    {"ba0102", 0, 0, 0, 0, 0},
    {"bb010203", 0, 0, 0, 0, 0},
    {"f8", 0, 0, 0, 0, 0},
    {"fb010203", 0, 0, 0, 0, 0},
};

static void test_rlp_header(void) {
  for (size_t i = 0; i < sizeof(rlp_headers) / sizeof(rlp_headers[0]); i++) {
    const rlp_head_t* h = &rlp_headers[i];
    uint8_t raw[16];
    size_t len = test_unhex(h->hex, raw, sizeof(raw));
    bool valid = false;
    int complete = rlpCanDecode(raw, (uint32_t)len, &valid);

    TEST_ASSERT_EQUAL_INT_MESSAGE(h->complete, complete, h->hex);
    if (!h->complete) {
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(h->valid, valid, h->hex);
    if (!h->valid) {
      continue;
    }

    uint32_t length = 0, offset = 0;
    bool list = false;
    TEST_ASSERT_TRUE_MESSAGE(rlpDecodeLength(raw, &length, &offset, &list), h->hex);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(h->length, length, h->hex);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(h->offset, offset, h->hex);
    TEST_ASSERT_EQUAL_INT_MESSAGE(h->list, list, h->hex);
  }
}

/* adjustDecimals is the Ledger helper that puts a decimal point into a digit string. Nothing in
 * this firmware calls it, but it writes into a buffer the caller sizes, so its bounds are pinned. */
static void test_adjust_decimals(void) {
  static const struct {
    const char* src;
    unsigned decimals;
    size_t room;
    const char* expect; /* NULL means it must refuse */
  } cases[] = {
      {"0", 18, 4, "0"},
      {"0", 18, 1, NULL},
      // The room asked for is the worst case before trailing zeroes are trimmed, not the length of
      // the answer: 19 digits plus a point plus a NUL.
      {"1000000000000000000", 18, 21, "1"},
      {"1000000000000000000", 18, 20, NULL},
      {"1500000000000000000", 18, 21, "1.5"},
      {"123456789", 9, 12, "0.123456789"},
      {"123456789", 9, 11, NULL},
      {"1234567890", 9, 13, "1.23456789"},
      {"123", 18, 22, "0.000000000000000123"},
      {"123", 18, 20, NULL},
      // Even with no decimals the helper reserves room for a point it will not write.
      {"21000", 0, 7, "21000"},
      {"21000", 0, 6, NULL},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char out[64];
    memset(out, 0xa5, sizeof(out));
    bool ok = adjustDecimals(cases[i].src, strlen(cases[i].src), out, cases[i].room,
                             (uint8_t)cases[i].decimals);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].expect != NULL, ok, cases[i].src);
    if (cases[i].expect == NULL) {
      continue;
    }
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].expect, out, cases[i].src);
    /* Digits the helper wrote and then trimmed with a NUL stay in the buffer, which is its own to
     * fill; what it must not touch is what it was not given. */
    for (size_t used = cases[i].room; used < sizeof(out); used++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, out[used], "adjustDecimals wrote past what it was given");
    }
  }
}

static void test_u32_from_be(void) {
  static const struct {
    uint8_t raw[8];
    uint8_t size;
    uint32_t expect;
  } cases[] = {
      {{0x00}, 1, 0},
      {{0x01}, 1, 1},
      {{0xff}, 1, 0xff},
      {{0x01, 0x00}, 2, 0x100},
      {{0x01, 0x02, 0x03, 0x04}, 4, 0x01020304},
      {{0xff, 0xff, 0xff, 0xff}, 4, 0xffffffff},
      {{0x01, 0x02, 0x03, 0x04, 0x05}, 5, 0x01020304}, /* clamped to a uint32 */
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(cases[i].expect, u32_from_BE(cases[i].raw, cases[i].size),
                                    "u32_from_BE");
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_transactions_whole);
  RUN_TEST(test_transactions_chunked);
  RUN_TEST(test_data_aliased_not_copied);
  RUN_TEST(test_prefix_wants_more_data);
  RUN_TEST(test_rejected);
  RUN_TEST(test_data_capacity_respected);
  RUN_TEST(test_rlp_header);
  RUN_TEST(test_adjust_decimals);
  RUN_TEST(test_u32_from_be);
  return UNITY_END();
}
