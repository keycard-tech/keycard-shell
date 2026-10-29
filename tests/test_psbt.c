#include <string.h>
#include "bitcoin/psbt.h"
#include "crypto/sha2.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_psbt.h"

/* The structure a parse must produce, digested with the recipe documented in
 * vectors_psbt.h: per record in parse order scope byte, key type byte, uint32_le key length,
 * key, uint32_le value length, value; then the uint32_le input, output and record counts. */
typedef struct {
  SHA256_CTX ctx;
  unsigned int inputs;
  unsigned int outputs;
  unsigned int records;
} capture_t;

static capture_t capture;

void setUp(void) {}

void tearDown(void) {}

static void update_u32(capture_t* out, uint32_t value) {
  uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16),
                      (uint8_t)(value >> 24)};
  sha256_Update(&out->ctx, bytes, sizeof(bytes));
}

static void capture_element(psbt_elem_t* elem) {
  if (elem->type == PSBT_ELEM_TXELEM) {
    switch (elem->elem.txelem->elem_type) {
      case PSBT_TXELEM_TXIN:
        capture.inputs++;
        break;
      case PSBT_TXELEM_TXOUT:
        capture.outputs++;
        break;
      default:
        break;
    }
    return;
  }

  const psbt_record_t* rec = elem->elem.rec;
  uint8_t scope = (uint8_t)rec->scope;

  sha256_Update(&capture.ctx, &scope, 1);
  sha256_Update(&capture.ctx, &rec->type, 1);
  update_u32(&capture, (uint32_t)rec->key_size);
  sha256_Update(&capture.ctx, rec->key, rec->key_size);
  update_u32(&capture, (uint32_t)rec->val_size);
  sha256_Update(&capture.ctx, rec->val, rec->val_size);

  capture.records++;
}

/* Parses in place out of a buffer of exactly the vector's length, so a read past the last byte
 * is a read past the end of an object and the sanitizers see it. */
static psbt_result_t parse(const char* psbt_hex, size_t* length, psbt_elem_handler_t* handler) {
  uint8_t data[*length];

  TEST_ASSERT_EQUAL_UINT((unsigned)*length, (unsigned)test_unhex(psbt_hex, data, *length));

  psbt_t psbt;
  psbt_init(&psbt, data, *length);
  return psbt_read(data, *length, &psbt, handler, NULL);
}

static void check_structure(const psbt_vector_t* vector) {
  size_t length = strlen(vector->psbt) / 2;

  sha256_Init(&capture.ctx);
  capture.inputs = capture.outputs = capture.records = 0;

  TEST_ASSERT_EQUAL_MESSAGE(PSBT_OK, parse(vector->psbt, &length, capture_element), vector->name);

  update_u32(&capture, capture.inputs);
  update_u32(&capture, capture.outputs);
  update_u32(&capture, capture.records);

  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Final(&capture.ctx, digest);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(vector->inputs, capture.inputs, vector->name);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(vector->outputs, capture.outputs, vector->name);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(vector->records, capture.records, vector->name);
  TEST_ASSERT_HEX_MESSAGE(digest, sizeof(digest), vector->digest, vector->name);
}

static void test_valid_psbt_structure(void) {
  for (size_t i = 0; i < PSBT_VECTOR_COUNT; i++) {
    check_structure(&PSBT_VECTORS[i]);
  }
}

/* BIP-174's "Fails Signer checks" cases are well-formed: the parser must hand them over
 * intact, and refusing them is the caller's job (core_btc.c), not the parser's. */
static void test_signer_rejects_cases_parse(void) {
  for (size_t i = 0; i < PSBT_SIGNER_REJECT_COUNT; i++) {
    check_structure(&PSBT_SIGNER_REJECTS[i]);
  }
}

static void test_structurally_invalid_psbt_rejected(void) {
  for (size_t i = 0; i < PSBT_REJECTED_COUNT; i++) {
    size_t length = strlen(PSBT_REJECTED[i].psbt) / 2;
    TEST_ASSERT_NOT_EQUAL_MESSAGE(PSBT_OK, parse(PSBT_REJECTED[i].psbt, &length, NULL),
                                  PSBT_REJECTED[i].name);
  }
}

/* Invalid because of what a known key type means -- value lengths, duplicate keys, a filled
 * scriptSig -- which this parser hands to its caller. The structure still has to come out
 * right, or the caller is making decisions on misplaced records. */
static void test_field_invalid_psbt_parses_faithfully(void) {
  for (size_t i = 0; i < PSBT_FIELD_INVALID_COUNT; i++) {
    check_structure(&PSBT_FIELD_INVALID[i]);
  }
}

/* Every truncation of a well-formed PSBT has to be refused. This is where a parser that peeks
 * at the next byte before asking whether one is left goes wrong. */
static void test_truncated_psbt_rejected(void) {
  for (size_t v = 0; v < PSBT_VECTOR_COUNT; v++) {
    size_t length = strlen(PSBT_VECTORS[v].psbt) / 2;

    uint8_t whole[2048];
    TEST_ASSERT_EQUAL_UINT((unsigned)length, (unsigned)test_unhex(PSBT_VECTORS[v].psbt, whole, sizeof(whole)));

    for (size_t cut = 1; cut < length; cut++) {
      uint8_t data[cut];
      memcpy(data, whole, cut);

      psbt_t psbt;
      psbt_init(&psbt, data, cut);
      TEST_ASSERT_NOT_EQUAL_MESSAGE(PSBT_OK, psbt_read(data, cut, &psbt, NULL, NULL),
                                    PSBT_VECTORS[v].name);
    }
  }
}

/* version, one input with an empty scriptSig, one output with an empty scriptPubKey, locktime */
static const char UNSIGNED_TX_HEX[] = "01000000" "01"
    "0000000000000000000000000000000000000000000000000000000000000000" "00000000"
    "00" "ffffffff" "01" "0000000000000000" "00" "00000000";

static const uint8_t KEY[33] = {0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                                18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
/* psbt_write_record() copies key even for a zero length, so the key of a record that is only
 * its type byte still has to be a valid pointer. */
static const uint8_t NO_KEY[1] = {0};

static const uint8_t PATH[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0x00};

/* What the firmware does when it writes a signed PSBT back out: build it with the writer and
 * read it with the parser. Both halves have to agree without anything in between. */
static void test_writer_roundtrip(void) {
  static uint8_t buffer[512];
  psbt_record_t rec;

  uint8_t unsigned_tx[64];
  size_t unsigned_tx_len = test_unhex(UNSIGNED_TX_HEX, unsigned_tx, sizeof(unsigned_tx));
  TEST_ASSERT_EQUAL_UINT(60, (unsigned)unsigned_tx_len);

  psbt_t psbt;
  psbt_init(&psbt, buffer, sizeof(buffer));

  rec = (psbt_record_t){.type = PSBT_GLOBAL_UNSIGNED_TX, .key = (uint8_t*)NO_KEY, .key_size = 0,
                        .val = unsigned_tx, .val_size = unsigned_tx_len};
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_write_global_record(&psbt, &rec));
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_new_input_record_set(&psbt));

  rec = (psbt_record_t){.type = PSBT_IN_BIP32_DERIVATION, .key = (uint8_t*)KEY,
                        .key_size = sizeof(KEY), .val = (uint8_t*)PATH, .val_size = sizeof(PATH)};
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_write_input_record(&psbt, &rec));
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_new_output_record_set(&psbt));

  rec = (psbt_record_t){.type = PSBT_OUT_BIP32_DERIVATION, .key = (uint8_t*)KEY,
                        .key_size = sizeof(KEY), .val = (uint8_t*)PATH, .val_size = sizeof(PATH)};
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_write_output_record(&psbt, &rec));
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_finalize(&psbt));

  size_t length = psbt_size(&psbt);
  TEST_ASSERT_TRUE(length < sizeof(buffer));

  sha256_Init(&capture.ctx);
  capture.inputs = capture.outputs = capture.records = 0;
  psbt_init(&psbt, buffer, length);
  TEST_ASSERT_EQUAL_INT(PSBT_OK, psbt_read(buffer, length, &psbt, capture_element, NULL));

  TEST_ASSERT_EQUAL_INT(1, capture.inputs);
  TEST_ASSERT_EQUAL_INT(1, capture.outputs);
  TEST_ASSERT_EQUAL_INT(3, capture.records);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_valid_psbt_structure);
  RUN_TEST(test_signer_rejects_cases_parse);
  RUN_TEST(test_structurally_invalid_psbt_rejected);
  RUN_TEST(test_field_invalid_psbt_parses_faithfully);
  RUN_TEST(test_truncated_psbt_rejected);
  RUN_TEST(test_writer_roundtrip);
  return UNITY_END();
}
