#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/core_btc_sig.h"
#include "crypto/ecdsa.h"
#include "framework/test_util.h"
#include "keycard/keycard_cmdset.h"
#include "unity.h"
#include "vectors/vectors_keycard_signature.h"

/* A signature the card made, shaped into the PSBT input record BIP-174 defines: partial signatures
 * are filed under the compressed public key with the sighash byte appended to the DER, taproot key
 * signatures under nothing with the 64 bytes as they are.
 *
 * The replies are the corpus of test_keycard_signature.c, so the same bytes drive both halves of the
 * path, plus the DER lengths a record has to reconcile and the sighash values it appends.
 * Expectations come from btc_sig_model() in generate.py, written from the record and not from this C.
 *
 * The value is assembled in the caller's buffer rather than borrowed from the reply: the template
 * ends with the DER, so the reply has no byte left for the sighash. Where a genuine reply was
 * rejected for wanting one, every ECDSA input failed to sign, which no device-independent test
 * noticed until it was a device symptom -- so the record's value pointer is asserted here, and so is
 * that the reader writes nothing into the reply but the one byte of the compressed key.
 */

#define CANARY 0xA5

static uint8_t* input;
static size_t input_len;

static uint8_t* load(const char* hex) {
  free(input);
  input_len = strlen(hex) / 2;
  input = malloc(input_len ? input_len : 1);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_MESSAGE(input_len, test_unhex(hex, input, input_len), "malformed vector");
  return input;
}

void setUp(void) {}

void tearDown(void) {
  free(input);
  input = NULL;
}

static void expect_bytes(const uint8_t* got, size_t got_len, const char* want, const char* label) {
  uint8_t expected_[160];
  size_t want_len = strlen(want) / 2;
  TEST_ASSERT_EQUAL_MESSAGE(want_len, test_unhex(want, expected_, sizeof(expected_)),
                            "malformed expected bytes");
  TEST_ASSERT_EQUAL_MESSAGE(want_len, got_len, label);
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_, got, want_len, label);
}

void test_btc_signature_records(void) {
  size_t accepted = 0;

  for (size_t i = 0; i < BTC_SIG_CASES_COUNT; i++) {
    const btc_sig_case_t* v = &BTC_SIG_CASES[i];
    char label[160];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->hex);
    uint8_t untouched[512];
    TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(sizeof(untouched), input_len, "vector longer than the copy");
    memcpy(untouched, buf, input_len);

    uint8_t sig_val[DER_ECDSA_MAX_SIGNATURE_LEN + 1];
    memset(sig_val, CANARY, sizeof(sig_val));

    psbt_record_t rec;
    memset(&rec, CANARY, sizeof(rec));

    app_err_t err;
    if (v->algo == KEYCARD_SIGN_BIP340_SCHNORR) {
      err = core_btc_read_schnorr_signature(buf, (uint16_t)input_len, &rec);
    } else {
      err = core_btc_read_signature(buf, (uint16_t)input_len, v->sighash, sig_val, &rec);
    }

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->ok ? ERR_OK : ERR_DATA, err, label);
    if (!v->ok) {
      /* Refusing must leave the reply as it arrived: the record is written from it, not onto it. */
      if (input_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(untouched, buf, input_len, label);
      }
      continue;
    }
    accepted++;

    TEST_ASSERT_EQUAL_INT_MESSAGE(PSBT_SCOPE_INPUTS, rec.scope, label);

    if (v->key == NULL) {
      TEST_ASSERT_NULL_MESSAGE(rec.key, label);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(0, rec.key_size, label);
    } else {
      TEST_ASSERT_EQUAL_UINT_MESSAGE(33, rec.key_size, label);
      expect_bytes(rec.key, rec.key_size, v->key, label);
    }

    if (v->algo == KEYCARD_SIGN_BIP340_SCHNORR) {
      /* A taproot value is the reply's own 64 bytes, which is the one borrow that fits. */
      TEST_ASSERT_TRUE_MESSAGE((rec.val >= buf && rec.val + rec.val_size <= buf + input_len), label);
      TEST_ASSERT_TRUE_MESSAGE((memcmp(untouched, buf, input_len) == 0), label);
    } else {
      TEST_ASSERT_EQUAL_PTR_MESSAGE(sig_val, rec.val, label);
    }
    expect_bytes(rec.val, rec.val_size, v->val, label);

    if (v->algo != KEYCARD_SIGN_BIP340_SCHNORR && v->key != NULL) {
      /* Compressing the key is the single byte the reader may write into the reply. */
      size_t key_off = (size_t)(rec.key - buf);
      TEST_ASSERT_TRUE_MESSAGE((key_off + 33 <= input_len), label);
      uint8_t patched[512];
      memcpy(patched, untouched, input_len);
      patched[key_off] = buf[key_off];
      if (input_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(patched, buf, input_len, label);
      }
    }
  }

  TEST_ASSERT_EQUAL_UINT_MESSAGE(BTC_SIG_ACCEPTED, accepted, "the table lost its records");
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_btc_signature_records);
  return UNITY_END();
}
