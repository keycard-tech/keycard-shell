#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/ecdsa.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_ecdsa_der.h"

/* ecdsa_sig_from_der reads a signature the secure element made, and its output is what gets
 * verified: against the CA key when pairing, against a recovered key when a signature is checked,
 * against the card's identity when a secure channel is opened. It now goes through the same bounded
 * TLV reader as the rest of the card's replies. The walk it replaces fed the sequence length into its
 * own arithmetic, so a signature truncated to within the length its header still claimed let the two
 * integer copies run past the end -- 14 rows of this corpus did that under the address sanitizer, the
 * largest being a 32-byte memcpy past a 71-byte buffer.
 *
 * The expectations come from der_model() in generate.py, written from X.690 rather than from this C,
 * and every row that asn1crypto's strict DER reader also accepts is checked against it during
 * generation. The firmware is laxer than strict DER in one documented way: it strips a single leading
 * zero from an INTEGER, so an over-padded encoding still names the same r and s.
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

void test_der_signatures(void) {
  for (size_t i = 0; i < DER_CASES_COUNT; i++) {
    const der_case_t* v = &DER_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    /* Exactly sized, so that a parser which reads past the encoding is reported rather than
     * answered by whatever the allocator happened to leave behind. */
    uint8_t* buf = load(v->hex);
    uint8_t sig[64];
    memset(sig, CANARY, sizeof(sig));

    const int got = ecdsa_sig_from_der(buf, input_len, sig);
    if (!v->ok) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, got, label);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, got, label);
    TEST_ASSERT_HEX_MESSAGE(sig, 64, v->sig, label);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_der_signatures);
  return UNITY_END();
}
