#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/ecdsa.h"
#include "framework/test_util.h"
#include "keycard/signature.h"
#include "unity.h"
#include "vectors/vectors_keycard_signature.h"

/* Where the key and the signature are in the reply to SIGN, which is what
 * keycard_read_signature_reply answers and what three callers used to each work out for themselves.
 * A reply is either the template, which names the key the signature is to be checked against, or a
 * bare 0x80 carrying its own recovery id and naming no key -- which the reader reports as key NULL.
 * Verifying a signature is the PKA's business and cannot run here; ecdsa_sig_from_der is called on
 * the bytes the reply yields only so that a signature picked up at the wrong offset is reported as
 * the nonsense it is instead of passing as one.
 *
 * The expectations come from sign_reply_model() in generate.py, written from the layout the applet
 * writes -- asserted against KeycardApplet.java while the vectors are generated -- and not from this
 * C.
 */

#define CANARY 0xA5

#define EXPECT_HEX(field, actual, actual_len, label)                                    \
  do {                                                                                  \
    uint8_t expected_[160];                                                             \
    size_t want_ = strlen(field) / 2;                                                   \
    TEST_ASSERT_EQUAL_MESSAGE(want_, test_unhex(field, expected_, sizeof(expected_)),   \
                              "malformed expected bytes");                              \
    TEST_ASSERT_EQUAL_MESSAGE(want_, (actual_len), label);                              \
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_, (actual), want_, label);                \
  } while (0)

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

void test_sign_replies(void) {
  size_t accepted = 0;

  for (size_t i = 0; i < SIGN_REPLY_CASES_COUNT; i++) {
    const sign_reply_case_t* v = &SIGN_REPLY_CASES[i];
    char label[160];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    /* Exactly sized, so that a reader which walks past the reply is reported rather than answered by
     * whatever the allocator left behind. */
    uint8_t* buf = load(v->hex);

    keycard_signature_t reply;
    memset(&reply, CANARY, sizeof(reply));
    const bool ok = keycard_read_signature_reply(buf, input_len, (keycard_sign_algo_t)v->algo, &reply);

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->ok, ok ? 1 : 0, label);
    if (!v->ok) {
      continue;
    }
    accepted++;

    /* The contract is a position and a length inside the reply, so agreeing on the bytes there is
     * the whole assertion. */
    if (v->key_absent) {
      TEST_ASSERT_NULL_MESSAGE(reply.key, label);
    } else {
      TEST_ASSERT_TRUE_MESSAGE((reply.key >= buf && reply.key + SIGN_REPLY_PUBKEY_LEN <= buf + input_len),
                               label);
      EXPECT_HEX(v->key, reply.key, SIGN_REPLY_PUBKEY_LEN, label);
    }
    TEST_ASSERT_TRUE_MESSAGE((reply.sig >= buf && reply.sig + reply.sig_len <= buf + input_len), label);
    EXPECT_HEX(v->sig, reply.sig, reply.sig_len, label);

    if (v->sig_der < 0) {
      continue;
    }
    uint8_t sig[64];
    const int der = ecdsa_sig_from_der(reply.sig, reply.sig_len, sig);
    TEST_ASSERT_EQUAL_INT_MESSAGE(v->sig_der ? 0 : 1, der, label);
  }

  TEST_ASSERT_EQUAL_UINT_MESSAGE(SIGN_REPLY_ACCEPTED, accepted, "the table lost accepted replies");
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_sign_replies);
  return UNITY_END();
}
