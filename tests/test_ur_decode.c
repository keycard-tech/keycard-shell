#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ur/ur_decode.h"
#include "unity.h"
#include "vectors/vectors_ur_decode.h"
#include "zcbor_decode.h"

/* The four decoders these cases drive are what app/qrcode/qrscan.c hands the bytes of a scanned UR
 * to, so each payload is something a QR code in front of the lens can carry. Nothing here copies a
 * payload first: the vector's own array, at its exact length, goes to the decoder, so a read past
 * the end lands in an ASan redzone rather than quietly in the next global. Each case decodes into a
 * fresh struct, and every accepted case also asserts that the zcbor_strings coming back point into
 * the payload -- qrscan hands over the camera buffer and never copies, and the UI reads those
 * pointers after the decoder has returned, which is only safe while that buffer lives.
 *
 * The verdict for each row, and the clause of the schema it comes from, is in
 * vectors/vectors_ur_decode.h. Where a row fails, read that column before touching the vector: the
 * expectation was written from ERC-4527 and cddl/ur.cddl, not from what the decoder does.
 */

static char label[256];

static const char* why(const char* name, const char* constraint) {
  if (constraint != NULL && constraint[0] != '\0') {
    snprintf(label, sizeof(label), "%s -- %s", name, constraint);
  } else {
    snprintf(label, sizeof(label), "%s", name);
  }
  return label;
}

static void cut_label(char* into, size_t size, const char* name, uint16_t cut, uint16_t total) {
  snprintf(into, size, "%s (cut at %u of %u)", name, (unsigned)cut, (unsigned)total);
}

static void check_string(const uint8_t* payload, size_t payload_len, const uint8_t* want,
                         size_t want_len, const struct zcbor_string* got, const char* m) {
  TEST_ASSERT_EQUAL_UINT32_MESSAGE((uint32_t)want_len, (uint32_t)got->len, m);
  if (want_len > 0) {
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, got->value, want_len, m);
  }
  TEST_ASSERT_TRUE_MESSAGE(got->value >= payload && got->value <= payload + payload_len, m);
  TEST_ASSERT_TRUE_MESSAGE(got->value + got->len <= payload + payload_len, m);
}

static void check_text(const uint8_t* payload, size_t payload_len, const char* want,
                       const struct zcbor_string* got, const char* m) {
  check_string(payload, payload_len, (const uint8_t*)want, want == NULL ? 0 : strlen(want), got, m);
}

static void check_path(const uint32_t* index, const uint8_t* hardened, uint8_t count,
                       const struct crypto_keypath* kp, const char* m) {
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(count,
                                   (uint32_t)kp->crypto_keypath_components_path_component_m_count, m);

  for (uint8_t i = 0; i < count; i++) {
    const struct path_component* pc = &kp->crypto_keypath_components_path_component_m[i];
    if (index[i] == UR_DECODE_PATH_NO_INDEX) {
      TEST_ASSERT_FALSE_MESSAGE(pc->path_component_child_index_m_present, m);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(pc->path_component_child_index_m_present, m);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(index[i], pc->path_component_child_index_m, m);
    }
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(hardened[i] ? 1 : 0, pc->path_component_is_hardened_m ? 1 : 0, m);
  }
}

static void eth_case(const ur_decode_eth_case_t* c) {
  const char* m = why(c->name, c->constraint);
  struct eth_sign_request out;
  memset(&out, 0xa5, sizeof(out));

  if (!c->accept) {
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_decode_eth_sign_request(c->cbor, c->cbor_len, &out, NULL), m);
    return;
  }

  size_t consumed = 0;
  TEST_ASSERT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                            cbor_decode_eth_sign_request(c->cbor, c->cbor_len, &out, &consumed), m);
  TEST_ASSERT_TRUE_MESSAGE(consumed <= c->cbor_len, m);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->request_id != NULL ? 1 : 0, out.eth_sign_request_request_id_present, m);
  if (c->request_id != NULL) {
    check_string(c->cbor, c->cbor_len, c->request_id, c->request_id_len,
                 &out.eth_sign_request_request_id.eth_sign_request_request_id, m);
  }

  check_string(c->cbor, c->cbor_len, c->sign_data, c->sign_data_len, &out.eth_sign_request_sign_data, m);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->data_type, out.eth_sign_request_data_type.sign_data_type_choice, m);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_chain_id, out.eth_sign_request_chain_id_present, m);
  if (c->has_chain_id) {
    TEST_ASSERT_EQUAL_INT32_MESSAGE(c->chain_id,
                                    out.eth_sign_request_chain_id.eth_sign_request_chain_id, m);
  }

  const struct crypto_keypath* kp = &out.eth_sign_request_derivation_path;
  if (c->path_count > 0) {
    check_path(c->path_index, c->path_hardened, c->path_count, kp, m);
  } else {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0,
                                     (uint32_t)kp->crypto_keypath_components_path_component_m_count, m);
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_fingerprint, kp->crypto_keypath_source_fingerprint_present, m);
  if (c->has_fingerprint) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->source_fingerprint,
                                     kp->crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint, m);
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_depth, kp->crypto_keypath_depth_present, m);
  if (c->has_depth) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->depth, kp->crypto_keypath_depth.crypto_keypath_depth, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->address != NULL ? 1 : 0, out.eth_sign_request_address_present, m);
  if (c->address != NULL) {
    check_string(c->cbor, c->cbor_len, c->address, c->address_len,
                 &out.eth_sign_request_address.eth_sign_request_address, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->origin != NULL ? 1 : 0,
                                  out.eth_sign_request_request_origin_present, m);
  if (c->origin != NULL) {
    check_text(c->cbor, c->cbor_len, c->origin,
               &out.eth_sign_request_request_origin.eth_sign_request_request_origin, m);
  }
}

static void btc_case(const ur_decode_btc_case_t* c) {
  const char* m = why(c->name, c->constraint);
  struct btc_sign_request out;
  memset(&out, 0xa5, sizeof(out));

  if (!c->accept) {
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_decode_btc_sign_request(c->cbor, c->cbor_len, &out, NULL), m);
    return;
  }

  size_t consumed = 0;
  TEST_ASSERT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                            cbor_decode_btc_sign_request(c->cbor, c->cbor_len, &out, &consumed), m);
  TEST_ASSERT_TRUE_MESSAGE(consumed <= c->cbor_len, m);

  check_string(c->cbor, c->cbor_len, c->request_id, c->request_id_len, &out.btc_sign_request_request_id, m);
  check_string(c->cbor, c->cbor_len, c->sign_data, c->sign_data_len, &out.btc_sign_request_sign_data, m);

  /* btc-sign-request carries a data-type, but the schema gives it exactly one value, so the
   * generated struct has nowhere to put it. The rows with data-type 2 are the check that the value
   * is still refused rather than merely unread. */
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->path_count > 0 ? 1 : 0,
                                  out.btc_sign_request_btc_derivation_paths_crypto_keypath_m_present, m);
  if (c->path_count > 0) {
    check_path(c->path_index, c->path_hardened, c->path_count,
               &out.btc_sign_request_btc_derivation_paths_crypto_keypath_m, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->btc_address != NULL ? 1 : 0,
                                  out.btc_sign_request_btc_addresses_present, m);
  if (c->btc_address != NULL) {
    check_text(c->cbor, c->cbor_len, c->btc_address,
               &out.btc_sign_request_btc_addresses.btc_sign_request_btc_addresses_btc_address_m, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->origin != NULL ? 1 : 0,
                                  out.btc_sign_request_btc_origin_present, m);
  if (c->origin != NULL) {
    check_text(c->cbor, c->cbor_len, c->origin,
               &out.btc_sign_request_btc_origin.btc_sign_request_btc_origin, m);
  }
}

static void psbt_case(const ur_decode_psbt_case_t* c) {
  const char* m = why(c->name, c->constraint);
  struct zcbor_string out;
  memset(&out, 0xa5, sizeof(out));

  if (!c->accept) {
    int res = c->tagged == UR_DECODE_PSBT_TAGGED
        ? cbor_decode_tagged_psbt(c->cbor, c->cbor_len, &out, NULL)
        : cbor_decode_psbt(c->cbor, c->cbor_len, &out, NULL);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS, res, m);
    return;
  }

  size_t consumed = 0;
  int res = c->tagged == UR_DECODE_PSBT_TAGGED
      ? cbor_decode_tagged_psbt(c->cbor, c->cbor_len, &out, &consumed)
      : cbor_decode_psbt(c->cbor, c->cbor_len, &out, &consumed);
  TEST_ASSERT_EQUAL_MESSAGE(ZCBOR_SUCCESS, res, m);
  TEST_ASSERT_TRUE_MESSAGE(consumed <= c->cbor_len, m);
  check_string(c->cbor, c->cbor_len, c->payload, c->payload_len, &out, m);
}

static void dev_case(const ur_decode_dev_case_t* c) {
  const char* m = why(c->name, c->constraint);
  struct dev_auth out;
  memset(&out, 0xa5, sizeof(out));

  if (!c->accept) {
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_decode_dev_auth(c->cbor, c->cbor_len, &out, NULL), m);
    return;
  }

  size_t consumed = 0;
  TEST_ASSERT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                            cbor_decode_dev_auth(c->cbor, c->cbor_len, &out, &consumed), m);
  TEST_ASSERT_TRUE_MESSAGE(consumed <= c->cbor_len, m);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->step, out.dev_auth_step.dev_auth_step_type_choice, m);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->dev_id != NULL ? 1 : 0, out.dev_auth_dev_id_present, m);
  if (c->dev_id != NULL) {
    check_string(c->cbor, c->cbor_len, c->dev_id, c->dev_id_len, &out.dev_auth_dev_id.dev_auth_dev_id, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_first_auth, out.dev_auth_first_auth_present, m);
  if (c->has_first_auth) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->first_auth, out.dev_auth_first_auth.dev_auth_first_auth, m);
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_auth_time, out.dev_auth_auth_time_present, m);
  if (c->has_auth_time) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->auth_time, out.dev_auth_auth_time.dev_auth_auth_time, m);
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->has_auth_count, out.dev_auth_auth_count_present, m);
  if (c->has_auth_count) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->auth_count, out.dev_auth_auth_count.dev_auth_auth_count, m);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->challenge != NULL ? 1 : 0, out.dev_auth_challenge_present, m);
  if (c->challenge != NULL) {
    check_string(c->cbor, c->cbor_len, c->challenge, c->challenge_len,
                 &out.dev_auth_challenge.dev_auth_challenge, m);
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->auth_sig != NULL ? 1 : 0, out.dev_auth_auth_sig_present, m);
  if (c->auth_sig != NULL) {
    check_string(c->cbor, c->cbor_len, c->auth_sig, c->auth_sig_len,
                 &out.dev_auth_auth_sig.dev_auth_auth_sig, m);
  }
}

void setUp(void) {}

void tearDown(void) {}

void test_eth_sign_request_rows(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_ETH_CASES) / sizeof(UR_DECODE_ETH_CASES[0]); i++) {
    eth_case(&UR_DECODE_ETH_CASES[i]);
  }
}

void test_btc_sign_request_rows(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_BTC_CASES) / sizeof(UR_DECODE_BTC_CASES[0]); i++) {
    btc_case(&UR_DECODE_BTC_CASES[i]);
  }
}

void test_psbt_rows(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_PSBT_CASES) / sizeof(UR_DECODE_PSBT_CASES[0]); i++) {
    psbt_case(&UR_DECODE_PSBT_CASES[i]);
  }
}

void test_dev_auth_rows(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_DEV_CASES) / sizeof(UR_DECODE_DEV_CASES[0]); i++) {
    dev_case(&UR_DECODE_DEV_CASES[i]);
  }
}

/* zcbor's entry function reports success as soon as one whole item has been read, so a payload with
 * bytes left over decodes and reports how much of itself it looked at. qrscan.c only compares the
 * result against ZCBOR_SUCCESS and ignores the count, which means a sender that appended something
 * this schema does not know about is answered as though it had not been appended. */
void test_consumption_stops_at_the_first_whole_item(void) {
  const ur_decode_psbt_case_t* whole = &UR_DECODE_PSBT_CASES[0];
  const ur_decode_psbt_case_t* extra = NULL;
  struct zcbor_string out;
  size_t consumed = 0;

  for (size_t i = 0; i < sizeof(UR_DECODE_PSBT_CASES) / sizeof(UR_DECODE_PSBT_CASES[0]); i++) {
    if (UR_DECODE_PSBT_CASES[i].cbor_len == whole->cbor_len + 1) {
      extra = &UR_DECODE_PSBT_CASES[i];
    }
  }
  TEST_ASSERT_NOT_NULL(extra);

  TEST_ASSERT_EQUAL_INT_MESSAGE(ZCBOR_SUCCESS,
                                cbor_decode_psbt(whole->cbor, whole->cbor_len, &out, &consumed), whole->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(whole->cbor_len, (uint32_t)consumed, whole->name);

  consumed = 999;
  TEST_ASSERT_EQUAL_INT_MESSAGE(ZCBOR_SUCCESS,
                                cbor_decode_psbt(extra->cbor, extra->cbor_len, &out, &consumed), extra->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(whole->cbor_len, (uint32_t)consumed, extra->name);
}

/* Truncation is what a lost QR part, an out-of-focus read and an interrupted sender all produce, and
 * a CBOR header promises more bytes than the camera got. zcbor closes a map for an optional tail
 * instead of failing, so some cuts decode. What must never happen is a partial value: sign-data cut
 * to its first bytes, a path missing its last component, a 31 byte challenge. ASan guards the reads;
 * these four tests guard the values, family by family. Where a cut is accepted, the fields it could
 * not finish are absent rather than half-present -- which is what lets core_btc.c refuse a request
 * with no derivation paths and the updater refuse a psbt it cannot use. */
void test_truncated_eth_sign_request_never_yields_a_partial_value(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_ETH_CASES) / sizeof(UR_DECODE_ETH_CASES[0]); i++) {
    const ur_decode_eth_case_t* c = &UR_DECODE_ETH_CASES[i];
    if (!c->accept) {
      continue;
    }
    for (uint16_t cut = 1; cut < c->cbor_len; cut++) {
      struct eth_sign_request out;
      size_t consumed = 0;
      memset(&out, 0xa5, sizeof(out));
      if (cbor_decode_eth_sign_request(c->cbor, cut, &out, &consumed) != ZCBOR_SUCCESS) {
        continue;
      }
      char m[300];
      cut_label(m, sizeof(m), c->name, cut, c->cbor_len);
      TEST_ASSERT_TRUE_MESSAGE(consumed <= cut, m);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->sign_data_len, (uint32_t)out.eth_sign_request_sign_data.len, m);
      if (c->sign_data_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(c->sign_data, out.eth_sign_request_sign_data.value,
                                         c->sign_data_len, m);
      }
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->data_type, out.eth_sign_request_data_type.sign_data_type_choice, m);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(
          c->path_count,
          (uint32_t)out.eth_sign_request_derivation_path.crypto_keypath_components_path_component_m_count, m);
    }
  }
}

void test_truncated_btc_sign_request_never_yields_a_partial_path(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_BTC_CASES) / sizeof(UR_DECODE_BTC_CASES[0]); i++) {
    const ur_decode_btc_case_t* c = &UR_DECODE_BTC_CASES[i];
    if (!c->accept) {
      continue;
    }
    for (uint16_t cut = 1; cut < c->cbor_len; cut++) {
      struct btc_sign_request out;
      size_t consumed = 0;
      memset(&out, 0xa5, sizeof(out));
      if (cbor_decode_btc_sign_request(c->cbor, cut, &out, &consumed) != ZCBOR_SUCCESS) {
        continue;
      }
      char m[300];
      cut_label(m, sizeof(m), c->name, cut, c->cbor_len);
      TEST_ASSERT_TRUE_MESSAGE(consumed <= cut, m);
      if (out.btc_sign_request_btc_derivation_paths_crypto_keypath_m_present) {
        check_path(c->path_index, c->path_hardened, c->path_count,
                   &out.btc_sign_request_btc_derivation_paths_crypto_keypath_m, m);
      }
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->sign_data_len, (uint32_t)out.btc_sign_request_sign_data.len, m);
    }
  }
}

void test_truncated_psbt_never_yields_a_partial_payload(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_PSBT_CASES) / sizeof(UR_DECODE_PSBT_CASES[0]); i++) {
    const ur_decode_psbt_case_t* c = &UR_DECODE_PSBT_CASES[i];
    if (!c->accept) {
      continue;
    }
    for (uint16_t cut = 1; cut < c->cbor_len; cut++) {
      struct zcbor_string out;
      size_t consumed = 0;
      memset(&out, 0xa5, sizeof(out));
      int res = c->tagged == UR_DECODE_PSBT_TAGGED
          ? cbor_decode_tagged_psbt(c->cbor, cut, &out, &consumed)
          : cbor_decode_psbt(c->cbor, cut, &out, &consumed);
      if (res != ZCBOR_SUCCESS) {
        continue;
      }
      char m[300];
      cut_label(m, sizeof(m), c->name, cut, c->cbor_len);
      TEST_ASSERT_TRUE_MESSAGE(consumed <= cut, m);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->payload_len, (uint32_t)out.len, m);
      if (c->payload_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(c->payload, out.value, c->payload_len, m);
      }
    }
  }
}

void test_truncated_dev_auth_never_yields_a_partial_value(void) {
  for (size_t i = 0; i < sizeof(UR_DECODE_DEV_CASES) / sizeof(UR_DECODE_DEV_CASES[0]); i++) {
    const ur_decode_dev_case_t* c = &UR_DECODE_DEV_CASES[i];
    if (!c->accept) {
      continue;
    }
    for (uint16_t cut = 1; cut < c->cbor_len; cut++) {
      struct dev_auth out;
      size_t consumed = 0;
      memset(&out, 0xa5, sizeof(out));
      if (cbor_decode_dev_auth(c->cbor, cut, &out, &consumed) != ZCBOR_SUCCESS) {
        continue;
      }
      char m[300];
      cut_label(m, sizeof(m), c->name, cut, c->cbor_len);
      TEST_ASSERT_TRUE_MESSAGE(consumed <= cut, m);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(c->step, out.dev_auth_step.dev_auth_step_type_choice, m);
      if (out.dev_auth_challenge_present) {
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(32u, (uint32_t)out.dev_auth_challenge.dev_auth_challenge.len, m);
      }
      if (out.dev_auth_auth_sig_present) {
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(64u, (uint32_t)out.dev_auth_auth_sig.dev_auth_auth_sig.len, m);
      }
    }
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_eth_sign_request_rows);
  RUN_TEST(test_btc_sign_request_rows);
  RUN_TEST(test_psbt_rows);
  RUN_TEST(test_dev_auth_rows);
  RUN_TEST(test_consumption_stops_at_the_first_whole_item);
  RUN_TEST(test_truncated_eth_sign_request_never_yields_a_partial_value);
  RUN_TEST(test_truncated_btc_sign_request_never_yields_a_partial_path);
  RUN_TEST(test_truncated_psbt_never_yields_a_partial_payload);
  RUN_TEST(test_truncated_dev_auth_never_yields_a_partial_value);
  return UNITY_END();
}
