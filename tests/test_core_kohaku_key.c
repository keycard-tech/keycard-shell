#include <string.h>

#include "core/core_kohaku_key.h"
#include "ui/i18n.h"
#include "ui_host.h"
#include "hal_host.h"
#include "unity.h"
#include "ur/ur.h"
#include "ur/ur_decode.h"
#include "zcbor_common.h"

static keycard_t card;

static app_err_t derive_result;
static unsigned derive_calls;
static uint8_t* derived_output;
static bool cleanup_verified;

app_err_t core_privacy_pools_v1_derive_at(
    keycard_t* kc, const char* path,
    size_t path_len, uint8_t out[32]) {
  TEST_ASSERT_EQUAL_PTR(&card, kc);
  TEST_ASSERT_EQUAL_STRING("m/28784'/1'/0'", path);
  TEST_ASSERT_EQUAL_size_t(strlen(path), path_len);

  derive_calls++;
  derived_output = out;
  memset(out, 0xa5, 32);
  return derive_result;
}

static void observe_result(void) {
  if (derived_output == NULL) return;

  for (size_t i = 0; i < 32; i++) {
    TEST_ASSERT_EQUAL_HEX8(0, derived_output[i]);
  }

  cleanup_verified = true;
  derived_output = NULL;
}


static uint8_t qr_test_request[22];
static size_t qr_test_request_len;
static unsigned qr_scan_calls;
static unsigned qr_display_calls;
static core_evt_t qr_scan_answer;
static core_evt_t qr_display_answer;

core_evt_t ui_qrscan(ur_type_t type, void* out) {
  TEST_ASSERT_EQUAL_INT(BYTES, type);
  qr_scan_calls++;

  if (qr_scan_answer != CORE_EVT_UI_OK) {
    return qr_scan_answer;
  }

  struct zcbor_string* request = out;
  request->value = qr_test_request;
  request->len = qr_test_request_len;
  return CORE_EVT_UI_OK;
}

core_evt_t ui_display_ur_qr(
    const char* title, const uint8_t* data,
    uint32_t len, ur_type_t type) {
  (void)title;
  qr_display_calls++;

  TEST_ASSERT_EQUAL_INT(BYTES, type);

  // The hardware-derived credential must already be erased.
  observe_result();

  struct zcbor_string decoded = {0};

  TEST_ASSERT_EQUAL_INT(
      ZCBOR_SUCCESS,
      cbor_decode_psbt(data, len, &decoded, NULL));

  TEST_ASSERT_EQUAL_UINT(53, decoded.len);
  TEST_ASSERT_EQUAL_MEMORY("KKR1", decoded.value, 4);
  TEST_ASSERT_EQUAL_HEX8(1, decoded.value[4]);
  TEST_ASSERT_EQUAL_MEMORY(
      qr_test_request + 5, decoded.value + 5, 16);

  // Independent SHA256-HMAC fixture:
  // key = 32 bytes of 0xa5
  // message = A7 receipt domain || 0x00 || 16 bytes of 0x42
  static const uint8_t EXPECTED_TAG[32] = {
      0x8a, 0x36, 0xe4, 0x48, 0x24, 0xfa, 0x81, 0x1a,
      0x63, 0x37, 0x5c, 0xe5, 0x8c, 0x86, 0x01, 0xda,
      0xd7, 0x69, 0xb8, 0x8e, 0x08, 0x4c, 0x0b, 0x14,
      0x7a, 0x4b, 0x6f, 0xec, 0xa4, 0xfa, 0x3b, 0x40,
  };

  TEST_ASSERT_EQUAL_MEMORY(
      EXPECTED_TAG, decoded.value + 21, sizeof(EXPECTED_TAG));

  return qr_display_answer;
}

void setUp(void) {
  memset(&card, 0, sizeof(card));
  host_ui_reset();
  memset(qr_test_request, 0, sizeof(qr_test_request));
  memcpy(qr_test_request, "KKQ1", 4);
  qr_test_request[4] = 1;
  memset(qr_test_request + 5, 0x42, 16);
  qr_test_request_len = 21;
  qr_scan_calls = 0;
  qr_display_calls = 0;
  qr_scan_answer = CORE_EVT_UI_OK;
  qr_display_answer = CORE_EVT_UI_OK;

  hal_host_rng_seed(0x1122334455667788ULL);
  i18n_set_strings(i18n_english_strings);

  card.sc.state = SC_READY;
  card.app_version = 0x0400;
  card.ch.version = SC_V2;
  card.ch.open = 1;

  derive_result = ERR_OK;
  derive_calls = 0;
  derived_output = NULL;
  cleanup_verified = false;

  host_ui_set_info_observer(observe_result);
}

void tearDown(void) {}


static void test_scan_cancel_never_derives(void) {
  qr_scan_answer = CORE_EVT_UI_CANCELLED;

  TEST_ASSERT_EQUAL_INT(
      ERR_CANCEL, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, qr_display_calls);
}

static void test_approval_cancel_never_derives(void) {
  host_ui_answer_prompt(CORE_EVT_UI_CANCELLED);

  TEST_ASSERT_EQUAL_INT(
      ERR_CANCEL, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, qr_display_calls);
}

static void test_legacy_keycard_rejected(void) {
  card.app_version = 0x0301;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(0, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
}

static void test_closed_channel_rejected(void) {
  card.ch.open = 0;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(0, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
}

static void assert_invalid_request(void) {
  unsigned before = qr_scan_calls;

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(before + 1, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, qr_display_calls);
}

static void test_malformed_requests_never_derive(void) {
  qr_test_request[0] = 'X';
  assert_invalid_request();
  qr_test_request[0] = 'K';

  qr_test_request[3] = '2';
  assert_invalid_request();
  qr_test_request[3] = '1';

  qr_test_request[4] = 2;
  assert_invalid_request();
  qr_test_request[4] = 1;

  qr_test_request_len = 20;
  assert_invalid_request();

  qr_test_request_len = 22;
  assert_invalid_request();
}

static void test_success_clears_before_display(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);

  TEST_ASSERT_EQUAL_INT(
      ERR_OK, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, qr_scan_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(1, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, qr_display_calls);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_rng_count());
  TEST_ASSERT_TRUE(cleanup_verified);
}

static void test_display_cancel(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  qr_display_answer = CORE_EVT_UI_CANCELLED;

  TEST_ASSERT_EQUAL_INT(
      ERR_CANCEL, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, qr_display_calls);
  TEST_ASSERT_TRUE(cleanup_verified);
}

static void test_failure_clears_before_display(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  derive_result = ERR_TXRX;

  TEST_ASSERT_EQUAL_INT(
      ERR_TXRX, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, qr_display_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
  TEST_ASSERT_TRUE(cleanup_verified);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_scan_cancel_never_derives);
  RUN_TEST(test_approval_cancel_never_derives);
  RUN_TEST(test_legacy_keycard_rejected);
  RUN_TEST(test_closed_channel_rejected);
  RUN_TEST(test_malformed_requests_never_derive);
  RUN_TEST(test_success_clears_before_display);
  RUN_TEST(test_display_cancel);
  RUN_TEST(test_failure_clears_before_display);
  return UNITY_END();
}
