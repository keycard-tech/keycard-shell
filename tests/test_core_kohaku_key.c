#include <string.h>

#include "core/core_kohaku_key.h"
#include "ui/i18n.h"
#include "ui_host.h"
#include "hal_host.h"
#include "unity.h"

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

static void observe_receipt(const char* text, uint32_t len) {
  observe_result();

  static const char expected[] =
      "Challenge:\n"
      "febf141233694cc2bf70c0c458bf29e7"
      "\nTag:\n"
      "57d386010f1489ba952a77134989f1b0"
      "6b852129a8e9109d476dd2725e8f5efa";

  TEST_ASSERT_EQUAL_UINT(sizeof(expected) - 1, len);
  TEST_ASSERT_EQUAL_MEMORY(expected, text, len);
}

void setUp(void) {
  memset(&card, 0, sizeof(card));
  host_ui_reset();
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
  host_ui_set_paged_text_observer(observe_receipt);
}

void tearDown(void) {}

static void test_cancel_never_derives(void) {
  TEST_ASSERT_EQUAL_INT(
      ERR_CANCEL, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_rng_count());
  TEST_ASSERT_EQUAL_UINT(0, host_ui_info_calls());
}

static void test_legacy_keycard_rejected(void) {
  card.app_version = 0x0301;
  host_ui_answer_prompt(CORE_EVT_UI_OK);

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(0, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
}

static void test_closed_channel_rejected(void) {
  card.ch.open = 0;
  host_ui_answer_prompt(CORE_EVT_UI_OK);

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_prompt_calls());
}

static void test_success_clears_before_display(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);

  TEST_ASSERT_EQUAL_INT(
      ERR_OK, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(1, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_info_calls());
  TEST_ASSERT_EQUAL_UINT(1, host_ui_paged_text_calls());
  TEST_ASSERT_EQUAL_UINT(16, hal_host_rng_count());
  TEST_ASSERT_TRUE(cleanup_verified);
}

static void test_rng_failure_never_derives(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  hal_host_rng_refuse_next();

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, host_ui_prompt_calls());
  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_rng_count());
  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
  TEST_ASSERT_EQUAL_UINT(0, host_ui_paged_text_calls());
}

static void test_failure_clears_before_display(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  derive_result = ERR_TXRX;

  TEST_ASSERT_EQUAL_INT(
      ERR_TXRX, core_kohaku_key_run_privacy_pools_v1(&card, true));

  TEST_ASSERT_EQUAL_UINT(1, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
  TEST_ASSERT_TRUE(cleanup_verified);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_cancel_never_derives);
  RUN_TEST(test_legacy_keycard_rejected);
  RUN_TEST(test_closed_channel_rejected);
  RUN_TEST(test_success_clears_before_display);
  RUN_TEST(test_rng_failure_never_derives);
  RUN_TEST(test_failure_clears_before_display);
  return UNITY_END();
}
