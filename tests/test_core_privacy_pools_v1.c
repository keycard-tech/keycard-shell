#include <stdint.h>
#include <string.h>

#include "core/core_privacy_pools_v1.h"
#include "framework/test_util.h"
#include "unity.h"

static keycard_t card;
static uint8_t output[32];
static app_err_t transport_result;
static uint16_t response_length;
static uint16_t response_status;
static int export_calls;

/* Synthetic Keycard response: no real hardware or secrets. */
app_err_t keycard_cmd_export_bip85_root(keycard_t* kc) {
  export_calls++;
  memset(&kc->apdu, 0xa5, sizeof(kc->apdu));

  for (size_t i = 0; i < 32; i++) {
    APDU_RESP(&kc->apdu)[i] = (uint8_t)i;
  }

  APDU_RESP(&kc->apdu)[32] = response_status >> 8;
  APDU_RESP(&kc->apdu)[33] = response_status & 0xff;
  kc->apdu.lr = response_length;

  return transport_result;
}

void setUp(void) {
  memset(&card, 0, sizeof(card));
  memset(output, 0xa5, sizeof(output));
  transport_result = ERR_OK;
  response_length = 34;
  response_status = SW_OK;
  export_calls = 0;
}

void tearDown(void) {}

static void assert_cleared(void) {
  uint8_t zero_apdu[sizeof(card.apdu)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(
      zero_apdu, &card.apdu, sizeof(card.apdu));
}

static void assert_output_cleared(void) {
  uint8_t zero[32] = {0};
  TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, output, sizeof(output));
}

static void test_success(void) {
  const char* path = "m/28784'/1'/0'";

  TEST_ASSERT_EQUAL_INT(
      ERR_OK, core_privacy_pools_v1_derive_at(
          &card, path, strlen(path), output));

  TEST_ASSERT_EQUAL_INT(1, export_calls);
  TEST_ASSERT_HEX(
      output, sizeof(output),
      "fe3e26d289a07d4cb4a2b38181a5060998688cd74d102a13cbcbb79ccff1faf9");
  assert_cleared();
}

static void test_bad_response_lengths(void) {
  const char* path = "m/28784'/1'/0'";
  const uint16_t lengths[] = {0, 1, 2, 33, 35, 65535};

  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
    response_length = lengths[i];
    memset(output, 0xa5, sizeof(output));

    TEST_ASSERT_EQUAL_INT(
        ERR_DATA, core_privacy_pools_v1_derive_at(
            &card, path, strlen(path), output));

    assert_output_cleared();
    assert_cleared();
  }
}

static void test_bad_status(void) {
  const char* path = "m/28784'/1'/0'";
  response_status = 0x6982;

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA, core_privacy_pools_v1_derive_at(
          &card, path, strlen(path), output));

  assert_output_cleared();
  assert_cleared();
}

static void test_transport_failure(void) {
  const char* path = "m/28784'/1'/0'";
  transport_result = ERR_TXRX;

  TEST_ASSERT_EQUAL_INT(
      ERR_TXRX, core_privacy_pools_v1_derive_at(
          &card, path, strlen(path), output));

  assert_output_cleared();
  assert_cleared();
}

static void test_keycard_buffer_aliasing(void) {
  const char* path = "m/28784'/1'/0'";

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA, core_privacy_pools_v1_derive_at(
          &card, path, strlen(path), card.apdu.data));
  TEST_ASSERT_EQUAL_INT(0, export_calls);
  assert_cleared();

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA, core_privacy_pools_v1_derive_at(
          &card, (const char*)card.apdu.data,
          16, output));
  TEST_ASSERT_EQUAL_INT(0, export_calls);
  assert_output_cleared();
  assert_cleared();
}

static void test_invalid_path_preflight(void) {
  const char* path = "m/28784'/2'/0'";

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA, core_privacy_pools_v1_derive_at(
          &card, path, strlen(path), output));

  TEST_ASSERT_EQUAL_INT(0, export_calls);
  assert_output_cleared();
  assert_cleared();
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_success);
  RUN_TEST(test_bad_response_lengths);
  RUN_TEST(test_bad_status);
  RUN_TEST(test_transport_failure);
  RUN_TEST(test_keycard_buffer_aliasing);
  RUN_TEST(test_invalid_path_preflight);
  return UNITY_END();
}
