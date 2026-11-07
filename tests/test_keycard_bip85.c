#include <stdint.h>
#include <string.h>

#include "keycard/keycard_cmdset.h"
#include "framework/test_util.h"
#include "unity.h"

static keycard_t card;
static uint8_t payload[16];
static uint32_t payload_len;
static int send_calls;
static app_err_t send_result;

app_err_t securechannel_send_apdu(
    smartcard_t* sc, secure_channel_t* channel,
    apdu_t* apdu, uint8_t* data, uint32_t len) {
  (void)sc;
  (void)channel;
  (void)apdu;

  send_calls++;
  payload_len = len;
  if (len == sizeof(payload)) {
    memcpy(payload, data, len);
  }

  return send_result;
}

void setUp(void) {
  memset(&card, 0, sizeof(card));
  memset(payload, 0, sizeof(payload));
  payload_len = 0;
  send_calls = 0;
  send_result = ERR_OK;

  card.app_version = 0x0400;
  card.ch.version = SC_V2;
  card.ch.open = 1;
}

void tearDown(void) {}

static void test_bip85_command_encoding(void) {
  const uint8_t expected_path[16] = {
    0x84, 0xfd, 0x1d, 0x48,
    0x80, 0x01, 0xf4, 0xa9,
    0x80, 0x00, 0x00, 0x20,
    0x80, 0x00, 0x00, 0x00
  };

  TEST_ASSERT_EQUAL_INT(
      ERR_OK, keycard_cmd_export_bip85_root(&card));

  TEST_ASSERT_EQUAL_INT(1, send_calls);
  TEST_ASSERT_EQUAL_UINT32(16, payload_len);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(
      expected_path, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_HEX8(0x80, APDU_CLA(&card.apdu));
  TEST_ASSERT_EQUAL_HEX8(0xc4, APDU_INS(&card.apdu));
  TEST_ASSERT_EQUAL_HEX8(32, APDU_P1(&card.apdu));
  TEST_ASSERT_EQUAL_HEX8(0, APDU_P2(&card.apdu));
}

static void test_reject_legacy_applet(void) {
  card.app_version = 0x0301;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, keycard_cmd_export_bip85_root(&card));
  TEST_ASSERT_EQUAL_INT(0, send_calls);
}

static void test_require_open_scv2(void) {
  card.ch.version = SC_V1;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, keycard_cmd_export_bip85_root(&card));
  TEST_ASSERT_EQUAL_INT(0, send_calls);

  card.ch.version = SC_V2;
  card.ch.open = 0;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, keycard_cmd_export_bip85_root(&card));
  TEST_ASSERT_EQUAL_INT(0, send_calls);
}

static void test_propagate_transport_error(void) {
  send_result = ERR_TXRX;

  TEST_ASSERT_EQUAL_INT(
      ERR_TXRX, keycard_cmd_export_bip85_root(&card));
  TEST_ASSERT_EQUAL_INT(1, send_calls);
}

static void test_null_card(void) {
  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO, keycard_cmd_export_bip85_root(NULL));
  TEST_ASSERT_EQUAL_INT(0, send_calls);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_bip85_command_encoding);
  RUN_TEST(test_reject_legacy_applet);
  RUN_TEST(test_require_open_scv2);
  RUN_TEST(test_propagate_transport_error);
  RUN_TEST(test_null_card);
  return UNITY_END();
}
