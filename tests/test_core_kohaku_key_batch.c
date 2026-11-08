#include <stdio.h>
#include <string.h>

#include "core/core_kohaku_key_batch.h"
#include "crypto/ecdsa.h"
#include "crypto/memzero.h"
#include "crypto/privacy_pools_v1.h"
#include "crypto/secp256k1.h"
#include "hal.h"
#include "hal_host.h"
#include "ui/i18n.h"
#include "ui_host.h"
#include "unity.h"
#include "ur/ur.h"
#include "ur/ur_decode.h"
#include "zcbor_common.h"

static keycard_t card;
static uint8_t request[196];
static size_t request_len;
static unsigned derive_calls;
static unsigned display_calls;
static uint8_t vector_request[196];
static size_t vector_request_len;
static uint8_t vector_response[172];

static const char* paths[] = {
    "m/28784'/1'/0'/1'/17'/0'",
    "m/28784'/1'/0'/0'/17'/0'",
};

app_err_t core_privacy_pools_v1_derive_at(
    keycard_t* kc, const char* path,
    size_t len, uint8_t out[32]) {
  TEST_ASSERT_EQUAL_PTR(&card, kc);
  derive_calls++;

  // Synthetic test root, never a hardware secret.
  uint8_t root[32];
  memset(root, 0x42, sizeof(root));

  app_err_t result =
      privacy_pools_v1_derive_at(root, path, len, out);
  memzero(root, sizeof(root));
  return result;
}

core_evt_t ui_display_ur_qr(
    const char* title, const uint8_t* data,
    uint32_t len, ur_type_t type) {
  (void)title;
  display_calls++;

  TEST_ASSERT_EQUAL_INT(BYTES, type);

  struct zcbor_string decoded = {0};
  TEST_ASSERT_EQUAL_INT(
      ZCBOR_SUCCESS,
      cbor_decode_psbt(data, len, &decoded, NULL));

  TEST_ASSERT_EQUAL_UINT(172, decoded.len);
  TEST_ASSERT_EQUAL_MEMORY("KKR3", decoded.value, 4);
  TEST_ASSERT_EQUAL_HEX8(3, decoded.value[4]);
  TEST_ASSERT_EQUAL_MEMORY(
      request + 5, decoded.value + 5, 16);

  memcpy(vector_response, decoded.value, sizeof(vector_response));
  return CORE_EVT_UI_OK;
}

void setUp(void) {
  memset(&card, 0, sizeof(card));
  card.sc.state = SC_READY;
  card.app_version = 0x0400;
  card.ch.version = SC_V2;
  card.ch.open = true;
  memset(request, 0, sizeof(request));

  host_ui_reset();
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  hal_host_rng_seed(0x1122334455667788ULL);
  i18n_set_strings(i18n_english_strings);

  derive_calls = 0;
  display_calls = 0;

  memcpy(request, "KKQ3", 4);
  request[4] = 3;
  memset(request + 5, 0x42, 16);

  uint8_t host_private[32] = {0};
  // Public synthetic test scalar; never a real private key.
  host_private[31] = 1;

  TEST_ASSERT_EQUAL_INT(
      0,
      ecdsa_get_public_key65(
          &secp256k1, host_private, request + 21));
  memzero(host_private, sizeof(host_private));

  request[86] = 2;
  request_len = 87;

  for (size_t i = 0; i < 2; i++) {
    size_t len = strlen(paths[i]);
    request[request_len++] = (uint8_t)len;
    memcpy(request + request_len, paths[i], len);
    request_len += len;
  }
}

void tearDown(void) {}

static void test_batch_encrypts_two_credentials(void) {
  memcpy(vector_request, request, request_len);
  vector_request_len = request_len;

  TEST_ASSERT_EQUAL_INT(
      ERR_OK,
      core_kohaku_key_run_batch(
          &card, request, request_len));

  TEST_ASSERT_EQUAL_UINT(2, derive_calls);
  TEST_ASSERT_EQUAL_UINT(1, display_calls);
}

static void test_cancel_never_derives(void) {
  host_ui_answer_prompt(CORE_EVT_UI_CANCELLED);

  TEST_ASSERT_EQUAL_INT(
      ERR_CANCEL,
      core_kohaku_key_run_batch(
          &card, request, request_len));

  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, display_calls);
}

static void test_invalid_path_never_derives(void) {
  request[88] = 'X';

  TEST_ASSERT_EQUAL_INT(
      ERR_DATA,
      core_kohaku_key_run_batch(
          &card, request, request_len));

  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, display_calls);
}

static void test_invalid_public_key_never_derives(void) {
  memset(request + 22, 0, 64);

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO,
      core_kohaku_key_run_batch(
          &card, request, request_len));

  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, display_calls);
}

static void test_closed_secure_channel_never_derives(void) {
  card.ch.open = false;

  TEST_ASSERT_EQUAL_INT(
      ERR_CRYPTO,
      core_kohaku_key_run_batch(
          &card, request, request_len));

  TEST_ASSERT_EQUAL_UINT(0, derive_calls);
  TEST_ASSERT_EQUAL_UINT(0, display_calls);
}

static void print_hex(const uint8_t* value, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", value[i]);
  }
  putchar('\n');
}

int main(int argc, char** argv) {
  UNITY_BEGIN();
  RUN_TEST(test_batch_encrypts_two_credentials);
  RUN_TEST(test_cancel_never_derives);
  RUN_TEST(test_invalid_path_never_derives);
  RUN_TEST(test_invalid_public_key_never_derives);
  RUN_TEST(test_closed_secure_channel_never_derives);
  int result = UNITY_END();

  if (result == 0 && argc == 2 &&
      strcmp(argv[1], "--vector") == 0) {
    printf("KKQ3_REQUEST_HEX=");
    print_hex(vector_request, vector_request_len);

    printf("KKR3_RESPONSE_HEX=");
    print_hex(vector_response, sizeof(vector_response));
  }

  return result;
}
