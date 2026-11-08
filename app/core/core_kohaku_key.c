#include "core_kohaku_key.h"
#include "core_kohaku_key_batch.h"

#include "core_privacy_pools_v1.h"
#include "crypto/memzero.h"
#include "crypto/hmac.h"
#include "crypto/rand.h"
#include "crypto/util.h"
#include <string.h>
#include "ui/i18n.h"
#include "ui/ui.h"
#include "ur/ur.h"
#include "ur/ur_encode.h"

app_err_t core_kohaku_key_run_privacy_pools_v1(
    keycard_t* kc, bool ready) {
  static const char CREDENTIAL_PATH[] = "m/28784'/1'/0'";
  static const uint8_t RECEIPT_DOMAIN[] =
      "kohaku-key/v4-a7/privacy-pools-v1/receipt";
  static const uint8_t REQUEST_MAGIC[] = {'K', 'K', 'Q', '1'};

  if (kc == NULL || !ready || kc->sc.state != SC_READY ||
      kc->app_version < 0x0400 ||
      kc->ch.version != SC_V2 || !kc->ch.open) {
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_UNAVAILABLE),
            LSTR(KOHAKU_PP_V1_UNAVAILABLE_SUB), 0);
    return ERR_CRYPTO;
  }

  struct zcbor_string qr_request = {0};

  if (ui_qrscan(BYTES, &qr_request) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  if (qr_request.value != NULL && qr_request.len >= 4 &&
      memcmp(qr_request.value, "KKQ3", 4) == 0) {
    return core_kohaku_key_run_batch(
        kc, qr_request.value, qr_request.len);
  }

  if (qr_request.value == NULL || qr_request.len != 21 ||
      memcmp(qr_request.value, REQUEST_MAGIC, 4) != 0 ||
      qr_request.value[4] != 1) {
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return ERR_DATA;
  }

  uint8_t challenge[16] = {0};
  memcpy(challenge, qr_request.value + 5, sizeof(challenge));

  if (ui_prompt(LSTR(MENU_PRIVACY_POOLS_V1),
                LSTR(KOHAKU_PP_V1_CONFIRM),
                UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    memzero(challenge, sizeof(challenge));
    return ERR_CANCEL;
  }

  uint8_t credential[32] = {0};
  app_err_t err = core_privacy_pools_v1_derive_at(
      kc, CREDENTIAL_PATH, sizeof(CREDENTIAL_PATH) - 1, credential);

  if (err != ERR_OK) {
    memzero(credential, sizeof(credential));
    memzero(challenge, sizeof(challenge));
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return err;
  }

  uint8_t response[53] = {'K', 'K', 'R', '1', 1};
  memcpy(response + 5, challenge, sizeof(challenge));

  const uint8_t separator = 0;
  HMAC_SHA256_CTX hmac;

  hmac_sha256_Init(&hmac, credential, sizeof(credential));
  hmac_sha256_Update(&hmac, RECEIPT_DOMAIN,
                     sizeof(RECEIPT_DOMAIN) - 1);
  hmac_sha256_Update(&hmac, &separator, 1);
  hmac_sha256_Update(&hmac, challenge, sizeof(challenge));
  hmac_sha256_Final(&hmac, response + 21);

  memzero(&hmac, sizeof(hmac));
  memzero(credential, sizeof(credential));

  struct zcbor_string qr_response = {
      .value = response,
      .len = sizeof(response),
  };

  uint8_t encoded[64] = {0};
  size_t encoded_len = 0;

  if (cbor_encode_psbt(encoded, sizeof(encoded),
                       &qr_response, &encoded_len) != ZCBOR_SUCCESS) {
    memzero(response, sizeof(response));
    memzero(encoded, sizeof(encoded));
    memzero(challenge, sizeof(challenge));
    return ERR_DATA;
  }

  core_evt_t result = ui_display_ur_qr(
      NULL, encoded, (uint32_t)encoded_len, BYTES);

  memzero(response, sizeof(response));
  memzero(encoded, sizeof(encoded));
  memzero(challenge, sizeof(challenge));

  return result == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}
