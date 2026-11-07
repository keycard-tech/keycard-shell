#include "core_kohaku_key.h"

#include "core_privacy_pools_v1.h"
#include "crypto/memzero.h"
#include "crypto/hmac.h"
#include "crypto/rand.h"
#include "crypto/util.h"
#include <string.h>
#include "ui/i18n.h"
#include "ui/ui.h"

app_err_t core_kohaku_key_run_privacy_pools_v1(
    keycard_t* kc, bool ready) {
  static const char path[] = "m/28784'/1'/0'";

  if (kc == NULL || !ready || kc->sc.state != SC_READY ||
      kc->app_version < 0x0400 ||
      kc->ch.version != SC_V2 || !kc->ch.open) {
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_UNAVAILABLE),
            LSTR(KOHAKU_PP_V1_UNAVAILABLE_SUB), 0);
    return ERR_CRYPTO;
  }

  if (ui_prompt(LSTR(MENU_PRIVACY_POOLS_V1),
                LSTR(KOHAKU_PP_V1_CONFIRM),
                UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  uint8_t challenge[16] = {0};
  if (hal_rng_next(challenge, sizeof(challenge)) != HAL_SUCCESS) {
    memzero(challenge, sizeof(challenge));
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return ERR_CRYPTO;
  }

  uint8_t credential[32] = {0};
  app_err_t err = core_privacy_pools_v1_derive_at(
      kc, path, sizeof(path) - 1, credential);

  if (err != ERR_OK) {
    memzero(credential, sizeof(credential));
    memzero(challenge, sizeof(challenge));
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return err;
  }

  static const uint8_t domain[] =
      "kohaku-key/v4-a7/privacy-pools-v1/receipt";
  const uint8_t separator = 0;
  uint8_t tag[32] = {0};
  HMAC_SHA256_CTX hmac;

  hmac_sha256_Init(&hmac, credential, sizeof(credential));
  hmac_sha256_Update(&hmac, domain, sizeof(domain) - 1);
  hmac_sha256_Update(&hmac, &separator, 1);
  hmac_sha256_Update(&hmac, challenge, sizeof(challenge));
  hmac_sha256_Final(&hmac, tag);

  memzero(credential, sizeof(credential));

  char receipt[128] = {0};
  char* cursor = receipt;
  static const char challenge_label[] = "Challenge:\n";
  static const char tag_label[] = "\nTag:\n";

  memcpy(cursor, challenge_label, sizeof(challenge_label) - 1);
  cursor += sizeof(challenge_label) - 1;
  base16_encode(challenge, cursor, sizeof(challenge));
  cursor += sizeof(challenge) * 2;

  memcpy(cursor, tag_label, sizeof(tag_label) - 1);
  cursor += sizeof(tag_label) - 1;
  base16_encode(tag, cursor, sizeof(tag));
  cursor += sizeof(tag) * 2;

  ui_display_paged_text(LSTR(KOHAKU_PP_V1_OK),
                        receipt, (uint32_t)(cursor - receipt));

  memzero(receipt, sizeof(receipt));
  memzero(tag, sizeof(tag));
  memzero(challenge, sizeof(challenge));
  return ERR_OK;
}
