#include "core_kohaku_key.h"

#include "core.h"
#include "core_privacy_pools_v1.h"
#include "crypto/memzero.h"
#include "ui/i18n.h"
#include "ui/ui.h"

app_err_t core_kohaku_key_run_privacy_pools_v1(void) {
  keycard_t* kc = &g_core.keycard;
  static const char path[] = "m/28784'/1'/0'";

  if (!g_core.ready || kc->sc.state != SC_READY ||
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

  uint8_t credential[32] = {0};
  app_err_t err = core_privacy_pools_v1_derive_at(
      kc, path, sizeof(path) - 1, credential);

  memzero(credential, sizeof(credential));

  if (err != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return err;
  }

  ui_info(ICON_INFO_SUCCESS, LSTR(KOHAKU_PP_V1_OK),
          LSTR(KOHAKU_PP_V1_OK_SUB), 0);
  return ERR_OK;
}
