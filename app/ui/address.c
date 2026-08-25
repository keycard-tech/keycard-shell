#include "crypto/bip32.h"
#include "screen/screen.h"
#include "ui/dialog.h"
#include "ui/settings_ui.h"
#include "ui/theme.h"
#include "ui/ui_internal.h"

#define BIP32_VERIFY_MAX_INDEX 2048
#define BIP32_VERIFY_PROGRESS_STEP 100

/*
 * Brute-force search for a scanned address, run in the UI thread so it can
 * render a progress bar and be cancelled from the keypad. The account key is
 * already exported (card is only involved during init), so all further
 * derivation is done on device.
 */
app_err_t ui_verify_address_search() {
  struct cmd_verify_address* va = &g_ui_cmd.params.verify_address;
  bip32_ctx_t* ctx = va->ctx;
  bip32_addr_hash_t hash = va->hash;
  const uint8_t* target = va->target;
  bool *found = va->found;

  dialog_title(LSTR(ADDRESS_VERIFY_TITLE));
  dialog_blank(TH_TITLE_HEIGHT);

  screen_area_t progress_area = {
      .x = TH_PROGRESS_LEFT_MARGIN,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_VERTICAL_MARGIN,
      .width = TH_PROGRESS_WIDTH,
      .height = TH_PROGRESS_HEIGHT
  };

  screen_text_ctx_t tooltip_ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_COLOR_TEXT_FG,
      .bg = TH_COLOR_TEXT_BG,
      .x = 0,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_WARN_VERTICAL_MARGIN,
  };

  screen_draw_centered_string(&tooltip_ctx, LSTR(ADDRESS_VERIFY_WAIT_SUB));

  dialog_nav_hints(ICON_NAV_CANCEL, ICON_NONE);

  const uint32_t total = 2 * (BIP32_VERIFY_MAX_INDEX + 1);
  uint32_t checked = 0;

  *found = false;

  for (uint32_t change = 0; change < 2; change++) {
    if (bip32_ctx_derive_change(ctx, change) != 0) {
      continue;
    }

    for (uint32_t index = 0; index <= BIP32_VERIFY_MAX_INDEX; index++) {
      uint8_t raw[RIPEMD160_DIGEST_LENGTH];

      if (bip32_ctx_derive_leaf(ctx, index) != 0) {
        break;
      }

      hash(ctx->leaf_pub, raw);
      checked++;

      if (memcmp(raw, target, RIPEMD160_DIGEST_LENGTH) == 0) {
        *found = true;
        return ERR_OK;
      }

      if ((checked % BIP32_VERIFY_PROGRESS_STEP) == 0) {
        uint8_t percent = (uint8_t) ((checked * 100) / total);
        ui_progressbar_render(&progress_area, percent);

        keypad_key_t k = ui_wait_keypress(0);
        if (k == KEYPAD_KEY_CANCEL || k == KEYPAD_KEY_BACK) {
          return ERR_CANCEL;
        }
      }
    }
  }

  return ERR_OK;
}
