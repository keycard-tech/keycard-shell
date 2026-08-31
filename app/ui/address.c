#include "screen/screen.h"
#include "ui/dialog.h"
#include "ui/settings_ui.h"
#include "ui/theme.h"
#include "ui/ui_internal.h"

#define BIP32_VERIFY_MAX_INDEX 2048
#define BIP32_VERIFY_PROGRESS_STEP 100

app_err_t ui_verify_address_search() {
  struct cmd_verify_address* va = &g_ui_cmd.params.verify_address;
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
      .x = TH_SCREEN_MARGIN,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_WARN_VERTICAL_MARGIN,
  };

  screen_draw_centered_string(&tooltip_ctx, LSTR(ADDRESS_VERIFY_WAIT_SUB));

  dialog_nav_hints(ICON_NAV_CANCEL, ICON_NONE);

  const uint32_t total = 2 * (BIP32_VERIFY_MAX_INDEX + 1);
  uint32_t checked = 0;

  *found = false;

  for (uint32_t change = 0; change < 2; change++) {
    for (uint32_t index = 0; index <= BIP32_VERIFY_MAX_INDEX; index++) {
      bool match = false;

      if (va->match(va->ctx, change, index, &match) != ERR_OK) {
        break;
      }
      checked++;

      if (match) {
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
