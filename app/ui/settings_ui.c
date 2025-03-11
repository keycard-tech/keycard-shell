#include "settings_ui.h"
#include "keypad/keypad.h"
#include "ui/dialog.h"
#include "ui/theme.h"
#include "ui/ui.h"
#include "ui/ui_internal.h"

#include <stdbool.h>

#define LCD_MAX_BRIGHTNESS 100
#define LCD_MIN_BRIGHTNESS 5

void ui_progressbar_render(const screen_area_t* area, uint8_t val) {
  uint16_t completed = val == 100 ? area->width : (area->width / 100) * val;

  screen_area_t full_area = {
      .x = area->x,
      .y = area->y,
      .width = completed,
      .height = area->height
  };

  screen_area_t empty_area = {
      .x = area->x + completed,
      .y = area->y,
      .width = area->width - completed,
      .height = area->height
  };

  screen_fill_area(&full_area, TH_COLOR_PROGRESS_FG);
  screen_fill_area(&empty_area, TH_COLOR_PROGRESS_BG);
}

static void handle_lcd_change(const screen_area_t* progress_area, bool increase) {
  do {
    if (increase) {
      if (*g_ui_cmd.params.lcd.brightness < LCD_MAX_BRIGHTNESS) {
        (*g_ui_cmd.params.lcd.brightness)++;
      }
    } else {
      if (*g_ui_cmd.params.lcd.brightness > LCD_MIN_BRIGHTNESS) {
        (*g_ui_cmd.params.lcd.brightness)--;
      }
    }

    hal_pwm_set_dutycycle(PWM_BACKLIGHT, *g_ui_cmd.params.lcd.brightness);
    ui_progressbar_render(progress_area, *g_ui_cmd.params.lcd.brightness);
    vTaskDelay(pdMS_TO_TICKS(50));
  } while(g_ui_ctx.keypad.last_key_long && !g_ui_ctx.keypad.last_key_released);
}

app_err_t settings_ui_lcd_brightness() {
  dialog_title(LSTR(LCD_BRIGHTNESS_TITLE));
  dialog_footer(TH_TITLE_HEIGHT);

  screen_area_t progress_area = {
      .x = TH_PROGRESS_LEFT_MARGIN,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_VERTICAL_MARGIN,
      .width = TH_PROGRESS_WIDTH,
      .height = TH_PROGRESS_HEIGHT
  };

  ui_progressbar_render(&progress_area, *g_ui_cmd.params.lcd.brightness);

  while(1) {
    switch(ui_wait_keypress(portMAX_DELAY)) {
    case KEYPAD_KEY_CANCEL:
      return ERR_CANCEL;
    case KEYPAD_KEY_BACK:
      return ERR_CANCEL;
    case KEYPAD_KEY_CONFIRM:
      return ERR_OK;
    case KEYPAD_KEY_LEFT:
      handle_lcd_change(&progress_area, false);
      break;
    case KEYPAD_KEY_RIGHT:
      handle_lcd_change(&progress_area, true);
      break;
    default:
      break;
    }
  }
}

static bool updating_progress() {
  uint32_t evt = ui_wait_event(portMAX_DELAY);

  if (evt & UI_CMD_EVT) {
    if (g_ui_cmd.type != UI_CMD_PROGRESS) {
      g_ui_cmd.received = 1;
      return false;
    }
  }

  return true;
}

app_err_t settings_ui_update_progress() {
  dialog_title(g_ui_cmd.params.progress.title);
  dialog_footer(TH_TITLE_HEIGHT);
  screen_area_t progress_area = {
      .x = TH_PROGRESS_LEFT_MARGIN,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_VERTICAL_MARGIN,
      .width = TH_PROGRESS_WIDTH,
      .height = TH_PROGRESS_HEIGHT
  };

  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_COLOR_TEXT_FG,
      .bg = TH_COLOR_TEXT_BG,
      .x = 0,
      .y = TH_TITLE_HEIGHT + TH_PROGRESS_WARN_VERTICAL_MARGIN,
  };

  screen_draw_centered_string(&ctx, LSTR(FW_UPGRADE_WARNING));

  do {
    ui_progressbar_render(&progress_area, g_ui_cmd.params.progress.value);
  } while(updating_progress());

  return ERR_OK;
}
