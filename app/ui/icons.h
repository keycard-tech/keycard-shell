#ifndef __ICONS__
#define __ICONS__

#include <stdint.h>
#include "error.h"
#include "screen/screen.h"
#include "font/font.h"
#include "theme.h"

typedef enum {
  ICON_BATTERY_ONE = 0x05,
  ICON_BATTERY_TWO = 0x06,
  ICON_BATTERY_FULL = 0x07,
  ICON_BATTERY_CHARGING = 0x08
} title_icon_t;

typedef enum {
  NAV_CIRCLE_FULL = 0x01,
  NAV_CIRCLE_EMPTY = 0x02,
  NAV_CIRCLE_FULL_SMALL = 0x03,
  NAV_BACKSPACE_EMPTY = 0x04,
} nav_glyph_t;

typedef enum {
 SYM_HASHTAG = 0x7f,
 SYM_DOWN_ARROW = 0x80,
 SYM_UP_ARROW = 0x81,
 SYM_CHECKMARK = 0x82,
 SYM_LEFT_CHEVRON = 0x83,
 SYM_RIGHT_CHEVRON = 0x84,
 SYM_CANCEL = 0x85,
 SYM_CROSS = 0x86,
 SYM_DOT = 0x87,
} symbol_glyph_t;

typedef enum {
 ICON_NAV_NEXT = 0,
 ICON_NAV_NEXT_HOLD,
 ICON_NAV_CANCEL,
 ICON_NAV_BACKSPACE,
 ICON_OK,
 ICON_FAIL,
 ICON_PIN_CURRENT,
 ICON_PIN_FULL,
 ICON_PIN_EMPTY,
 ICON_NONE = 255
} icon_t;

typedef enum {
  ICON_INFO_BASE = 0x01,
  ICON_INFO_SUCCESS = 0x02,
  ICON_INFO_ERROR = 0x03,
  ICON_INFO_UPLOAD = 0x04,
  ICON_INFO_WARN = 0x05,
} info_icon_t;

app_err_t icon_draw(const screen_text_ctx_t* ctx, icon_t icon);
app_err_t icon_draw_info(const screen_text_ctx_t* ctx, info_icon_t icon);
app_err_t icon_draw_battery_indicator(const screen_text_ctx_t* ctx, uint8_t level);

#endif
