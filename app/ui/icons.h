#ifndef __ICONS__
#define __ICONS__

#include <stdint.h>
#include "error.h"
#include "screen/screen.h"
#include "font/font.h"
#include "theme.h"

typedef enum {
  ICON_BATTERY_LOW = 0x80,
  ICON_BATTERY_ONE = 0x81,
  ICON_BATTERY_TWO = 0x82,
  ICON_BATTERY_FULL = 0x83,
  ICON_BATTERY_CHARGING = 0x84
} title_icon_t;

typedef enum {
  NAV_CIRCLE_FULL = 0x01,
  NAV_CIRCLE_EMPTY = 0x02,
  NAV_CIRCLE_FULL_SMALL = 0x03,
  NAV_BACKSPACE_FULL = 0x04,
  NAV_BACKSPACE_EMPTY = 0x05,
  NAV_CANCEL_GLYPH = 0x06,
  NAV_QR_GLYPH = 0x07
} nav_glyph_t;

typedef enum {
 SYM_HASHTAG = 0x7f,
 SYM_DOWN_ARROW = 0x80,
 SYM_UP_ARROW = 0x81,
 SYM_CHECKMARK = 0x82,
 SYM_LEFT_CHEVRON = 0x83,
 SYM_RIGHT_CHEVRON = 0x84,
 SYM_DOWN_CHEVRON = 0x85,
} symbol_glyph_t;

typedef enum {
 ICON_NAV_NEXT = 0,
 ICON_NAV_CONFIRM,
 ICON_NAV_BACK,
 ICON_NAV_CANCEL,
 ICON_NAV_BACKSPACE,
 ICON_NAV_NONE = 255
} nav_icon_t;

app_err_t icon_draw_nav(screen_text_ctx_t* ctx, nav_icon_t icon);

#endif
