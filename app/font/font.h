#ifndef _FONT_H_
#define _FONT_H_

#include <stdint.h>

typedef struct {
  uint16_t bitmapOffset;
  uint8_t width;
  uint8_t height;
  uint8_t xAdvance;
  int8_t xOffset;
  int8_t yOffset;
} glyph_t;

typedef struct {
  const uint8_t *bitmap;
  const glyph_t *glyph;
  uint32_t first;
  uint32_t last;
  uint8_t baseline;
  uint8_t yAdvance;
} font_t;

extern const font_t inter_16px;
extern const font_t inter_18px;
extern const font_t icons_28px;

typedef enum {
  ICON_BATTERY_LOW = 0x80,
  ICON_BATTERY_ONE = 0x81,
  ICON_BATTERY_TWO = 0x82,
  ICON_BATTERY_FULL = 0x83,
  ICON_BATTERY_CHARGING = 0x84,
  ICON_CIRCLE_EMPTY = 0x85,
  ICON_CIRCLE_FULL = 0x86,
  ICON_CIRCLE_EMPTY_LARGE = 0x87,
} icons_t;

#define ICON_NAV_NEXT ICON_CIRCLE_FULL
#define ICON_NAV_CONFIRM ICON_CIRCLE_EMPTY
//TODO: change this
#define ICON_NAV_BACK ICON_CIRCLE_FULL
#define ICON_NAV_CANCEL ICON_CIRCLE_EMPTY
#define ICON_NAV_BACKSPACE ICON_CIRCLE_EMPTY

#define FONT_HASHTAG 0x7f
#define FONT_DOWN_ARROW 0x80
#define FONT_UP_ARROW 0x81
#define FONT_CHECKMARK 0x82
#define FONT_LEFT_CHEVRON 0x83
#define FONT_RIGHT_CHEVRON 0x84
#define FONT_DOWN_CHEVRON 0x85

#define FONT_ICON_AS_STRING(__NAME__, __CODE__) char __NAME__[2] = { __CODE__, 0x00 };

#endif
