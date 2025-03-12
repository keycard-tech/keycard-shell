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
extern const font_t navigation_24px;
extern const font_t msg_40px;

#endif
