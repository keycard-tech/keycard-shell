#include "font.h"

const uint8_t msg_40px_bitmaps[] = {
  0x00, 0x03, 0xff, 0x80, 0x00, 0x00, 0x0f, 0xff, 0xf0, 0x00, 0x00, 0x3f, 
  0xff, 0xfc, 0x00, 0x00, 0x7f, 0x00, 0xfe, 0x00, 0x01, 0xf8, 0x00, 0x1f, 
  0x80, 0x03, 0xf0, 0x00, 0x0f, 0xc0, 0x07, 0xc0, 0x00, 0x03, 0xe0, 0x0f, 
  0x80, 0x00, 0x01, 0xf0, 0x0f, 0x00, 0x00, 0x00, 0xf0, 0x1e, 0x00, 0x00, 
  0x00, 0x78, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x3c, 0x00, 0x00, 0x00, 0x3c, 
  0x78, 0x00, 0x00, 0x00, 0x1e, 0x70, 0x00, 0x00, 0x00, 0x0e, 0x70, 0x00, 
  0x00, 0x00, 0x0e, 0xf0, 0x00, 0x00, 0x00, 0x0f, 0xe0, 0x00, 0x00, 0x00, 
  0x07, 0xe0, 0x00, 0x00, 0x00, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x07, 0xe0, 
  0x00, 0x00, 0x00, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x07, 0xe0, 0x00, 0x00, 
  0x00, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x07, 
  0xf0, 0x00, 0x00, 0x00, 0x0f, 0x70, 0x00, 0x00, 0x00, 0x0e, 0x70, 0x00, 
  0x00, 0x00, 0x0e, 0x78, 0x00, 0x00, 0x00, 0x1e, 0x3c, 0x00, 0x00, 0x00, 
  0x3c, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x1e, 0x00, 0x00, 0x00, 0x78, 0x0f, 
  0x00, 0x00, 0x00, 0xf0, 0x0f, 0x80, 0x00, 0x01, 0xf0, 0x07, 0xc0, 0x00, 
  0x03, 0xe0, 0x03, 0xf0, 0x00, 0x0f, 0xc0, 0x01, 0xf8, 0x00, 0x1f, 0x80, 
  0x00, 0x7f, 0x00, 0xfe, 0x00, 0x00, 0x3f, 0xff, 0xfc, 0x00, 0x00, 0x0f, 
  0xff, 0xf0, 0x00, 0x00, 0x03, 0xff, 0x80, 0x00, 0x00, 0x07, 0x00, 0x0f, 
  0x00, 0x1f, 0x00, 0x3e, 0x00, 0x7c, 0xe0, 0xf8, 0xf1, 0xf0, 0xfb, 0xe0, 
  0x7f, 0xc0, 0x3f, 0x80, 0x1f, 0x00, 0x0e, 0x00, 0xe0, 0x07, 0xf0, 0x0f, 
  0xf8, 0x1f, 0x7c, 0x3e, 0x3e, 0x7c, 0x1f, 0xf8, 0x0f, 0xf0, 0x07, 0xe0, 
  0x07, 0xe0, 0x0f, 0xf0, 0x1f, 0xf8, 0x3e, 0x7c, 0x7c, 0x3e, 0xf8, 0x1f, 
  0xf0, 0x0f, 0xe0, 0x07, 0x03, 0x00, 0x1e, 0x00, 0xfc, 0x07, 0xf8, 0x3f, 
  0xf1, 0xff, 0xef, 0xff, 0xfd, 0xef, 0xe7, 0x9c, 0x1e, 0x00, 0x78, 0x01, 
  0xe0, 0x07, 0x80, 0x1e, 0x00, 0x78, 0x01, 0xe0, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0x00, 0xff, 0xff, 
};

const glyph_t msg_40px_glyphs[] = {
  {    0,   40,   40,   40,     0,  -40}, // 0x01
  {  200,   16,   12,   16,     0,  -25}, // 0x02
  {  224,   16,   16,   16,     0,  -28}, // 0x03
  {  256,   14,   16,   16,     1,  -28}, // 0x04
  {  284,    4,   16,   16,     6,  -28}, // 0x05
};

const font_t msg_40px = { msg_40px_bitmaps, msg_40px_glyphs, 0x01, 0x05, 40, 40 };
