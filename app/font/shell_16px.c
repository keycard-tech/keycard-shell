#include "font.h"

const uint8_t shell_16px_bitmaps[] = {
  0x00, 0xff, 0xff, 0xfc, 0xf0, 0xcf, 0x3c, 0xc0, 0x18, 0xc3, 0x19, 0xff, 
  0xbf, 0xf3, 0x18, 0x63, 0x3f, 0xf7, 0xfe, 0x63, 0x0c, 0x60, 0x08, 0x04, 
  0x0f, 0x8f, 0xec, 0x9e, 0x4f, 0xa0, 0xf0, 0x1f, 0x07, 0xf2, 0x79, 0x37, 
  0xf1, 0xf0, 0x20, 0x10, 0xf0, 0x1c, 0x81, 0xa4, 0x19, 0xe1, 0x80, 0x18, 
  0x01, 0x80, 0x18, 0x01, 0x80, 0x18, 0x79, 0x82, 0x58, 0x12, 0x80, 0xf0, 
  0x30, 0x78, 0xcc, 0xcc, 0x78, 0x30, 0x7b, 0xff, 0xcc, 0xce, 0xff, 0x7b, 
  0xfc, 0x19, 0xcc, 0xe7, 0x33, 0x9c, 0xe7, 0x39, 0xce, 0x71, 0x8e, 0x71, 
  0x8e, 0x30, 0xc7, 0x18, 0xe7, 0x18, 0xe7, 0x39, 0xce, 0x73, 0x9c, 0xce, 
  0x73, 0x39, 0x80, 0x0c, 0x33, 0x3e, 0xdd, 0xfe, 0x1e, 0x0f, 0xc7, 0xfb, 
  0xb7, 0xcc, 0xc3, 0x00, 0x0c, 0x03, 0x00, 0xc0, 0x30, 0xff, 0xff, 0xf0, 
  0xc0, 0x30, 0x0c, 0x03, 0x00, 0xf4, 0xff, 0xfc, 0xf0, 0x18, 0xc6, 0x33, 
  0x98, 0xc6, 0x73, 0x18, 0xce, 0x63, 0x18, 0xc0, 0x3e, 0x3f, 0xb8, 0xf8, 
  0xbc, 0x5e, 0x4f, 0x27, 0xa3, 0xd1, 0xf1, 0xdf, 0xc7, 0xc0, 0x19, 0xdf, 
  0xb9, 0x8c, 0x63, 0x18, 0xc6, 0x30, 0x3c, 0x7e, 0xc3, 0xc3, 0x03, 0x06, 
  0x0e, 0x1c, 0x38, 0x70, 0xff, 0xff, 0x3c, 0x7e, 0xc3, 0x03, 0x03, 0x1e, 
  0x1f, 0x03, 0x03, 0xc3, 0x7e, 0x3c, 0x0e, 0x07, 0x07, 0x87, 0xc3, 0x63, 
  0xb1, 0x99, 0x8c, 0xff, 0xff, 0xc1, 0x80, 0xc0, 0xff, 0xff, 0x06, 0x0f, 
  0x9f, 0x81, 0x83, 0x07, 0x8f, 0xfb, 0xe0, 0x3c, 0x7f, 0xe3, 0xc0, 0xdc, 
  0xfe, 0xe7, 0xc3, 0xc3, 0xe7, 0x7e, 0x3c, 0xff, 0xff, 0x06, 0x06, 0x0c, 
  0x0c, 0x18, 0x18, 0x30, 0x30, 0x60, 0x60, 0x3c, 0x7e, 0xc3, 0xc3, 0x66, 
  0x3c, 0x7e, 0xe7, 0xc3, 0xc3, 0x7e, 0x3c, 0x3c, 0x7e, 0xc3, 0xc3, 0xc3, 
  0xe7, 0x7f, 0x3b, 0x03, 0xc3, 0x7e, 0x3c, 0xff, 0x80, 0x3f, 0xe0, 0xff, 
  0x80, 0x3f, 0xd0, 0x06, 0x1c, 0x71, 0xc7, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 
  0x18, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x07, 0xff, 0xfe, 0xc1, 0xc1, 0xc1, 
  0xc1, 0xc1, 0xc7, 0x1c, 0x71, 0xc3, 0x00, 0x7c, 0xfe, 0xc3, 0x03, 0x03, 
  0x07, 0x0e, 0x1c, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x0f, 0xf0, 0x1f, 
  0xf8, 0x38, 0x1c, 0x70, 0x0e, 0xe3, 0xc7, 0xc7, 0xe3, 0xce, 0x73, 0xcc, 
  0x33, 0xcc, 0x33, 0xcc, 0x33, 0xce, 0x77, 0xc7, 0xfe, 0xe3, 0xdc, 0x70, 
  0x00, 0x38, 0x00, 0x1f, 0xf8, 0x0f, 0xf0, 0x3c, 0x7e, 0xe7, 0xc3, 0xc3, 
  0xff, 0xff, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xfe, 0xff, 0xc3, 0xc3, 0xc3, 
  0xfe, 0xff, 0xc3, 0xc3, 0xc3, 0xff, 0xfe, 0x1e, 0x3f, 0xd8, 0x78, 0x0c, 
  0x06, 0x03, 0x01, 0x80, 0xc0, 0x30, 0xdf, 0xe3, 0xc0, 0xfe, 0x3f, 0xcc, 
  0x1b, 0x06, 0xc0, 0xf0, 0x3c, 0x0f, 0x03, 0xc1, 0xb0, 0x6f, 0xf3, 0xf8, 
  0xff, 0xff, 0xc0, 0xc0, 0xc0, 0xfe, 0xfe, 0xc0, 0xc0, 0xc0, 0xff, 0xff, 
  0xff, 0xff, 0xc0, 0xc0, 0xc0, 0xfe, 0xfe, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 
  0x1f, 0x1f, 0xe6, 0x1f, 0x03, 0xc0, 0x30, 0xec, 0x3f, 0x03, 0xc0, 0xf8, 
  0x77, 0xf8, 0xfc, 0xc0, 0xf0, 0x3c, 0x0f, 0x03, 0xc0, 0xff, 0xff, 0xff, 
  0x03, 0xc0, 0xf0, 0x3c, 0x0f, 0x03, 0xff, 0xff, 0xff, 0x06, 0x0c, 0x18, 
  0x30, 0x60, 0xc1, 0x83, 0xc7, 0x8f, 0xfb, 0xe0, 0xc1, 0xe1, 0xf1, 0xd9, 
  0xcd, 0xc7, 0xc3, 0xe1, 0xb8, 0xce, 0x63, 0xb0, 0xf8, 0x30, 0xc1, 0x83, 
  0x06, 0x0c, 0x18, 0x30, 0x60, 0xc1, 0x83, 0xff, 0xf0, 0xe0, 0x7f, 0x0f, 
  0xf9, 0xfd, 0xfb, 0xcf, 0x3c, 0x63, 0xc0, 0x3c, 0x03, 0xc0, 0x3c, 0x03, 
  0xc0, 0x3c, 0x03, 0xe0, 0xf8, 0x3f, 0x0f, 0x63, 0xd8, 0xf3, 0x3c, 0xcf, 
  0x1b, 0xc6, 0xf0, 0xfc, 0x3f, 0x07, 0x1e, 0x1f, 0xe6, 0x1b, 0x03, 0xc0, 
  0xf0, 0x3c, 0x0f, 0x03, 0xc0, 0xd8, 0x67, 0xf8, 0x78, 0xfc, 0xfe, 0xc3, 
  0xc3, 0xc3, 0xc3, 0xfe, 0xfc, 0xc0, 0xc0, 0xc0, 0xc0, 0x1e, 0x1f, 0xe6, 
  0x1b, 0x03, 0xc0, 0xf0, 0x3c, 0x0f, 0x1b, 0xc7, 0xd8, 0x67, 0xfc, 0x7b, 
  0xfc, 0xfe, 0xc3, 0xc3, 0xc3, 0xc3, 0xfe, 0xf8, 0xdc, 0xce, 0xc7, 0xc3, 
  0x3e, 0x3f, 0xb0, 0x78, 0x3e, 0x03, 0xc0, 0x7c, 0x07, 0xc1, 0xe0, 0xdf, 
  0xc7, 0xc0, 0xff, 0xff, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
  0x18, 0x18, 0xc0, 0xf0, 0x3c, 0x0f, 0x03, 0xc0, 0xf0, 0x3c, 0x0f, 0x03, 
  0xc0, 0xd8, 0x67, 0xf8, 0x78, 0xc1, 0xe0, 0xf0, 0x78, 0x3c, 0x1e, 0x0f, 
  0x8e, 0xc6, 0x36, 0x1f, 0x07, 0x01, 0x00, 0xc3, 0x0f, 0x0c, 0x3c, 0x30, 
  0xf0, 0xc3, 0xc3, 0x0f, 0x0c, 0x3e, 0x31, 0xd8, 0xc6, 0x37, 0xb0, 0xff, 
  0xc1, 0xce, 0x02, 0x10, 0xc1, 0xe0, 0xd8, 0xcc, 0x67, 0x61, 0xf0, 0x70, 
  0x7c, 0x77, 0x31, 0xb8, 0xf8, 0x30, 0xc0, 0xf0, 0x3c, 0x0d, 0x86, 0x61, 
  0x8c, 0xc3, 0xf0, 0x78, 0x0c, 0x03, 0x00, 0xc0, 0x30, 0xff, 0xff, 0xf0, 
  0x1c, 0x0e, 0x07, 0x03, 0x81, 0xc0, 0xe0, 0x70, 0x38, 0x0f, 0xff, 0xff, 
  0xff, 0x6d, 0xb6, 0xdb, 0x6d, 0xbf, 0xc6, 0x31, 0x8e, 0x31, 0x8c, 0x71, 
  0x8c, 0x63, 0x8c, 0x63, 0x18, 0xfd, 0xb6, 0xdb, 0x6d, 0xb6, 0xff, 0x10, 
  0x71, 0xf7, 0x7c, 0x60, 0xff, 0xff, 0x7f, 0x00, 0x3d, 0xff, 0x18, 0x37, 
  0xf8, 0xf1, 0xff, 0x76, 0xc0, 0xc0, 0xc0, 0xdc, 0xfe, 0xe3, 0xc3, 0xc3, 
  0xc3, 0xe3, 0xfe, 0xdc, 0x3c, 0xff, 0x9e, 0x0c, 0x18, 0x39, 0xbf, 0x3c, 
  0x03, 0x03, 0x03, 0x3b, 0x7f, 0xc7, 0xc3, 0xc3, 0xc3, 0xc7, 0x7f, 0x3b, 
  0x3c, 0x7e, 0xc3, 0xc3, 0xff, 0xc0, 0xc3, 0x7e, 0x3c, 0x1c, 0xf3, 0x3f, 
  0xfc, 0xc3, 0x0c, 0x30, 0xc3, 0x0c, 0x3b, 0x7f, 0xc7, 0xc3, 0xc3, 0xc3, 
  0xc7, 0x7f, 0x3b, 0x03, 0xfe, 0x7c, 0xc0, 0xc0, 0xc0, 0xdc, 0xfe, 0xc7, 
  0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xf3, 0xff, 0xff, 0x6c, 0x36, 0xdb, 
  0x6d, 0xb6, 0xf0, 0xc0, 0xc0, 0xc0, 0xc7, 0xce, 0xdc, 0xf8, 0xf8, 0xdc, 
  0xce, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xdc, 0xef, 0xff, 0xc6, 0x3c, 0x63, 
  0xc6, 0x3c, 0x63, 0xc6, 0x3c, 0x63, 0xc6, 0x30, 0xdc, 0xfe, 0xc7, 0xc3, 
  0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0x3c, 0x7e, 0xe7, 0xc3, 0xc3, 0xc3, 0xe7, 
  0x7e, 0x3c, 0xdc, 0xfe, 0xc7, 0xc3, 0xc3, 0xc3, 0xc7, 0xfe, 0xdc, 0xc0, 
  0xc0, 0xc0, 0x3b, 0x7f, 0xe3, 0xc3, 0xc3, 0xc3, 0xe3, 0x7f, 0x3b, 0x03, 
  0x03, 0x03, 0xdf, 0xf1, 0x8c, 0x63, 0x18, 0xc0, 0x7e, 0xff, 0xc3, 0xe0, 
  0x7c, 0x0f, 0xc3, 0xff, 0x7e, 0x63, 0x19, 0xef, 0x31, 0x8c, 0x63, 0x1e, 
  0x70, 0xc7, 0x8f, 0x1e, 0x3c, 0x78, 0xf1, 0xff, 0x76, 0xc1, 0xe0, 0xf8, 
  0xec, 0x67, 0x71, 0xb0, 0xf8, 0x38, 0x1c, 0x00, 0xc0, 0x3c, 0x63, 0xe6, 
  0x76, 0x66, 0x76, 0xe3, 0x6c, 0x3f, 0xc1, 0x98, 0x19, 0x80, 0xc3, 0xc3, 
  0x66, 0x3c, 0x18, 0x7e, 0x66, 0xc3, 0xc3, 0xc1, 0xe0, 0xf8, 0xec, 0x67, 
  0x71, 0xb0, 0xf8, 0x38, 0x18, 0x1c, 0x3c, 0x1c, 0x00, 0xff, 0xf0, 0xc6, 
  0x31, 0x8c, 0x3f, 0xfc, 0x37, 0x66, 0x66, 0x6c, 0xc6, 0x66, 0x66, 0x73, 
  0xff, 0xff, 0xff, 0xff, 0xfc, 0xce, 0x66, 0x66, 0x63, 0x36, 0x66, 0x66, 
  0xec, 0x38, 0xdf, 0x7e, 0xfb, 0x1c, 0x19, 0x81, 0x98, 0x19, 0x8f, 0xff, 
  0xff, 0xf1, 0x98, 0x19, 0x8f, 0xff, 0xff, 0xf1, 0x98, 0x19, 0x81, 0x98, 
  0x06, 0x00, 0x60, 0x06, 0x00, 0x60, 0x06, 0x0c, 0x63, 0xe6, 0x77, 0x6e, 
  0x3f, 0xc1, 0xf8, 0x0f, 0x00, 0x60, 0x06, 0x00, 0xf0, 0x1f, 0x83, 0xfc, 
  0x76, 0xee, 0x67, 0xc6, 0x30, 0x60, 0x06, 0x00, 0x60, 0x06, 0x00, 0x60, 
  0x00, 0x30, 0x07, 0x00, 0xe0, 0x1c, 0xc3, 0x8e, 0x70, 0x7e, 0x03, 0xc0, 
  0x18, 0x00, 0x06, 0x1c, 0x71, 0xc7, 0x1c, 0x38, 0x38, 0x38, 0x38, 0x38, 
  0x30, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc3, 0x8e, 0x38, 0xe3, 0x86, 0x00, 
  0x0f, 0x07, 0xf9, 0xc3, 0xb0, 0x3c, 0x01, 0x80, 0x30, 0x06, 0x00, 0x60, 
  0x6e, 0x1c, 0xff, 0x07, 0x80, 0xc0, 0xf8, 0x77, 0x38, 0xfc, 0x1e, 0x07, 
  0x83, 0xf1, 0xce, 0xe1, 0xf0, 0x30, 0x0c, 0x07, 0x83, 0xf1, 0xfe, 0xff, 
  0xff, 0xf7, 0xf8, 0xfc, 0x1e, 0x03, 0x00, 
};

const glyph_t shell_16px_glyphs[] = {
  {    0,    1,    1,    4,    0,    0}, // 0x20 ' '
  {    1,    2,   14,    3,    0,   -1}, // 0x21 '!'
  {    5,    6,    3,    7,    0,    1}, // 0x22 '"'
  {    8,   11,   10,   12,    0,    1}, // 0x23 '#'
  {   22,    9,   16,   10,    0,   -1}, // 0x24 '$'
  {   40,   13,   12,   14,    0,    1}, // 0x25 '%'
  {   60,    8,   12,    9,    0,    1}, // 0x26 '&'
  {   72,    2,    3,    3,    0,    1}, // 0x27 '''
  {   73,    5,   20,    6,    0,   -3}, // 0x28 '('
  {   86,    5,   20,    6,    0,   -3}, // 0x29 ')'
  {   99,   10,   10,   11,    0,    1}, // 0x2a '*'
  {  112,   10,   10,   12,    1,    2}, // 0x2b '+'
  {  125,    2,    3,    4,    1,   11}, // 0x2c ','
  {  126,    7,    2,    8,    0,    8}, // 0x2d '-'
  {  128,    2,    2,    4,    1,   11}, // 0x2e '.'
  {  129,    5,   17,    7,    1,   -2}, // 0x2f '/'
  {  140,    9,   12,   10,    0,    1}, // 0x30 '0'
  {  154,    5,   12,    6,    0,    1}, // 0x31 '1'
  {  162,    8,   12,    9,    0,    1}, // 0x32 '2'
  {  174,    8,   12,    9,    0,    1}, // 0x33 '3'
  {  186,    9,   12,   10,    0,    1}, // 0x34 '4'
  {  200,    7,   12,    8,    0,    1}, // 0x35 '5'
  {  211,    8,   12,    9,    0,    1}, // 0x36 '6'
  {  223,    8,   12,    9,    0,    1}, // 0x37 '7'
  {  235,    8,   12,    9,    0,    1}, // 0x38 '8'
  {  247,    8,   12,    9,    0,    1}, // 0x39 '9'
  {  259,    3,    9,    5,    1,    3}, // 0x3a ':'
  {  263,    3,   10,    5,    1,    3}, // 0x3b ';'
  {  267,    7,   11,    8,    0,    2}, // 0x3c '<'
  {  277,    9,    7,   11,    1,    4}, // 0x3d '='
  {  285,    7,   11,    9,    1,    2}, // 0x3e '>'
  {  295,    8,   14,    9,    0,   -1}, // 0x3f '?'
  {  309,   16,   17,   17,    0,    0}, // 0x40 '@'
  {  343,    8,   12,    9,    0,    1}, // 0x41 'A'
  {  355,    8,   12,    9,    0,    1}, // 0x42 'B'
  {  367,    9,   12,   10,    0,    1}, // 0x43 'C'
  {  381,   10,   12,   11,    0,    1}, // 0x44 'D'
  {  396,    8,   12,    9,    0,    1}, // 0x45 'E'
  {  408,    8,   12,    9,    0,    1}, // 0x46 'F'
  {  420,   10,   12,   11,    0,    1}, // 0x47 'G'
  {  435,   10,   12,   11,    0,    1}, // 0x48 'H'
  {  450,    2,   12,    3,    0,    1}, // 0x49 'I'
  {  453,    7,   12,    8,    0,    1}, // 0x4a 'J'
  {  464,    9,   12,   10,    0,    1}, // 0x4b 'K'
  {  478,    7,   12,    8,    0,    1}, // 0x4c 'L'
  {  489,   12,   12,   13,    0,    1}, // 0x4d 'M'
  {  507,   10,   12,   11,    0,    1}, // 0x4e 'N'
  {  522,   10,   12,   11,    0,    1}, // 0x4f 'O'
  {  537,    8,   12,    9,    0,    1}, // 0x50 'P'
  {  549,   10,   12,   11,    0,    1}, // 0x51 'Q'
  {  564,    8,   12,    9,    0,    1}, // 0x52 'R'
  {  576,    9,   12,   10,    0,    1}, // 0x53 'S'
  {  590,    8,   12,    9,    0,    1}, // 0x54 'T'
  {  602,   10,   12,   11,    0,    1}, // 0x55 'U'
  {  617,    9,   12,   10,    0,    1}, // 0x56 'V'
  {  631,   14,   12,   15,    0,    1}, // 0x57 'W'
  {  652,    9,   12,   10,    0,    1}, // 0x58 'X'
  {  666,   10,   12,   11,    0,    1}, // 0x59 'Y'
  {  681,   10,   12,   11,    0,    1}, // 0x5a 'Z'
  {  696,    3,   16,    5,    1,   -1}, // 0x5b '['
  {  702,    5,   17,    7,    1,   -2}, // 0x5c '\'
  {  713,    3,   16,    4,    0,   -1}, // 0x5d ']'
  {  719,    7,    5,    8,    0,    1}, // 0x5e '^'
  {  724,    8,    2,    9,    0,   11}, // 0x5f '_'
  {  726,    3,    3,    4,    0,    1}, // 0x60 '`'
  {  728,    7,    9,    8,    0,    4}, // 0x61 'a'
  {  736,    8,   12,    9,    0,    1}, // 0x62 'b'
  {  748,    7,    9,    8,    0,    4}, // 0x63 'c'
  {  756,    8,   12,    9,    0,    1}, // 0x64 'd'
  {  768,    8,    9,    9,    0,    4}, // 0x65 'e'
  {  777,    6,   12,    7,    0,    1}, // 0x66 'f'
  {  786,    8,   12,    9,    0,    4}, // 0x67 'g'
  {  798,    8,   12,    9,    0,    1}, // 0x68 'h'
  {  810,    2,   12,    4,    1,    1}, // 0x69 'i'
  {  813,    3,   15,    4,    0,    1}, // 0x6a 'j'
  {  819,    8,   12,    9,    0,    1}, // 0x6b 'k'
  {  831,    2,   12,    3,    0,    1}, // 0x6c 'l'
  {  834,   12,    9,   13,    0,    4}, // 0x6d 'm'
  {  848,    8,    9,    9,    0,    4}, // 0x6e 'n'
  {  857,    8,    9,    9,    0,    4}, // 0x6f 'o'
  {  866,    8,   12,    9,    0,    4}, // 0x70 'p'
  {  878,    8,   12,    9,    0,    4}, // 0x71 'q'
  {  890,    5,    9,    6,    0,    4}, // 0x72 'r'
  {  896,    8,    9,    9,    0,    4}, // 0x73 's'
  {  905,    5,   12,    6,    0,    1}, // 0x74 't'
  {  913,    7,    9,    8,    0,    4}, // 0x75 'u'
  {  921,    9,    9,   10,    0,    4}, // 0x76 'v'
  {  932,   12,    9,   13,    0,    4}, // 0x77 'w'
  {  946,    8,    9,    9,    0,    4}, // 0x78 'x'
  {  955,    9,   12,   10,    0,    4}, // 0x79 'y'
  {  969,    6,    9,    7,    0,    4}, // 0x7a 'z'
  {  976,    4,   16,    5,    0,   -1}, // 0x7b '{'
  {  984,    2,   19,    4,    1,   -2}, // 0x7c '|'
  {  989,    4,   16,    5,    0,   -1}, // 0x7d '}'
  {  997,   10,    4,   11,    0,    5}, // 0x7e '~'
  { 1002,   12,   12,   16,    0,    2}, // 0x7f
  { 1020,   12,   12,   16,    0,    2}, // 0x80
  { 1038,   12,   12,   16,    0,    2}, // 0x81
  { 1056,   12,    9,   16,    2,    3}, // 0x82
  { 1070,    7,   12,   16,    4,    1}, // 0x83
  { 1081,    7,   12,   16,    5,    1}, // 0x84
  { 1092,   11,   12,   16,    3,    2}, // 0x85
  { 1109,   10,   10,   16,    3,    3}, // 0x86
  { 1122,   10,   10,   16,    3,    4}, // 0x87
};

const font_t shell_16px = { shell_16px_bitmaps, shell_16px_glyphs, 0x20, 0x87, 3, 20 };
