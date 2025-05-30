#include "font.h"

const uint8_t shell_18px_bitmaps[] = {
  0x00, 0xff, 0xff, 0xff, 0xfc, 0x7f, 0xc0, 0xcf, 0x3c, 0xf3, 0x0c, 0x60, 
  0x63, 0x03, 0x18, 0xff, 0xf7, 0xff, 0x8c, 0x60, 0x63, 0x03, 0x18, 0x18, 
  0xc7, 0xff, 0x3f, 0xf8, 0x63, 0x03, 0x18, 0x18, 0xc0, 0x04, 0x00, 0x80, 
  0x7c, 0x3f, 0xef, 0x5f, 0xc9, 0xf9, 0x07, 0xe0, 0x7f, 0x03, 0xf8, 0x17, 
  0x82, 0x7e, 0x4f, 0xeb, 0xdf, 0xf0, 0xf8, 0x04, 0x00, 0x80, 0x78, 0x0f, 
  0xf0, 0x7c, 0xc3, 0xb3, 0x1c, 0xfc, 0xe1, 0xe7, 0x00, 0x38, 0x01, 0xc0, 
  0x0e, 0x78, 0x73, 0xf3, 0x8c, 0xdc, 0x33, 0xe0, 0xff, 0x01, 0xe0, 0x1e, 
  0x07, 0xf1, 0xc6, 0x38, 0xc7, 0x38, 0x7e, 0x07, 0x03, 0xb3, 0xe3, 0x7c, 
  0x7f, 0x87, 0x78, 0xe7, 0xfe, 0x7c, 0xc0, 0xff, 0x19, 0xcc, 0xe7, 0x3b, 
  0x9c, 0xe7, 0x39, 0xce, 0x73, 0x9c, 0x73, 0x9c, 0x63, 0x8c, 0xc7, 0x18, 
  0xe7, 0x38, 0xe7, 0x39, 0xce, 0x73, 0x9c, 0xe7, 0x73, 0x9c, 0xce, 0x60, 
  0x06, 0x0c, 0x63, 0xe6, 0x77, 0x6e, 0x3f, 0xc0, 0xf0, 0x1f, 0x83, 0xfc, 
  0x76, 0xee, 0x67, 0xc6, 0x30, 0x60, 0x0c, 0x03, 0x00, 0xc0, 0x30, 0xff, 
  0xff, 0xf0, 0xc0, 0x30, 0x0c, 0x03, 0x00, 0xff, 0xbc, 0xff, 0xff, 0xff, 
  0x80, 0x0c, 0x30, 0xc3, 0x1c, 0x61, 0x86, 0x38, 0xc3, 0x0c, 0x71, 0x86, 
  0x18, 0xe3, 0x0c, 0x30, 0x1f, 0x07, 0xf1, 0xc7, 0x38, 0xee, 0x2f, 0xc5, 
  0xf9, 0x3f, 0x27, 0xe8, 0xfd, 0x1d, 0xc7, 0x38, 0xe3, 0xf8, 0x3e, 0x00, 
  0x1e, 0x7d, 0xff, 0x7c, 0xe1, 0xc3, 0x87, 0x0e, 0x1c, 0x38, 0x70, 0xe1, 
  0xc0, 0x3f, 0x1f, 0xef, 0x3f, 0x87, 0x01, 0xc0, 0x70, 0x38, 0x1c, 0x0f, 
  0x07, 0x83, 0xc1, 0xe0, 0xff, 0xff, 0xf0, 0x3f, 0x0f, 0xf3, 0x87, 0x00, 
  0xe0, 0x3c, 0x1e, 0x03, 0xe0, 0x0e, 0x00, 0xe0, 0x1f, 0x83, 0xf8, 0xf7, 
  0xfc, 0x3e, 0x00, 0x03, 0xc0, 0xf8, 0x1f, 0x06, 0xe1, 0xdc, 0x73, 0x8c, 
  0x73, 0x8e, 0xe1, 0xdf, 0xff, 0xff, 0x80, 0xe0, 0x1c, 0x03, 0x80, 0x7f, 
  0x9f, 0xe6, 0x01, 0x80, 0xef, 0x3f, 0xef, 0x3c, 0x07, 0x01, 0xc0, 0x7e, 
  0x1f, 0xce, 0x7f, 0x87, 0x80, 0x1f, 0x07, 0xf9, 0xc7, 0xb0, 0x0e, 0x79, 
  0xff, 0xbc, 0x7f, 0x07, 0xe0, 0xfc, 0x1f, 0x83, 0xb8, 0xe3, 0xfc, 0x3e, 
  0x00, 0xff, 0xff, 0xfc, 0x03, 0x80, 0xe0, 0x1c, 0x07, 0x00, 0xe0, 0x38, 
  0x07, 0x01, 0xc0, 0x38, 0x0e, 0x01, 0xc0, 0x70, 0x00, 0x1f, 0x07, 0xf1, 
  0xc7, 0x38, 0xe7, 0x1c, 0x3e, 0x0f, 0xe3, 0x8e, 0xe0, 0xfc, 0x1f, 0x83, 
  0xf8, 0xf7, 0xfc, 0x3e, 0x00, 0x1f, 0x0f, 0xf1, 0xc7, 0x70, 0x7e, 0x0f, 
  0xc1, 0xf8, 0x3f, 0x8f, 0x7f, 0xe7, 0x9c, 0x03, 0x78, 0xe7, 0xf8, 0x3e, 
  0x00, 0xff, 0x80, 0x07, 0xfc, 0xff, 0x80, 0x07, 0xfa, 0x00, 0x06, 0x1c, 
  0x71, 0xc7, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x18, 0xff, 0xff, 0xc0, 0x00, 
  0x00, 0x07, 0xff, 0xfe, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc7, 0x1c, 0x71, 
  0xc3, 0x00, 0x3e, 0x3f, 0xb8, 0xfc, 0x70, 0x38, 0x3c, 0x3c, 0x3c, 0x1c, 
  0x0e, 0x00, 0x03, 0x81, 0xc0, 0xe0, 0x03, 0xf0, 0x03, 0xff, 0x03, 0xc0, 
  0xf0, 0xc0, 0x0c, 0x63, 0xd9, 0x99, 0xfe, 0x6c, 0xe3, 0x8f, 0x30, 0x63, 
  0xcc, 0x18, 0xf3, 0x06, 0x3c, 0xc1, 0x8f, 0x38, 0xe7, 0x67, 0xff, 0x98, 
  0xf9, 0xe3, 0x00, 0x00, 0xf0, 0x00, 0x0f, 0xfc, 0x00, 0xfe, 0x00, 0x1f, 
  0x07, 0xf1, 0xff, 0x78, 0xfe, 0x0f, 0xc1, 0xf8, 0x3f, 0xff, 0xff, 0xfc, 
  0x1f, 0x83, 0xf0, 0x7e, 0x0f, 0xc1, 0xc0, 0xff, 0x1f, 0xf3, 0x8f, 0x70, 
  0xee, 0x1d, 0xc7, 0x3f, 0xc7, 0xfc, 0xe1, 0xdc, 0x1f, 0x83, 0xf0, 0xff, 
  0xfd, 0xff, 0x00, 0x0f, 0xc1, 0xff, 0x1e, 0x1c, 0xe0, 0x7e, 0x01, 0xf0, 
  0x03, 0x80, 0x1c, 0x00, 0xe0, 0x07, 0x00, 0xdc, 0x0e, 0xf0, 0xe3, 0xfe, 
  0x07, 0xe0, 0xff, 0x0f, 0xfc, 0xe1, 0xee, 0x0e, 0xe0, 0x7e, 0x07, 0xe0, 
  0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xe0, 0xee, 0x1e, 0xff, 0xcf, 0xf0, 0xff, 
  0xff, 0xff, 0x80, 0x70, 0x0e, 0x01, 0xc0, 0x3f, 0xe7, 0xfc, 0xe0, 0x1c, 
  0x03, 0x80, 0x70, 0x0f, 0xff, 0xff, 0xc0, 0xff, 0xff, 0xff, 0x80, 0x70, 
  0x0e, 0x01, 0xc0, 0x3f, 0xe7, 0xfc, 0xe0, 0x1c, 0x03, 0x80, 0x70, 0x0e, 
  0x01, 0xc0, 0x00, 0x0f, 0xc1, 0xff, 0x1e, 0x1c, 0xe0, 0x7e, 0x00, 0x70, 
  0x03, 0x83, 0xfc, 0x1f, 0xe0, 0x1f, 0x00, 0xdc, 0x0e, 0xf0, 0xe3, 0xfe, 
  0x07, 0xe0, 0xe0, 0xfc, 0x1f, 0x83, 0xf0, 0x7e, 0x0f, 0xc1, 0xff, 0xff, 
  0xff, 0xe0, 0xfc, 0x1f, 0x83, 0xf0, 0x7e, 0x0f, 0xc1, 0xc0, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xc0, 0x01, 0xc0, 0x70, 0x1c, 0x07, 0x01, 0xc0, 0x70, 
  0x1c, 0x07, 0x01, 0xf8, 0x7e, 0x1f, 0xcf, 0x7f, 0x8f, 0xc0, 0xe0, 0x7e, 
  0x0e, 0xe1, 0xce, 0x38, 0xe7, 0x0f, 0xe0, 0xfc, 0x0f, 0xc0, 0xee, 0x0e, 
  0x70, 0xe3, 0x8e, 0x1c, 0xe0, 0xee, 0x07, 0xe0, 0x38, 0x0e, 0x03, 0x80, 
  0xe0, 0x38, 0x0e, 0x03, 0x80, 0xe0, 0x38, 0x0e, 0x03, 0x80, 0xff, 0xff, 
  0xf0, 0xf8, 0x1f, 0xf8, 0x1f, 0xf8, 0x1f, 0xfc, 0x3f, 0xec, 0x37, 0xec, 
  0x37, 0xee, 0x77, 0xe6, 0x67, 0xe6, 0x67, 0xe7, 0xe7, 0xe3, 0xc7, 0xe3, 
  0xc7, 0xe1, 0x87, 0xe1, 0x87, 0xf0, 0x3f, 0xc1, 0xfe, 0x0f, 0xf8, 0x7e, 
  0xc3, 0xf3, 0x1f, 0x98, 0xfc, 0x67, 0xe3, 0x3f, 0x0d, 0xf8, 0x7f, 0xc1, 
  0xfe, 0x0f, 0xf0, 0x3c, 0x0f, 0xc0, 0xff, 0xc7, 0x87, 0x9c, 0x0e, 0xe0, 
  0x1f, 0x80, 0x7e, 0x01, 0xf8, 0x07, 0xe0, 0x1f, 0x80, 0x77, 0x03, 0x9e, 
  0x1e, 0x3f, 0xf0, 0x3f, 0x00, 0xff, 0x9f, 0xfb, 0x87, 0xf0, 0x7e, 0x0f, 
  0xc1, 0xf8, 0x77, 0xfc, 0xff, 0x1c, 0x03, 0x80, 0x70, 0x0e, 0x01, 0xc0, 
  0x00, 0x0f, 0xc0, 0xff, 0xc7, 0x87, 0x9c, 0x0e, 0xe0, 0x1f, 0x80, 0x7e, 
  0x01, 0xf8, 0x07, 0xe1, 0x9f, 0x87, 0x77, 0x0f, 0x9e, 0x1e, 0x3f, 0xfc, 
  0x3f, 0x30, 0xff, 0x9f, 0xfb, 0x87, 0xf0, 0x7e, 0x0f, 0xc1, 0xf8, 0x77, 
  0xfc, 0xff, 0x1c, 0xf3, 0x8e, 0x71, 0xee, 0x1f, 0xc1, 0xc0, 0x1f, 0x0f, 
  0xfb, 0xc7, 0xf0, 0x7e, 0x01, 0xf0, 0x1f, 0xc0, 0xfe, 0x01, 0xe0, 0x1f, 
  0x83, 0xf8, 0xf7, 0xfc, 0x3e, 0x00, 0xff, 0xff, 0xfc, 0x38, 0x07, 0x00, 
  0xe0, 0x1c, 0x03, 0x80, 0x70, 0x0e, 0x01, 0xc0, 0x38, 0x07, 0x00, 0xe0, 
  0x1c, 0x00, 0xe0, 0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xe0, 
  0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xf0, 0xf7, 0x9e, 0x3f, 0xc1, 0xf8, 0xe0, 
  0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xe0, 0x7e, 0x07, 0xe0, 0x77, 0x0e, 0x70, 
  0xe3, 0x9c, 0x39, 0xc1, 0xf8, 0x1f, 0x80, 0xf0, 0xe0, 0x00, 0xfc, 0x00, 
  0x1f, 0x83, 0x83, 0xf0, 0x70, 0x7e, 0x0e, 0x0f, 0xc1, 0xc1, 0xf8, 0x38, 
  0x3b, 0x87, 0x0e, 0x70, 0xe1, 0xc7, 0x3e, 0x70, 0xe7, 0xce, 0x0f, 0xdf, 
  0x81, 0xfb, 0xf0, 0x1e, 0x3c, 0x00, 0xe0, 0x3f, 0x83, 0xde, 0x3c, 0x7b, 
  0xc1, 0xfc, 0x07, 0xc0, 0x1c, 0x01, 0xf0, 0x1f, 0xc1, 0xef, 0x1e, 0x3d, 
  0xe0, 0xfe, 0x03, 0xe0, 0x0c, 0xe0, 0x3f, 0x01, 0xf8, 0x0f, 0xe0, 0xf7, 
  0x07, 0x1c, 0x70, 0xff, 0x83, 0xf8, 0x0f, 0x80, 0x38, 0x01, 0xc0, 0x0e, 
  0x00, 0x70, 0x03, 0x80, 0xff, 0xff, 0xfc, 0x07, 0x00, 0xe0, 0x38, 0x0e, 
  0x03, 0x80, 0x70, 0x1c, 0x07, 0x01, 0xc0, 0x38, 0x0f, 0xff, 0xff, 0xc0, 
  0xff, 0xf9, 0xce, 0x73, 0x9c, 0xe7, 0x39, 0xce, 0x73, 0x9c, 0xff, 0xc0, 
  0xc3, 0x0c, 0x30, 0xe1, 0x86, 0x18, 0x70, 0xc3, 0x0c, 0x38, 0x61, 0x86, 
  0x1c, 0x30, 0xc3, 0xff, 0xce, 0x73, 0x9c, 0xe7, 0x39, 0xce, 0x73, 0x9c, 
  0xe7, 0xff, 0xc0, 0x0c, 0x07, 0x83, 0xf1, 0xce, 0xe1, 0xf0, 0x30, 0xff, 
  0xff, 0xfc, 0xcf, 0xfe, 0x1f, 0x1f, 0xef, 0x1c, 0x07, 0x07, 0xdf, 0xff, 
  0x1f, 0x87, 0xe3, 0xff, 0xf3, 0xdc, 0xe0, 0x38, 0x0e, 0x03, 0xbc, 0xff, 
  0xbc, 0xee, 0x1f, 0x87, 0xe1, 0xf8, 0x7e, 0x1f, 0xce, 0xff, 0xbb, 0x80, 
  0x1f, 0x1f, 0xe7, 0x1f, 0x83, 0xe0, 0x38, 0x0e, 0x03, 0x83, 0x71, 0xdf, 
  0xe1, 0xf0, 0x01, 0xc0, 0x70, 0x1c, 0xf7, 0x7f, 0xdc, 0xfe, 0x1f, 0x87, 
  0xe1, 0xf8, 0x7e, 0x1d, 0xcf, 0x7f, 0xc7, 0x70, 0x1e, 0x1f, 0xe7, 0x1b, 
  0x83, 0xff, 0xff, 0xfe, 0x03, 0x80, 0x71, 0xdf, 0xe1, 0xf0, 0x1e, 0x7c, 
  0xe7, 0xff, 0xe7, 0x0e, 0x1c, 0x38, 0x70, 0xe1, 0xc3, 0x87, 0x00, 0x1e, 
  0xef, 0xfd, 0xc7, 0xf0, 0x7e, 0x0f, 0xc1, 0xf8, 0x3f, 0x07, 0x71, 0xef, 
  0xfc, 0x7b, 0x80, 0x77, 0x1e, 0xff, 0x87, 0xe0, 0xe0, 0x38, 0x0e, 0x03, 
  0xbc, 0xff, 0xbc, 0xfe, 0x1f, 0x87, 0xe1, 0xf8, 0x7e, 0x1f, 0x87, 0xe1, 
  0xf8, 0x70, 0xff, 0x8f, 0xff, 0xff, 0xff, 0xc0, 0x39, 0xce, 0x03, 0x9c, 
  0xe7, 0x39, 0xce, 0x73, 0x9f, 0xdc, 0xe0, 0x38, 0x0e, 0x03, 0x87, 0xe3, 
  0xb9, 0xce, 0xe3, 0xf0, 0xfc, 0x3f, 0x8e, 0xf3, 0x9e, 0xe3, 0xf8, 0x70, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0xee, 0x39, 0xfe, 0xfb, 0xcf, 0x3f, 
  0x1c, 0x7e, 0x38, 0xfc, 0x71, 0xf8, 0xe3, 0xf1, 0xc7, 0xe3, 0x8f, 0xc7, 
  0x1f, 0x8e, 0x38, 0xee, 0x7f, 0xbc, 0xfc, 0x7e, 0x3f, 0x1f, 0x8f, 0xc7, 
  0xe3, 0xf1, 0xf8, 0xe0, 0x1f, 0x0f, 0xf9, 0xc7, 0x70, 0x7e, 0x0f, 0xc1, 
  0xf8, 0x3f, 0x07, 0x71, 0xcf, 0xf8, 0x7c, 0x00, 0xee, 0x3f, 0xef, 0x3b, 
  0x87, 0xe1, 0xf8, 0x7e, 0x1f, 0x87, 0xf3, 0xbf, 0xee, 0xf3, 0x80, 0xe0, 
  0x38, 0x00, 0x1d, 0xdf, 0xf7, 0x3f, 0x87, 0xe1, 0xf8, 0x7e, 0x1f, 0x87, 
  0x73, 0xdf, 0xf3, 0xdc, 0x07, 0x01, 0xc0, 0x70, 0xef, 0xff, 0x38, 0xe3, 
  0x8e, 0x38, 0xe3, 0x8e, 0x00, 0x3e, 0x3f, 0xb8, 0xfc, 0x0f, 0x83, 0xf8, 
  0x3e, 0x07, 0xe3, 0xbf, 0x8f, 0x80, 0x38, 0x70, 0xe7, 0xff, 0xe7, 0x0e, 
  0x1c, 0x38, 0x70, 0xe1, 0xc3, 0xe3, 0xc0, 0xe1, 0xf8, 0x7e, 0x1f, 0x87, 
  0xe1, 0xf8, 0x7e, 0x1f, 0x87, 0xf3, 0xdf, 0xf3, 0xdc, 0xe1, 0xf8, 0x7e, 
  0x1f, 0x87, 0x61, 0x98, 0x67, 0x38, 0xcc, 0x3f, 0x07, 0x80, 0xc0, 0xe0, 
  0x07, 0xe0, 0x07, 0xe1, 0x87, 0xe1, 0x87, 0x61, 0x86, 0x63, 0xc6, 0x77, 
  0xee, 0x37, 0xec, 0x3e, 0x7c, 0x1e, 0x78, 0x0c, 0x30, 0xc3, 0xe7, 0x66, 
  0x7e, 0x3c, 0x18, 0x3c, 0x7e, 0x66, 0xe7, 0xc3, 0xc0, 0xf8, 0x7e, 0x19, 
  0x8e, 0x73, 0x9c, 0xc3, 0x70, 0xfc, 0x1e, 0x07, 0x81, 0xc0, 0x70, 0x1c, 
  0x1e, 0x0f, 0x00, 0xff, 0xff, 0xc1, 0xc0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 
  0x70, 0x7f, 0xff, 0xe0, 0x1e, 0x7c, 0xe1, 0xc3, 0x87, 0x0e, 0x1c, 0xf1, 
  0xe0, 0xe1, 0xc3, 0x87, 0x0e, 0x1c, 0x3e, 0x3c, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xf0, 0xf1, 0xf0, 0xe1, 0xc3, 0x87, 0x0e, 0x1c, 0x1e, 
  0x3c, 0xe1, 0xc3, 0x87, 0x0e, 0x1c, 0xf9, 0xe0, 0x78, 0xff, 0x3c, 0xff, 
  0x1e, 
};

const glyph_t shell_18px_glyphs[] = {
  {    0,    1,    1,    5,    0,    0}, // 0x20 ' '
  {    1,    3,   14,    5,    0,    1}, // 0x21 '!'
  {    7,    6,    4,    8,    0,    1}, // 0x22 '"'
  {   10,   13,   14,   15,    0,    1}, // 0x23 '#'
  {   33,   11,   18,   13,    0,   -1}, // 0x24 '$'
  {   58,   14,   14,   16,    0,    1}, // 0x25 '%'
  {   83,   11,   14,   13,    0,    1}, // 0x26 '&'
  {  103,    2,    4,    4,    0,    1}, // 0x27 '''
  {  104,    5,   22,    7,    0,   -3}, // 0x28 '('
  {  118,    5,   22,    7,    0,   -3}, // 0x29 ')'
  {  132,   12,   12,   14,    0,    1}, // 0x2a '*'
  {  150,   10,   10,   13,    1,    3}, // 0x2b '+'
  {  163,    3,    5,    6,    1,   12}, // 0x2c ','
  {  165,    8,    2,   10,    0,    8}, // 0x2d '-'
  {  167,    3,    3,    6,    1,   12}, // 0x2e '.'
  {  169,    6,   20,    9,    1,   -2}, // 0x2f '/'
  {  184,   11,   14,   13,    0,    1}, // 0x30 '0'
  {  204,    7,   14,    9,    0,    1}, // 0x31 '1'
  {  217,   10,   14,   12,    0,    1}, // 0x32 '2'
  {  235,   11,   14,   13,    0,    1}, // 0x33 '3'
  {  255,   11,   14,   13,    0,    1}, // 0x34 '4'
  {  275,   10,   14,   12,    0,    1}, // 0x35 '5'
  {  293,   11,   14,   13,    0,    1}, // 0x36 '6'
  {  313,   11,   14,   13,    0,    1}, // 0x37 '7'
  {  333,   11,   14,   13,    0,    1}, // 0x38 '8'
  {  353,   11,   14,   13,    0,    1}, // 0x39 '9'
  {  373,    3,   10,    6,    1,    5}, // 0x3a ':'
  {  377,    3,   11,    6,    1,    5}, // 0x3b ';'
  {  382,    7,   11,    9,    0,    4}, // 0x3c '<'
  {  392,    9,    7,   12,    1,    6}, // 0x3d '='
  {  400,    7,   11,   10,    1,    4}, // 0x3e '>'
  {  410,    9,   14,   11,    0,    1}, // 0x3f '?'
  {  426,   18,   18,   20,    0,   -1}, // 0x40 '@'
  {  467,   11,   14,   13,    0,    1}, // 0x41 'A'
  {  487,   11,   14,   13,    0,    1}, // 0x42 'B'
  {  507,   13,   14,   15,    0,    1}, // 0x43 'C'
  {  530,   12,   14,   14,    0,    1}, // 0x44 'D'
  {  551,   11,   14,   13,    0,    1}, // 0x45 'E'
  {  571,   11,   14,   13,    0,    1}, // 0x46 'F'
  {  591,   13,   14,   15,    0,    1}, // 0x47 'G'
  {  614,   11,   14,   13,    0,    1}, // 0x48 'H'
  {  634,    3,   14,    5,    0,    1}, // 0x49 'I'
  {  640,   10,   14,   12,    0,    1}, // 0x4a 'J'
  {  658,   12,   14,   14,    0,    1}, // 0x4b 'K'
  {  679,   10,   14,   12,    0,    1}, // 0x4c 'L'
  {  697,   16,   14,   18,    0,    1}, // 0x4d 'M'
  {  725,   13,   14,   15,    0,    1}, // 0x4e 'N'
  {  748,   14,   14,   16,    0,    1}, // 0x4f 'O'
  {  773,   11,   14,   13,    0,    1}, // 0x50 'P'
  {  793,   14,   14,   16,    0,    1}, // 0x51 'Q'
  {  818,   11,   14,   13,    0,    1}, // 0x52 'R'
  {  838,   11,   14,   13,    0,    1}, // 0x53 'S'
  {  858,   11,   14,   13,    0,    1}, // 0x54 'T'
  {  878,   12,   14,   14,    0,    1}, // 0x55 'U'
  {  899,   12,   14,   14,    0,    1}, // 0x56 'V'
  {  920,   19,   14,   21,    0,    1}, // 0x57 'W'
  {  954,   13,   14,   15,    0,    1}, // 0x58 'X'
  {  977,   13,   14,   15,    0,    1}, // 0x59 'Y'
  { 1000,   11,   14,   13,    0,    1}, // 0x5a 'Z'
  { 1020,    5,   18,    7,    0,   -1}, // 0x5b '['
  { 1032,    6,   20,    8,    0,   -2}, // 0x5c '\'
  { 1047,    5,   18,    7,    0,   -1}, // 0x5d ']'
  { 1059,   10,    6,   13,    1,    1}, // 0x5e '^'
  { 1067,   11,    2,   13,    0,   13}, // 0x5f '_'
  { 1070,    3,    5,    5,    0,   -1}, // 0x60 '`'
  { 1072,   10,   11,   12,    0,    4}, // 0x61 'a'
  { 1086,   10,   14,   12,    0,    1}, // 0x62 'b'
  { 1104,   10,   11,   12,    0,    4}, // 0x63 'c'
  { 1118,   10,   14,   12,    0,    1}, // 0x64 'd'
  { 1136,   10,   11,   12,    0,    4}, // 0x65 'e'
  { 1150,    7,   14,    9,    0,    1}, // 0x66 'f'
  { 1163,   11,   15,   13,    0,    4}, // 0x67 'g'
  { 1184,   10,   14,   12,    0,    1}, // 0x68 'h'
  { 1202,    3,   14,    6,    1,    1}, // 0x69 'i'
  { 1208,    5,   16,    6,    0,    1}, // 0x6a 'j'
  { 1218,   10,   14,   12,    0,    1}, // 0x6b 'k'
  { 1236,    3,   14,    5,    0,    1}, // 0x6c 'l'
  { 1242,   15,   11,   17,    0,    4}, // 0x6d 'm'
  { 1263,    9,   11,   11,    0,    4}, // 0x6e 'n'
  { 1276,   11,   11,   13,    0,    4}, // 0x6f 'o'
  { 1292,   10,   14,   12,    0,    4}, // 0x70 'p'
  { 1310,   10,   14,   12,    0,    4}, // 0x71 'q'
  { 1328,    6,   11,    8,    0,    4}, // 0x72 'r'
  { 1337,    9,   11,   11,    0,    4}, // 0x73 's'
  { 1350,    7,   14,    9,    0,    1}, // 0x74 't'
  { 1363,   10,   11,   12,    0,    4}, // 0x75 'u'
  { 1377,   10,   11,   12,    0,    4}, // 0x76 'v'
  { 1391,   16,   11,   18,    0,    4}, // 0x77 'w'
  { 1413,    8,   11,   10,    0,    4}, // 0x78 'x'
  { 1424,   10,   15,   12,    0,    4}, // 0x79 'y'
  { 1443,    9,   11,   11,    0,    4}, // 0x7a 'z'
  { 1456,    7,   18,    9,    0,   -1}, // 0x7b '{'
  { 1472,    3,   20,    5,    0,   -2}, // 0x7c '|'
  { 1480,    7,   18,    9,    0,   -1}, // 0x7d '}'
  { 1496,   10,    4,   12,    0,    6}, // 0x7e '~'
};

const font_t shell_18px = { shell_18px_bitmaps, shell_18px_glyphs, 0x20, 0x7e, 3, 20 };
