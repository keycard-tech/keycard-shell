/*
 * Copyright (C) 2014, Michele Balistreri
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include "tlv.h"
#include "common.h"

uint16_t tlv_read_tag(uint8_t *buf, uint16_t *out_tag) {
  uint16_t i = 0;

  *out_tag = buf[i++];

  if((*out_tag & 0x1F) == 0x1F) {
    *out_tag = *out_tag << 8 | buf[i++];
  }

  return i;
}

uint16_t tlv_read_length(uint8_t *buf, uint16_t *out_len) {
  uint16_t i = 0;
  *out_len = buf[i++];

  if (*out_len > 0x7f) {
    uint16_t lenOfLen = APP_MIN((*out_len & 0x7f), 2);
    *out_len = 0;

    while(lenOfLen--) {
      *out_len = (*out_len << 8) | buf[i++];
    }
  }

  return i;
}

uint16_t tlv_read_fixed_primitive(uint16_t tag, uint16_t len, uint8_t *buf, uint8_t *out) {
  uint16_t _len;
  uint16_t off = tlv_read_primitive(tag, len, buf, out, &_len);
  if (_len != len) {
    return TLV_INVALID;
  }

  return off;
}

uint16_t tlv_read_primitive(uint16_t tag, uint16_t max_len, uint8_t *buf, uint8_t *out, uint16_t *len) {
  uint16_t _tag;
  uint16_t off = tlv_read_tag(buf, &_tag);

  if (tag != _tag) {
    *len = TLV_INVALID;
    return TLV_INVALID;
  }

  off += tlv_read_length(&buf[off], len);
  
  if (max_len < *len) {
    return TLV_INVALID;
  }

  memcpy(out, &buf[off], *len);    
  off += *len;

  return off;
}

uint16_t tlv_write_tag(uint8_t *buf, uint16_t in_tag) {
  int max_shift = (sizeof(uint16_t) - 1) * 8;
  uint16_t i = 0;

  while((in_tag >> max_shift) == 0x00) {
    max_shift -= 8;
  }

  while(max_shift >= 0) {
    buf[i++] = ((in_tag >> max_shift) & 0xff);
    max_shift -= 8;
  }

  return i;
}

uint16_t tlv_write_length(uint8_t *buf, uint16_t in_len) {
  uint16_t i = 0;

  if (in_len <= 0x7f) {
    buf[i++] = in_len;
  } else if (in_len <= 0xff) {
    buf[i++] = 0x81;
    buf[i++] = in_len;
  } else {
    buf[i++] = 0x82;
    buf[i++] = in_len >> 8;
    buf[i++] = in_len & 0xff;
  }

  return i;
}

uint16_t tlv_write_undefined_length(uint8_t *buf) {
  buf[0] = 0x80;
  
  return 1;
}

uint16_t tlv_write_undefined_length_terminator(uint8_t *buf) {
  buf[0] = 0x00;
  buf[1] = 0x00;

  return 2;
}
