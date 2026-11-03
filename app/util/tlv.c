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

void tlv_open(tlv_t* tlv, const uint8_t* buf, size_t len) {
  tlv->p = buf;
  tlv->end = buf + len;
}

static bool tlv_has(const tlv_t* tlv, uint16_t count) {
  return (uint16_t)(tlv->end - tlv->p) >= count;
}

bool tlv_read_tag(tlv_t* tlv, uint16_t* out_tag) {
  if (!tlv_has(tlv, 1)) {
    return false;
  }

  const uint8_t first = tlv->p[0];
  if ((first & 0x1F) != 0x1F) {
    *out_tag = first;
    tlv->p++;
    return true;
  }

  if (!tlv_has(tlv, 2) || (tlv->p[1] & 0x80)) {
    /* More than two tag octets: unsupported as not used by Keycard. */
    return false;
  }

  *out_tag = ((uint16_t)first << 8) | tlv->p[1];
  tlv->p += 2;
  return true;
}

bool tlv_expect_tag(tlv_t* tlv, uint16_t tag) {
  uint16_t read;
  return tlv_read_tag(tlv, &read) && (read == tag);
}

bool tlv_read_length(tlv_t* tlv, uint16_t* out_len) {
  if (!tlv_has(tlv, 1)) {
    return false;
  }

  const uint8_t first = tlv->p[0];
  if (first < 0x80) {
    *out_len = first;
    tlv->p++;
    return true;
  }

  if (first == 0x80) {
    /* Indefinite length: unsupported as not used by Keycard. */
    return false;
  }

  const uint16_t octets = first & 0x7F;
  if (octets > 2) {
    /* Lengths of more than 65535: unsupported as not used by Keycard. */
    return false;
  }

  if (!tlv_has(tlv, 1 + octets)) {
    return false;
  }

  uint16_t len = 0;
  for (uint16_t i = 0; i < octets; i++) {
    len = (len << 8) | tlv->p[1 + i];
  }

  *out_len = len;
  tlv->p += 1 + octets;
  return true;
}

bool tlv_enter(tlv_t* tlv, uint16_t tag, tlv_t* out) {
  const uint8_t* const start = tlv->p;
  uint16_t len;
  if (!tlv_expect_tag(tlv, tag) || !tlv_read_length(tlv, &len) || !tlv_has(tlv, len)) {
    tlv->p = start;
    return false;
  }

  out->p = tlv->p;
  out->end = tlv->p + len;
  tlv->p += len;
  return true;
}

bool tlv_read_value(tlv_t* tlv, uint16_t tag, const uint8_t** out, uint16_t* out_len) {
  const uint8_t* const start = tlv->p;
  uint16_t len;
  if (!tlv_expect_tag(tlv, tag) || !tlv_read_length(tlv, &len) || !tlv_has(tlv, len)) {
    tlv->p = start;
    return false;
  }

  *out = tlv->p;
  *out_len = len;
  tlv->p += len;
  return true;
}

bool tlv_read_primitive(tlv_t* tlv, uint16_t tag, uint16_t max_len, uint8_t* out, uint16_t* out_len) {
  const uint8_t* const start = tlv->p;
  const uint8_t* value;
  uint16_t len;
  if (!tlv_read_value(tlv, tag, &value, &len)) {
    return false;
  }
  if (len > max_len) {
    tlv->p = start;
    return false;
  }

  memcpy(out, value, len);
  *out_len = len;
  return true;
}

bool tlv_read_fixed(tlv_t* tlv, uint16_t tag, uint16_t len, uint8_t* out) {
  const uint8_t* const start = tlv->p;
  const uint8_t* value;
  uint16_t read;
  if (!tlv_read_value(tlv, tag, &value, &read)) {
    return false;
  }
  if (read != len) {
    tlv->p = start;
    return false;
  }

  memcpy(out, value, len);
  return true;
}
