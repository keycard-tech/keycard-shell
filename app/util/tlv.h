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

#ifndef TLV_H
#define	TLV_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* A cursor over a response from the secure element, [p, end). Every read is checked against end and
 * advances p only on success, so a malformed response stops the parse instead of moving the parse
 * past the buffer. */
typedef struct {
  const uint8_t* p;
  const uint8_t* end;
} tlv_t;

void tlv_open(tlv_t* tlv, const uint8_t* buf, size_t len);

/* The next object's tag, or false if the buffer ends or the tag needs more than two octets. */
bool tlv_read_tag(tlv_t* tlv, uint16_t* out_tag);

/* The next object's tag, which has to be tag. */
bool tlv_expect_tag(tlv_t* tlv, uint16_t tag);

/* The next object's length, or false if the buffer ends, the length is indefinite, or it needs more
 * than two octets. Non-minimal encodings are accepted. */
bool tlv_read_length(tlv_t* tlv, uint16_t* out_len);

/* A constructed object with the given tag, as a cursor over its contents. */
bool tlv_enter(tlv_t* tlv, uint16_t tag, tlv_t* out);

/* A primitive object with the given tag, borrowed rather than copied. The caller that writes into
 * what it borrowed is patching the response buffer itself. */
bool tlv_read_value(tlv_t* tlv, uint16_t tag, const uint8_t** out, uint16_t* out_len);

/* A primitive object with the given tag, copied to out, which holds max_len bytes. */
bool tlv_read_primitive(tlv_t* tlv, uint16_t tag, uint16_t max_len, uint8_t* out, uint16_t* out_len);

/* A primitive object with the given tag and exactly len bytes, copied to out. */
bool tlv_read_fixed(tlv_t* tlv, uint16_t tag, uint16_t len, uint8_t* out);

#endif	/* TLV_H */
