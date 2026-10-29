/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include "rand.h"
#include "common.h"

uint32_t random32(void) {
  uint32_t val;
  random_buffer((uint8_t*)&val, 4);

  return val;
}

// Result in range [0-n)
uint32_t random_uniform(uint32_t n) {
  uint32_t x = 0, max = 0xFFFFFFFF - (0xFFFFFFFF % n);
  while ((x = random32()) >= max)
    ;
  return APP_MIN(x / (max / n), n - 1);
}

void random_unique_in_range(uint8_t max, uint8_t count, uint8_t* out) {
  assert(max <= 32);
  assert(count <= max);

  uint32_t selected = 0;
  while(__builtin_popcount(selected) < count) {
    selected |= (1 << random_uniform(max));
  }

  uint8_t out_count = 0;
  uint8_t val = 0;
  while(out_count < count) {
    if (selected & 0x1) {
      out[out_count++] = val;
    }

    selected >>= 1;
    val++;
  }
}

void random_permute(char *str, size_t len) {
  for (int i = len - 1; i >= 1; i--) {
    int j = random_uniform(i + 1);
    char t = str[j];
    str[j] = str[i];
    str[i] = t;
  }
}
