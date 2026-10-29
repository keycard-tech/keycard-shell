#include "util.h"
#include "common.h"

const char* const HEX_DIGITS = "0123456789abcdef";

uint32_t pad_iso9797_m1(uint8_t* data, uint8_t plen, uint32_t size) {
  uint32_t padding = plen - (size % plen);
  data[size] = 0x80;
  memset(&data[size+1], 0, (padding - 1));
  return padding + size;
}

uint32_t unpad_iso9797_m1(uint8_t* data, uint32_t size) {
  while((size > 0) && data[--size] != 0x80) {}
  return size;
}

uint8_t* u32toa(uint32_t value, uint8_t* buf, uint32_t len) {
  uint8_t *p = &buf[len - 1];
  *p-- = '\0';

  do {
    *p-- = (value % 10) + '0';
    value /= 10;
  } while (value > 0);

  return (p + 1);
}

uint8_t* u64toa(uint64_t value, uint8_t* buf, uint32_t len) {
  uint8_t *p = &buf[len - 1];
  *p-- = '\0';

  do {
    *p-- = (value % 10) + '0';
    value /= 10;
  } while (value > 0);

  return (p + 1);
}

// if the used C library has it, prefer its version instead
APP_WEAK size_t strnlen(const char *s, size_t maxlen) {
  size_t res;

  for (res = 0; res < maxlen; res++) {
    if (s[res] == '\0') {
      break;
    }
  }

  return res;
}

static inline uint8_t base16_hexlet_decode(char c) {
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  } else if ((c >= 'a') && (c <= 'f')) {
    return 10 + (c - 'a');
  } else if ((c >= 'A') && (c <= 'F')) {
    return 10 + (c - 'A');
  }

  return 0xff;
}

bool base16_decode(const char* s, uint8_t* out, size_t hex_len) {
  if (hex_len & 1) {
    out[0] = base16_hexlet_decode(s[0]);

    if (out[0] == 0xff) {
      return false;
    }

    return base16_decode(&s[1], &out[1], hex_len - 1);
  }

  const char *s_end = &s[hex_len];

  while(s < s_end) {
    uint8_t nh = base16_hexlet_decode(*(s++));
    uint8_t nl = base16_hexlet_decode(*(s++));
    if (nl == 0xff || nh == 0xff) {
      return false;
    } else {
      *(out++) = (nh << 4) | nl;
    }
  }

  return true;
}

void base16_encode(const uint8_t* data, char* out, size_t len) {
  for (int i = 0; i < len; i++) {
    *(out++) = HEX_DIGITS[(data[i] >> 4) & 0xf];
    *(out++) = HEX_DIGITS[data[i] & 0xf];
  }

  *out = '\0';
}

bool atoi256BE(const char* str, size_t len, uint8_t out[32]) {
  int i;
  bool neg;

  if (str[0] == '-') {
    neg = true;
    i = 1;
  } else if (str[0] == '+') {
    neg = false;
    i = 1;
  } else {
    neg = false;
    i = 0;
  }

  uint32_t limbs[9];
  memset(limbs, 0, sizeof(uint32_t) * 9);

  while(i < len) {
    if (!(str[i] >= '0' && str[i] <= '9')) {
      return false;
    }

    int d = (str[i++] - '0');

    for (int j = 0; j < 9; j++) {
      limbs[j] *= 10;
    }

    limbs[0] += d;

    for (int j = 0; j < 8; j++) {
      limbs[j + 1] += limbs[j] >> 28;
      limbs[j] &= 0x0fffffff;
    }
  }

  if (neg) {
    for (int i = 0; i < 9; i++) {
      limbs[i] = ~limbs[i] & 0x0fffffff;
    }

    limbs[0] += 1;

    for (int i = 0; i < 8; i++) {
      limbs[i + 1] += limbs[i] >> 28;
      limbs[i] &= 0x0fffffff;
    }
  }

  uint32_t* out32 = (uint32_t*) out;

  out32[7] = rev32(((limbs[1] & 0xf) << 28) | limbs[0]);
  out32[6] = rev32(((limbs[2] & 0xff) << 24) | (limbs[1] >> 4));
  out32[5] = rev32(((limbs[3] & 0xfff) << 20) | (limbs[2] >> 8));
  out32[4] = rev32(((limbs[4] & 0xffff) << 16) | (limbs[3] >> 12));
  out32[3] = rev32(((limbs[5] & 0xfffff) << 12) | (limbs[4] >> 16));
  out32[2] = rev32(((limbs[6] & 0xffffff) << 8) | (limbs[5] >> 20));
  out32[1] = rev32(((limbs[7] & 0xfffffff) << 4) | (limbs[6] >> 24));
  out32[0] = rev32((limbs[8] & 0xffffffff) | (limbs[7] >> 28));

  return true;
}
