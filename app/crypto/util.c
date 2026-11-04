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

bool decimal_to_256(const char* digits, size_t len, uint8_t out[32]) {
  uint32_t limbs[8];
  memset(limbs, 0, sizeof(limbs));

  for (size_t i = 0; i < len; i++) {
    if ((digits[i] < '0') || (digits[i] > '9')) {
      return false;
    }

    uint64_t carry = digits[i] - '0';

    for (int j = 7; j >= 0; j--) {
      uint64_t acc = ((uint64_t) limbs[j] << 3) + ((uint64_t) limbs[j] << 1) + carry;
      limbs[j] = (uint32_t) acc;
      carry = acc >> 32;
    }

    if (carry != 0) {
      return false;
    }
  }

  for (int j = 0; j < 8; j++) {
    out[j * 4] = limbs[j] >> 24;
    out[j * 4 + 1] = (limbs[j] >> 16) & 0xff;
    out[j * 4 + 2] = (limbs[j] >> 8) & 0xff;
    out[j * 4 + 3] = limbs[j] & 0xff;
  }

  return true;
}

static bool hex_to_256(const char* digits, size_t len, uint8_t mag[32]) {
  if ((len == 0) || (len > 64)) {
    return false;
  }

  memset(mag, 0, 32);

  return base16_decode(digits, &mag[32 - ((len + 1) / 2)], len);
}

static bool is_ws(char c) {
  return ((c == ' ') || (c == '\t') || (c == '\n') || ((c >= '\v') && (c <= '\r')));
}

int compare_256(const uint8_t a[32], const uint8_t b[32]) {
  for (unsigned i = 0; i < 32; i++) {
    if (a[i] != b[i]) {
      return (a[i] < b[i]) ? -1 : 1;
    }
  }

  return 0;
}

bool str_to_int256(const char* str, size_t len, uint8_t mag[32], bool* negative) {
  size_t start = 0;

  while ((start < len) && is_ws(str[start])) {
    start++;
  }

  while ((len > start) && is_ws(str[len - 1])) {
    len--;
  }

  bool neg = false;

  if ((start < len) && ((str[start] == '-') || (str[start] == '+'))) {
    neg = (str[start] == '-');

    if (++start == len) {
      return false;
    }
  }

  if (start == len) {
    memset(mag, 0, 32);
    *negative = false;
    return true;
  }

  *negative = neg;

  if (((len - start) >= 2) && (str[start] == '0') && ((str[start + 1] == 'x') || (str[start + 1] == 'X'))) {
    if (neg) {
      return false;
    }

    return hex_to_256(&str[start + 2], len - start - 2, mag);
  }

  return decimal_to_256(&str[start], len - start, mag);
}

void negate_256(uint8_t v[32]) {
  uint16_t carry = 1;

  for (int i = 31; i >= 0; i--) {
    v[i] = (uint8_t) (~v[i]);
    carry += v[i];
    v[i] = (uint8_t) carry;
    carry >>= 8;
  }
}

size_t significant_256(const uint8_t v[32]) {
  size_t i = 0;

  while ((i < 32) && (v[i] == 0)) {
    i++;
  }

  return 32 - i;
}
