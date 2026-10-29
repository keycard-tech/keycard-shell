#include <ctype.h>
#include <string.h>

#include "addr_uri.h"

#define REQ_PREFIX "req-"
#define PAY_PREFIX "pay-"

static const char BITCOIN_SCHEME[] = "bitcoin";
static const char ETHEREUM_SCHEME[] = "ethereum";
static const char INDEX_KEY[] = "index";

/* Query keys that name a destination other than the address in the path. */
static const char* const OTHER_DESTINATION_KEYS[] = {
  "lightning", "lno", "sp", "pay", "bc", "tb", "pop"
};

static bool _prefix_eq(const char* name, size_t len, const char* prefix) {
  size_t prefix_len = strlen(prefix);

  if (len < prefix_len) {
    return false;
  }

  for (size_t i = 0; i < prefix_len; i++) {
    if (tolower((unsigned char)name[i]) != prefix[i]) {
      return false;
    }
  }

  return true;
}

static bool _name_eq(const char* name, size_t len, const char* expected) {
  return (len == strlen(expected)) && _prefix_eq(name, len, expected);
}

static bool _is_delimiter(char c) {
  return (c == ':') || (c == '?') || (c == '/') || (c == '#') || (c == '@');
}

static size_t _scan(const char* s, size_t len) {
  size_t off = 0;

  while ((off < len) && !_is_delimiter(s[off])) {
    off++;
  }

  return off;
}

static bool _parse_scheme(const char* name, size_t len, addr_uri_t* out) {
  if (_name_eq(name, len, BITCOIN_SCHEME)) {
    out->scheme = ADDR_URI_BITCOIN;
  } else if (_name_eq(name, len, ETHEREUM_SCHEME)) {
    out->scheme = ADDR_URI_ETHEREUM;
  } else {
    return false;
  }

  return true;
}

static bool _parse_index(const char* value, size_t len, uint32_t* index) {
  uint32_t parsed = 0;

  if (len == 0) {
    return false;
  }

  while (len--) {
    if (!isdigit((unsigned char)*value)) {
      return false;
    }

    uint32_t digit = *value++ - '0';

    if (parsed > ((UINT32_MAX - digit) / 10)) {
      return false;
    }

    parsed = parsed * 10 + digit;
  }

  if (parsed == ADDR_URI_INDEX_NONE) {
    return false;
  }

  *index = parsed;
  return true;
}

static bool _parse_query(const char* query, size_t len, uint32_t* index) {
  while (len > 0) {
    const char* sep = memchr(query, '&', len);
    size_t item_len = sep ? (size_t)(sep - query) : len;

    if (item_len > 0) {
      const char* eq = memchr(query, '=', item_len);
      size_t key_len = eq ? (size_t)(eq - query) : item_len;

      if (_prefix_eq(query, item_len, REQ_PREFIX)) {
        return false;
      }

      for (size_t i = 0; i < sizeof(OTHER_DESTINATION_KEYS) / sizeof(*OTHER_DESTINATION_KEYS); i++) {
        if (_name_eq(query, key_len, OTHER_DESTINATION_KEYS[i])) {
          return false;
        }
      }

      if ((eq != NULL) && _name_eq(query, key_len, INDEX_KEY) &&
          !_parse_index(eq + 1, item_len - key_len - 1, index)) {
        return false;
      }
    }

    if (sep == NULL) {
      break;
    }

    query = sep + 1;
    len -= item_len + 1;
  }

  return true;
}

bool address_uri_parse(const char* in, size_t in_len, addr_uri_t* out) {
  const char* body = in;
  size_t len = in_len;
  size_t head;

  out->scheme = ADDR_URI_NONE;
  out->index = ADDR_URI_INDEX_NONE;

  while ((len > 0) && isspace((unsigned char)body[0])) {
    body++;
    len--;
  }

  while ((len > 0) && isspace((unsigned char)body[len - 1])) {
    len--;
  }

  head = _scan(body, len);

  if ((head < len) && (body[head] == ':')) {
    if (!_parse_scheme(body, head, out)) {
      return false;
    }

    body += head + 1;
    len -= head + 1;

    if ((out->scheme == ADDR_URI_ETHEREUM) && (len >= strlen(PAY_PREFIX)) &&
        !strncmp(body, PAY_PREFIX, strlen(PAY_PREFIX))) {
      body += strlen(PAY_PREFIX);
      len -= strlen(PAY_PREFIX);
    }

    head = _scan(body, len);
  }

  if ((head == 0) || (head >= MAX_ADDR_LEN)) {
    return false;
  }

  memcpy(out->address, body, head);
  out->address[head] = '\0';

  body += head;
  len -= head;

  if (len == 0) {
    return true;
  }

  char delimiter = *body;

  body++;
  len--;

  /* a fragment never carries payment data, a path is an ERC-681 function call */
  if ((delimiter == '#') || (delimiter == '/')) {
    return false;
  }

  if (delimiter == '@') {
    while ((len > 0) && (*body != '?')) {
      if (!isdigit((unsigned char)*body)) {
        return false;
      }

      body++;
      len--;
    }

    if (len == 0) {
      return true;
    }

    body++;
    len--;
  }

  return _parse_query(body, len, &out->index);
}
