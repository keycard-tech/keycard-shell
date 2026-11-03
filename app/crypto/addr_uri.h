#ifndef __ADDR_URI_H__
#define __ADDR_URI_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "address.h"

#define ADDR_URI_INDEX_NONE UINT32_MAX

typedef enum {
  ADDR_URI_NONE,
  ADDR_URI_BITCOIN,
  ADDR_URI_ETHEREUM
} addr_uri_scheme_t;

typedef struct {
  char address[MAX_ADDR_LEN];
  addr_uri_scheme_t scheme;
  uint32_t index;
} addr_uri_t;

/**
 * Split a scanned or typed address URI: surrounding whitespace, an optional
 * case-insensitive 'bitcoin:'/'ethereum:' scheme (ERC-681's 'pay-' target prefix
 * included), the target, and an optional query.
 *
 * Accepted only when the URI cannot point somewhere other than that target, so a
 * required-but-unsupported parameter or a key naming a second destination refuses the
 * whole string. Whether the target is an address is the caller's judgement.
 *
 * @param in NUL-terminated not required; only in_len bytes are read
 * @return false if the string is not something to act on, in which case the output
 *         holds whatever the parse reached: the verdict is all a caller may use
 */
bool address_uri_parse(const char* in, size_t in_len, addr_uri_t* out);

#endif
