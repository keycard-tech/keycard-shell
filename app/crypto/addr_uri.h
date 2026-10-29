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
 * Split a scanned or typed address string: surrounding whitespace, an optional
 * case-insensitive 'bitcoin:' (BIP21/BIP321) or 'ethereum:'/'ethereum:pay-'
 * (ERC-681) scheme, the address itself and an optional query.
 *
 * A URI is accepted only when it cannot redirect the payment away from the
 * address: required-but-unsupported parameters ('req-', BIP321) and query keys
 * naming another destination (lightning, lno, sp, pay, bc, tb, pop) are
 * rejected, as are fragments, a '/function' path (the ERC-681 address is then
 * the token contract) and ENS names. 'amount', 'label', 'message', the ERC-681
 * chain id and unknown non-required keys carry no destination and are ignored.
 *
 * @param in NUL-terminated not required; only in_len bytes are read
 * @return false if the string is not an address we are willing to act on
 */
bool address_uri_parse(const char* in, size_t in_len, addr_uri_t* out);

#endif
