#ifndef __CORE_PRIVACY_POOLS_V1_H__
#define __CORE_PRIVACY_POOLS_V1_H__

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "keycard/keycard.h"

/* Derive a V3-compatible credential using an authenticated Keycard.
 * The caller must erase out after use.
 * path must not alias the Keycard APDU buffer.
 */
app_err_t core_privacy_pools_v1_derive_at(
    keycard_t* kc,
    const char* path,
    size_t path_len,
    uint8_t out[32]);

#endif
