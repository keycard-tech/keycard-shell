#ifndef __PRIVACY_POOLS_V1_H__
#define __PRIVACY_POOLS_V1_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "error.h"

/* Root and output must be distinct buffers.
 * The caller owns and must erase both secret buffers.
 */
bool privacy_pools_v1_valid_path(const char* path, size_t len);

app_err_t privacy_pools_v1_derive_at(
    const uint8_t root[32],
    const char *path,
    size_t path_len,
    uint8_t out[32]);

#endif
