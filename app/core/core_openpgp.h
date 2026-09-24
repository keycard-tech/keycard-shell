#ifndef CORE_OPENPGP_H
#define CORE_OPENPGP_H

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "openpgp/openpgp_v4.h"

app_err_t core_openpgp_prepare_primary_key(
    uint8_t *path,
    uint16_t path_len,
    uint32_t creation_time,
    uint8_t *primary_key_body,
    size_t primary_key_body_capacity,
    size_t *primary_key_body_len,
    uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN]);

#endif
