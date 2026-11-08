#ifndef CORE_KOHAKU_KEY_BATCH_H
#define CORE_KOHAKU_KEY_BATCH_H

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "keycard/keycard.h"

app_err_t core_kohaku_key_run_batch(
    keycard_t* kc, const uint8_t* request, size_t request_len);

#endif
