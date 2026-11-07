#ifndef __CORE_KOHAKU_KEY_H__
#define __CORE_KOHAKU_KEY_H__

#include <stdbool.h>

#include "error.h"
#include "keycard/keycard.h"

app_err_t core_kohaku_key_run_privacy_pools_v1(keycard_t* kc, bool ready);

#endif
