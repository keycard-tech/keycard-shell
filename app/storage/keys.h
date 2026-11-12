#ifndef __KEYS__
#define __KEYS__

#include <stdint.h>
#include "error.h"

typedef enum {
  DEV_AUTH_PRIV_KEY,
  FW_VERIFICATION_KEY,
  DB_VERIFICATION_KEY,
  KEYCARD_CA_KEY,
  PAIRING_ENC_PRIV_KEY
} key_type_t;

app_err_t key_read_private(key_type_t type, uint8_t* out);
app_err_t key_read_public(key_type_t type, const uint8_t** out);

#endif
