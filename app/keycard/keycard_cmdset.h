#ifndef __KEYCARD_CMDSET_H
#define __KEYCARD_CMDSET_H

#include "keycard.h"
#include "error.h"

typedef enum {
  KEYCARD_PIN = 0,
  KEYCARD_PUK,
  KEYCARD_PAIRING
} keycard_credentials_t;

app_err_t keycard_cmd_select(keycard_t* kc, const uint8_t* aid, uint32_t len);
app_err_t keycard_cmd_pair(keycard_t* kc, uint8_t step, uint8_t* data);
app_err_t keycard_cmd_autopair(keycard_t* kc, const uint8_t* psk, pairing_t* pairing);
app_err_t keycard_cmd_unpair(keycard_t* kc, uint8_t idx);
app_err_t keycard_cmd_verify_pin(keycard_t* kc, uint8_t* pin);
app_err_t keycard_cmd_change_credential(keycard_t* kc, keycard_credentials_t type, uint8_t* credentials, uint8_t len);
app_err_t keycard_cmd_unblock_pin(keycard_t* kc, uint8_t* pin, uint8_t* puk);
app_err_t keycard_cmd_get_status(keycard_t* kc);
app_err_t keycard_cmd_init(keycard_t* kc, uint8_t* sc_pub, uint8_t* pin, uint8_t* puk, uint8_t* psk, uint8_t pin_retries, uint8_t puk_retries, uint8_t* duress_pin);
app_err_t keycard_cmd_generate_mnemonic(keycard_t* kc, uint8_t len);
app_err_t keycard_cmd_load_seed(keycard_t* kc, uint8_t* seed);
app_err_t keycard_cmd_export_key(keycard_t* kc, uint8_t export_type, uint8_t* path, uint8_t len);
app_err_t keycard_cmd_sign(keycard_t* kc, uint8_t* path, uint8_t path_len, uint8_t* hash);
app_err_t keycard_cmd_factory_reset(keycard_t* kc);
app_err_t keycard_cmd_get_data(keycard_t* kc);
app_err_t keycard_cmd_set_data(keycard_t* kc, uint8_t* data, int8_t len);
app_err_t keycard_cmd_identify(keycard_t* kc, const uint8_t challenge[SHA256_DIGEST_LENGTH]);

#endif
