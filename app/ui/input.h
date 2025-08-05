#ifndef _UI_INPUT_
#define _UI_INPUT_

#include <stdint.h>
#include "error.h"

#define SECRET_NEW_CODE -1

typedef enum {
  UI_READ_STRING_UNDISMISSABLE = 1,
  UI_READ_STRING_ALLOW_EMPTY = 2,
} ui_read_string_opt_t;

typedef enum {
  UI_SECRET_PIN = 0,
  UI_SECRET_PUK = 1,
  UI_SECRET_DURESS = 2,
} ui_secret_type_t;

app_err_t input_secret();
app_err_t input_mnemonic();
app_err_t input_display_mnemonic();
app_err_t input_string();
app_err_t input_number();

#endif
