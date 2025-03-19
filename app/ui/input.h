#ifndef _UI_INPUT_
#define _UI_INPUT_

#include <stdint.h>
#include "error.h"

typedef enum {
  UI_READ_STRING_UNDISMISSABLE = 1,
  UI_READ_STRING_ALLOW_EMPTY = 2,
} ui_read_string_opt_t;

app_err_t input_pin();
app_err_t input_puk();
app_err_t input_mnemonic();
app_err_t input_display_mnemonic();
app_err_t input_string();

#endif
