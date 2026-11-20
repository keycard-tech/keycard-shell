#ifndef UI_AMOUNT_H
#define UI_AMOUNT_H

#include <stddef.h>

#include "crypto/bignum.h"

/* A dialog_data value field: SCREEN_WIDTH - TH_TEXT_HORIZONTAL_MARGIN measured from TH_LABEL_WIDTH at
 * shell_16px's mean advance. */
#define UI_AMOUNT_FIELD_LEN 23

#define TICKER_MAX_LEN 16

/* out must hold UI_AMOUNT_FIELD_LEN + 1 bytes. */
void ui_amount_format(const bignum256* value, const char* ticker, unsigned int decimals, char* out);

#endif
