#ifndef UI_AMOUNT_H
#define UI_AMOUNT_H

#include <stddef.h>

#define BIGNUM_STRING_LEN 100

/* Callers must reserve BIGNUM_STRING_LEN + ticker_len + 2 bytes.
 * TODO: Verify the maximum formatted value, localized label, and ticker
 * lengths at build time so this bound can be reduced. */
void ui_amount_adapt(char* amount, size_t amount_len, const char* ticker, size_t ticker_len);

#endif
