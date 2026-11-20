#ifndef UI_AMOUNT_H
#define UI_AMOUNT_H

#include <stddef.h>

#define BIGNUM_STRING_LEN 100

/* Database tickers are bounded so the amount buffers can be fixed size. Longer than this and bn_format
 * refuses the whole string rather than overflowing. */
#define TICKER_MAX_LEN 16

/* Callers must reserve BIGNUM_STRING_LEN + TICKER_MAX_LEN + 2 bytes.
 * TODO: Verify the maximum formatted value, localized label, and ticker
 * lengths at build time so this bound can be reduced. */
void ui_amount_adapt(char* amount, size_t amount_len, const char* ticker, size_t ticker_len);

#endif
