#include "amount.h"
#include "i18n.h"
#include <string.h>

static void append_label(char* out, const char* label, const char* ticker) {
  size_t len = strlen(label);
  memcpy(out, label, len);

  if (!*ticker) {
    out[len] = '\0';
    return;
  }

  out[len++] = ' ';

  size_t keep = strlen(ticker);
  if (keep > UI_AMOUNT_FIELD_LEN - len) {
    keep = UI_AMOUNT_FIELD_LEN - len;
  }

  memcpy(out + len, ticker, keep);
  out[len + keep] = '\0';
}

void ui_amount_format(const bignum256* value, const char* ticker, unsigned int decimals, char* out) {
  const size_t whole_len = bn_format(value, NULL, NULL, 0, -(int)decimals, false, ',', out, UI_AMOUNT_FIELD_LEN + 1);
  const size_t ticker_len = strlen(ticker);

  if (!whole_len || whole_len + 1 + ticker_len > UI_AMOUNT_FIELD_LEN) {
    append_label(out, LSTR(TX_UNLIMITED), ticker);
    return;
  }

  int fraction = UI_AMOUNT_FIELD_LEN - whole_len - ticker_len - 2;
  if (fraction < 0) {
    fraction = 0;
  } else if (fraction > (int)decimals) {
    fraction = decimals;
  }

  if (!bn_format(value, NULL, ticker, fraction, -(int)(decimals - fraction), false, ',', out, UI_AMOUNT_FIELD_LEN + 1)) {
    append_label(out, LSTR(TX_UNLIMITED), ticker);
    return;
  }

  if (whole_len == 1 && out[0] == '0' && out[1] != '.' && !bn_is_zero(value)) {
    append_label(out, LSTR(TX_TOOLITTLE), ticker);
  }
}
