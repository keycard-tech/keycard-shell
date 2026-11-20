#include "amount.h"
#include "i18n.h"
#include <stdbool.h>
#include <string.h>

#define DATA_FIELD_MAX_LEN 23

void ui_amount_adapt(char* amount, size_t amount_len, const char* ticker, size_t ticker_len) {
  if (amount_len <= DATA_FIELD_MAX_LEN) {
    return;
  }

  int i = 0;
  int ticker_off = (DATA_FIELD_MAX_LEN - ticker_len - 1);
  bool all_zero = true;

  while(amount[i] != '.') {
    if (amount[i] != '0') {
      all_zero = false;
    }

    if (i >= ticker_off) {
      const char* label = LSTR(TX_UNLIMITED);
      ticker_off = strlen(label);
      memcpy(amount, label, ticker_off);
      goto add_ticker;
    }

    i++;
  }

  while(i < ticker_off) {
    if (amount[i] >= '1' && amount[i] <= '9') {
      all_zero = false;
    }

    i++;
  }

  if (all_zero) {
    const char* label = LSTR(TX_TOOLITTLE);
    ticker_off = strlen(label);
    memcpy(amount, label, ticker_off);
    goto add_ticker;
  }

  if (amount[ticker_off - 1] == '.') {
    ticker_off--;
  }

add_ticker:
  amount[ticker_off++] = ' ';
  memcpy(&amount[ticker_off], ticker, ticker_len + 1);
}
