#ifndef _UI_DIALOG_
#define _UI_DIALOG_

#include <stdint.h>
#include "error.h"
#include "screen/screen.h"
#include "font/font.h"
#include "icons.h"
#include "theme.h"

typedef enum {
  UI_INFO_UNDISMISSABLE = 1,
  UI_INFO_NEXT = 2,
  UI_INFO_CANCELLABLE = 4,
  UI_INFO_DANGEROUS = 8,
} ui_info_opt_t;

app_err_t dialog_begin_line(screen_text_ctx_t* ctx, uint16_t line_height);
app_err_t dialog_end_line(screen_text_ctx_t* ctx);

app_err_t dialog_inverted_string(screen_text_ctx_t* ctx, const char* str, uint16_t padding);

app_err_t dialog_title_colors(const char* title, uint16_t bg, uint16_t fg);
app_err_t dialog_footer_colors(uint16_t yOff, uint16_t bg);
app_err_t dialog_nav_hints_colors(icon_t left, icon_t right, uint16_t bg, uint16_t fg);
app_err_t dialog_pager_colors(size_t page, size_t last_page, size_t base_page, uint16_t bg, uint16_t fg);
app_err_t dialog_margin(uint16_t yOff, uint16_t height);

app_err_t dialog_confirm_eth_tx();
app_err_t dialog_confirm_btc_tx();
app_err_t dialog_confirm_msg();
app_err_t dialog_confirm_eip712();

app_err_t dialog_info();
app_err_t dialog_prompt();

static inline app_err_t dialog_title(const char* title) {
  return dialog_title_colors(title, TH_COLOR_TITLE_BG, TH_COLOR_TITLE_FG);
}

static inline app_err_t dialog_footer(uint16_t yOff) {
  return dialog_footer_colors(yOff, TH_COLOR_BG);
}

static inline app_err_t dialog_nav_hints(icon_t left, icon_t right) {
  return dialog_nav_hints_colors(left, right, TH_COLOR_BG, TH_COLOR_FG);
}

static inline app_err_t dialog_pager(size_t page, size_t last_page) {
  return dialog_pager_colors(page, last_page, 1, TH_COLOR_BG, TH_COLOR_FG);
}

#endif
