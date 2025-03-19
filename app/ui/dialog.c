#include "dialog.h"
#include "crypto/address.h"
#include "crypto/bignum.h"
#include "crypto/segwit_addr.h"
#include "crypto/script.h"
#include "crypto/util.h"
#include "ethereum/eth_data.h"
#include "ethereum/eth_db.h"
#include "ethereum/ethUstream.h"
#include "ethereum/ethUtils.h"
#include "mem.h"
#include "theme.h"
#include "ui/ui_internal.h"

#define TX_CONFIRM_TIMEOUT 30000
#define BIGNUM_STRING_LEN 84
#define MAX_PAGE_COUNT 50
#define MESSAGE_MAX_X (SCREEN_WIDTH - TH_TEXT_HORIZONTAL_MARGIN)
#define MESSAGE_MAX_Y (SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT - 16)

#define BTC_DIALOG_PAGE_ITEMS 1

static app_err_t dialog_wait_dismiss(ui_info_opt_t opts) {
  icon_t left = opts & UI_INFO_CANCELLABLE ? ICON_NAV_CANCEL : ICON_NONE;
  icon_t right = opts & UI_INFO_NEXT ? ICON_NAV_NEXT : ICON_NAV_CONFIRM;

  dialog_nav_hints(left, right);

  while(1) {
    switch(ui_wait_keypress(portMAX_DELAY)) {
    case KEYPAD_KEY_CANCEL:
      return opts & UI_INFO_CANCELLABLE ? ERR_CANCEL : ERR_OK;
    case KEYPAD_KEY_BACK:
      if (opts & UI_INFO_CANCELLABLE) {
        return ERR_CANCEL;
      }
      break;
    case KEYPAD_KEY_CONFIRM:
      return ERR_OK;
    default:
      break;
    }
  }
}

static app_err_t dialog_wait_paged(size_t* page, size_t last_page) {
  dialog_nav_hints(ICON_NAV_CANCEL, ICON_NAV_CONFIRM);
  dialog_pager(*page, last_page);

  switch(ui_wait_keypress(pdMS_TO_TICKS(TX_CONFIRM_TIMEOUT))) {
  case KEYPAD_KEY_LEFT:
    if (*page > 0) {
      (*page)--;
    } else {
      *page = last_page;
    }
    return ERR_NEED_MORE_DATA;
  case KEYPAD_KEY_RIGHT:
    if (*page < last_page) {
      (*page)++;
    } else {
      *page = 0;
    }
    return ERR_NEED_MORE_DATA;
  case KEYPAD_KEY_CANCEL:
  case KEYPAD_KEY_BACK:
  case KEYPAD_KEY_INVALID:
    return ERR_CANCEL;
  case KEYPAD_KEY_CONFIRM:
    return ERR_OK;
  default:
    return ERR_NEED_MORE_DATA;
  }
}

app_err_t dialog_begin_line(screen_text_ctx_t* ctx, uint16_t line_height) {
  screen_area_t fillarea = { 0, ctx->y, SCREEN_WIDTH, line_height };
  ctx->v1 = ctx->y;
  ctx->v2 = line_height;
  ctx->y += ((line_height - ctx->font->yAdvance) / 2);

  return screen_fill_area(&fillarea, ctx->bg) == HAL_SUCCESS? ERR_OK : ERR_HW;
}

app_err_t dialog_end_line(screen_text_ctx_t* ctx) {
  ctx->y = ctx->v1 + ctx->v2;
  return ERR_OK;
}

app_err_t dialog_inverted_string(screen_text_ctx_t* ctx, const char* str, uint16_t padding) {
  screen_area_t padarea = {
      ctx->x - padding,
      ctx->y - (padding / 2),
      screen_string_width(ctx, str) + (padding * 2),
      ctx->font->yAdvance + padding
  };

  screen_fill_area(&padarea, ctx->fg);

  uint16_t tmp = ctx->fg;
  ctx->fg = ctx->bg;
  ctx->bg = tmp;
  app_err_t err = screen_draw_string(ctx, str) == HAL_SUCCESS? ERR_OK : ERR_HW;
  ctx->bg = ctx->fg;
  ctx->fg = tmp;
  return err;
}

app_err_t dialog_title_colors(const char* title, uint16_t bg, uint16_t fg) {
  screen_area_t area = { 0, 0, SCREEN_WIDTH, TH_TITLE_HEIGHT };
  screen_fill_area(&area, bg);

  screen_text_ctx_t ctx = { TH_FONT_TITLE, fg, bg, TH_TITLE_LEFT_MARGIN, TH_TITLE_TOP_MARGIN };
  screen_draw_string(&ctx, title);

  ctx.x = TH_TITLE_ICON_LEFT_MARGIN;
  ctx.y = TH_TITLE_ICON_TOP_MARGIN;

  return icon_draw_battery_indicator(&ctx, g_ui_ctx.battery);
}

app_err_t dialog_footer_colors(uint16_t yOff, uint16_t bg) {
  screen_area_t area = { 0, yOff, SCREEN_WIDTH, SCREEN_HEIGHT - yOff };
  return screen_fill_area(&area, bg);
}

app_err_t dialog_nav_hints_colors(icon_t left, icon_t right, uint16_t bg, uint16_t fg) {
  screen_area_t hint_area = {
      .x = 0,
      .y = SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT,
      .width = TH_NAV_HINT_WIDTH,
      .height = TH_NAV_HINT_HEIGHT
  };

  screen_fill_area(&hint_area, bg);

  screen_text_ctx_t ctx = {
      .bg = bg,
      .fg = fg,
      .x = TH_NAV_HINT_LEFT_X,
      .y = TH_NAV_HINT_TOP
  };

  if (left != ICON_NONE) {
    icon_draw(&ctx, left);
  }

  hint_area.x = SCREEN_WIDTH - TH_NAV_HINT_WIDTH;
  screen_fill_area(&hint_area, bg);

  if (right != ICON_NONE) {
    ctx.bg = bg;
    ctx.fg = fg;
    ctx.x = TH_NAV_HINT_RIGHT_X;
    ctx.y = TH_NAV_HINT_TOP,
    icon_draw(&ctx, right);
  }

  return ERR_OK;
}

app_err_t dialog_pager_colors(size_t page, size_t last_page, size_t base_page, uint16_t bg, uint16_t fg) {
  uint8_t page_indicator[(UINT32_STRING_LEN * 2) + 4];
  size_t total_len = 0;
  page_indicator[total_len++] = SYM_LEFT_CHEVRON;
  page_indicator[total_len++] = ' ';

  uint8_t page_str[UINT32_STRING_LEN];
  uint8_t* p = u32toa(page + base_page, page_str, UINT32_STRING_LEN);
  uint8_t p_len = strlen((char *) p);
  memcpy(&page_indicator[total_len], p, p_len);
  total_len += p_len;

  if (last_page != UINT32_MAX) {
    page_indicator[total_len++] = '/';

    p = u32toa(last_page + base_page, page_str, UINT32_STRING_LEN);
    p_len = strlen((char *) p);
    memcpy(&page_indicator[total_len], p, p_len);
    total_len += p_len;
  }

  page_indicator[total_len++] = ' ';
  page_indicator[total_len++] = SYM_RIGHT_CHEVRON;
  page_indicator[total_len] = '\0';

  screen_text_ctx_t ctx = {
      .x = 0,
      .y = TH_NAV_PAGER_TOP,
      .font = TH_FONT_TITLE,
      .bg = bg,
      .fg = fg,
  };

  screen_draw_centered_string(&ctx, (char*) page_indicator);
  return ERR_OK;
}

app_err_t dialog_margin(uint16_t yOff, uint16_t height) {
  screen_area_t area = { 0, yOff, SCREEN_WIDTH, height };
  return screen_fill_area(&area, TH_COLOR_BG);
}

static inline void dialog_label_ctx(screen_text_ctx_t *ctx) {
  ctx->font = TH_FONT_LABEL;
  ctx->fg = TH_COLOR_LABEL_FG;
  ctx->bg = TH_COLOR_LABEL_BG;
  ctx->x = TH_TEXT_HORIZONTAL_MARGIN;
}

static inline void dialog_label(screen_text_ctx_t *ctx, const char* label) {
  dialog_label_ctx(ctx);
  dialog_begin_line(ctx, TH_LABEL_HEIGHT);
  screen_draw_string(ctx, label);
}

static inline void dialog_label_only(screen_text_ctx_t *ctx, const char* label) {
  dialog_label(ctx, label);
  dialog_end_line(ctx);
}

static inline void dialog_data_ctx(screen_text_ctx_t *ctx) {
  ctx->font = TH_FONT_DATA;
  ctx->fg = TH_COLOR_DATA_FG;
  ctx->bg = TH_COLOR_DATA_BG;
  ctx->x = TH_LABEL_WIDTH;
}

static inline void dialog_data(screen_text_ctx_t *ctx, const char* data) {
  dialog_data_ctx(ctx);
  screen_draw_string(ctx, data);
  dialog_end_line(ctx);
}

static void dialog_chain(screen_text_ctx_t *ctx, const char* name) {
  dialog_label(ctx, LSTR(TX_CHAIN));
  dialog_data(ctx, name);
}

static void dialog_address(screen_text_ctx_t *ctx, i18n_str_id_t label, addr_type_t addr_type, const uint8_t* addr) {
  char str[MAX_ADDR_LEN];
  address_format(addr_type, addr, str);

  dialog_label_ctx(ctx);
  dialog_begin_line(ctx, TH_LABEL_HEIGHT * 2);
  ctx->y = ctx->v1;
  screen_draw_string(ctx, LSTR(label));

  dialog_data_ctx(ctx);
  screen_draw_text(ctx, (SCREEN_WIDTH - TH_TEXT_HORIZONTAL_MARGIN), ctx->y +(TH_LABEL_HEIGHT * 2), (uint8_t*) str, strlen(str), false, false);
  dialog_end_line(ctx);
}

static void dialog_address_block(screen_text_ctx_t *ctx, i18n_str_id_t label, addr_type_t addr_type, const uint8_t* addr) {
  char str[MAX_ADDR_LEN];
  address_format(addr_type, addr, str);
  dialog_label_only(ctx, LSTR(label));

  dialog_begin_line(ctx, (TH_DATA_HEIGHT * 2));
  dialog_data_ctx(ctx);
  ctx->y = ctx->v1;
  ctx->x = TH_TEXT_HORIZONTAL_MARGIN;

  screen_draw_text(ctx, (SCREEN_WIDTH - TH_TEXT_HORIZONTAL_MARGIN), ctx->y + (TH_DATA_HEIGHT * 2), (uint8_t*) str, strlen(str), false, false);
  dialog_end_line(ctx);
}

static void dialog_amount(screen_text_ctx_t* ctx, i18n_str_id_t prompt, const bignum256* amount, int decimals, const char* ticker) {
  char tmp[BIGNUM_STRING_LEN+strlen(ticker)+2];
  bn_format(amount, NULL, ticker, decimals, 0, 0, ',', tmp, sizeof(tmp));

  dialog_label(ctx, LSTR(prompt));
  dialog_data(ctx, tmp);
}

static void dialog_btc_amount(screen_text_ctx_t* ctx, i18n_str_id_t prompt, uint64_t amount) {
  //TODO: better formatting, add ticker
  uint8_t tmp[UINT64_STRING_LEN];
  uint8_t* p = u64toa(amount, tmp, UINT64_STRING_LEN);

  dialog_label(ctx, LSTR(prompt));
  dialog_data(ctx, (char*) p);
}

static app_err_t dialog_confirm_eth_transfer(eth_data_type_t data_type) {
  eth_transfer_info tx_info;

  tx_info.data_str = g_camera_fb[0];
  tx_info.data_type = data_type;

  eth_extract_transfer_info(g_ui_cmd.params.eth_tx.tx, &tx_info);

  screen_text_ctx_t ctx;
  size_t pages[MAX_PAGE_COUNT];
  size_t page = 0;
  size_t last_page = 0;

  if (tx_info.data_str_len) {
    last_page = 1;
    pages[1] = 0;
    ctx.font = TH_FONT_TEXT;

    while(1) {
      ctx.x = TH_TEXT_HORIZONTAL_MARGIN;

      if (last_page > 1) {
        ctx.y = TH_TITLE_HEIGHT + TH_TEXT_VERTICAL_MARGIN;
      } else {
        ctx.y = TH_TITLE_HEIGHT + TH_LABEL_HEIGHT;
      }

      size_t offset = pages[last_page];
      size_t to_display = tx_info.data_str_len - offset;
      size_t remaining = screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, &tx_info.data_str[offset], to_display, true, false);

      if (!remaining || last_page == (MAX_PAGE_COUNT - 1)) {
        break;
      }

      pages[++last_page] = offset + (to_display - remaining);
    }
  }

  dialog_title(LSTR(TX_CONFIRM_TRANSFER));

  app_err_t ret = ERR_NEED_MORE_DATA;

  while(ret == ERR_NEED_MORE_DATA) {
    ctx.y = TH_TITLE_HEIGHT;

    if (page == 0) {
      dialog_address(&ctx, TX_SIGNER, ADDR_ETH, g_ui_cmd.params.eth_tx.addr);
      dialog_address(&ctx, TX_ADDRESS, ADDR_ETH, tx_info.to);
      dialog_chain(&ctx, tx_info.chain.name);

      dialog_amount(&ctx, TX_AMOUNT, &tx_info.value, tx_info.token.decimals, tx_info.token.ticker);
      dialog_amount(&ctx, TX_FEE, &tx_info.fees, 18, tx_info.chain.ticker);
      dialog_footer(ctx.y);
    } else {
      size_t offset = pages[page];

      if (page == 1) {
        dialog_label_only(&ctx, LSTR(TX_DATA));
        ctx.font = TH_FONT_TEXT;
        ctx.fg = TH_COLOR_TEXT_FG;
        ctx.bg = TH_COLOR_TEXT_BG;
        ctx.x = TH_TEXT_HORIZONTAL_MARGIN;
        dialog_footer(ctx.y);
      } else {
        ctx.x = TH_TEXT_HORIZONTAL_MARGIN;
        ctx.y = TH_TITLE_HEIGHT + TH_TEXT_VERTICAL_MARGIN;
        dialog_footer(TH_TITLE_HEIGHT);
      }

      screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, &tx_info.data_str[offset], (tx_info.data_str_len - offset), false, false);
    }

    ret = dialog_wait_paged(&page, last_page);
  }

  return ret;
}

static app_err_t dialog_confirm_approval(const eth_approve_info* info, const uint8_t* signer, bool has_fees) {
  screen_text_ctx_t ctx;

  dialog_title(LSTR(TX_CONFIRM_APPROVAL));

  size_t page = 0;
  app_err_t ret = ERR_NEED_MORE_DATA;
  while(ret == ERR_NEED_MORE_DATA) {
    ctx.y = TH_TITLE_HEIGHT;

    if (page == 0) {
      dialog_address(&ctx, TX_SIGNER, ADDR_ETH, signer);
      dialog_address(&ctx, TX_SPENDER, ADDR_ETH, info->spender);
      dialog_chain(&ctx, info->chain.name);
      dialog_amount(&ctx, TX_AMOUNT, &info->value, info->token.decimals, info->token.ticker);

      if (has_fees) {
        dialog_amount(&ctx, TX_FEE, &info->fees, 18, info->chain.ticker);
      }
    } else {
      dialog_address(&ctx, EIP712_CONTRACT, ADDR_ETH, info->token.addr);
    }

    dialog_footer(ctx.y);
    ret = dialog_wait_paged(&page, 1);
  }

  return ret;
}

app_err_t dialog_confirm_eth_tx() {
  eth_data_type_t data_type = eth_data_recognize(g_ui_cmd.params.eth_tx.tx);

  if (data_type == ETH_DATA_ERC20_APPROVE) {
    eth_approve_info info;
    eth_extract_approve_info(g_ui_cmd.params.eth_tx.tx, &info);
    return dialog_confirm_approval(&info, g_ui_cmd.params.eth_tx.addr, true);
  } else {
    return dialog_confirm_eth_transfer(data_type);
  }
}

void dialog_confirm_btc_summary(const btc_tx_ctx_t* tx) {
  screen_text_ctx_t ctx;
  ctx.y = TH_TITLE_HEIGHT;

  uint64_t total_input = 0;
  uint64_t signed_amount = 0;
  uint64_t total_output = 0;

  bool has_sighash_none = false;

  for (int i = 0; i < tx->input_count; i++) {
    uint64_t t;
    memcpy(&t, tx->input_data[i].amount, sizeof(uint64_t));
    total_input += t;
    if (tx->input_data[i].can_sign) {
      signed_amount += t;
    }

    if ((tx->input_data[i].sighash_flag & SIGHASH_MASK) == SIGHASH_NONE) {
      has_sighash_none = true;
    }
  }

  uint64_t change = 0;
  int dest_idx = -1;

  for (int i = 0; i < tx->output_count; i++) {
    uint64_t t;
    memcpy(&t, tx->outputs[i].amount, sizeof(uint64_t));
    total_output += t;
    if (tx->output_is_change[i]) {
      change += t;
    } else {
      if (dest_idx == -1) {
        dest_idx = i;
      } else {
        dest_idx = -2;
      }
    }
  }

  dialog_btc_amount(&ctx, TX_AMOUNT, total_input);

  if (total_input != signed_amount) {
    dialog_btc_amount(&ctx, TX_SIGNED_AMOUNT, signed_amount);
  }

  if (change) {
    dialog_btc_amount(&ctx, TX_CHANGE, change);
  }

  dialog_btc_amount(&ctx, TX_FEE, total_input - total_output);


  if (has_sighash_none) {
    ctx.x = TH_TEXT_HORIZONTAL_MARGIN;
    screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, (const uint8_t*) LSTR(TX_SIGHASH_WARNING), strlen(LSTR(TX_SIGHASH_WARNING)), false, false);
  } else {
    char buf[BIGNUM_STRING_LEN];
    dialog_label(&ctx, LSTR(TX_ADDRESS));

    if (dest_idx >= 0) {
      script_output_to_address(tx->outputs[dest_idx].script, tx->outputs[dest_idx].script_len, buf);
      dialog_data(&ctx, buf);
    } else {
      dialog_data(&ctx, LSTR(TX_MULTIPLE_RECIPIENT));
    }
  }
}

static inline void dialog_btc_sign_scheme_format(char* buf, uint32_t flag) {
  int off = 0;
  if (flag & SIGHASH_ANYONECANPAY) {
    const char* anyonecanpay = LSTR(TX_SIGN_ANYONECANPAY);
    off = strlen(anyonecanpay);
    memcpy(buf, LSTR(TX_SIGN_ANYONECANPAY), off);
    buf[off++] = ' ';
    buf[off++] = '|';
    buf[off++] = ' ';
  }

  const char* str;

  switch(flag & SIGHASH_MASK) {
  case SIGHASH_ALL:
    str = LSTR(TX_SIGN_ALL);
    break;
  case SIGHASH_NONE:
    str = LSTR(TX_SIGN_NONE);
    break;
  case SIGHASH_SINGLE:
    str = LSTR(TX_SIGN_SINGLE);
    break;
  default:
    str = "";
    break;
  }

  strcpy(&buf[off], str);
}

void dialog_confirm_btc_inouts(const btc_tx_ctx_t* tx, size_t page) {
  screen_text_ctx_t ctx;
  ctx.y = TH_TITLE_HEIGHT;
  size_t i = page * BTC_DIALOG_PAGE_ITEMS;
  size_t displayed = 0;
  char buf[BIGNUM_STRING_LEN];

  while((i < tx->input_count) && (displayed < BTC_DIALOG_PAGE_ITEMS)) {
    dialog_label(&ctx, LSTR(TX_INPUT));
    char* idx = (char *) u32toa(i, (uint8_t *) buf, BIGNUM_STRING_LEN);
    dialog_data(&ctx, idx);

    dialog_label(&ctx, LSTR(TX_ADDRESS));
    script_output_to_address(tx->input_data[i].script_pubkey, tx->input_data[i].script_pubkey_len, buf);
    dialog_data(&ctx, buf);

    uint64_t t;
    memcpy(&t, tx->input_data[i].amount, sizeof(uint64_t));
    dialog_btc_amount(&ctx, TX_AMOUNT, t);

    dialog_label(&ctx, LSTR(TX_SIGN_SCHEME));
    dialog_btc_sign_scheme_format(buf, tx->input_data[i].sighash_flag);
    dialog_data(&ctx, buf);

    dialog_label(&ctx, LSTR(TX_SIGNED));
    dialog_data(&ctx, tx->input_data[i].can_sign ? LSTR(TX_YES) : LSTR(TX_NO));

    i++;
    displayed++;
  }

  i -= tx->input_count;

  while ((i < tx->output_count) && (displayed < BTC_DIALOG_PAGE_ITEMS)) {
    dialog_label(&ctx, LSTR(TX_OUTPUT));
    char* idx = (char *) u32toa(i, (uint8_t *) buf, BIGNUM_STRING_LEN);
    dialog_data(&ctx, idx);

    dialog_label(&ctx, LSTR(TX_ADDRESS));
    script_output_to_address(tx->outputs[i].script, tx->outputs[i].script_len, buf);
    dialog_data(&ctx, buf);

    uint64_t t;
    memcpy(&t, tx->outputs[i].amount, sizeof(uint64_t));
    dialog_btc_amount(&ctx, TX_AMOUNT, t);

    dialog_label(&ctx, LSTR(TX_CHANGE));
    dialog_data(&ctx, tx->output_is_change[i] ? LSTR(TX_YES) : LSTR(TX_NO));

    i++;
    displayed++;
  }
}

app_err_t dialog_confirm_bip322(const btc_tx_ctx_t* tx) {
  dialog_title(LSTR(MSG_CONFIRM_TITLE));
  dialog_footer(TH_TITLE_HEIGHT);

  screen_text_ctx_t ctx;
  ctx.y = TH_TITLE_HEIGHT;
  char buf[BIGNUM_STRING_LEN];

  dialog_label(&ctx, LSTR(TX_ADDRESS));
  script_output_to_address(tx->input_data[0].script_pubkey, tx->input_data[0].script_pubkey_len, buf);
  dialog_data(&ctx, buf);

  while(1) {
    switch(ui_wait_keypress(pdMS_TO_TICKS(TX_CONFIRM_TIMEOUT))) {
    case KEYPAD_KEY_CANCEL:
    case KEYPAD_KEY_BACK:
    case KEYPAD_KEY_INVALID:
      return ERR_CANCEL;
    case KEYPAD_KEY_CONFIRM:
      return ERR_OK;
    default:
      break;
    }
  }
}

app_err_t dialog_confirm_btc_tx() {
  const btc_tx_ctx_t* tx = g_ui_cmd.params.btc_tx.tx;

  if (btc_is_bip322(tx)) {
    return dialog_confirm_bip322(tx);
  }

  dialog_title(LSTR(TX_CONFIRM_TRANSFER));

  size_t page = 0;
  size_t last_page = ((tx->input_count + tx->output_count) + (BTC_DIALOG_PAGE_ITEMS - 1)) / BTC_DIALOG_PAGE_ITEMS;

  app_err_t ret = ERR_NEED_MORE_DATA;

  while(ret == ERR_NEED_MORE_DATA) {
    dialog_footer(TH_TITLE_HEIGHT);

    if (page == 0) {
      dialog_confirm_btc_summary(tx);
    } else {
      dialog_confirm_btc_inouts(tx, (page - 1));
    }

    ret = dialog_wait_paged(&page, last_page);
  }

  return ret;
}

app_err_t dialog_confirm_text_based(const uint8_t* data, size_t len, eip712_domain_t* eip712) {
  size_t pages[MAX_PAGE_COUNT];
  size_t last_page = 0;
  pages[0] = 0;

  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_COLOR_TEXT_FG,
      .bg = TH_COLOR_TEXT_BG,
  };

  while(1) {
    ctx.x = TH_TEXT_HORIZONTAL_MARGIN;

    if (last_page > 0) {
      ctx.y = TH_TITLE_HEIGHT + TH_TEXT_VERTICAL_MARGIN;
    } else if (eip712) {
      ctx.y = TH_TITLE_HEIGHT + (TH_DATA_HEIGHT * 4) + (TH_LABEL_HEIGHT * 4);
    } else {
      ctx.y = TH_TITLE_HEIGHT + (TH_DATA_HEIGHT * 1) + (TH_LABEL_HEIGHT * 2);
    }

    size_t offset = pages[last_page];
    size_t to_display = len - offset;
    size_t remaining = screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, &data[offset], to_display, true, false);

    if (!remaining || last_page == (MAX_PAGE_COUNT - 1)) {
      break;
    }

    pages[++last_page] = offset + (to_display - remaining);
  }

  size_t page = 0;

  app_err_t ret = ERR_NEED_MORE_DATA;

  while(ret == ERR_NEED_MORE_DATA) {
    size_t offset = pages[page];

    dialog_title(LSTR(eip712 ? EIP712_CONFIRM_TITLE : MSG_CONFIRM_TITLE));

    if (page == 0) {
      ctx.y = TH_TITLE_HEIGHT;

      if (eip712) {
        dialog_address(&ctx, TX_SIGNER, ADDR_ETH, g_ui_cmd.params.eip712.addr);
        dialog_address(&ctx, EIP712_CONTRACT, ADDR_ETH, &eip712->address[EIP712_ADDR_OFF]);

        dialog_label(&ctx, LSTR(TX_CHAIN));

        chain_desc_t chain;
        chain.chain_id = eip712->chainID;

        uint8_t num[11];
        if (eth_db_lookup_chain(&chain) != ERR_OK) {
          chain.name = (char*) u32toa(chain.chain_id, num, 11);
        }

        dialog_data(&ctx, chain.name);
        dialog_label(&ctx, LSTR(EIP712_NAME));
        dialog_data(&ctx, eip712->name);
        dialog_footer(ctx.y);
        ctx.y = SCREEN_HEIGHT;
      } else {
        dialog_address_block(&ctx, TX_SIGNER, g_ui_cmd.params.msg.addr_type, g_ui_cmd.params.msg.addr);
        dialog_label_only(&ctx, LSTR(MSG_LABEL));
      }

      ctx.font = TH_FONT_TEXT;
      ctx.fg = TH_COLOR_TEXT_FG;
      ctx.bg = TH_COLOR_TEXT_BG;
      ctx.x = TH_TEXT_HORIZONTAL_MARGIN;
      dialog_footer(ctx.y);
    } else {
      ctx.x = TH_TEXT_HORIZONTAL_MARGIN;
      ctx.y = TH_TITLE_HEIGHT + TH_TEXT_VERTICAL_MARGIN;
      dialog_footer(TH_TITLE_HEIGHT);
    }

    screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, &data[offset], (len - offset), false, false);
    ret = dialog_wait_paged(&page, last_page);
  }

  return ret;
}

app_err_t dialog_confirm_msg() {
  return dialog_confirm_text_based(g_ui_cmd.params.msg.data, g_ui_cmd.params.msg.len, NULL);
}

app_err_t dialog_confirm_eip712() {
  eip712_data_type_t type = eip712_recognize(g_ui_cmd.params.eip712.data);

  if (type == EIP712_PERMIT) {
    eth_approve_info info;
    if (eip712_extract_permit(g_ui_cmd.params.eip712.data, &info) != ERR_OK) {
      return ERR_DATA;
    }

    return dialog_confirm_approval(&info, g_ui_cmd.params.eip712.addr, false);
  } else if (type == EIP712_PERMIT_SINGLE) {
    eth_approve_info info;
    if (eip712_extract_permit_single(g_ui_cmd.params.eip712.data, &info) != ERR_OK) {
      return ERR_DATA;
    }

    return dialog_confirm_approval(&info, g_ui_cmd.params.eip712.addr, false);
  } else {
    eip712_domain_t domain;
    if (eip712_extract_domain(g_ui_cmd.params.eip712.data, &domain) != ERR_OK) {
      return ERR_DATA;
    }

    size_t len = eip712_to_string(g_ui_cmd.params.eip712.data, g_camera_fb[0]);
    return dialog_confirm_text_based(g_camera_fb[0], len, &domain);
  }
}

app_err_t dialog_info() {
  dialog_title("");
  dialog_footer(TH_TITLE_HEIGHT);

  screen_text_ctx_t ctx = {
      .font = TH_FONT_INFO,
      .fg = TH_COLOR_TEXT_FG,
      .bg = TH_COLOR_TEXT_BG,
      .x = (SCREEN_WIDTH - (TH_INFO_ICONS)->yAdvance) / 2,
      .y = TH_TITLE_HEIGHT + TH_INFO_ICON_TOP_MARGIN
  };

  icon_draw_info(&ctx, g_ui_cmd.params.info.icon);
  ctx.x = TH_SCREEN_MARGIN;
  ctx.y +=  (TH_INFO_ICONS)->yAdvance + TH_INFO_ICON_BOTTOM_MARGIN;
  screen_draw_centered_string(&ctx,  g_ui_cmd.params.info.msg);

  if (g_ui_cmd.params.info.subtext) {
    ctx.x = TH_SCREEN_MARGIN;
    ctx.y += TH_INFO_SUBTEXT_MARGIN;
    ctx.fg = TH_COLOR_INACTIVE;
    ctx.font = TH_FONT_TEXT;
    screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, (uint8_t*) g_ui_cmd.params.info.subtext, strlen(g_ui_cmd.params.info.subtext), false, true);
  }

  if (g_ui_cmd.params.info.options & UI_INFO_UNDISMISSABLE) {
    vTaskSuspend(NULL);
  }

  return dialog_wait_dismiss(g_ui_cmd.params.info.options);
}

app_err_t dialog_prompt() {
  dialog_title(g_ui_cmd.params.prompt.title);
  dialog_footer(TH_TITLE_HEIGHT);

  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_COLOR_TEXT_FG,
      .bg = TH_COLOR_TEXT_BG,
      .x = TH_TEXT_HORIZONTAL_MARGIN,
      .y = TH_TITLE_HEIGHT + TH_PROMPT_VERTICAL_MARGIN
  };

  size_t len = strlen(g_ui_cmd.params.prompt.msg);
  screen_draw_text(&ctx, MESSAGE_MAX_X, MESSAGE_MAX_Y, (const uint8_t*) g_ui_cmd.params.prompt.msg, len, false, false);

  return dialog_wait_dismiss(UI_INFO_CANCELLABLE | UI_INFO_NEXT);
}
