#include <stddef.h>

#include "common.h"
#include "dialog.h"
#include "menu.h"
#include "keypad/keypad.h"
#include "screen/screen.h"
#include "theme.h"
#include "ui_internal.h"

const menu_t menu_keycard = {
  5, {
    {MENU_CARD_NAME, NULL},
    {MENU_CHANGE_PIN, NULL},
    {MENU_CHANGE_PUK, NULL},
    {MENU_CHANGE_PAIRING, NULL},
    {MENU_RESET_CARD, NULL},
  }
};

const menu_t menu_device = {
  6, {
    {MENU_DEV_AUTH, NULL},
    {MENU_UPDATE, NULL},
    {MENU_BRIGHTNESS, NULL},
    {MENU_SET_OFF_TIME, NULL},
    {MENU_USB, NULL},
    {MENU_INSTRUCTIONS, NULL},
  }
};

const menu_t menu_info = {
  2, {
    {MENU_SW_INFO, NULL},
    {MENU_ELABEL, NULL},
  }
};

const menu_t menu_connect = {
  5, {
    {MENU_CONNECT_EIP4527, NULL},
    {MENU_CONNECT_BITCOIN, NULL},
    {MENU_CONNECT_BITCOIN_MULTISIG, NULL},
    {MENU_CONNECT_BITCOIN_TESTNET, NULL},
    {MENU_CONNECT_MULTICOIN, NULL},
  }
};

const menu_t menu_addresses = {
  2, {
    {MENU_ETHEREUM, NULL},
    {MENU_BITCOIN, NULL},
  }
};

const menu_t menu_settings = {
  3, {
    {MENU_KEYCARD, &menu_keycard},
    {MENU_DEVICE, &menu_device},
    {MENU_INFO, &menu_info},
  }
};

const menu_t menu_mainmenu = {
  5, {
    {MENU_QRCODE, NULL},
    {MENU_CONNECT, NULL},
    {MENU_ADDRESSES, &menu_addresses},
    {MENU_SETTINGS, &menu_settings},
    {MENU_HELP, NULL},
  }
};

const menu_t menu_mnemonic = {
  3, {
    {MENU_MNEMO_IMPORT, NULL},
    {MENU_MNEMO_GENERATE, NULL},
    {MENU_MNEMO_SCAN, NULL},
  }
};

const menu_t menu_mnemonic_length = {
  6, {
    {MENU_MNEMO_12WORDS, NULL},
    {MENU_MNEMO_12WORDS_PASS, NULL},
    {MENU_MNEMO_24WORDS, NULL},
    {MENU_MNEMO_24WORDS_PASS, NULL},
    {MENU_MNEMO_SLIP39, NULL},
    {MENU_MNEMO_SLIP39_PASS, NULL},
  }
};

const menu_t menu_mnemonic_has_pass = {
  2, {
    {MENU_MNEMO_WITH_PASS, NULL},
    {MENU_MNEMO_NO_PASS, NULL},
  }
};

const menu_t menu_autooff = {
  5, {
    {MENU_OFF_3MINS, NULL},
    {MENU_OFF_5MINS, NULL},
    {MENU_OFF_10MINS, NULL},
    {MENU_OFF_30MINS, NULL},
    {MENU_OFF_NEVER, NULL},
  }
};

const menu_t menu_onoff = {
  2, {
    {MENU_ON, NULL},
    {MENU_OFF, NULL},
  }
};

const menu_t menu_showhide = {
  2, {
    {MENU_SHOW, NULL},
    {MENU_HIDE, NULL},
  }
};

const menu_t menu_keycard_blocked = {
  2, {
    {MENU_UNBLOCK_PUK, NULL},
    {MENU_RESET_CARD, NULL},
  }
};

const menu_t menu_keycard_pair = {
  2, {
    {MENU_PAIR, NULL},
    {MENU_RESET_CARD, NULL},
  }
};

#define MENU_MAX_DEPTH 5
#define GLYPH_AS_STRING(__NAME__, __CODE__) char __NAME__[2] = { __CODE__, 0x00 }

typedef app_err_t (*menu_draw_func_t)(screen_text_ctx_t* ctx, const char* str);

static app_err_t menu_draw_inverted(screen_text_ctx_t* ctx, const char* str) {
  return dialog_inverted_string(ctx, str, TH_MENU_CONSTRAST_PADDING);
}

static app_err_t menu_margin(uint16_t yOff, uint16_t height) {
  screen_area_t area = { 0, yOff, SCREEN_WIDTH, height };
  return screen_fill_area(&area, TH_COLOR_BG);
}

void menu_render_entry(const menu_entry_t* entry, uint8_t is_selected, uint16_t yOff) {
  screen_text_ctx_t ctx;
  ctx.font = TH_FONT_MENU;

  ctx.x = TH_MENU_LEFT_MARGIN;
  ctx.y = yOff;
  ctx.bg = TH_COLOR_MENU_BG;

  menu_draw_func_t menu_draw;

  dialog_begin_line(&ctx, TH_MENU_HEIGHT);

  if (is_selected) {
    ctx.bg = TH_COLOR_MENU_SELECTED_BG;
    ctx.fg = TH_COLOR_MENU_SELECTED_FG;
    menu_draw = menu_draw_inverted;
  } else {
    ctx.fg = TH_COLOR_MENU_FG;
    menu_draw = (menu_draw_func_t) screen_draw_string;
  }

  menu_draw(&ctx, LSTR(entry->label_id));

  ctx.x += TH_MENU_CONSTRAST_PADDING;

  if (is_selected && (entry->submenu != NULL)) {
    GLYPH_AS_STRING(attr, SYM_RIGHT_CHEVRON);
    menu_draw(&ctx, attr);
  } else if (g_ui_cmd.params.menu.marked == entry->label_id) {
    GLYPH_AS_STRING(attr, SYM_CHECKMARK);
    menu_draw(&ctx, attr);
  }

  dialog_end_line(&ctx);
}

enum menu_draw_mode {
  MENU_ALL,
  MENU_NEXT,
  MENU_PREV,
  MENU_NONE
};

void menu_render(const menu_t* menu, const char* title, uint8_t selected, enum menu_draw_mode mode) {
  uint16_t yOff = TH_TITLE_HEIGHT + TH_MENU_VERTICAL_MARGIN;

  int i, l;

  switch(mode) {
  case MENU_ALL:
    dialog_title(title);
    menu_margin(TH_TITLE_HEIGHT, TH_MENU_VERTICAL_MARGIN);
    i = 0;
    l = menu->len;
    break;
  case MENU_NEXT:
    i = APP_MAX(0, selected);
    l = APP_MIN(menu->len, (selected + 2));
    yOff += (i * TH_MENU_HEIGHT);
    break;
  case MENU_PREV:
    i = APP_MAX(0, (selected - 1));
    l = APP_MIN(menu->len, (selected + 1));
    yOff += (i * TH_MENU_HEIGHT);
    break;
  case MENU_NONE:
  default:
    return;
  }

  for (; i < l; i++) {
    menu_render_entry(&menu->entries[i], i == selected, yOff);
    yOff += TH_MENU_HEIGHT;
  }

  if (mode == MENU_ALL) {
    dialog_blank(yOff);

    if (!(g_ui_cmd.params.menu.options & UI_MENU_NOCANCEL)) {
      dialog_nav_hints(ICON_NAV_CANCEL, ICON_NONE);
    }

    if (g_ui_cmd.params.menu.options & UI_MENU_PAGED) {
      dialog_pager(g_ui_cmd.params.menu.current_page, g_ui_cmd.params.menu.last_page, false);
    }
  }
}

static uint8_t menu_scan(const menu_t* menu, const char* title, i18n_str_id_t to_find, const menu_t* menus[MENU_MAX_DEPTH], const char* titles[MENU_MAX_DEPTH], uint8_t selected[MENU_MAX_DEPTH], uint8_t depth) {
  int found = -1;
  int res = 0xff;

  for (int i = 0; i < menu->len; i++) {
    if (menu->entries[i].label_id == to_find) {
      found = i;
      res = depth;
      break;
    } else if (menu->entries[i].submenu) {
      res = menu_scan(menu->entries[i].submenu, LSTR(menu->entries[i].label_id), to_find, menus, titles, selected, (depth + 1));
      if (res != 0xff) {
        found = i;
        break;
      }
    }
  }

  if (found != -1) {
    titles[depth] = title;
    menus[depth] = menu;
    selected[depth] = found;
  }

  return res;
}

app_err_t menu_run() {
  const menu_t* menus[MENU_MAX_DEPTH];
  const char* titles[MENU_MAX_DEPTH];
  uint8_t selected[MENU_MAX_DEPTH];

  enum menu_draw_mode draw = MENU_ALL;
  i18n_str_id_t* output = g_ui_cmd.params.menu.selected;
  uint8_t depth = menu_scan(g_ui_cmd.params.menu.menu, g_ui_cmd.params.menu.title, *output, menus, titles, selected, 0);

  while(1) {
    const menu_t* menu = menus[depth];
    menu_render(menu, titles[depth], selected[depth], draw);

    switch(ui_wait_keypress(portMAX_DELAY)) {
      case KEYPAD_KEY_CANCEL:
        *output = menu->entries[selected[depth]].label_id;
        return ERR_CANCEL;
      case KEYPAD_KEY_BACK:
        if (depth) {
          depth--;
          draw = MENU_ALL;
        } else {
          return ERR_CANCEL;
        }
        break;
      case KEYPAD_KEY_UP:
        if (selected[depth] > 0) {
          selected[depth]--;
          draw = MENU_NEXT;
        } else {
          selected[depth] = menu->len - 1;
          draw = MENU_ALL;
        }
        break;
      case KEYPAD_KEY_DOWN:
        if (selected[depth] < (menu->len - 1)) {
          selected[depth]++;
          draw = MENU_PREV;
        } else {
          selected[depth] = 0;
          draw = MENU_ALL;
        }
        break;
      case KEYPAD_KEY_CONFIRM:
        const menu_entry_t* entry = &menu->entries[selected[depth]];
        if (entry->submenu) {
          assert(depth < (MENU_MAX_DEPTH - 1));
          menus[++depth] = entry->submenu;
          titles[depth] = LSTR(entry->label_id);
          selected[depth] = 0;
          draw = MENU_ALL;
        } else {
          *output = entry->label_id;
          return ERR_OK;
        }
        break;
      default:
        draw = MENU_NONE;
        break;
    }
  }
}
