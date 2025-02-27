#include <string.h>

#include "input.h"
#include "common.h"
#include "dialog.h"
#include "theme.h"
#include "crypto/bip39.h"
#include "crypto/util.h"
#include "crypto/rand.h"
#include "keypad/keypad.h"
#include "ui/ui.h"
#include "ui/ui_internal.h"

#define PIN_LEN 6
#define PUK_LEN 12
#define DIG_INV ' '

#define KEY_BACKSPACE 0x08
#define KEY_RETURN 0x0d
#define KEY_ESCAPE 0x1b

#define WORD_MAX_LEN 8

#define KEYBOARD_TOP_Y (SCREEN_HEIGHT - (TH_KEYBOARD_KEY_SIZE * 3))

#define KEYBOARD_ROW0_LEN 10
#define KEYBOARD_ROW1_LEN 10
#define KEYBOARD_ROW2_LEN 9
#define KEYBOARD_ROW3_LEN 7

#define KEYBOARD_ROW0_LIMIT KEYBOARD_ROW0_LEN
#define KEYBOARD_ROW1_LIMIT (KEYBOARD_ROW0_LIMIT + KEYBOARD_ROW1_LEN)
#define KEYBOARD_ROW2_LIMIT (KEYBOARD_ROW1_LIMIT + KEYBOARD_ROW2_LEN)
#define KEYBOARD_ROW3_LIMIT (KEYBOARD_ROW2_LIMIT + KEYBOARD_ROW3_LEN)

#define KEYBOARD_EXT_FIRST_KEY 0
#define KEYBOARD_FIRST_KEY KEYBOARD_ROW0_LIMIT

const char KEYPAD_TO_DIGIT[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', DIG_INV, '0', DIG_INV, DIG_INV, DIG_INV};
const char KEYBOARD_MAP[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
    'z', 'x', 'c', 'v', 'b', 'n', 'm'
};

static app_err_t input_render_secret(uint16_t yOff, int len, int pos) {
  uint16_t start_x = (SCREEN_WIDTH - ((len * (TH_NAV_ICONS)->yAdvance) + (TH_PIN_DIGIT_MARGIN * (len - 1)))) / 2;

  screen_text_ctx_t ctx = {
      .bg = TH_COLOR_BG,
      .font = TH_NAV_ICONS,
      .x = start_x,
      .y = yOff
  };

  screen_area_t area = {
      .x = start_x,
      .y = yOff,
      .width = (TH_NAV_ICONS)->yAdvance,
      .height = (TH_NAV_ICONS)->yAdvance
  };

  char c;

  for (int i = 0; i < len; i++) {
    if (i < pos) {
      c = NAV_CIRCLE_FULL;
      ctx.fg = TH_COLOR_FG;
    } else if (i == pos) {
      c = NAV_CIRCLE_EMPTY;
      ctx.fg = TH_COLOR_FG;
    } else {
      c = NAV_CIRCLE_FULL_SMALL;
      ctx.fg = TH_COLOR_INACTIVE;
    }

    screen_fill_area(&area, TH_COLOR_BG);
    screen_draw_char(&ctx, c);
    ctx.x += (TH_NAV_ICONS)->yAdvance + TH_PIN_DIGIT_MARGIN;
    area.x = ctx.x;
  }

  return ERR_OK;
}

static app_err_t input_pin_entry(const char* title, char* out, char* compare, bool dismissable) {
  dialog_title("");
  dialog_footer(TH_TITLE_HEIGHT);

  uint8_t position = 0;
  bool comparison_failed = false;
  bool prev_comparison = comparison_failed;
  uint16_t start_y = (SCREEN_HEIGHT - ((TH_FONT_TEXT)->yAdvance + TH_PIN_FIELD_VERTICAL_MARGIN + (TH_NAV_ICONS)->yAdvance)) / 2;

  screen_text_ctx_t ctx = {
      .bg = TH_COLOR_TEXT_BG,
      .font = TH_FONT_TEXT,
  };

  screen_area_t label_area = { .width = SCREEN_WIDTH, .height = (TH_FONT_TEXT)->yAdvance, .x = 0, .y = start_y};

  while(1) {
    ctx.x = 0;
    ctx.y = start_y;

    if (prev_comparison != comparison_failed) {
      screen_fill_area(&label_area, ctx.bg);
    }

    if (comparison_failed) {
      ctx.fg = TH_COLOR_ERROR;
      screen_draw_centered_string(&ctx, LSTR(PIN_LABEL_MISMATCH));
    } else {
      ctx.fg = TH_COLOR_TEXT_FG;
      screen_draw_centered_string(&ctx, title);
    }

    input_render_secret(ctx.y + TH_PIN_FIELD_VERTICAL_MARGIN, PIN_LEN, position);
    keypad_key_t key = ui_wait_keypress(portMAX_DELAY);
    if (key == KEYPAD_KEY_BACK) {
      if (position > 0) {
        position--;
      } else if (dismissable) {
        return ERR_CANCEL;
      }
    } else if (key == KEYPAD_KEY_CONFIRM) {
      if ((position == PIN_LEN) && !comparison_failed) {
        return ERR_OK;
      }
    } else if (position < PIN_LEN) {
      char digit = KEYPAD_TO_DIGIT[key];
      if (digit != DIG_INV) {
        out[position++] = digit;
      }
    }

    if (compare) {
      prev_comparison = comparison_failed;
      comparison_failed = strncmp(out, compare, position) != 0;
    }

    if (position == PIN_LEN) {
      dialog_nav_hints(ICON_NAV_BACKSPACE, ICON_NAV_NEXT);
    } else if (position > 0) {
      dialog_nav_hints(ICON_NAV_BACKSPACE, ICON_NAV_NONE);
    } else {
      dialog_nav_hints(dismissable ? ICON_NAV_BACK : ICON_NAV_NONE, ICON_NAV_NONE);
    }
  }
}

app_err_t input_pin() {
  if (g_ui_cmd.params.input_pin.retries == PIN_NEW_CODE) {
    while(1) {
      if (input_pin_entry(LSTR(PIN_CREATE_TITLE), (char *) g_ui_cmd.params.input_pin.out, NULL, g_ui_cmd.params.input_pin.dismissable) != ERR_OK) {
        return ERR_CANCEL;
      }

      char repeat[PIN_LEN];

      if (input_pin_entry(LSTR(PIN_LABEL_REPEAT), repeat, (char *) g_ui_cmd.params.input_pin.out, true) == ERR_OK) {
        return ERR_OK;
      }
    }
  } else {
    return input_pin_entry(LSTR(PIN_INPUT_TITLE), (char *) g_ui_cmd.params.input_pin.out, NULL, g_ui_cmd.params.input_pin.dismissable);
  }
}

app_err_t input_puk() {
  dialog_title("");
  dialog_footer(TH_TITLE_HEIGHT);

  screen_text_ctx_t ctx = {
      .bg = TH_COLOR_TEXT_BG,
      .fg = TH_COLOR_TEXT_FG,
      .font = TH_FONT_TEXT,
      .x = 0,
      .y = (SCREEN_HEIGHT - ((TH_FONT_TEXT)->yAdvance + TH_PIN_FIELD_VERTICAL_MARGIN + ((TH_NAV_ICONS)->yAdvance) * 2) + (TH_PUK_FIELD_VERTICAL_MARGIN * 2)) / 2
  };

  screen_draw_centered_string(&ctx, (g_ui_cmd.params.input_pin.retries == PUK_NEW_CODE) ? LSTR(PUK_CREATE_TITLE) : LSTR(PUK_INPUT_TITLE));

  char* out = (char *) g_ui_cmd.params.input_pin.out;
  uint8_t position = 0;

  while(1) {
    input_render_secret(ctx.y + TH_PIN_FIELD_VERTICAL_MARGIN, 6, position);
    input_render_secret((ctx.y + TH_PIN_FIELD_VERTICAL_MARGIN) + ((TH_NAV_ICONS)->yAdvance + TH_PUK_FIELD_VERTICAL_MARGIN), 6, position - 6);

    keypad_key_t key = ui_wait_keypress(portMAX_DELAY);
    if (key == KEYPAD_KEY_BACK) {
      if (position > 0) {
        position--;
      } else if (g_ui_cmd.params.input_pin.retries == PUK_NEW_CODE) {
        return ERR_CANCEL;
      }
    } else if (key == KEYPAD_KEY_CONFIRM) {
      if (position == PUK_LEN) {
        return ERR_OK;
      }
    } else if (position < PUK_LEN) {
      char digit = KEYPAD_TO_DIGIT[key];
      if (digit != DIG_INV) {
        out[position++] = digit;
      }
    }
  }
}

static inline void input_keyboard_render_key(char c, uint16_t x, uint16_t y, bool selected) {
  screen_area_t key_area = { .x = x, .y = y, .width = TH_KEYBOARD_KEY_SIZE, .height = TH_KEYBOARD_KEY_SIZE };
  screen_text_ctx_t ctx = { .font = TH_FONT_TEXT, .fg = TH_COLOR_TEXT_FG, .y = y };

  const glyph_t* glyph = screen_lookup_glyph(ctx.font, (uint32_t) c);
  ctx.bg = selected ? TH_KEYBOARD_KEY_SELECTED_BG : TH_KEYBOARD_KEY_BG;
  ctx.x = x + ((TH_KEYBOARD_KEY_SIZE - glyph->width) / 2);

  screen_fill_area(&key_area, ctx.bg);
  screen_draw_glyph(&ctx, glyph);
}

static inline void input_keyboard_render(int idx, bool extended) {
  int i = KEYBOARD_ROW0_LIMIT;

  while (i < KEYBOARD_ROW1_LIMIT) {
    input_keyboard_render_key(KEYBOARD_MAP[i], ((i - KEYBOARD_ROW0_LIMIT) * TH_KEYBOARD_KEY_SIZE), KEYBOARD_TOP_Y, idx == i);
    i++;
  }

  while (i < KEYBOARD_ROW2_LIMIT) {
    input_keyboard_render_key(KEYBOARD_MAP[i], ((i - KEYBOARD_ROW1_LIMIT) * TH_KEYBOARD_KEY_SIZE) + (TH_KEYBOARD_KEY_SIZE / 2), (KEYBOARD_TOP_Y + TH_KEYBOARD_KEY_SIZE), idx == i);
    i++;
  }

  while (i < KEYBOARD_ROW3_LIMIT) {
    input_keyboard_render_key(KEYBOARD_MAP[i], ((i - KEYBOARD_ROW2_LIMIT)* TH_KEYBOARD_KEY_SIZE) + TH_KEYBOARD_KEY_SIZE, (KEYBOARD_TOP_Y + (TH_KEYBOARD_KEY_SIZE * 2)), idx == i);
    i++;
  }
}

static char input_keyboard(int *idx, bool extended) {
  while(1) {
    input_keyboard_render(*idx, extended);

    switch(ui_wait_keypress(portMAX_DELAY)) {
    case KEYPAD_KEY_UP:
      if (*idx >= KEYBOARD_ROW2_LIMIT) {
        *idx -= KEYBOARD_ROW2_LEN;
      } else if (*idx >= KEYBOARD_ROW1_LIMIT) {
        *idx -= KEYBOARD_ROW1_LEN;
      } else if (*idx >= KEYBOARD_ROW0_LIMIT) {
        *idx -= KEYBOARD_ROW0_LEN;
      } else {
        *idx = APP_MIN(*idx + KEYBOARD_ROW2_LIMIT, (KEYBOARD_ROW3_LIMIT - 1));
      }
      break;
    case KEYPAD_KEY_LEFT:
      if ((*idx > KEYBOARD_ROW2_LIMIT) ||
          ((*idx > KEYBOARD_ROW1_LIMIT) && (*idx < KEYBOARD_ROW2_LIMIT)) ||
          ((*idx > KEYBOARD_ROW0_LIMIT) && (*idx < KEYBOARD_ROW1_LIMIT)) ||
          ((*idx > 0) && (*idx < KEYBOARD_ROW0_LIMIT))) {
        (*idx)--;
      } else {
        if (*idx == KEYBOARD_ROW0_LIMIT) {
          *idx = KEYBOARD_ROW1_LIMIT - 1;
        } else if (*idx == KEYBOARD_ROW1_LIMIT) {
          *idx = KEYBOARD_ROW2_LIMIT - 1;
        } else {
          *idx = KEYBOARD_ROW3_LIMIT - 1;
        }
      }
      break;
    case KEYPAD_KEY_RIGHT:
      if ((*idx < (KEYBOARD_ROW0_LIMIT - 1)) ||
          ((*idx < (KEYBOARD_ROW1_LIMIT - 1)) && (*idx >= KEYBOARD_ROW0_LIMIT)) ||
          ((*idx < (KEYBOARD_ROW2_LIMIT - 1)) && (*idx >= KEYBOARD_ROW1_LIMIT)) ||
          ((*idx < (KEYBOARD_ROW3_LIMIT - 1)) && (*idx >= KEYBOARD_ROW2_LIMIT))) {
        (*idx)++;
      }  else {
        if (*idx == KEYBOARD_ROW1_LIMIT - 1) {
          *idx = KEYBOARD_ROW0_LIMIT;
        } else if (*idx == KEYBOARD_ROW2_LIMIT - 1) {
          *idx = KEYBOARD_ROW1_LIMIT;
        } else {
          *idx = KEYBOARD_ROW2_LIMIT;
        }
      }
      break;
    case KEYPAD_KEY_DOWN:
      if (*idx < KEYBOARD_ROW0_LIMIT) {
        *idx = APP_MIN(*idx + KEYBOARD_ROW0_LEN, (KEYBOARD_ROW1_LIMIT - 1));
      } else if (*idx < KEYBOARD_ROW1_LIMIT) {
        *idx = APP_MIN(*idx + KEYBOARD_ROW1_LEN, (KEYBOARD_ROW2_LIMIT - 1));
      } else if (*idx < KEYBOARD_ROW2_LIMIT) {
        *idx = APP_MIN(*idx + KEYBOARD_ROW2_LEN, (KEYBOARD_ROW3_LIMIT - 1));
      } else {
        *idx -= KEYBOARD_ROW2_LIMIT;
      }
      break;
    case KEYPAD_KEY_BACK:
      return g_ui_ctx.keypad.last_key_long ? KEY_ESCAPE : KEY_BACKSPACE;
    case KEYPAD_KEY_CONFIRM:
      return g_ui_ctx.keypad.last_key_long ? KEY_RETURN : KEYBOARD_MAP[*idx];
    default:
      break;
    }
  }
}

static void input_render_text_field(const char* str, screen_area_t* field_area, int len, int suggestion_len) {
  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_TEXT_FIELD_FG,
      .bg = TH_TEXT_FIELD_BG,
      .x = field_area->x,
      .y = field_area->y
  };

  screen_fill_area(field_area, ctx.bg);

  screen_draw_chars(&ctx, str, len);

  screen_area_t cursor_area = {
      .x = ctx.x,
      .y = field_area->y,
      .width = TH_TEXT_FIELD_CURSOR_WIDTH,
      .height = field_area->height
  };

  screen_fill_area(&cursor_area, TH_TEXT_FIELD_CURSOR_COLOR);
  ctx.fg = TH_TEXT_FIELD_SUGGESTION_FG;
  screen_draw_chars(&ctx, &str[len], suggestion_len);
}


static void input_mnemonic_title(uint8_t i) {
  const char* base_title = LSTR(MNEMO_WORD_TITLE);
  int base_len = strlen(base_title);
  int buf_len = base_len + 4;
  uint8_t title_buf[buf_len];
  char* title = (char *) u32toa(i + 1, title_buf, buf_len);
  title -= base_len;
  memcpy(title, base_title, base_len);
  dialog_title(title);
}

static void input_render_editable_text_field(const char* str, int len, int suggestion_len) {
  screen_area_t field_area = {
      .x = TH_TEXT_FIELD_MARGIN,
      .y = TH_TEXT_FIELD_TOP,
      .width = SCREEN_WIDTH - (TH_TEXT_FIELD_MARGIN * 2),
      .height = TH_TEXT_FIELD_HEIGHT
  };

  input_render_text_field(str, &field_area, len, suggestion_len);
  const char* action_hint = (suggestion_len == 0) && (len == 0) ? LSTR(HINT_CANCEL) : LSTR(HINT_CONFIRM);

  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_COLOR_INACTIVE,
      .bg = TH_COLOR_BG,
      .x = field_area.x,
      .y = field_area.y + field_area.height + TH_TEXT_FIELD_HINT_MARGIN
  };

  field_area.y = ctx.y;
  field_area.x = 0;
  field_area.width = SCREEN_WIDTH;
  screen_fill_area(&field_area, ctx.bg);
  screen_draw_string(&ctx, action_hint);
}

static void input_mnemonic_render(const char* word, int len, uint16_t idx) {
  int suggestion_len;

  if (idx != UINT16_MAX) {
    word = BIP39_WORDLIST_ENGLISH[idx];
    suggestion_len = strlen(word) - len;
  } else {
    suggestion_len = 0;
  }

  input_render_editable_text_field(word, len, suggestion_len);
}

static uint16_t input_mnemonic_lookup(char* word, int len, uint16_t idx) {
  if (len == 0) {
    return UINT16_MAX;
  }

  while (idx < BIP39_WORD_COUNT) {
    int cmp = strncmp(word, BIP39_WORDLIST_ENGLISH[idx], len);

    if (cmp == 0) {
      return idx;
    } else if (cmp < 0) {
      return UINT16_MAX;
    } else {
      idx++;
    }
  }

  return UINT16_MAX;
}

static app_err_t input_mnemonic_get_word(int i, uint16_t* idx) {
  input_mnemonic_title(i);
  dialog_footer(TH_TITLE_HEIGHT);

  char word[WORD_MAX_LEN];
  int len = 0;
  int key_idx = KEYBOARD_FIRST_KEY;

  while(1) {
    input_mnemonic_render(word, len, *idx);
    char c = input_keyboard(&key_idx, false);

    if (c == KEY_RETURN) {
      if (*idx != UINT16_MAX) {
        return ERR_OK;
      }
    } else if (c == KEY_BACKSPACE) {
      if (len > 0) {
        len--;
        *idx = input_mnemonic_lookup(word, len, 0);
      }
    } else if (c == KEY_ESCAPE) {
      return ERR_CANCEL;
    } else if (len < WORD_MAX_LEN) {
      word[len++] = c;
      *idx = input_mnemonic_lookup(word, len, ((*idx) == UINT16_MAX ? 0 : *idx));
    }
  }
}

app_err_t input_mnemonic() {
  dialog_footer(TH_TITLE_HEIGHT);

  memset(g_ui_cmd.params.mnemo.indexes, 0xff, (sizeof(uint16_t) * g_ui_cmd.params.mnemo.len));

  int i = 0;

  while (i < g_ui_cmd.params.mnemo.len) {
    app_err_t err = input_mnemonic_get_word(i, &g_ui_cmd.params.mnemo.indexes[i]);

    if (err == ERR_OK) {
      i++;
    } else if (i > 0){
      i--;
    } else {
      return ERR_CANCEL;
    }
  }

  return ERR_OK;
}

static void input_render_mnemonic_word(int word_num, const char* str, screen_area_t* field_area, int len) {
  screen_text_ctx_t ctx = {
      .font = TH_FONT_TEXT,
      .fg = TH_TEXT_FIELD_FG,
      .bg = TH_TEXT_FIELD_BG,
      .x = field_area->x,
      .y = field_area->y
  };

  screen_fill_area(field_area, ctx.bg);

  char num[4];
  num[0] = word_num >= 10 ? (word_num / 10) + '0' : ' ';
  num[1] = (word_num % 10) + '0';
  num[2] = '.';
  num[3] = ' ';
  screen_draw_chars(&ctx, num, 4);
  screen_draw_chars(&ctx, str, len);
}

app_err_t input_display_mnemonic() {
  dialog_title(LSTR(MNEMO_BACKUP_TITLE));
  int page = 0;
  int last_page = g_ui_cmd.params.mnemo.len == 12 ? 0 : 1;

  while(1) {
    dialog_footer(TH_TITLE_HEIGHT);

    screen_area_t field_area = {
        .y = TH_TITLE_HEIGHT + TH_MNEMONIC_TOP_MARGIN,
        .width = TH_MNEMONIC_FIELD_WIDTH,
        .height = TH_TEXT_FIELD_HEIGHT
    };

    for (int i = 0; i < 6; i++) {
      field_area.x = TH_MNEMONIC_LEFT_MARGIN;

      for (int j = 0; j < 2; j++) {
        int word_num = (page * 12) + ((i * 2) + j);
        const char* word = BIP39_WORDLIST_ENGLISH[g_ui_cmd.params.mnemo.indexes[word_num]];
        input_render_mnemonic_word(word_num + 1, word, &field_area, strlen(word));
        field_area.x += TH_MNEMONIC_FIELD_WIDTH + TH_MNEMONIC_LEFT_MARGIN;
      }

      field_area.y += TH_TEXT_FIELD_HEIGHT + TH_MNEMONIC_TOP_MARGIN;
    }

    dialog_nav_hints(ICON_NAV_BACK, page == last_page ? ICON_NAV_NEXT : ICON_NAV_NONE);

    if (last_page > 0) {
      dialog_pager(page, last_page);
    }

    switch(ui_wait_keypress(portMAX_DELAY)) {
    case KEYPAD_KEY_LEFT:
      page = 0;
      break;
    case KEYPAD_KEY_RIGHT:
      if (last_page > 0) {
        page = 1;
      }
      break;
    case KEYPAD_KEY_CANCEL:
    case KEYPAD_KEY_BACK:
      return ERR_CANCEL;
    case KEYPAD_KEY_CONFIRM:
      if (page == last_page) {
        return ERR_OK;
      }
      break;
    default:
      break;
    }
  }
}

app_err_t input_string() {
  dialog_title(g_ui_cmd.params.input_string.title);
  dialog_footer(TH_TITLE_HEIGHT);

  int len = 0;
  int key_idx = KEYBOARD_EXT_FIRST_KEY;

  while(1) {
    input_render_editable_text_field(g_ui_cmd.params.input_string.out, len, 0);
    char c = input_keyboard(&key_idx, true);

    if (c == KEY_RETURN) {
      g_ui_cmd.params.input_string.out[len] = '\0';
      *g_ui_cmd.params.input_string.len = len;
      return ERR_OK;
    } else if (c == KEY_BACKSPACE) {
      if (len > 0) {
        len--;
      }
    } else if (c == KEY_ESCAPE) {
      return ERR_CANCEL;
    } else if (len < *g_ui_cmd.params.input_string.len) {
      g_ui_cmd.params.input_string.out[len++] = c;
    }
  }
}
