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

#define KEY_ACK 0x06
#define KEY_BACKSPACE 0x08
#define KEY_RETURN 0x0d
#define KEY_ESCAPE 0x1b
#define KEY_NONE 0xff

#define WORD_MAX_LEN 8

#define KEYBOARD_MNEMONIC_INITIAL_MASK 0x37FFFFF

#define KEYBOARD_ROW0_LEN 9
#define KEYBOARD_ROW1_LEN 9
#define KEYBOARD_ROW2_LEN 8
#define KEYBOARD_ROW_EXTRA_LEN 3

#define KEYBOARD_ROW0_LIMIT KEYBOARD_ROW0_LEN
#define KEYBOARD_ROW1_LIMIT (KEYBOARD_ROW0_LIMIT + KEYBOARD_ROW1_LEN)
#define KEYBOARD_ROW2_LIMIT (KEYBOARD_ROW1_LIMIT + KEYBOARD_ROW2_LEN)
#define KEYBOARD_ROW_EXTRA_LIMIT (KEYBOARD_ROW2_LIMIT + KEYBOARD_ROW_EXTRA_LEN)

#define KEYBOARD_NUMERIC_LINE_LEN 5

#define KEYBOARD_NUMERIC_ALPHA_IDX 10
#define KEYBOARD_NUMERIC_SPACE_IDX 11

#define KEYBOARD_ALPHA_NUMERIC_IDX 26
#define KEYBOARD_ALPHA_CASE_IDX 27
#define KEYBOARD_ALPHA_SPACE_IDX 28

#define KEYBOARD_MNEMONIC_SUGGESTION1_IDX 26
#define KEYBOARD_MNEMONIC_SUGGESTION2_IDX 27
#define KEYBOARD_MNEMONIC_SUGGESTION3_IDX 28

#define KEYBOARD_CHAR(k, c) ((k->layout == KEYBOARD_UPPERCASE ? 'A' : 'a') + c)
#define KEYBOARD_ENABLED(k, c) ((k->keymask & (1 << c)) >> c)

#define KEYBOARD_LINE_WIDTH(__LEN__) ((__LEN__ * (TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN)) + TH_KEYBOARD_KEY_MARGIN)

#define MNEMONIC_BACKUP_REFRESH_MS 60000

typedef enum {
  KEYBOARD_MNEMONIC,
  KEYBOARD_LOWERCASE,
  KEYBOARD_UPPERCASE,
  KEYBOARD_NUMERIC
} keyboard_layout_t;

typedef struct {
  uint32_t keymask;
  uint8_t idx;
  keyboard_layout_t layout;
} keyboard_state_t;

typedef struct {
  i18n_str_id_t title_enter;
  i18n_str_id_t title_new;
  i18n_str_id_t title_repeat;
  uint8_t secret_len;
} secret_spec_t;

const char KEYPAD_TO_DIGIT[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', DIG_INV, '0', DIG_INV, DIG_INV, DIG_INV};

const secret_spec_t SECRET_SPEC[] = {
    {PIN_INPUT_TITLE, PIN_CREATE_TITLE, PIN_LABEL_REPEAT, PIN_LEN},
    {PUK_INPUT_TITLE, PUK_CREATE_TITLE, PUK_LABEL_REPEAT, PUK_LEN},
    {PIN_INPUT_TITLE, DURESS_CREATE_TITLE, DURESS_LABEL_REPEAT, PIN_LEN},
};

static app_err_t input_render_secret(uint16_t yOff, int len, int pos, icon_t full, icon_t current) {
  uint16_t start_x = (SCREEN_WIDTH - ((len * (TH_NAV_ICONS)->yAdvance) + (TH_PIN_DIGIT_MARGIN * (len - 1)))) / 2;

  screen_text_ctx_t ctx = {
      .bg = TH_COLOR_BG,
      .fg = TH_COLOR_FG,
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

  icon_t icon;

  for (int i = 0; i < len; i++) {
    if (i < pos) {
      icon = full;
    } else if (i == pos) {
      icon = current;
    } else {
      icon = ICON_PIN_EMPTY;
    }

    screen_fill_area(&area, TH_COLOR_BG);
    icon_draw(&ctx, icon);
    ctx.x += (TH_NAV_ICONS)->yAdvance + TH_PIN_DIGIT_MARGIN;
    area.x = ctx.x;
  }

  return ERR_OK;
}

static app_err_t input_secret_entry(const char* title, char* out, char* compare, size_t secret_len, bool dismissable) {
  dialog_title("");
  dialog_blank(TH_TITLE_HEIGHT);

  uint8_t position = 0;
  bool comparison_failed = false;
  uint16_t start_y = (SCREEN_HEIGHT - TH_TITLE_HEIGHT - TH_NAV_HINT_HEIGHT - ((TH_FONT_TEXT)->yAdvance + TH_PIN_FIELD_VERTICAL_MARGIN + (TH_NAV_ICONS)->yAdvance));
  if (secret_len > PIN_LEN) {
    start_y -= (TH_PUK_FIELD_VERTICAL_MARGIN + (TH_NAV_ICONS)->yAdvance);
  }
  start_y = TH_TITLE_HEIGHT + (start_y / 2);

  icon_t full_icon = compare ? ICON_OK : ICON_PIN_FULL;

  screen_text_ctx_t ctx = {
      .bg = TH_COLOR_TEXT_BG,
      .fg = TH_COLOR_TEXT_FG,
      .font = TH_FONT_TEXT,
      .y = start_y
  };

  screen_draw_centered_string(&ctx, title);
  start_y = ctx.y;

  while(1) {
    ctx.x = 0;
    ctx.y = start_y;

    if (position == secret_len) {
      dialog_nav_hints(ICON_NAV_BACKSPACE, ICON_NAV_NEXT);
    } else if (position > 0) {
      dialog_nav_hints(ICON_NAV_BACKSPACE, ICON_NONE);
    } else {
      dialog_nav_hints(dismissable ? ICON_NAV_CANCEL : ICON_NONE, ICON_NONE);
    }

    input_render_secret(ctx.y + TH_PIN_FIELD_VERTICAL_MARGIN, PIN_LEN, (position - comparison_failed), full_icon, comparison_failed ? ICON_FAIL : ICON_PIN_CURRENT);
    if (secret_len > PIN_LEN) {
      input_render_secret((ctx.y + TH_PIN_FIELD_VERTICAL_MARGIN) + ((TH_NAV_ICONS)->yAdvance + TH_PUK_FIELD_VERTICAL_MARGIN), PIN_LEN, (position - PIN_LEN - comparison_failed), full_icon, comparison_failed ? ICON_FAIL : ICON_PIN_CURRENT);
    }

    keypad_key_t key = ui_wait_keypress(portMAX_DELAY);
    if (key == KEYPAD_KEY_BACK) {
      if (position > 0) {
        position--;
      } else if (dismissable) {
        return ERR_CANCEL;
      }
    } else if (key == KEYPAD_KEY_CONFIRM) {
      if ((position == secret_len) && !comparison_failed) {
        return ERR_OK;
      }
    } else if ((position < secret_len) && !comparison_failed) {
      char digit = KEYPAD_TO_DIGIT[key];
      if (digit != DIG_INV) {
        out[position++] = digit;
      }
    }

    if (compare) {
      comparison_failed = strncmp(out, compare, position) != 0;
    }
  }
}

app_err_t input_secret() {
  const secret_spec_t* s = &SECRET_SPEC[g_ui_cmd.params.input_secret.type];

  if (g_ui_cmd.params.input_secret.retries == SECRET_NEW_CODE) {
    while(1) {
      if (input_secret_entry(LSTR(s->title_new), (char *) g_ui_cmd.params.input_secret.out, NULL, s->secret_len, g_ui_cmd.params.input_secret.dismissable) != ERR_OK) {
        return ERR_CANCEL;
      }

      char repeat[s->secret_len];

      if (input_secret_entry(LSTR(s->title_repeat), repeat, (char *) g_ui_cmd.params.input_secret.out, s->secret_len, true) == ERR_OK) {
        return ERR_OK;
      }
    }
  } else {
    return input_secret_entry(LSTR(s->title_enter), (char *) g_ui_cmd.params.input_secret.out, NULL, s->secret_len, g_ui_cmd.params.input_secret.dismissable);
  }
}

static inline void input_keyboard_render_key(char c, uint16_t x, uint16_t y, bool selected, bool enabled) {
  screen_area_t key_area = { .x = x, .y = y, .width = TH_KEYBOARD_KEY_SIZE, .height = TH_KEYBOARD_KEY_SIZE };
  screen_text_ctx_t ctx = { .font = TH_FONT_TEXT };

  const glyph_t* glyph = screen_lookup_glyph(ctx.font, (uint32_t) c);

  if (!enabled) {
    ctx.bg = selected ? TH_KEYBOARD_KEY_DISABLED_SELECTED_BG : TH_KEYBOARD_KEY_DISABLED_BG;
    ctx.fg = TH_KEYBOARD_KEY_DISABLED_SELECTED_FG;
  } else if (selected) {
    ctx.bg = TH_KEYBOARD_KEY_SELECTED_BG;
    ctx.fg = TH_KEYBOARD_KEY_SELECTED_FG;
  } else {
    ctx.bg = TH_KEYBOARD_KEY_BG;
    ctx.fg = TH_KEYBOARD_KEY_FG;
  }

  ctx.x = x + ((TH_KEYBOARD_KEY_SIZE - glyph->width) / 2);
  ctx.y = y + ((TH_KEYBOARD_KEY_SIZE - ctx.font->yAdvance) / 2);

  screen_fill_area(&key_area, ctx.bg);
  screen_draw_glyph(&ctx, glyph);
}

static inline void input_keyboard_render_spacebar(uint16_t x, uint16_t y, uint16_t width, bool selected) {
  screen_area_t key_area = { .x = x, .y = y, .width = width, .height = TH_KEYBOARD_KEY_SIZE };
  screen_text_ctx_t ctx = { .font = TH_FONT_TEXT };

  if (selected) {
    ctx.bg = TH_KEYBOARD_KEY_SELECTED_BG;
    ctx.fg = TH_KEYBOARD_KEY_SELECTED_FG;
  } else {
    ctx.bg = TH_KEYBOARD_KEY_BG;
    ctx.fg = TH_KEYBOARD_KEY_FG;
  }

  screen_fill_area(&key_area, ctx.bg);

  screen_area_t glyph_area = {
      .x = x + ((width - 30) / 2),
      .y = y + 12,
      .width = 30,
      .height = 5
  };

  screen_fill_area(&glyph_area, ctx.fg);

  screen_area_t sub_area = {
      .x = glyph_area.x + 2,
      .y = glyph_area.y,
      .width = glyph_area.width - 4,
      .height = glyph_area.height - 2
  };

  screen_fill_area(&sub_area, ctx.bg);
}

static inline void input_keyboard_render_suggestion(uint16_t x, uint16_t y, uint16_t idx, bool selected, bool enabled) {
  screen_area_t key_area = { .x = x, .y = y, .width = TH_KEYBOARD_KEY_SUGGESTION_SIZE, .height = TH_KEYBOARD_KEY_SIZE };
  screen_text_ctx_t ctx = { .font = TH_FONT_TEXT };

  if (!enabled) {
    ctx.bg = selected ? TH_KEYBOARD_KEY_DISABLED_SELECTED_BG : TH_KEYBOARD_KEY_DISABLED_BG;
    ctx.fg = TH_KEYBOARD_KEY_DISABLED_SELECTED_FG;
  } else if (selected) {
    ctx.bg = TH_KEYBOARD_KEY_SELECTED_BG;
    ctx.fg = TH_KEYBOARD_KEY_SELECTED_FG;
  } else {
    ctx.bg = TH_KEYBOARD_KEY_BG;
    ctx.fg = TH_KEYBOARD_KEY_FG;
  }

  screen_fill_area(&key_area, ctx.bg);

  if (enabled) {
    const char* str = g_ui_cmd.params.mnemo.wordlist[idx];
    size_t label_width = screen_string_width(&ctx, str);
    ctx.x = x + ((TH_KEYBOARD_KEY_SUGGESTION_SIZE - label_width) / 2);
    ctx.y = y + ((TH_KEYBOARD_KEY_SIZE - ctx.font->yAdvance) / 2);
    screen_draw_string(&ctx, str);
  }
}

// private macro to be used inside input_keyboard_render_* functions
#define _INPUT_KEYBOARD_RENDER_LINE(__LEN__, __LIMIT__, __GLYPH__) \
{ \
  x = (SCREEN_WIDTH - KEYBOARD_LINE_WIDTH(__LEN__)) / 2; \
\
  while (i < __LIMIT__) { \
    input_keyboard_render_key(__GLYPH__, x, y, keyboard->idx == i, KEYBOARD_ENABLED(keyboard, i)); \
    x += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN; \
    i++; \
  } \
\
  y += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN; \
}

static void input_keyboard_render_alpha(keyboard_state_t* keyboard, uint16_t suggestion_idx) {
  uint8_t i = 0;
  uint16_t x;
  uint16_t y = TH_KEYBOARD_TOP + ((keyboard->layout == KEYBOARD_MNEMONIC) ? (TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN) : 0);

  _INPUT_KEYBOARD_RENDER_LINE(KEYBOARD_ROW0_LEN, KEYBOARD_ROW0_LIMIT, KEYBOARD_CHAR(keyboard, i));
  _INPUT_KEYBOARD_RENDER_LINE(KEYBOARD_ROW0_LEN, KEYBOARD_ROW1_LIMIT, KEYBOARD_CHAR(keyboard, i));
  _INPUT_KEYBOARD_RENDER_LINE(KEYBOARD_ROW0_LEN, KEYBOARD_ROW2_LIMIT, KEYBOARD_CHAR(keyboard, i));

  if (keyboard->layout == KEYBOARD_MNEMONIC) {
    y = TH_KEYBOARD_TOP;
    x = (SCREEN_WIDTH - KEYBOARD_LINE_WIDTH(KEYBOARD_ROW0_LEN)) / 2;

    input_keyboard_render_suggestion(x, y, suggestion_idx, keyboard->idx == i++, KEYBOARD_ENABLED(keyboard, KEYBOARD_MNEMONIC_SUGGESTION1_IDX));
    x += TH_KEYBOARD_KEY_SUGGESTION_SIZE + TH_KEYBOARD_KEY_MARGIN;
    input_keyboard_render_suggestion(x, y, suggestion_idx + 1, keyboard->idx == i++, KEYBOARD_ENABLED(keyboard, KEYBOARD_MNEMONIC_SUGGESTION2_IDX));
    x += TH_KEYBOARD_KEY_SUGGESTION_SIZE + TH_KEYBOARD_KEY_MARGIN;
    input_keyboard_render_suggestion(x, y, suggestion_idx + 2, keyboard->idx == i++, KEYBOARD_ENABLED(keyboard, KEYBOARD_MNEMONIC_SUGGESTION3_IDX));
  } else {
    x = (SCREEN_WIDTH - KEYBOARD_LINE_WIDTH(KEYBOARD_ROW0_LEN)) / 2;
    input_keyboard_render_key(SYM_HASHTAG, x, y, keyboard->idx == i++, true);
    x += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN;
    input_keyboard_render_key((keyboard->layout == KEYBOARD_LOWERCASE) ? SYM_UP_ARROW : SYM_DOWN_ARROW, x, y, keyboard->idx == i++, true);
    x += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN;
    input_keyboard_render_spacebar(x, y, (KEYBOARD_LINE_WIDTH(KEYBOARD_ROW2_LEN) - KEYBOARD_LINE_WIDTH(2) - TH_KEYBOARD_KEY_MARGIN), keyboard->idx == i++);
  }
}

static void input_keyboard_render_numeric(keyboard_state_t* keyboard) {
  uint8_t i = 0;
  uint16_t x;
  uint16_t y = TH_KEYBOARD_TOP;

  _INPUT_KEYBOARD_RENDER_LINE(KEYBOARD_NUMERIC_LINE_LEN, KEYBOARD_NUMERIC_LINE_LEN, ('0' + (i + 1) % 10));
  _INPUT_KEYBOARD_RENDER_LINE(KEYBOARD_NUMERIC_LINE_LEN, (KEYBOARD_NUMERIC_LINE_LEN * 2), ('0' + (i + 1) % 10));

  x = (SCREEN_WIDTH - KEYBOARD_LINE_WIDTH(KEYBOARD_NUMERIC_LINE_LEN)) / 2;
  y += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN;

  input_keyboard_render_key('a', x, y, keyboard->idx == i++, true);
  x += TH_KEYBOARD_KEY_SIZE + TH_KEYBOARD_KEY_MARGIN;

  input_keyboard_render_spacebar(x, y, (KEYBOARD_LINE_WIDTH(KEYBOARD_NUMERIC_LINE_LEN) - KEYBOARD_LINE_WIDTH(1) - TH_KEYBOARD_KEY_MARGIN), keyboard->idx == i++);
}

#undef _INPUT_KEYBOARD_RENDER_LINE

static void input_keyboard_blank() {
  screen_area_t keyboard_area = { .x = 0, .y = TH_KEYBOARD_TOP, .width = SCREEN_WIDTH, .height = (SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT - TH_KEYBOARD_TOP) };
  screen_fill_area(&keyboard_area, TH_COLOR_BG);
}

static void input_keyboard_navigate_up(keyboard_state_t* keyboard) {
  if (keyboard->idx >= KEYBOARD_ROW2_LIMIT) {
    keyboard->idx = KEYBOARD_ROW1_LIMIT + ((keyboard->idx - KEYBOARD_ROW2_LIMIT) * ((keyboard->layout == KEYBOARD_MNEMONIC) ? 3 : 1));
  } else if (keyboard->idx >= KEYBOARD_ROW1_LIMIT) {
    keyboard->idx -= KEYBOARD_ROW1_LEN;
  } else if (keyboard->idx >= KEYBOARD_ROW0_LIMIT) {
    keyboard->idx -= KEYBOARD_ROW0_LEN;
  } else {
    keyboard->idx = KEYBOARD_ROW2_LIMIT + ((keyboard->layout == KEYBOARD_MNEMONIC) ? (keyboard->idx / 3) : APP_MIN(keyboard->idx, (KEYBOARD_ROW_EXTRA_LEN - 1)));
  }
}

static void input_keyboard_navigate_down(keyboard_state_t* keyboard) {
  if (keyboard->idx < KEYBOARD_ROW0_LIMIT) {
    keyboard->idx = APP_MIN(keyboard->idx + KEYBOARD_ROW0_LEN, (KEYBOARD_ROW1_LIMIT - 1));
  } else if (keyboard->idx < KEYBOARD_ROW1_LIMIT) {
    keyboard->idx = APP_MIN(keyboard->idx + KEYBOARD_ROW1_LEN, (KEYBOARD_ROW2_LIMIT - 1));
  } else if (keyboard->idx < KEYBOARD_ROW2_LIMIT) {
    keyboard->idx = KEYBOARD_ROW2_LIMIT + ((keyboard->layout == KEYBOARD_MNEMONIC) ? ((keyboard->idx - KEYBOARD_ROW1_LIMIT) / 3) : APP_MIN((keyboard->idx - KEYBOARD_ROW1_LIMIT), (KEYBOARD_ROW_EXTRA_LEN - 1)));
  } else {
    keyboard->idx = (keyboard->idx - KEYBOARD_ROW2_LIMIT) * ((keyboard->layout == KEYBOARD_MNEMONIC) ? 3 : 1);
  }
}

static bool input_keyboard_can_go_left(uint8_t idx) {
  return
      (idx > KEYBOARD_ROW2_LIMIT) ||
      (idx > KEYBOARD_ROW1_LIMIT && (idx < KEYBOARD_ROW2_LIMIT)) ||
      ((idx > KEYBOARD_ROW0_LIMIT) && (idx < KEYBOARD_ROW1_LIMIT)) ||
      ((idx > 0) && (idx < KEYBOARD_ROW0_LIMIT));
}

static void input_keyboard_navigate_left(keyboard_state_t* keyboard) {
  if (input_keyboard_can_go_left(keyboard->idx)) {
    keyboard->idx--;
  } else {
    if (keyboard->idx == KEYBOARD_ROW0_LIMIT) {
      keyboard->idx = KEYBOARD_ROW1_LIMIT - 1;
    } else if (keyboard->idx == KEYBOARD_ROW1_LIMIT) {
      keyboard->idx = KEYBOARD_ROW2_LIMIT - 1;
    } else if (keyboard->idx == KEYBOARD_ROW2_LIMIT) {
      keyboard->idx = KEYBOARD_ROW_EXTRA_LIMIT - 1;
    } else {
      keyboard->idx = KEYBOARD_ROW0_LIMIT - 1;
    }
  }
}

static bool input_keyboard_can_go_right(uint8_t idx) {
  return
      (idx < (KEYBOARD_ROW0_LIMIT - 1)) ||
      ((idx < (KEYBOARD_ROW1_LIMIT - 1)) && (idx >= KEYBOARD_ROW0_LIMIT)) ||
      ((idx < (KEYBOARD_ROW2_LIMIT - 1)) && (idx >= KEYBOARD_ROW1_LIMIT)) ||
      ((idx < (KEYBOARD_ROW_EXTRA_LIMIT - 1)) && (idx >= KEYBOARD_ROW2_LIMIT));
}

static void input_keyboard_navigate_right(keyboard_state_t* keyboard) {
  if (input_keyboard_can_go_right(keyboard->idx)) {
    keyboard->idx++;
  } else {
    if (keyboard->idx == KEYBOARD_ROW1_LIMIT - 1) {
      keyboard->idx = KEYBOARD_ROW0_LIMIT;
    } else if (keyboard->idx == KEYBOARD_ROW2_LIMIT - 1) {
      keyboard->idx = KEYBOARD_ROW1_LIMIT;
    } else if (keyboard->idx == KEYBOARD_ROW_EXTRA_LIMIT - 1) {
      keyboard->idx = KEYBOARD_ROW2_LIMIT;
    } else {
      keyboard->idx = 0;
    }
  }
}

static bool input_keyboard_find_active_in_row(keyboard_state_t* keyboard) {
  if (KEYBOARD_ENABLED(keyboard, keyboard->idx)) {
    return true;
  }

  uint8_t off = 0;
  bool has_left = true;
  bool has_right = true;

  while(has_left || has_right) {
    if (has_left && input_keyboard_can_go_left(keyboard->idx - off)) {
      if (KEYBOARD_ENABLED(keyboard, (keyboard->idx - (off + 1)))) {
        keyboard->idx -= (off + 1);
        return true;
      }
    } else {
      has_left = false;
    }

    if (has_right && input_keyboard_can_go_right(keyboard->idx + off)) {
      if (KEYBOARD_ENABLED(keyboard, (keyboard->idx + (off + 1)))) {
        keyboard->idx += (off + 1);
        return true;
      }
    } else {
      has_right = false;
    }

    off++;
  }

  return false;
}

static void input_keyboard_find_active_top(keyboard_state_t* keyboard) {
  uint8_t idx = keyboard->idx;
  uint8_t count = 4;
  do {
    input_keyboard_navigate_up(keyboard);
    if (input_keyboard_find_active_in_row(keyboard)) {
      return;
    }
  } while(count--);

  keyboard->idx = idx;
}

static void input_keyboard_find_active_bottom(keyboard_state_t* keyboard) {
  uint8_t idx = keyboard->idx;
  uint8_t count = 4;
  do {
    input_keyboard_navigate_down(keyboard);
    if (input_keyboard_find_active_in_row(keyboard)) {
      return;
    }
  } while(count--);

  keyboard->idx = idx;
}

static void input_keyboard_find_active_left(keyboard_state_t* keyboard) {
  uint8_t idx = keyboard->idx;

  do {
    input_keyboard_navigate_left(keyboard);

    if (KEYBOARD_ENABLED(keyboard, keyboard->idx)) {
      return;
    }
  } while(keyboard->idx != idx);
}

static void input_keyboard_find_active_right(keyboard_state_t* keyboard) {
  uint8_t idx = keyboard->idx;

  do {
    input_keyboard_navigate_right(keyboard);

    if (KEYBOARD_ENABLED(keyboard, keyboard->idx)) {
      return;
    }
  } while(keyboard->idx != idx);
}

static char input_keyboard_navigate_alpha(keyboard_state_t* keyboard) {
  char ret = KEY_NONE;

  switch(ui_wait_keypress(portMAX_DELAY)) {
  case KEYPAD_KEY_UP:
    input_keyboard_find_active_top(keyboard);
    break;
  case KEYPAD_KEY_LEFT:
    input_keyboard_find_active_left(keyboard);
    break;
  case KEYPAD_KEY_RIGHT:
    input_keyboard_find_active_right(keyboard);
    break;
  case KEYPAD_KEY_DOWN:
    input_keyboard_find_active_bottom(keyboard);
    break;
  case KEYPAD_KEY_BACK:
    ret = g_ui_ctx.keypad.last_key_long ? KEY_ESCAPE : KEY_BACKSPACE;
    break;
  case KEYPAD_KEY_CONFIRM:
    if (g_ui_ctx.keypad.last_key_long) {
      ret = KEY_RETURN;
    } else if ((keyboard->layout == KEYBOARD_MNEMONIC) && (keyboard->idx >= KEYBOARD_MNEMONIC_SUGGESTION1_IDX)) {
      ret = KEY_ACK;
    } else {
      switch(keyboard->idx) {
      case KEYBOARD_ALPHA_NUMERIC_IDX:
        input_keyboard_blank();
        keyboard->idx = 0;
        keyboard->layout = KEYBOARD_NUMERIC;
        break;
      case KEYBOARD_ALPHA_CASE_IDX:
        keyboard->layout = keyboard->layout == KEYBOARD_UPPERCASE ? KEYBOARD_LOWERCASE : KEYBOARD_UPPERCASE;
        break;
      case KEYBOARD_ALPHA_SPACE_IDX:
        ret = ' ';
        break;
      default:
        ret = KEYBOARD_CHAR(keyboard, keyboard->idx);
        break;
      }
    }
    break;
  default:
    break;
  }

  return ret;
}

static char input_keyboard_navigate_numeric(keyboard_state_t* keyboard) {
  char ret = KEY_NONE;

  switch(ui_wait_keypress(portMAX_DELAY)) {
  case KEYPAD_KEY_UP:
    if (keyboard->idx > (KEYBOARD_NUMERIC_LINE_LEN * 2)) {
      keyboard->idx = KEYBOARD_NUMERIC_LINE_LEN + (keyboard->idx - (KEYBOARD_NUMERIC_LINE_LEN * 2));
    } else if (keyboard->idx >= KEYBOARD_NUMERIC_LINE_LEN) {
      keyboard->idx -= KEYBOARD_NUMERIC_LINE_LEN;
    } else {
      keyboard->idx = (KEYBOARD_NUMERIC_LINE_LEN * 2) + APP_MIN(keyboard->idx, 1);
    }
    break;
  case KEYPAD_KEY_LEFT:
    if ((keyboard->idx > (KEYBOARD_NUMERIC_LINE_LEN * 2)) ||
        (keyboard->idx > KEYBOARD_NUMERIC_LINE_LEN && (keyboard->idx < (KEYBOARD_NUMERIC_LINE_LEN * 2))) ||
        ((keyboard->idx > 0) && (keyboard->idx < KEYBOARD_NUMERIC_LINE_LEN))) {
      keyboard->idx--;
    } else {
      if (keyboard->idx == 0) {
        keyboard->idx = KEYBOARD_NUMERIC_LINE_LEN - 1;
      } else if (keyboard->idx == KEYBOARD_NUMERIC_LINE_LEN) {
        keyboard->idx = (KEYBOARD_NUMERIC_LINE_LEN * 2) - 1;
      } else {
        keyboard->idx++;
      }
    }
    break;
  case KEYPAD_KEY_RIGHT:
    if ((keyboard->idx < (KEYBOARD_NUMERIC_LINE_LEN - 1)) ||
        ((keyboard->idx < ((KEYBOARD_NUMERIC_LINE_LEN * 2) - 1)) && (keyboard->idx >= KEYBOARD_NUMERIC_LINE_LEN)) ||
        (keyboard->idx == (KEYBOARD_NUMERIC_LINE_LEN * 2))) {
      keyboard->idx++;
    }  else {
      if (keyboard->idx == KEYBOARD_NUMERIC_LINE_LEN - 1) {
        keyboard->idx = 0;
      } else if (keyboard->idx == (KEYBOARD_NUMERIC_LINE_LEN * 2) - 1) {
        keyboard->idx = KEYBOARD_NUMERIC_LINE_LEN;
      } else {
        keyboard->idx--;
      }
    }
    break;
  case KEYPAD_KEY_DOWN:
    if (keyboard->idx < KEYBOARD_NUMERIC_LINE_LEN) {
      keyboard->idx += KEYBOARD_NUMERIC_LINE_LEN;
    } else if (keyboard->idx < (KEYBOARD_NUMERIC_LINE_LEN * 2)) {
      keyboard->idx = (KEYBOARD_NUMERIC_LINE_LEN * 2) + ((keyboard->idx == KEYBOARD_NUMERIC_LINE_LEN) ? 0 : 1);
    } else {
      keyboard->idx = (keyboard->idx == (KEYBOARD_NUMERIC_LINE_LEN * 2)) ? 0 : 1;
    }
    break;
  case KEYPAD_KEY_BACK:
    ret = g_ui_ctx.keypad.last_key_long ? KEY_ESCAPE : KEY_BACKSPACE;
    break;
  case KEYPAD_KEY_CONFIRM:
    if (g_ui_ctx.keypad.last_key_long) {
      ret = KEY_RETURN;
    } else {
      if (keyboard->idx == KEYBOARD_NUMERIC_SPACE_IDX) {
        ret = ' ';
      } else if (keyboard->idx == KEYBOARD_NUMERIC_ALPHA_IDX) {
        input_keyboard_blank();
        keyboard->idx = 0;
        keyboard->layout = KEYBOARD_LOWERCASE;
      } else {
        ret = '0' + (keyboard->idx + 1) % 10;
      }
    }
    break;
  default:
    break;
  }

  return ret;
}

static char input_keyboard(keyboard_state_t* keyboard, uint16_t suggestion_idx) {
  char c = KEY_NONE;

  while(c == KEY_NONE) {
    if (keyboard->layout == KEYBOARD_NUMERIC) {
      input_keyboard_render_numeric(keyboard);
      c = input_keyboard_navigate_numeric(keyboard);
    } else {
      input_keyboard_render_alpha(keyboard, suggestion_idx);
      c = input_keyboard_navigate_alpha(keyboard);
    }
  }

  return c;
}

static void input_nav_hints(uint8_t len, bool allow_dismiss, bool valid) {
  icon_t nav_left;

  if (len > 0) {
    nav_left = ICON_NAV_BACKSPACE;
  } else if (allow_dismiss) {
    nav_left = ICON_NAV_CANCEL;
  } else {
    nav_left = ICON_NONE;
  }

  icon_t nav_right;

  if (valid) {
    nav_right = ICON_NAV_NEXT_HOLD;
  } else {
    nav_right = ICON_NONE;
  }

  dialog_nav_hints(nav_left, nav_right);

  if (allow_dismiss) {
    screen_text_ctx_t ctx = { .font = TH_FONT_TEXT, .bg = TH_COLOR_BG, .fg = TH_COLOR_FG, .x = TH_NAV_HINT_INPUT_LEFT_X, .y = TH_NAV_HINT_INPUT_TOP };
    screen_draw_string(&ctx, LSTR(INPUT_NAV_EXIT));
  } else {
    screen_area_t hint_area = { .x = TH_NAV_HINT_INPUT_LEFT_X, .y = SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT, .width = TH_NAV_HINT_INPUT_LEFT_WIDTH, .height = TH_NAV_HINT_HEIGHT };
    screen_fill_area(&hint_area, TH_COLOR_BG);
  }

  if (valid) {
    screen_text_ctx_t ctx = { .font = TH_FONT_TEXT, .bg = TH_COLOR_BG, .fg = TH_COLOR_ACCENT, .x = TH_NAV_HINT_INPUT_RIGHT_X, .y = TH_NAV_HINT_INPUT_TOP };
    screen_draw_string(&ctx, LSTR(INPUT_NAV_SAVE));
  } else {
    screen_area_t hint_area = { .x = TH_NAV_HINT_INPUT_RIGHT_X, .y = SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT, .width = TH_NAV_HINT_INPUT_RIGHT_WIDTH, .height = TH_NAV_HINT_HEIGHT };
    screen_fill_area(&hint_area, TH_COLOR_BG);
  }
}

static void input_render_text_field(const char* str, const char* prompt, screen_area_t* field_area, int len, int suggestion_len) {
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
      .x = ctx.x + (TH_TEXT_FIELD_CURSOR_MARGIN/2),
      .y = field_area->y,
      .width = TH_TEXT_FIELD_CURSOR_WIDTH,
      .height = ctx.font->yAdvance
  };

  screen_fill_area(&cursor_area, TH_TEXT_FIELD_CURSOR_COLOR);
  ctx.x += TH_TEXT_FIELD_CURSOR_MARGIN + TH_TEXT_FIELD_CURSOR_WIDTH;
  ctx.fg = TH_TEXT_FIELD_SUGGESTION_FG;
  screen_draw_chars(&ctx, &str[len], suggestion_len);

  if (!len && !suggestion_len) {
    ctx.x += TH_TEXT_FIELD_CURSOR_MARGIN;
    screen_draw_string(&ctx, prompt);
  }
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

static inline void input_render_editable_text_field(const char* str, const char* prompt, int len, int suggestion_len) {
  screen_area_t field_area = {
      .x = TH_TEXT_FIELD_MARGIN,
      .y = TH_TEXT_FIELD_TOP,
      .width = SCREEN_WIDTH - (TH_TEXT_FIELD_MARGIN * 2),
      .height = TH_TEXT_FIELD_HEIGHT
  };

  input_render_text_field(str, prompt, &field_area, len, suggestion_len);
}

static void input_mnemonic_render(const char* word, int len, uint16_t idx) {
  int suggestion_len;

  if (idx != UINT16_MAX) {
    word = g_ui_cmd.params.mnemo.wordlist[idx];
    suggestion_len = strlen(word) - len;
  } else {
    suggestion_len = 0;
  }

  input_render_editable_text_field(word, LSTR(PROMPT_MNEMONIC), len, suggestion_len);
}

static void input_mnemonic_lookup(char* word, int len, uint16_t* idx, uint32_t* keymask, uint16_t *more_res) {
  *more_res = 0;
  *keymask = 0;

  if (len == 0) {
    *keymask = KEYBOARD_MNEMONIC_INITIAL_MASK;
    *idx = UINT16_MAX;
    return;
  }

  uint16_t i = 0;

  while (i < g_ui_cmd.params.mnemo.wordlist_len) {
    int cmp = strncmp(word, g_ui_cmd.params.mnemo.wordlist[i], len);

    if (cmp == 0) {
      *idx = i;

      *keymask |= 1 << (('z' - 'a') + 1);

      if (g_ui_cmd.params.mnemo.wordlist[i][len] != '\0') {
        *keymask |= (1 << (g_ui_cmd.params.mnemo.wordlist[i][len] - 'a'));
      }

      while(++i < g_ui_cmd.params.mnemo.wordlist_len) {
        if (strncmp(word, g_ui_cmd.params.mnemo.wordlist[i], len) != 0) {
          return;
        }

        if (g_ui_cmd.params.mnemo.wordlist[i][len] != '\0') {
          *keymask |= (1 << (g_ui_cmd.params.mnemo.wordlist[i][len] - 'a'));
        }

        (*more_res)++;

        uint8_t tmp = (*more_res + ('z' - 'a') + 1);
        // on ARM, the if is redundant but technically without it we enter undefined behavior territory
        if (tmp < (sizeof(uint32_t) * 8)) {
          *keymask |= 1 << tmp;
        }
      }
      return;
    } else if (cmp < 0) {
      *idx = UINT16_MAX;
      return;
    } else {
      i++;
    }
  }

  *idx = UINT16_MAX;
  return;
}

static app_err_t input_mnemonic_get_word(int i, uint16_t* idx) {
  input_mnemonic_title(i);
  dialog_blank(TH_TITLE_HEIGHT);

  char word[WORD_MAX_LEN];
  int len = 0;
  keyboard_state_t keyboard;
  keyboard.keymask = KEYBOARD_MNEMONIC_INITIAL_MASK;
  keyboard.idx = 0;
  keyboard.layout = KEYBOARD_MNEMONIC;
  uint16_t more_res = 0;
  bool valid = (*idx != UINT16_MAX);

  input_nav_hints(len, true, valid);

  while(1) {
    input_mnemonic_render(word, len, *idx);
    char c = input_keyboard(&keyboard, *idx);

    if (c == KEY_RETURN) {
      if (valid) {
        return ERR_OK;
      }
    } else if (c == KEY_ACK) {
      uint16_t idx_off = (keyboard.idx - KEYBOARD_MNEMONIC_SUGGESTION1_IDX);
      if (KEYBOARD_ENABLED((&keyboard), keyboard.idx)) {
        *idx += idx_off;
        return ERR_OK;
      }
    } else if (c == KEY_BACKSPACE) {
      if (len > 0) {
        len--;
        *idx = 0;
        input_mnemonic_lookup(word, len, idx, &keyboard.keymask, &more_res);
      }
    } else if (c == KEY_ESCAPE) {
      return ERR_CANCEL;
    } else if ((len < WORD_MAX_LEN) && KEYBOARD_ENABLED((&keyboard), keyboard.idx)) {
      word[len++] = c;
      input_mnemonic_lookup(word, len, idx, &keyboard.keymask, &more_res);
    }

    valid = (*idx != UINT16_MAX);
    input_nav_hints(len, true, valid);
  }
}

app_err_t input_mnemonic() {
  dialog_blank(TH_TITLE_HEIGHT);

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

static void input_render_mnemonic_word(int word_num, const char* str, screen_area_t* field_area) {
  screen_fill_area(field_area, TH_TEXT_FIELD_BG);
  dialog_ordered_point(field_area->x, field_area->y, word_num, str);
}

app_err_t input_display_mnemonic() {
  dialog_title(g_ui_cmd.params.mnemo.title);
  int page = 0;
  int page_len = g_ui_cmd.params.mnemo.len == 20 ? 10 : 12;
  int last_page = g_ui_cmd.params.mnemo.len == 12 ? 0 : 1;

  while(1) {
    dialog_blank(TH_TITLE_HEIGHT);

    screen_area_t field_area = {
        .y = TH_TITLE_HEIGHT + TH_MNEMONIC_TOP_MARGIN + TH_TEXT_VERTICAL_MARGIN,
        .width = TH_MNEMONIC_FIELD_WIDTH,
        .height = TH_TEXT_FIELD_HEIGHT
    };

    for (int i = 0; i < 6; i++) {
      field_area.x = TH_MNEMONIC_LEFT_MARGIN;

      for (int j = 0; j < ((page_len / 2) + 1); j += (page_len / 2)) {
        int word_num = (page * page_len) + (i + j);
        const char* word = g_ui_cmd.params.mnemo.wordlist[g_ui_cmd.params.mnemo.indexes[word_num]];
        input_render_mnemonic_word(word_num + 1, word, &field_area);
        field_area.x += TH_MNEMONIC_FIELD_WIDTH + TH_MNEMONIC_LEFT_MARGIN;
      }

      field_area.y += TH_ORDER_INDEX_SIZE + TH_MNEMONIC_TOP_MARGIN;
    }

    dialog_nav_hints(ICON_NAV_CANCEL, page == last_page ? ICON_NAV_NEXT : ICON_NONE);

    if (last_page > 0) {
      dialog_pager(page, last_page, true);
    }

    switch(ui_wait_keypress(pdMS_TO_TICKS(MNEMONIC_BACKUP_REFRESH_MS))) {
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
      hal_inactivity_timer_reset();
      break;
    }
  }
}

app_err_t input_string() {
  dialog_title(g_ui_cmd.params.input_string.title);
  dialog_blank(TH_TITLE_HEIGHT);

  int len = 0;
  keyboard_state_t keyboard;
  keyboard.keymask = UINT32_MAX;
  keyboard.idx = 0;
  keyboard.layout = KEYBOARD_LOWERCASE;
  bool allow_dismiss = !(g_ui_cmd.params.input_string.options & UI_READ_STRING_UNDISMISSABLE);
  bool allow_empty = g_ui_cmd.params.input_string.options & UI_READ_STRING_ALLOW_EMPTY;
  bool valid = allow_empty;

  input_nav_hints(len, allow_dismiss, valid);

  while(1) {
    input_render_editable_text_field(g_ui_cmd.params.input_string.out, g_ui_cmd.params.input_string.prompt, len, 0);
    char c = input_keyboard(&keyboard, UINT16_MAX);

    if (c == KEY_RETURN) {
      if (valid) {
        g_ui_cmd.params.input_string.out[len] = '\0';
        *g_ui_cmd.params.input_string.len = len;
        return ERR_OK;
      }
    } else if (c == KEY_BACKSPACE) {
      if (len > 0) {
        len--;
      }
    } else if (c == KEY_ESCAPE) {
      if (allow_dismiss) {
        return ERR_CANCEL;
      }
    } else if (len < *g_ui_cmd.params.input_string.len) {
      g_ui_cmd.params.input_string.out[len++] = c;
    }

    valid = (len > 0) || allow_empty;
    input_nav_hints(len, allow_dismiss, valid);
  }
}
