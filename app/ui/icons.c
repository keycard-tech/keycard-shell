#include "icons.h"
#include <string.h>

#define ICON_ATTR_X_MASK 0x03
#define ICON_ATTR_Y_MASK 0x0C

typedef enum {
  ICON_ATTR_STROKED = 0x10,
  ICON_ATTR_INHERIT_FG = 0x20,
  ICON_ATTR_NOTOP = 0x40
} icon_attr_t;


typedef struct {
  char base;
  char top;
  uint8_t attr;
  uint16_t base_color;
} composite_icon_desc_t;

const static composite_icon_desc_t NAV_ICONS[] = {
    {.base = NAV_CIRCLE_FULL, .top = SYM_RIGHT_CHEVRON, .attr = 1, .base_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_EMPTY, .top = SYM_RIGHT_CHEVRON, .attr = (ICON_ATTR_STROKED | 1), .base_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_EMPTY, .top = SYM_CANCEL, .attr = (ICON_ATTR_STROKED | ICON_ATTR_INHERIT_FG), .base_color = 0},
    {.base = NAV_BACKSPACE_EMPTY, .top = SYM_CANCEL, .attr = (ICON_ATTR_STROKED | ICON_ATTR_INHERIT_FG | 2) , .base_color = 0},
    {.base = NAV_CIRCLE_FULL, .top = SYM_CHECKMARK, .attr = (1 << 2), .base_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_FULL, .top = SYM_CHECKMARK, .attr = (1 << 2), .base_color = TH_COLOR_SUCCESS},
    {.base = NAV_CIRCLE_FULL, .top = SYM_CROSS, .attr = 0, .base_color = TH_COLOR_ERROR},
    {.base = NAV_CIRCLE_EMPTY, .top = 0, .attr = (ICON_ATTR_STROKED | ICON_ATTR_INHERIT_FG | ICON_ATTR_NOTOP), .base_color = 0},
    {.base = NAV_CIRCLE_FULL, .top = 0, .attr = (ICON_ATTR_INHERIT_FG | ICON_ATTR_NOTOP), .base_color = 0},
    {.base = NAV_CIRCLE_FULL_SMALL, .top = 0, .attr = ICON_ATTR_NOTOP, .base_color = TH_COLOR_INACTIVE},
};

const static uint16_t INFO_ICONS[] = { TH_COLOR_SUCCESS, TH_COLOR_ERROR, TH_COLOR_FG, TH_COLOR_ERROR };

app_err_t icon_draw(const screen_text_ctx_t* ctx, icon_t icon) {
  screen_text_ctx_t c_ctx;
  memcpy(&c_ctx, ctx, sizeof(screen_text_ctx_t));

  c_ctx.font = TH_NAV_ICONS;

  if (!(NAV_ICONS[icon].attr & ICON_ATTR_INHERIT_FG)) {
    c_ctx.fg = NAV_ICONS[icon].base_color;
  }

  screen_draw_char(&c_ctx, NAV_ICONS[icon].base);

  if (NAV_ICONS[icon].attr & ICON_ATTR_NOTOP) {
    return ERR_OK;
  }

  if (!(NAV_ICONS[icon].attr & ICON_ATTR_STROKED)) {
    c_ctx.bg = c_ctx.fg;
    c_ctx.fg = ctx->bg;
  }

  c_ctx.font = TH_FONT_TEXT;

  const glyph_t *top_original = screen_lookup_glyph(c_ctx.font, NAV_ICONS[icon].top);
  glyph_t top;
  memcpy(&top, top_original, sizeof(glyph_t));

  top.xOffset = 0;
  top.yOffset = -c_ctx.font->baseline;
  top.xAdvance = top.width;

  c_ctx.x += (((TH_NAV_ICONS)->yAdvance - top.width) / 2) + (NAV_ICONS[icon].attr & ICON_ATTR_X_MASK);
  c_ctx.y += (((TH_NAV_ICONS)->yAdvance - top.height) / 2) + ((NAV_ICONS[icon].attr & ICON_ATTR_Y_MASK) >> 2);

  screen_draw_glyph(&c_ctx, &top);

  return ERR_OK;
}

app_err_t icon_draw_info(const screen_text_ctx_t* ctx, info_icon_t icon) {
  screen_text_ctx_t c_ctx;
  memcpy(&c_ctx, ctx, sizeof(screen_text_ctx_t));

  c_ctx.fg = INFO_ICONS[icon - 2];
  c_ctx.font = TH_INFO_ICONS;
  screen_draw_char(&c_ctx, ICON_INFO_BASE);
  c_ctx.x += 12;
  screen_draw_char(&c_ctx, icon);

  return ERR_OK;
}
