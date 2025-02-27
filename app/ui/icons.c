#include "icons.h"
#include <string.h>

typedef struct {
  char base;
  char top;
  uint16_t base_color;
  uint16_t top_color;
} composite_icon_desc_t;

const static composite_icon_desc_t NAV_ICONS[] = {
    {.base = NAV_CIRCLE_FULL, .top = SYM_RIGHT_CHEVRON, .base_color = TH_COLOR_ACCENT, .top_color = TH_COLOR_FG},
    {.base = NAV_CIRCLE_EMPTY, .top = SYM_RIGHT_CHEVRON, .base_color = TH_COLOR_ACCENT, .top_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_EMPTY, .top = NAV_CANCEL_GLYPH, .base_color = TH_COLOR_FG, .top_color = TH_COLOR_FG},
    {.base = NAV_CIRCLE_FULL, .top = SYM_RIGHT_CHEVRON, .base_color = TH_COLOR_FG, .top_color = TH_COLOR_BG},
    {.base = NAV_BACKSPACE_EMPTY, .top = NAV_CANCEL_GLYPH, .base_color = TH_COLOR_FG, .top_color = TH_COLOR_FG},
};

app_err_t icon_draw_nav(screen_text_ctx_t* ctx, nav_icon_t icon) {
  ctx->font = TH_NAV_ICONS;

  ctx->fg = NAV_ICONS[icon].base_color;
  screen_draw_char(ctx, NAV_ICONS[icon].base);

  if (NAV_ICONS[icon].top_color != NAV_ICONS[icon].base_color) {
    ctx->bg = ctx->fg;
  }

  ctx->fg = NAV_ICONS[icon].top_color;
  if (NAV_ICONS[icon].top >= SYM_HASHTAG) {
    ctx->font = TH_FONT_TEXT;
  }

  const glyph_t *top_original = screen_lookup_glyph(ctx->font, NAV_ICONS[icon].top);
  glyph_t top;
  memcpy(&top, top_original, sizeof(glyph_t));

  top.xOffset = 0;
  top.yOffset = -ctx->font->baseline;
  top.xAdvance = top.width;
  ctx->x += ((TH_NAV_ICONS)->yAdvance - top.width) / 2;
  ctx->y += ((TH_NAV_ICONS)->yAdvance - top.height) / 2;

  screen_draw_glyph(ctx, &top);

  return ERR_OK;
}
