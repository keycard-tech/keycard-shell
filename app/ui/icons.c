#include "icons.h"

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

  //TODO: redo this
  ctx->x += 4;
  ctx->y += 1;
  ctx->fg = NAV_ICONS[icon].top_color;
  if (NAV_ICONS[icon].top >= SYM_HASHTAG) {
    ctx->font = TH_FONT_TEXT;
    screen_draw_char(ctx, NAV_ICONS[icon].top);
  }

  return ERR_OK;
}
