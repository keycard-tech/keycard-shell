#include "icons.h"
#include <string.h>

typedef struct {
  char base;
  char top;
  bool stroked;
  uint16_t base_color;
} composite_icon_desc_t;

const static composite_icon_desc_t NAV_ICONS[] = {
    {.base = NAV_CIRCLE_FULL, .top = SYM_RIGHT_CHEVRON, .stroked = false, .base_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_EMPTY, .top = SYM_RIGHT_CHEVRON, .stroked = true, .base_color = TH_COLOR_ACCENT},
    {.base = NAV_CIRCLE_EMPTY, .top = SYM_CANCEL, .stroked = true, .base_color = TH_COLOR_FG},
    {.base = NAV_BACKSPACE_EMPTY, .top = SYM_CANCEL, .stroked = true, .base_color = TH_COLOR_FG},
    {.base = NAV_CIRCLE_FULL, .top = SYM_CHECKMARK, .stroked = false, .base_color = TH_COLOR_ACCENT},
};

app_err_t icon_draw(screen_text_ctx_t* ctx, icon_t icon) {
  ctx->font = TH_NAV_ICONS;

  ctx->fg = NAV_ICONS[icon].base_color;
  screen_draw_char(ctx, NAV_ICONS[icon].base);

  if (!NAV_ICONS[icon].stroked) {
    ctx->fg = ctx->bg;
    ctx->bg = NAV_ICONS[icon].base_color;
  }

  ctx->font = TH_FONT_TEXT;

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
