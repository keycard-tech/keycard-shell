#ifndef _UI_SETTINGS_
#define _UI_SETTINGS_

#include "error.h"
#include "screen/screen.h"

void ui_progressbar_render(const screen_area_t* area, uint8_t val);
app_err_t settings_ui_lcd_brightness();
app_err_t settings_ui_update_progress();
app_err_t settings_ui_devinfo();

#endif
