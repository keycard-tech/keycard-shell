#ifndef _UI_SETTINGS_
#define _UI_SETTINGS_

#include <stdint.h>
#include "error.h"
#include "screen/screen.h"

app_err_t settings_ui_lcd_brightness();
app_err_t settings_ui_update_progress();
app_err_t settings_ui_devinfo();
app_err_t settings_ui_dbinfo();

#endif
