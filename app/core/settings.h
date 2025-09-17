#ifndef __CORE_SETTINGS__
#define __CORE_SETTINGS__

#include "common.h"
#include <stdbool.h>

#define SETTINGS_SHUTDOWN_SECS(__TIME__) (__TIME__ * 1000)
#define SETTINGS_SHUTDOWN_MINS(__TIME__) SETTINGS_SHUTDOWN_SECS(__TIME__ * 60)
#define SETTINGS_SHUTDOWN_NEVER UINT32_MAX

#define SETTINGS_DEF_SHUTDOWN_TIMEOUT SETTINGS_SHUTDOWN_MINS(3)
#define SETTINGS_DEF_LCD_BRIGHTNESS 75
#define SETTINGS_DEF_ENABLE_USB 1
#define SETTINGS_DEF_SKIP_HELP 0

typedef struct __attribute__((packed)) {
  uint8_t lcd_brightness;
  bool skip_help;
  bool enable_usb;
  uint32_t shutdown_timeout;
} settings_t;

extern settings_t g_settings;

void settings_load();
void settings_commit();

void settings_lcd_brightness();
void settings_set_off_time();
void settings_usb_onoff();
void settings_help_onoff();

#endif
