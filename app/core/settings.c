#include "settings.h"
#include "storage/fs.h"
#include "ui/ui.h"
#include "ui/i18n.h"
#include "usb/usb.h"

#include <string.h>

#define FS_SETTINGS 0x5331

struct __attribute__((packed)) settings_entry {
  fs_entry_t entry;
  settings_t settings;
};

settings_t g_settings;
static struct settings_entry* _settings_entry;

fs_action_t _settings_match_settings(void* ctx, fs_entry_t* entry) {
  return entry->magic == FS_SETTINGS ? FS_ACCEPT : FS_REJECT;
}

void settings_load() {
  i18n_set_strings(i18n_english_strings);
  _settings_entry = (struct settings_entry*) fs_find(_settings_match_settings, NULL);

  if (!_settings_entry) {
    g_settings.enable_usb = SETTINGS_DEF_ENABLE_USB;
    g_settings.lang = SETTINGS_DEF_LANG;
    g_settings.lcd_brightness = SETTINGS_DEF_LCD_BRIGHTNESS;
    g_settings.shutdown_timeout = SETTINGS_DEF_SHUTDOWN_TIMEOUT;
  } else {
    memcpy(&g_settings, &_settings_entry->settings, sizeof(settings_t));
  }
}

void settings_commit() {
  if (_settings_entry) {
    if (!memcmp(&g_settings, &_settings_entry->settings, sizeof(settings_t))) {
      return;
    }

    if (fs_erase(&_settings_entry->entry) != ERR_OK) {
      return;
    }
  }

  APP_ALIGNED(struct settings_entry entry, 4);
  entry.entry.magic = FS_SETTINGS;
  entry.entry.len = sizeof(settings_t);
  memcpy(&entry.settings, &g_settings, sizeof(settings_t));
  fs_write(&entry.entry, sizeof(struct settings_entry));
}

void settings_lcd_brightness() {
  uint8_t new_brightness = g_settings.lcd_brightness;
  if (ui_settings_brightness(&new_brightness) == CORE_EVT_UI_OK) {
    g_settings.lcd_brightness = new_brightness;
  }

  hal_pwm_set_dutycycle(PWM_BACKLIGHT, g_settings.lcd_brightness);
}

void settings_set_off_time() {
  i18n_str_id_t selected;

  switch(g_settings.shutdown_timeout) {
  case SETTINGS_SHUTDOWN_MINS(3):
    selected = MENU_OFF_3MINS;
    break;
  case SETTINGS_SHUTDOWN_MINS(5):
    selected = MENU_OFF_5MINS;
    break;
  case SETTINGS_SHUTDOWN_MINS(10):
    selected = MENU_OFF_10MINS;
    break;
  case SETTINGS_SHUTDOWN_MINS(30):
    selected = MENU_OFF_30MINS;
    break;
  case SETTINGS_SHUTDOWN_NEVER:
    selected = MENU_OFF_NEVER;
    break;
  default:
    selected = MENU_OFF_3MINS;
    break;
  }

  if (ui_menu(LSTR(AUTO_OFF_TITLE), &menu_autooff, &selected, selected, 0, UI_MENU_NOCANCEL, 0, 0) != CORE_EVT_UI_OK) {
    return;
  }

  switch(selected) {
  case MENU_OFF_3MINS:
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(3);
    break;
  case MENU_OFF_5MINS:
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(5);
    break;
  case MENU_OFF_10MINS:
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(10);
    break;
  case MENU_OFF_30MINS:
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(30);
    break;
  case MENU_OFF_NEVER:
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_NEVER;
    break;
  default:
    return;
  }

  hal_inactivity_timer_set(g_settings.shutdown_timeout);
}

void settings_usb_onoff() {
  i18n_str_id_t selected = g_settings.enable_usb ? MENU_ON : MENU_OFF;

  if (ui_menu(LSTR(USB_ENABLE_TITLE), &menu_onoff, &selected, selected, 0, UI_MENU_NOCANCEL, 0, 0) != CORE_EVT_UI_OK) {
    return;
  }

  bool prev = g_settings.enable_usb;
  g_settings.enable_usb = selected == MENU_OFF ? false : true;

  if (prev == g_settings.enable_usb) {
    return;
  } else if (g_settings.enable_usb) {
    usb_start_if_connected();
  } else {
    pwr_usb_unplugged(false);
  }
}
