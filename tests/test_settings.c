#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "ui_host.h"
#include "core/settings.h"
#include "storage/fs.h"
#include "ui/i18n.h"

/*
 * settings.c is two writes and an erase away from the store, and four menus away from the user. The
 * store half is the interesting half: the entry is found by fs_find(), which answers the first match,
 * and the pointer it returns is kept in a file static that only load() refreshes -- so what commit()
 * does depends on whether anything has been read since the store last changed.
 *
 * The seam (host/ui_host.c) scripts the menus and remembers the setters. Whatever is not scripted
 * answers CORE_EVT_UI_CANCELLED, so an unscripted test reads as the user declining.
 */

#define MAGIC_OTHER 0x1234

static uint8_t* scratch;

void setUp(void) {
  if (scratch == NULL) {
    scratch = hal_host_low_mem(4096);
  }

  hal_host_flash_reset();
  host_ui_reset();
  settings_load();
}

void tearDown(void) {
}

struct census {
  uint32_t seen;
};

static fs_action_t keep_all(void* ctx, fs_entry_t* entry) {
  (void)entry;

  ((struct census*) ctx)->seen++;

  /* FS_ACCEPT means keep: a census leaves the store as it found it. */
  return FS_ACCEPT;
}

static uint32_t count_entries(void) {
  struct census census = { 0 };

  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase_all(keep_all, &census));
  return census.seen;
}

static void write_other_entry(void) {
  fs_entry_t* entry = (fs_entry_t*) scratch;

  entry->magic = MAGIC_OTHER;
  entry->len = 16;
  memset(scratch + sizeof(fs_entry_t), 0x5b, 16);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(entry, sizeof(fs_entry_t) + 16));
}

static void test_the_first_boot_loads_the_defaults(void) {
  TEST_ASSERT_EQUAL_UINT8(SETTINGS_DEF_LCD_BRIGHTNESS, g_settings.lcd_brightness);
  TEST_ASSERT_EQUAL_UINT32(SETTINGS_DEF_SHUTDOWN_TIMEOUT, g_settings.shutdown_timeout);
  TEST_ASSERT_EQUAL_INT(1, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_INT(0, g_settings.skip_help);

  /* Loading also puts the string table back, which is all a host can see of it: the device has one
   * language, so this is the arm that runs on every boot. */
  settings_load();
  TEST_ASSERT_EQUAL_STRING(i18n_english_strings[AUTO_OFF_TITLE], LSTR(AUTO_OFF_TITLE));
}

static void test_a_stored_entry_wins_over_the_defaults(void) {
  g_settings.lcd_brightness = 42;
  g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(30);
  g_settings.enable_usb = false;
  g_settings.skip_help = true;
  settings_commit();

  memset(&g_settings, 0, sizeof(g_settings));
  settings_load();

  TEST_ASSERT_EQUAL_UINT8(42, g_settings.lcd_brightness);
  TEST_ASSERT_EQUAL_UINT32(SETTINGS_SHUTDOWN_MINS(30), g_settings.shutdown_timeout);
  TEST_ASSERT_EQUAL_INT(0, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_INT(1, g_settings.skip_help);
  TEST_ASSERT_EQUAL_UINT(1, count_entries());
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());
}

static void test_the_first_entry_in_the_log_is_the_one_that_loads(void) {
  /* commit() remembers nothing: only load() sets the static pointer, so a second commit with nothing
   * read in between appends instead of replacing. What comes back after that is the older of the two,
   * because fs_find() stops at the first match -- the same shape as a duplicated whitelist card. */
  memset(&g_settings, 0, sizeof(g_settings));
  settings_commit();

  g_settings.lcd_brightness = 90;
  settings_commit();

  TEST_ASSERT_EQUAL_UINT(2, count_entries());

  settings_load();
  TEST_ASSERT_EQUAL_UINT8(0, g_settings.lcd_brightness);
}

static void test_a_commit_that_changes_nothing_writes_nothing(void) {
  settings_commit();

  settings_load();

  const size_t programs = hal_host_flash_programs();
  settings_commit();

  TEST_ASSERT_EQUAL_size_t(programs, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_UINT(1, count_entries());
}

static void test_a_failed_erase_leaves_the_old_entry(void) {
  g_settings.lcd_brightness = 60;
  settings_commit();
  settings_load();

  g_settings.lcd_brightness = 20;
  hal_host_flash_interrupt_after(-1, 0);
  settings_commit();
  hal_host_flash_interrupt_after(-1, -1);

  /* The erase is what makes room, so with nothing erased there is nothing to write and the stored
   * value is still the one a reload finds. */
  settings_load();
  TEST_ASSERT_EQUAL_UINT8(60, g_settings.lcd_brightness);
  TEST_ASSERT_EQUAL_UINT(1, count_entries());
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());
}

static void test_a_declined_factory_reset_changes_nothing(void) {
  g_settings.lcd_brightness = 33;
  settings_commit();
  write_other_entry();

  settings_factory_reset();

  TEST_ASSERT_EQUAL_UINT(0, host_ui_reboot_calls());
  TEST_ASSERT_EQUAL_UINT(2, count_entries());
}

static void test_a_factory_reset_empties_the_store_and_reboots(void) {
  g_settings.lcd_brightness = 33;
  settings_commit();
  write_other_entry();
  settings_load();

  const size_t programs = hal_host_flash_programs();
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  settings_factory_reset();

  TEST_ASSERT_EQUAL_UINT(1, host_ui_reboot_calls());
  TEST_ASSERT_EQUAL_UINT(0, count_entries());

  /* The reboot is there because the ordinary one would commit what is in RAM, writing back an entry
   * for a store that was just erased. */
  TEST_ASSERT_EQUAL_size_t(programs, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());
}

static void test_the_backlight_is_applied_whether_the_menu_agreed_or_not(void) {
  hal_pwm_set_dutycycle(PWM_BACKLIGHT, g_settings.lcd_brightness);

  host_ui_answer_brightness(CORE_EVT_UI_OK, 90);
  settings_lcd_brightness();

  TEST_ASSERT_EQUAL_UINT8(90, g_settings.lcd_brightness);
  TEST_ASSERT_EQUAL_UINT8(90, host_ui_pwm_dutycycle());

  host_ui_answer_brightness(CORE_EVT_UI_CANCELLED, 10);
  settings_lcd_brightness();

  TEST_ASSERT_EQUAL_UINT8(90, g_settings.lcd_brightness);
  TEST_ASSERT_EQUAL_UINT8(90, host_ui_pwm_dutycycle());
  TEST_ASSERT_EQUAL_UINT(3, host_ui_pwm_calls());
}

static void test_the_off_time_maps_both_ways(void) {
  g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(10);

  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_OFF_NEVER);
  settings_set_off_time();

  TEST_ASSERT_EQUAL_UINT(MENU_OFF_10MINS, host_ui_menu_marked());
  TEST_ASSERT_EQUAL_UINT32(SETTINGS_SHUTDOWN_NEVER, g_settings.shutdown_timeout);
  TEST_ASSERT_EQUAL_UINT32(SETTINGS_SHUTDOWN_NEVER, host_ui_inactivity_timeout());
  TEST_ASSERT_EQUAL_UINT(1, host_ui_inactivity_calls());

  /* A value the menu cannot name starts at three minutes, and a choice the timeout cannot name leaves
   * the setting alone and the timer untouched. */
  g_settings.shutdown_timeout = 1234;
  host_ui_answer_menu(CORE_EVT_UI_CANCELLED, 0);
  settings_set_off_time();
  TEST_ASSERT_EQUAL_UINT(MENU_OFF_3MINS, host_ui_menu_marked());

  const unsigned timer_calls = host_ui_inactivity_calls();
  g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(5);
  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_ON);
  settings_set_off_time();

  TEST_ASSERT_EQUAL_UINT32(SETTINGS_SHUTDOWN_MINS(5), g_settings.shutdown_timeout);
  TEST_ASSERT_EQUAL_UINT(timer_calls, host_ui_inactivity_calls());
}

static void test_every_off_time_value_has_a_menu_entry_and_back(void) {
  const struct {
    uint32_t timeout;
    i18n_str_id_t entry;
  } table[] = {
    { SETTINGS_SHUTDOWN_MINS(3), MENU_OFF_3MINS },
    { SETTINGS_SHUTDOWN_MINS(5), MENU_OFF_5MINS },
    { SETTINGS_SHUTDOWN_MINS(10), MENU_OFF_10MINS },
    { SETTINGS_SHUTDOWN_MINS(30), MENU_OFF_30MINS },
    { SETTINGS_SHUTDOWN_NEVER, MENU_OFF_NEVER },
  };

  for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
    g_settings.shutdown_timeout = SETTINGS_SHUTDOWN_MINS(3);
    host_ui_answer_menu(CORE_EVT_UI_OK, table[i].entry);
    settings_set_off_time();

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(table[i].timeout, g_settings.shutdown_timeout, "wrong minutes");
    TEST_ASSERT_EQUAL_UINT32(table[i].timeout, host_ui_inactivity_timeout());

    /* And the value it just stored is the one the menu opens on next time. */
    host_ui_answer_menu(CORE_EVT_UI_CANCELLED, 0);
    settings_set_off_time();
    TEST_ASSERT_EQUAL_UINT_MESSAGE(table[i].entry, host_ui_menu_marked(), "menu opens elsewhere");
  }
}

static void test_a_format_that_fails_says_so_and_stays_up(void) {
  host_ui_answer_prompt(CORE_EVT_UI_OK);
  hal_host_flash_refuse_unlock(true);
  settings_factory_reset();

  TEST_ASSERT_EQUAL_UINT(0, host_ui_reboot_calls());
  TEST_ASSERT_TRUE(host_ui_info_calls() > 0);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());

  hal_host_flash_refuse_unlock(false);
}

static void test_turning_usb_off_unplugs_it_and_on_needs_a_cable(void) {
  TEST_ASSERT_EQUAL_INT(1, g_settings.enable_usb);

  host_ui_answer_menu(CORE_EVT_UI_CANCELLED, 0);
  settings_usb_onoff();
  TEST_ASSERT_EQUAL_INT(1, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_usb_unplugged_calls());

  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_OFF);
  settings_usb_onoff();

  TEST_ASSERT_EQUAL_INT(0, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_usb_unplugged_calls());

  /* The same answer again is not a change, so the plug state is not announced twice. */
  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_OFF);
  settings_usb_onoff();
  TEST_ASSERT_EQUAL_UINT(1, host_ui_usb_unplugged_calls());

  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_ON);
  settings_usb_onoff();
  TEST_ASSERT_EQUAL_INT(1, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_UINT(0, host_ui_usb_plugged_calls());

  host_ui_vusb_connected(true);
  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_ON);
  g_settings.enable_usb = false;
  settings_usb_onoff();

  TEST_ASSERT_EQUAL_INT(1, g_settings.enable_usb);
  TEST_ASSERT_EQUAL_UINT(1, host_ui_usb_plugged_calls());
}

static void test_help_visibility_maps_to_show_and_hide(void) {
  g_settings.skip_help = false;

  host_ui_answer_menu(CORE_EVT_UI_CANCELLED, 0);
  settings_help_onoff();
  TEST_ASSERT_EQUAL_INT(0, g_settings.skip_help);

  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_HIDE);
  settings_help_onoff();

  TEST_ASSERT_EQUAL_UINT(MENU_SHOW, host_ui_menu_marked());
  TEST_ASSERT_EQUAL_INT(1, g_settings.skip_help);

  host_ui_answer_menu(CORE_EVT_UI_OK, MENU_SHOW);
  settings_help_onoff();
  TEST_ASSERT_EQUAL_INT(0, g_settings.skip_help);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_the_first_boot_loads_the_defaults);
  RUN_TEST(test_a_stored_entry_wins_over_the_defaults);
  RUN_TEST(test_the_first_entry_in_the_log_is_the_one_that_loads);
  RUN_TEST(test_a_commit_that_changes_nothing_writes_nothing);
  RUN_TEST(test_a_failed_erase_leaves_the_old_entry);
  RUN_TEST(test_a_declined_factory_reset_changes_nothing);
  RUN_TEST(test_a_factory_reset_empties_the_store_and_reboots);
  RUN_TEST(test_the_backlight_is_applied_whether_the_menu_agreed_or_not);
  RUN_TEST(test_the_off_time_maps_both_ways);
  RUN_TEST(test_every_off_time_value_has_a_menu_entry_and_back);
  RUN_TEST(test_a_format_that_fails_says_so_and_stays_up);
  RUN_TEST(test_turning_usb_off_unplugs_it_and_on_needs_a_cable);
  RUN_TEST(test_help_visibility_maps_to_show_and_hide);

  return UNITY_END();
}
