#ifdef TEST_APP
#include "FreeRTOS.h"
#include "task.h"

#include "common.h"
#include "core/core.h"
#include "core/settings.h"
#include "keycard/keycard.h"
#include "keycard/keycard_cmdset.h"
#include "mem.h"
#include "ui/ui_internal.h"
#include "usb/usb.h"
#include "ur/ur.h"
#include "ur/ur_types.h"
#include "ur/ur_encode.h"

#define TEST_AID_LEN 9
const uint8_t TEST_AID[] = {0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01};

#define INS_TEST_INFO 0x02
#define INS_TEST_RUN 0x04
#define INS_TEST_END 0x06

#define P1_TEST_USB 0x01
#define P1_TEST_KEYPAD 0x02
#define P1_TEST_BUTTON 0x03
#define P1_TEST_BACKLIGHT 0x04
#define P1_TEST_LCD 0x05
#define P1_TEST_CARD 0x06
#define P1_TEST_CARD_PRESENCE 0x07
#define P1_TEST_CAMERA 0x08

app_err_t core_usb_get_app_config(apdu_t* cmd);

core_evt_t ui_info_usb(const char* msg) {
  g_ui_cmd.type = UI_CMD_INFO;
  g_ui_cmd.params.info.dismissable = 1;
  g_ui_cmd.params.info.msg = msg;

  while (ui_signal_wait(1) != CORE_EVT_USB_CMD) {
    continue;
  }

  return CORE_EVT_USB_CMD;
}

static void core_keypad_test(apdu_t* apdu) {
  g_ui_cmd.type = UI_CMD_INPUT_STRING;
  if (ui_signal_wait(0) != CORE_EVT_UI_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x01);
    return;
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_button_test(apdu_t* apdu) {
  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_backlight_test(apdu_t* apdu) {
  hal_pwm_set_dutycycle(PWM_BACKLIGHT, 10);

  if (ui_prompt("Brightness test", "Screen is at minimum brightness. Press is OK if readable, cancel otherwise") != CORE_EVT_UI_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x01);
    return;
  }

  hal_pwm_set_dutycycle(PWM_BACKLIGHT, 100);
  if (ui_prompt("Brightness test", "Screen is at full brightness. Press is OK if very bright, cancel otherwise") != CORE_EVT_UI_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x02);
    return;
  }

  hal_pwm_set_dutycycle(PWM_BACKLIGHT, 75);

  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_lcd_test(apdu_t* apdu) {
  g_ui_cmd.type = UI_CMD_LCD_TEST;
  if (ui_signal_wait(0) != CORE_EVT_UI_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x01);
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_camera_test(apdu_t* apdu) {
  struct dev_auth auth;

  if (ui_qrscan(DEV_AUTH, &auth) != CORE_EVT_UI_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x01);
    return;
  }

  if (memcmp(auth.dev_auth_challenge.dev_auth_challenge.value, "0123456789abcdefABCDEF9876543210", 32)) {
    core_usb_err_sw(apdu, 0x6f, 0x02);
    return;
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_card_test(apdu_t* apdu) {
  while (hal_gpio_get(GPIO_SMARTCARD_PRESENT) == GPIO_RESET) {
    ui_info("Insert card and press OK", 1);
  }

  keycard_init(&g_core.keycard);
  smartcard_activate(&g_core.keycard.sc);

  if (g_core.keycard.sc.state != SC_READY) {
    core_usb_err_sw(apdu, 0x6f, 0x01);
    return;
  }

  if (keycard_cmd_select(&g_core.keycard, TEST_AID, TEST_AID_LEN) != ERR_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x02);
    return;
  }

  if (APDU_SW(&g_core.keycard.apdu) != SW_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x03);
    return;
  }

  app_info_t info;
  if (application_info_parse(APDU_RESP(&g_core.keycard.apdu), &info) != ERR_OK) {
    core_usb_err_sw(apdu, 0x6f, 0x04);
    return;
  }

  smartcard_deactivate(&g_core.keycard.sc);

  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_card_presence_test(apdu_t* apdu) {
  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_usb_test(apdu_t* apdu) {
  core_usb_err_sw(apdu, 0x90, 0x00);
}

static void core_test_run(apdu_t* apdu) {
  switch(APDU_P1(apdu)) {
  case P1_TEST_USB:
    core_usb_test(apdu);
    break;
  case P1_TEST_KEYPAD:
    core_keypad_test(apdu);
    break;
  case P1_TEST_BUTTON:
    core_button_test(apdu);
    break;
  case P1_TEST_BACKLIGHT:
    core_backlight_test(apdu);
    break;
  case P1_TEST_LCD:
    core_lcd_test(apdu);
    break;
  case P1_TEST_CARD:
    core_card_test(apdu);
    break;
  case P1_TEST_CARD_PRESENCE:
    core_card_presence_test(apdu);
    break;
  case P1_TEST_CAMERA:
    core_camera_test(apdu);
  default:
    core_usb_err_sw(apdu, 0x6a, 0x86);
  }
}

static void core_test_end(apdu_t* apdu) {
  core_usb_err_sw(apdu, 0x90, 0x00);
  command_init_send(&g_core.usb_command);
  vTaskDelay(pdMS_TO_TICKS(20));

  g_bootcmd = BOOTCMD_SWITCH_FW;
  hal_reboot();
}

static void core_test_process_cmd() {
  apdu_t* apdu = &g_core.usb_command.apdu;

  if (APDU_CLA(apdu) != 0xe0) {
    core_usb_err_sw(apdu, 0x6e, 0x00);
  } else {
    switch(APDU_INS(apdu)) {
    case INS_TEST_INFO:
      core_usb_get_app_config(apdu);
      break;
    case INS_TEST_RUN:
      core_test_run(apdu);
      break;
    case INS_TEST_END:
      core_test_end(apdu);
      break;
    default:
      core_usb_err_sw(apdu, 0x6d, 0x00);
      break;
    }
  }

  command_init_send(&g_core.usb_command);
}

void core_task_entry(void* pvParameters) {
  while (usb_connected()) {
    ui_info("Unplug USB and press OK", 1);
  }

  g_core.ready = true;

  ui_info_usb("Plug USB and connect testbench");

  while (1) {
    core_test_process_cmd();
    ui_info_usb("Waiting for next command...");
  }
}
#endif
