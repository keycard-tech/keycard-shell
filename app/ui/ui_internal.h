#ifndef _UI_INTERNAL_
#define _UI_INTERNAL_

#include "FreeRTOS.h"
#include "task.h"

#include "menu.h"
#include "dialog.h"
#include "input.h"
#include "keypad/keypad.h"
#include "bitcoin/bitcoin.h"
#include "core/core.h"
#include "ethereum/ethUstream.h"
#include "qrcode/qrcode.h"
#include "ur/ur_types.h"
#include "ur/ur.h"

#define UI_NOTIFICATION_IDX 2

#define UI_CMD_EVT 1
#define UI_KEY_EVT 2

extern struct ui_cmd g_ui_cmd;
extern struct ui_ctx g_ui_ctx;

enum cmd_type {
  UI_CMD_INFO,
  UI_CMD_PROMPT,
  UI_CMD_MENU,
  UI_CMD_DISPLAY_ETH_TX,
  UI_CMD_DISPLAY_BTC_TX,
  UI_CMD_DISPLAY_MSG,
  UI_CMD_DISPLAY_EIP712,
  UI_CMD_DISPLAY_QR,
  UI_CMD_DISPLAY_ADDRESS_QR,
  UI_CMD_DISPLAY_MSG_QR,
  UI_CMD_QRSCAN,
  UI_CMD_INPUT_PIN,
  UI_CMD_INPUT_PUK,
  UI_CMD_INPUT_STRING,
  UI_CMD_INPUT_MNEMO,
  UI_CMD_DISPLAY_MNEMO,
  UI_CMD_LCD_BRIGHTNESS,
  UI_CMD_PROGRESS,
  UI_CMD_DEVINFO,
  UI_CMD_DBINFO,
#ifdef TEST_APP
  UI_CMD_KEYPAD_TEST,
  UI_CMD_LCD_TEST,
#endif
};

struct cmd_info {
  const char* msg;
  const char* subtext;
  info_icon_t icon;
  ui_info_opt_t options;
};

struct cmd_prompt {
  const char* title;
  const char* msg;
  ui_info_opt_t options;
};

struct cmd_eth_txn {
  const uint8_t* addr;
  const txContent_t* tx;
};

struct cmd_btc_txn {
  const btc_tx_ctx_t* tx;
};

struct cmd_msg {
  addr_type_t addr_type;
  const uint8_t* addr;
  const uint8_t* data;
  uint32_t len;
};

struct cmd_eip712 {
  const uint8_t* addr;
  const eip712_ctx_t* data;
};

struct cmd_qrout {
  const char* title;
  const uint8_t* data;
  uint32_t len;
  ur_type_t type;
};

struct cmd_address_qr {
  const char* title;
  const char* address;
  uint32_t* index;
};

struct cmd_msg_qr {
  const char* title;
  const char* msg;
  const char* label;
};

struct cmd_menu {
  const char* title;
  const menu_t* menu;
  i18n_str_id_t* selected;
  i18n_str_id_t marked;
};

struct cmd_qrscan {
  void* out;
  ur_type_t type;
};

struct cmd_input_pin {
  uint8_t* out;
  int8_t retries;
  uint8_t dismissable;
};

struct cmd_input_string {
  const char* title;
  char* out;
  uint8_t* len;
  ui_read_string_opt_t options;
};

struct cmd_mnemo {
  uint16_t* indexes;
  uint32_t len;
};

struct cmd_brightness {
  uint8_t* brightness;
};

struct cmd_progress {
  const char* title;
  uint8_t value;
};

struct cmd_devinfo {
  const char* fw_version;
  const char* db_version;
  const char* sn;
};

union cmd_params {
  struct cmd_info info;
  struct cmd_prompt prompt;
  struct cmd_eth_txn eth_tx;
  struct cmd_btc_txn btc_tx;
  struct cmd_msg msg;
  struct cmd_eip712 eip712;
  struct cmd_qrout qrout;
  struct cmd_address_qr address;
  struct cmd_msg_qr qrmsg;
  struct cmd_menu menu;
  struct cmd_qrscan qrscan;
  struct cmd_input_pin input_pin;
  struct cmd_input_string input_string;
  struct cmd_mnemo mnemo;
  struct cmd_brightness lcd;
  struct cmd_progress progress;
  struct cmd_devinfo devinfo;
};

struct ui_cmd {
  enum cmd_type type;
  uint8_t received;
  app_err_t result;
  union cmd_params params;
};

struct ui_ctx {
  keypad_t keypad;
  uint8_t battery;
};

static inline uint32_t ui_wait_event(uint32_t timeout) {
  uint32_t evt;
  return xTaskNotifyWaitIndexed(UI_NOTIFICATION_IDX, 0, UINT32_MAX, &evt, timeout) == pdPASS ? evt : 0;
}

static inline keypad_key_t ui_wait_keypress(uint32_t timeout) {
  uint32_t evt = ui_wait_event(timeout);

  if (evt & UI_CMD_EVT) {
    g_ui_cmd.received = 1;
    return KEYPAD_KEY_CANCEL;
  } else if (evt & UI_KEY_EVT) {
    return g_ui_ctx.keypad.last_key;
  }

  return KEYPAD_KEY_INVALID;
}

static inline void ui_signal() {
  xTaskNotifyIndexed(APP_TASK(ui), UI_NOTIFICATION_IDX, UI_CMD_EVT, eSetBits);
}

static inline core_evt_t ui_signal_wait(uint8_t allow_usb) {
  ui_signal();
  return core_wait_event(portMAX_DELAY, allow_usb);
}

#endif
