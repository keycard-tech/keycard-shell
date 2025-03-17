#include "app_tasks.h"
#include "core/core.h"
#include "crypto/rand.h"
#include "crypto/bip39.h"
#include "mem.h"
#include "error.h"
#include "ui.h"
#include "ui_internal.h"

#define MNEMO_WORDS_TO_CONFIRM 4
#define MNEMO_CHOICE_COUNT 3

core_evt_t ui_qrscan(ur_type_t type, void* out) {
  g_ui_cmd.type = UI_CMD_QRSCAN;
  g_ui_cmd.params.qrscan.out = out;
  g_ui_cmd.params.qrscan.type = type;
  return ui_signal_wait(0);
}

core_evt_t ui_qrscan_tx(ur_type_t* type, void* out) {
  core_evt_t res = ui_qrscan(UR_ANY_TX, out);
  *type = g_ui_cmd.params.qrscan.type;
  return res;
}

core_evt_t ui_menu(const char* title, const menu_t* menu, i18n_str_id_t* selected, i18n_str_id_t marked, uint8_t allow_usb) {
  g_ui_cmd.type = UI_CMD_MENU;
  g_ui_cmd.params.menu.title = title;
  g_ui_cmd.params.menu.menu = menu;
  g_ui_cmd.params.menu.selected = selected;
  g_ui_cmd.params.menu.marked = marked;
  return ui_signal_wait(allow_usb);
}

core_evt_t ui_display_eth_tx(const uint8_t* address, const txContent_t* tx) {
  g_ui_cmd.type = UI_CMD_DISPLAY_ETH_TX;
  g_ui_cmd.params.eth_tx.addr = address;
  g_ui_cmd.params.eth_tx.tx = tx;
  return ui_signal_wait(0);
}

core_evt_t ui_display_btc_tx(const btc_tx_ctx_t* tx) {
  g_ui_cmd.type = UI_CMD_DISPLAY_BTC_TX;
  g_ui_cmd.params.btc_tx.tx = tx;
  return ui_signal_wait(0);
}

core_evt_t ui_display_msg(addr_type_t addr_type, const uint8_t* address, const uint8_t* msg, uint32_t len) {
  g_ui_cmd.type = UI_CMD_DISPLAY_MSG;
  g_ui_cmd.params.msg.addr_type = addr_type;
  g_ui_cmd.params.msg.addr = address;
  g_ui_cmd.params.msg.data = msg;
  g_ui_cmd.params.msg.len = len;
  return ui_signal_wait(0);
}

core_evt_t ui_display_eip712(const uint8_t* address, const eip712_ctx_t* eip712) {
  g_ui_cmd.type = UI_CMD_DISPLAY_EIP712;
  g_ui_cmd.params.eip712.addr = address;
  g_ui_cmd.params.eip712.data = eip712;
  return ui_signal_wait(0);
}

core_evt_t ui_display_ur_qr(const char* title, const uint8_t* data, uint32_t len, ur_type_t type) {
  g_ui_cmd.type = UI_CMD_DISPLAY_QR;
  g_ui_cmd.params.qrout.title = title;
  g_ui_cmd.params.qrout.data = data;
  g_ui_cmd.params.qrout.len = len;
  g_ui_cmd.params.qrout.type = type;
  return ui_signal_wait(0);
}

core_evt_t ui_display_address_qr(const char* title, const char* address, uint32_t* index) {
  g_ui_cmd.type = UI_CMD_DISPLAY_ADDRESS_QR;
  g_ui_cmd.params.address.title = title;
  g_ui_cmd.params.address.address = address;
  g_ui_cmd.params.address.index = index;

  return ui_signal_wait(0);
}

core_evt_t ui_info(info_icon_t icon, const char* msg, const char* subtext, ui_info_opt_t opts) {
  g_ui_cmd.type = UI_CMD_INFO;
  g_ui_cmd.params.info.icon = icon;
  g_ui_cmd.params.info.msg = msg;
  g_ui_cmd.params.info.subtext = subtext;
  g_ui_cmd.params.info.options = opts;
  return ui_signal_wait(0);
}

core_evt_t ui_prompt(const char* title, const char* msg) {
  g_ui_cmd.type = UI_CMD_PROMPT;
  g_ui_cmd.params.prompt.title = title;
  g_ui_cmd.params.prompt.msg = msg;
  return ui_signal_wait(0);
}

core_evt_t ui_wrong_auth(const char* msg, uint8_t retries) {
  size_t label_len = strlen(LSTR(PIN_LABEL_REMAINING_ATTEMPTS));
  char remaining_attempts[label_len + 2];
  memcpy(remaining_attempts, LSTR(PIN_LABEL_REMAINING_ATTEMPTS), label_len);
  remaining_attempts[label_len] = retries + '0';
  remaining_attempts[label_len + 1] = '\0';

  g_ui_cmd.type = UI_CMD_INFO;
  g_ui_cmd.params.info.icon = ICON_INFO_ERROR;
  g_ui_cmd.params.info.msg = msg;
  g_ui_cmd.params.info.subtext = remaining_attempts;
  g_ui_cmd.params.info.options = UI_INFO_NEXT;
  return ui_signal_wait(0);
}

void ui_card_inserted() {

}

void ui_card_removed() {
}

void ui_card_transport_error() {
  ui_info(ICON_INFO_ERROR, LSTR(INFO_CARD_ERROR_MSG), LSTR(INFO_CARD_ERROR_SUB), UI_INFO_UNDISMISSABLE);
}

void ui_card_accepted() {
}

void ui_keycard_wrong_card() {
  ui_info(ICON_INFO_ERROR, LSTR(INFO_NOT_KEYCARD), NULL, UI_INFO_UNDISMISSABLE);
}

void ui_keycard_old_card() {
  ui_info(ICON_INFO_ERROR, LSTR(INFO_OLD_KEYCARD), NULL, UI_INFO_UNDISMISSABLE);
}

void ui_keycard_not_initialized() {
}

void ui_keycard_init_failed() {
}

void ui_keycard_no_keys() {
}

void ui_keycard_ready() {
}

void ui_keycard_paired() {
}

void ui_keycard_already_paired() {
}

void ui_keycard_pairing_failed() {
}

void ui_keycard_flash_failed() {
}

void ui_keycard_secure_channel_failed() {
}

void ui_keycard_secure_channel_ok() {
}

void ui_keycard_pin_ok() {
}

void ui_keycard_puk_ok() {
}

void ui_keycard_wrong_pin(uint8_t retries) {
  if (retries > 0) {
    ui_wrong_auth(LSTR(PIN_WRONG_WARNING), retries);
  } else {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_KEYCARD_BLOCKED), NULL, 0);
  }
}

void ui_keycard_wrong_puk(uint8_t retries) {
  ui_wrong_auth(LSTR(PUK_WRONG_WARNING), retries);
}

core_evt_t ui_keycard_not_genuine() {
  return ui_prompt("", LSTR(INFO_NOT_GENUINE));
}

core_evt_t ui_prompt_try_puk() {
  i18n_str_id_t selected = MENU_UNBLOCK_PUK;
  while (ui_menu(LSTR(INFO_KEYCARD_BLOCKED), &menu_keycard_blocked, &selected, -1, 0) != CORE_EVT_UI_OK) {
    ;
  }

  return selected == MENU_RESET_CARD ? CORE_EVT_UI_CANCELLED : CORE_EVT_UI_OK;
}

core_evt_t ui_confirm_factory_reset() {
  return ui_prompt(LSTR(FACTORY_RESET_TITLE), LSTR(FACTORY_RESET_WARNING));
}

core_evt_t ui_keycard_no_pairing_slots() {
  return ui_info(ICON_INFO_ERROR, LSTR(INFO_NO_PAIRING_SLOTS), NULL, 0);
}

core_evt_t ui_read_pin(uint8_t* out, int8_t retries, uint8_t dismissable) {
  g_ui_cmd.type = UI_CMD_INPUT_PIN;
  g_ui_cmd.params.input_pin.dismissable = dismissable;
  g_ui_cmd.params.input_pin.retries = retries;
  g_ui_cmd.params.input_pin.out = out;

  return ui_signal_wait(0);
}

core_evt_t ui_read_puk(uint8_t* out, int8_t retries, uint8_t dismissable) {
  g_ui_cmd.type = UI_CMD_INPUT_PUK;
  g_ui_cmd.params.input_pin.dismissable = dismissable;
  g_ui_cmd.params.input_pin.retries = retries;
  g_ui_cmd.params.input_pin.out = out;

  return ui_signal_wait(0);
}

core_evt_t ui_read_pairing(uint8_t* pairing, uint8_t *len) {
  while(ui_read_string(LSTR(PAIRING_INPUT_TITLE), (char*) pairing, len) != CORE_EVT_UI_OK) {
    continue;
  }

  return CORE_EVT_UI_OK;
}

core_evt_t ui_read_string(const char* title, char* out, uint8_t* len) {
  g_ui_cmd.type = UI_CMD_INPUT_STRING;
  g_ui_cmd.params.input_string.title = title;
  g_ui_cmd.params.input_string.out = out;
  g_ui_cmd.params.input_string.len = len;

  return ui_signal_wait(0);
}

void ui_seed_loaded() {
}

core_evt_t ui_read_mnemonic_len(uint32_t* len) {
  i18n_str_id_t mode_selected = MENU_MNEMO_IMPORT;
  core_evt_t ret;

  while(1) {
    const menu_t* word_menu;

    if (ui_menu(LSTR(MNEMO_TITLE), &menu_mnemonic, &mode_selected, -1, 0) == CORE_EVT_UI_OK) {
      if (mode_selected == MENU_MNEMO_IMPORT) {
        ret = CORE_EVT_UI_OK;
        word_menu = &menu_mnemonic_import;
      } else {
        ret = CORE_EVT_UI_CANCELLED;
        word_menu = &menu_mnemonic_generate;
      }

      i18n_str_id_t selected = MENU_MNEMO_12WORDS;
      if (ui_menu(LSTR(mode_selected), word_menu, &selected, -1, 0) == CORE_EVT_UI_OK) {
        switch(selected) {
        case MENU_MNEMO_12WORDS:
          *len = 12;
          break;
        case MENU_MNEMO_18WORDS:
          *len = 18;
          break;
        case MENU_MNEMO_24WORDS:
        default:
          *len = 24;
          break;
        }

        return ret;
      }
    }
  }
}
core_evt_t ui_display_mnemonic(uint16_t* indexes, uint32_t len) {
  g_ui_cmd.type = UI_CMD_DISPLAY_MNEMO;
  g_ui_cmd.params.mnemo.indexes = indexes;
  g_ui_cmd.params.mnemo.len = len;

  return ui_signal_wait(0);
}

static app_err_t ui_backup_confirm_mnemonic(uint16_t* indexes, uint32_t len) {
  const char* const* tmp = *i18n_strings;

  if (ui_prompt(LSTR(MNEMO_BACKUP_TITLE), LSTR(MNEMO_VERIFY_PROMPT)) != CORE_EVT_UI_OK) {
    return ERR_OK;
  }

  uint8_t positions[MNEMO_WORDS_TO_CONFIRM];
  random_unique_in_range(len, MNEMO_WORDS_TO_CONFIRM, positions);

  const char* base_title = LSTR(MNEMO_WORD_BACKUP_TITLE);
  size_t base_len = strlen(base_title);
  char title[strlen(base_title) + 4];
  memcpy(title, base_title, base_len);
  title[base_len + 2] = '\0';

  menu_t* choices = (menu_t*)g_mem_heap;
  choices->len = MNEMO_CHOICE_COUNT;

  int retries = 3;

  for (int i = 0; i < MNEMO_WORDS_TO_CONFIRM; i++) {
    uint8_t pos = positions[i] + 1;

    if (pos > 9) {
      title[base_len] = (pos / 10) + '0';
      title[base_len+1] = (pos % 10) + '0';
    } else {
      title[base_len] = (pos % 10) + '0';
      title[base_len+1] = '\0';
    }

    bool correct_included = false;

    for (int j = 0; j < MNEMO_CHOICE_COUNT; j++) {
      choices->entries[j].submenu = NULL;

      bool duplicate;

      do {
        duplicate = false;
        choices->entries[j].label_id = random_uniform(BIP39_WORD_COUNT);
        for(int k = 0; k < j; k++) {
          if (choices->entries[j].label_id == choices->entries[k].label_id) {
            duplicate = true;
            break;
          }
        }
      } while(duplicate);

      if (choices->entries[j].label_id == indexes[pos - 1]) {
        correct_included = true;
      }
    }

    if (!correct_included) {
      choices->entries[random_uniform(MNEMO_CHOICE_COUNT)].label_id = indexes[pos - 1];
    }

    bool correct = false;

    do {
      i18n_str_id_t selected = choices->entries[0].label_id;

      i18n_set_strings(BIP39_WORDLIST_ENGLISH);
      core_evt_t err = ui_menu(title, choices, &selected, -1, 0);
      i18n_set_strings(tmp);

      if (err != CORE_EVT_UI_OK) {
        return ERR_CANCEL;
      }

      if (selected != indexes[pos - 1]) {
        if (--retries == 0) {
          ui_info(ICON_INFO_ERROR, LSTR(MNEMO_MISMATCH_LIMIT), NULL, 0);
          return ERR_CANCEL;
        } else {
          ui_wrong_auth(LSTR(MNEMO_MISMATCH), retries);
        }
      } else {
        correct = true;
      }
    } while(!correct);
  }

  return ERR_OK;
}

core_evt_t ui_backup_mnemonic(uint16_t* indexes, uint32_t len) {
  ui_info(ICON_INFO_ERROR, LSTR(MNEMO_BACKUP_PROMPT), NULL, 0);

  do {
    if (ui_display_mnemonic(indexes, len) == CORE_EVT_UI_CANCELLED) {
      return CORE_EVT_UI_CANCELLED;
    }
  } while(ui_backup_confirm_mnemonic(indexes, len) != ERR_OK);

  return CORE_EVT_UI_OK;
}

core_evt_t ui_read_mnemonic(uint16_t* indexes, uint32_t len) {
  g_ui_cmd.type = UI_CMD_INPUT_MNEMO;
  g_ui_cmd.params.mnemo.indexes = indexes;
  g_ui_cmd.params.mnemo.len = len;

  return ui_signal_wait(0);
}

core_evt_t ui_confirm_eth_address(const char* address) {
  return CORE_EVT_UI_OK;
}

core_evt_t ui_device_auth(uint32_t first_auth, uint32_t auth_time, uint32_t auth_count) {
  g_ui_cmd.type = UI_CMD_DEV_AUTH;
  g_ui_cmd.params.auth.first_auth = first_auth;
  g_ui_cmd.params.auth.auth_time = auth_time;
  g_ui_cmd.params.auth.auth_count = auth_count;

  return ui_signal_wait(0);
}

core_evt_t ui_settings_brightness(uint8_t* brightness) {
  g_ui_cmd.type = UI_CMD_LCD_BRIGHTNESS;
  g_ui_cmd.params.lcd.brightness = brightness;

  return ui_signal_wait(0);
}

void ui_update_progress(const char* title, uint8_t progress) {
  g_ui_cmd.type = UI_CMD_PROGRESS;
  g_ui_cmd.params.progress.title = title;
  g_ui_cmd.params.progress.value = progress;

  return ui_signal();
}
