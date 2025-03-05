#include "card.h"
#include "core.h"
#include "keycard/keycard_cmdset.h"
#include "pwr.h"

void card_change_name() {
  char name[KEYCARD_NAME_MAX_LEN + 1];
  uint8_t len = KEYCARD_NAME_MAX_LEN;

  if (ui_read_string(LSTR(MENU_CARD_NAME), name, &len) != CORE_EVT_UI_OK) {
    return;
  }

  if (keycard_set_name(&g_core.keycard, name) == ERR_OK) {
    ui_info(LSTR(CARD_NAME_CHANGE_SUCCESS), 1);
  } else {
    ui_card_transport_error();
  }
}

void card_change_pin() {
  SC_BUF(pin, KEYCARD_PIN_LEN);

  if (ui_read_pin(pin, PIN_NEW_CODE, 1) != CORE_EVT_UI_OK) {
    return;
  }

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PIN, pin, KEYCARD_PIN_LEN);
  memset(pin, 0, KEYCARD_PIN_LEN);

  if (err == ERR_OK) {
    ui_info(LSTR(PIN_CHANGE_SUCCESS), 1);
  } else {
    ui_card_transport_error();
  }
}

void card_change_puk() {
  SC_BUF(puk, KEYCARD_PUK_LEN);

  if (ui_read_puk(puk, PUK_NEW_CODE, 1) != CORE_EVT_UI_OK) {
    return;
  }

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PUK, puk, KEYCARD_PUK_LEN);
  memset(puk, 0, KEYCARD_PUK_LEN);

  if (err == ERR_OK) {
    ui_info(LSTR(PUK_CHANGE_SUCCESS), 1);
  } else {
    ui_card_transport_error();
  }
}

void card_change_pairing() {
  if (ui_prompt(LSTR(PAIRING_CHANGE_TITLE), LSTR(PAIRING_CHANGE_PROMPT)) != CORE_EVT_UI_OK) {
    return;
  }

  SC_BUF(password, KEYCARD_PAIRING_PASS_MAX_LEN);
  uint8_t len = KEYCARD_PAIRING_PASS_MAX_LEN;

  if (ui_read_string(LSTR(PAIRING_CREATE_TITLE), (char *) password, &len) != CORE_EVT_UI_OK) {
    return;
  }

  uint8_t pairing[32];

  keycard_pairing_password_hash(password, len, pairing);
  memset(password, 0, len);

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PAIRING, pairing, 32);

  if (err == ERR_OK) {
    ui_info(LSTR(PAIRING_CHANGE_SUCCESS), 1);
  } else {
    ui_card_transport_error();
  }
}

void card_reset() {
  if (keycard_factoryreset(&g_core.keycard) == ERR_OK) {
    pwr_reboot();
  }
}
