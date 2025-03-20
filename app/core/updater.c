#include "common.h"
#include "core.h"
#include "crypto/ecdsa.h"
#include "crypto/sha2.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "ethereum/eth_db.h"
#include "mem.h"
#include "iso7816/smartcard.h"
#include "storage/keys.h"
#include "pwr.h"
#include "ui/ui.h"
#include "ur/ur.h"

#define SIG_LEN 64
#define MIN_DB_LEN (SIG_LEN + 8)
#define UPDATE_SEGMENT_LEN 240
#define FW_UPGRADE_REBOOT_DELAY 150

#define MAX_INFO_SIZE 1024

static char* append_label(char* dst, const char* label) {
  size_t label_len = strlen(label);
  memcpy(dst, label, label_len);
  dst += label_len;
  *dst = '\0';
  return dst;
}

static char* append_fw_version(char* dst, const uint8_t* version) {
  uint8_t tmp[4];
  uint8_t* digits;

  for (int i = 0; i < 3; i++) {
    digits = u32toa(version[i], tmp, 4);
    size_t seg_len = strlen((char *) digits);
    memcpy(dst, digits, seg_len);
    dst += seg_len;
    *(dst++) = '.';
  }

  *(--dst) = '\0';

  return dst;
}

static char* append_db_version(char* dst, uint32_t version) {
  uint8_t tmp[11];
  uint8_t* digits = u32toa(version, tmp, 11);
  size_t seg_len = strlen((char* ) digits);
  memcpy(dst, digits, seg_len);
  dst += seg_len;
  *dst = '\0';

  return dst;
}

static char* append_sn(char* dst, const uint8_t uid[HAL_DEVICE_UID_LEN]) {
  memcpy(dst, &uid[6], 6);
  dst += 6;

  uint32_t wafer = uid[0] | (uid[2] << 8) | (uid[4] << 16);
  base16_encode((uint8_t*) &wafer, dst, 3);
  dst += 6;

  *dst = '\0';

  return dst;
}

void device_info() {
  char info[MAX_INFO_SIZE];
  char* p = append_label(info, LSTR(DEVICE_INFO_FW));
  p = append_fw_version(p, FW_VERSION);
  *(p++) = '\n';

  uint32_t db_ver;
  if (eth_db_lookup_version(&db_ver) == ERR_OK) {
    p = append_label(p, LSTR(DEVICE_INFO_DB));
    p = append_db_version(p, db_ver);
    *(p++) = '\n';
  }

  uint8_t device_uid[HAL_DEVICE_UID_LEN];
  hal_device_uid(device_uid);

  p = append_label(p, LSTR(DEVICE_INFO_SN));
  append_sn(p, device_uid);

  ui_prompt(LSTR(MENU_INFO), info, 0);
}

void device_help() {

}

static app_err_t updater_verify_db(uint8_t* data, size_t data_len) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  size_t len = data_len - SIG_LEN;

  sha256_Raw(data, len, digest);

  const uint8_t* key;
  key_read_public(DB_VERIFICATION_KEY, &key);
  return ecdsa_verify(&secp256k1, key, &data[len], digest) ? ERR_DATA : ERR_OK;
}

static app_err_t updater_confirm_database_update(uint32_t db_ver) {
  char info[MAX_INFO_SIZE];
  append_db_version(info, db_ver);

  if (ui_info(ICON_INFO_UPLOAD, LSTR(DB_UPDATE_CONFIRM), info, UI_INFO_CANCELLABLE | UI_INFO_NEXT) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  return ERR_OK;
}

static app_err_t updater_database_update(uint8_t* data, size_t len) {
  uint32_t version;

  if ((len < MIN_DB_LEN) ||
      (updater_verify_db(data, len) != ERR_OK) ||
      (eth_db_extract_version(data, &version) != ERR_OK)) {
    ui_info(ICON_INFO_ERROR, LSTR(DB_UPDATE_INVALID), NULL, 0);
    return ERR_DATA;
  }

  if (updater_confirm_database_update(version) != ERR_OK) {
    return ERR_CANCEL;
  }

  if (eth_db_update(data, len - SIG_LEN) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(DB_UPDATE_ERROR), NULL, 0);
    return ERR_DATA;
  } else {
    ui_info(ICON_INFO_ERROR, LSTR(DB_UPDATE_OK), NULL, 0);
  }

  return ERR_OK;
}

static app_err_t updater_prompt_version() {
  uint32_t db_ver;
  if (eth_db_lookup_version(&db_ver) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(DB_UPDATE_NO_DB), NULL, 0);
    return ERR_CANCEL;
  }

  char info[MAX_INFO_SIZE];

  char *p = append_label(info, LSTR(DB_UPDATE_PROMPT));
  p = append_label(p, LSTR(DEVICE_INFO_DB));
  append_db_version(p, db_ver);

  if (ui_prompt(LSTR(DB_UPDATE_TITLE), info, (UI_INFO_CANCELLABLE | UI_INFO_NEXT)) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  return ERR_OK;
}

void updater_database_run() {
  if (updater_prompt_version() != ERR_OK) {
    return;
  }

  data_t data;

  if (ui_qrscan(FS_DATA, &data) != CORE_EVT_UI_OK) {
    return;
  }

  updater_database_update(data.data, data.len);
}

static void updater_clear_flash_area() {
  const int fw_block = HAL_FLASH_ADDR_TO_BLOCK(HAL_FLASH_FW_UPGRADE_AREA);
  hal_flash_begin_program();

  for (int i = fw_block; i < (fw_block + HAL_FLASH_FW_BLOCK_COUNT); i++) {
    hal_flash_erase(i);
  }

  hal_flash_end_program();
}

static app_err_t updater_verify_firmware() {
  uint8_t* const fw_upgrade_area = (uint8_t*) HAL_FLASH_FW_UPGRADE_AREA;

  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha2;
  sha256_Init(&sha2);
  sha256_Update(&sha2, fw_upgrade_area, HAL_FW_HEADER_OFFSET);
  sha256_Update(&sha2, &fw_upgrade_area[HAL_FW_HEADER_OFFSET + SIG_LEN], ((HAL_FLASH_FW_BLOCK_COUNT * HAL_FLASH_BLOCK_SIZE) - (HAL_FW_HEADER_OFFSET + SIG_LEN)));
  sha256_Final(&sha2, digest);

  const uint8_t* key;
  key_read_public(FW_VERIFICATION_KEY, &key);
  return ecdsa_verify_raw_pub(&secp256k1, key, &fw_upgrade_area[HAL_FW_HEADER_OFFSET], digest) ? ERR_DATA : ERR_OK;
}

static inline void updater_fw_switch() {
  g_bootcmd = BOOTCMD_SWITCH_FW;
  pwr_reboot();
}

static inline uint8_t updater_progress() {
  if (g_core.data.msg.len == 0) {
    return 0;
  }

  return (g_core.data.msg.received * 100) / g_core.data.msg.len;
}

static app_err_t updater_confirm_fw_upgrade() {
  const char* prompt = LSTR(FW_UPGRADE_CONFIRM);
  size_t len = strlen(prompt);

  char info[MAX_INFO_SIZE];
  memcpy(info, prompt, len);

  uint32_t ver_off = ((uint32_t ) FW_VERSION) - HAL_FLASH_FW_START_ADDR;
  append_fw_version(info, (uint8_t*)(HAL_FLASH_FW_UPGRADE_AREA + ver_off));

  if (ui_info(ICON_INFO_UPLOAD, LSTR(FW_UPGRADE_CONFIRM), info, UI_INFO_CANCELLABLE | UI_INFO_NEXT) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  return ERR_OK;
}

app_err_t updater_usb_fw_upgrade(command_t *cmd, apdu_t* apdu) {
  apdu->has_lc = 1;
  uint8_t* data = APDU_DATA(apdu);
  size_t len = APDU_LC(apdu);
  uint8_t first_segment = APDU_P1(apdu) == 0;

  if (first_segment) {
    g_core.data.msg.len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    g_core.data.msg.received = 0;
    data += 4;
    len -= 4;

    updater_clear_flash_area();
  }

  if ((len % HAL_FLASH_WORD_SIZE) || g_core.data.msg.received >= (HAL_FLASH_FW_BLOCK_COUNT * HAL_FLASH_BLOCK_SIZE)) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  }

  uint8_t* const fw_upgrade_area = (uint8_t*) HAL_FLASH_FW_UPGRADE_AREA;
  hal_flash_begin_program();
  hal_flash_program(data, &fw_upgrade_area[g_core.data.msg.received], len);
  hal_flash_end_program();

  g_core.data.msg.received += len;
  ui_update_progress(LSTR(FW_UPGRADE_TITLE), updater_progress());

  if (g_core.data.msg.received > g_core.data.msg.len) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  } else if (g_core.data.msg.received == g_core.data.msg.len) {
    if (updater_verify_firmware() != ERR_OK) {
      updater_clear_flash_area();
      core_usb_err_sw(apdu, 0x6a, 0x80);
      ui_info(ICON_INFO_ERROR, LSTR(FW_UPGRADE_INVALID), NULL, 0);
      return ERR_DATA;
    }

    if (updater_confirm_fw_upgrade() == ERR_OK) {
      core_usb_err_sw(apdu, 0x90, 0x00);
      command_init_send(cmd);
      vTaskDelay(pdMS_TO_TICKS(FW_UPGRADE_REBOOT_DELAY));
      updater_fw_switch();
      return ERR_OK;
    } else {
      core_usb_err_sw(apdu, 0x69, 0x82);
      return ERR_CANCEL;
    }
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
  return ERR_NEED_MORE_DATA;
}

app_err_t updater_usb_db_upgrade(apdu_t* apdu) {
  apdu->has_lc = 1;
  uint8_t* data = APDU_DATA(apdu);
  size_t len = APDU_LC(apdu);
  uint8_t first_segment = APDU_P1(apdu) == 0;

  if (first_segment) {
    g_core.data.msg.len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    g_core.data.msg.received = 0;
    data += 4;
    len -= 4;
  }

  if ((g_core.data.msg.received + len) > MEM_HEAP_SIZE) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  }

  memcpy(&g_mem_heap[g_core.data.msg.received], data, len);

  g_core.data.msg.received += len;
  ui_update_progress(LSTR(DB_UPDATE_TITLE), updater_progress());

  if (g_core.data.msg.received > g_core.data.msg.len) {
    core_usb_err_sw(apdu, 0x6a, 0x80);
    return ERR_DATA;
  } else if (g_core.data.msg.received == g_core.data.msg.len) {
    if (updater_database_update(g_mem_heap, g_core.data.msg.len) != ERR_OK) {
      core_usb_err_sw(apdu, 0x6a, 0x80);
      return ERR_DATA;
    } else {
      core_usb_err_sw(apdu, 0x90, 0x00);
      return ERR_OK;
    }
  }

  core_usb_err_sw(apdu, 0x90, 0x00);
  return ERR_NEED_MORE_DATA;
}
