#include "core_multisig.h"

#include <string.h>

#include "bitcoin/multisig.h"
#include "bitcoin/multisig_crypto.h"
#include "core.h"
#include "crypto/memzero.h"
#include "storage/multisig_store.h"
#include "ui/ui.h"

#define MULTISIG_REF_MAX MULTISIG_MAX_KEYS
#define MULTISIG_SER_MAX 512
#define MULTISIG_TXT_MAX 512

/* Scratch state. Only one multisig action runs at a time in the core task. */
static multisig_t s_desc;
static multisig_entry_t* s_refs[MULTISIG_REF_MAX];
static uint8_t s_ser[MULTISIG_SER_MAX];
static char s_txt[MULTISIG_TXT_MAX];

/*
 * Open a multisig crypto session: export the EIP1581 private scalar from the
 * card and derive the per-card keys + search blob. The card is already
 * authenticated (PIN) from activation, so no extra prompt is needed.
 */
static app_err_t multisig_session_open(multisig_crypto_t* m) {
  uint8_t path_bytes[MULTISIG_EIP1581_PATH_LEN * 4];
  uint8_t root[MULTISIG_ROOT_LEN];

  for (int i = 0; i < MULTISIG_EIP1581_PATH_LEN; i++) {
    uint32_t v = multisig_eip1581_path[i];
    path_bytes[i * 4] = (v >> 24) & 0xff;
    path_bytes[i * 4 + 1] = (v >> 16) & 0xff;
    path_bytes[i * 4 + 2] = (v >> 8) & 0xff;
    path_bytes[i * 4 + 3] = v & 0xff;
  }

  app_err_t err = core_export_private(&g_core.keycard, path_bytes, sizeof(path_bytes), root);
  if (err != ERR_OK) {
    memzero(root, sizeof(root));
    return err;
  }

  multisig_crypto_init(m, root, g_core.master_fingerprint);
  memzero(root, sizeof(root));
  return ERR_OK;
}

/*
 * List the descriptors stored for this card and let the user pick one,
 * decrypting it into `out`. Returns false if cancelled / none stored.
 */
static bool multisig_pick(multisig_crypto_t* m, multisig_t* out) {
  size_t count = multisig_store_list(m, s_refs, MULTISIG_REF_MAX);
  if (count > MULTISIG_REF_MAX) count = MULTISIG_REF_MAX;

  if (count == 0) {
    ui_info(ICON_INFO_ERROR, LSTR(MULTISIG_NO_DESCRIPTORS_MSG), LSTR(MULTISIG_NO_DESCRIPTORS_SUB), 0);
    return false;
  }

  uint32_t sel = 0;
  if (count > 1) {
    if (ui_read_number(LSTR(MULTISIG_PICK_TITLE), 0, count - 1, &sel, true) != CORE_EVT_UI_OK) {
      return false;
    }
  }
  if (sel >= count) return false;

  size_t ser_len;
  if (multisig_store_read(m, s_refs[sel], s_ser, sizeof(s_ser), &ser_len) != ERR_OK) return false;
  if (multisig_deserialize(s_ser, ser_len, out) != ERR_OK) return false;
  return true;
}

void core_multisig_import() {
  multisig_crypto_t m;
  multisig_t d;
  struct zcbor_string desc;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  if (ui_qrscan(BYTES, &desc) != CORE_EVT_UI_OK) {
    multisig_crypto_wipe(&m);
    return;
  }

  if (multisig_parse_text((const char*) desc.value, desc.len, &d) != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(MULTISIG_IMPORT_INVALID_MSG), LSTR(MULTISIG_IMPORT_INVALID_SUB), 0);
    multisig_crypto_wipe(&m);
    return;
  }

  if (ui_prompt(LSTR(MULTISIG_TITLE), LSTR(MULTISIG_IMPORT_CONFIRM), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    multisig_crypto_wipe(&m);
    return;
  }

  size_t ser_len;
  app_err_t err = multisig_serialize(&d, s_ser, sizeof(s_ser), &ser_len);
  if (err == ERR_OK) {
    err = multisig_store_save(&m, s_ser, ser_len);
  }
  memzero(s_ser, sizeof(s_ser));
  multisig_crypto_wipe(&m);

  if (err != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return;
  }

  ui_info(ICON_INFO_SUCCESS, LSTR(MULTISIG_IMPORT_OK_MSG), LSTR(MULTISIG_IMPORT_OK_SUB), 0);
}

void core_multisig_browse() {
  multisig_crypto_t m;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  if (!multisig_pick(&m, &s_desc)) {
    multisig_crypto_wipe(&m);
    return;
  }

  uint32_t index = 0;
  do {
    char addr[MAX_ADDR_LEN];

    if (multisig_derive_address(&s_desc, 0, index, addr) != ERR_OK) {
      ui_info(ICON_INFO_ERROR, LSTR(MULTISIG_IMPORT_INVALID_MSG), LSTR(MULTISIG_IMPORT_INVALID_SUB), 0);
      multisig_crypto_wipe(&m);
      return;
    }

    if (ui_display_address_qr(LSTR(MULTISIG_ADDR_TITLE), addr, &index) == CORE_EVT_UI_CANCELLED) {
      ui_read_number_direct(LSTR(ADDRESS_INDEX_TITLE), &index);
    }
  } while (index != UINT32_MAX);

  multisig_crypto_wipe(&m);
}

void core_multisig_export() {
  multisig_crypto_t m;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  if (!multisig_pick(&m, &s_desc)) {
    multisig_crypto_wipe(&m);
    return;
  }

  multisig_to_text(&s_desc, s_txt, sizeof(s_txt));
  ui_display_msg_qr(LSTR(MULTISIG_ADDR_TITLE), s_txt, s_desc.name);

  multisig_crypto_wipe(&m);
}

void core_multisig_delete() {
  multisig_crypto_t m;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  size_t count = multisig_store_list(&m, s_refs, MULTISIG_REF_MAX);
  if (count > MULTISIG_REF_MAX) count = MULTISIG_REF_MAX;

  if (count == 0) {
    ui_info(ICON_INFO_ERROR, LSTR(MULTISIG_NO_DESCRIPTORS_MSG), LSTR(MULTISIG_NO_DESCRIPTORS_SUB), 0);
    multisig_crypto_wipe(&m);
    return;
  }

  uint32_t sel = 0;
  if (count > 1) {
    if (ui_read_number(LSTR(MULTISIG_PICK_TITLE), 0, count - 1, &sel, true) != CORE_EVT_UI_OK) {
      multisig_crypto_wipe(&m);
      return;
    }
  }
  if (sel >= count) {
    multisig_crypto_wipe(&m);
    return;
  }

  if (ui_prompt(LSTR(MULTISIG_TITLE), LSTR(MULTISIG_DELETE_CONFIRM), UI_INFO_DANGEROUS) != CORE_EVT_UI_OK) {
    multisig_crypto_wipe(&m);
    return;
  }

  multisig_store_delete(&m, s_refs[sel]);
  multisig_crypto_wipe(&m);

  ui_info(ICON_INFO_SUCCESS, LSTR(MULTISIG_DELETE_OK_MSG), LSTR(MULTISIG_DELETE_OK_SUB), 0);
}
