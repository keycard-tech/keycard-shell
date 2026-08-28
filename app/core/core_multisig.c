#include "core_multisig.h"

#include <string.h>

#include "bitcoin/multisig.h"
#include "bitcoin/multisig_crypto.h"
#include "core.h"
#include "crypto/memzero.h"
#include "mem.h"
#include "storage/multisig_store.h"
#include "ui/i18n.h"
#include "ui/ui.h"
#include "ur/ur.h"
#include "ur/ur_encode.h"
#include "zcbor_common.h"

#define MULTISIG_REF_MAX MULTISIG_MAX_KEYS
#define MULTISIG_SER_MAX 768

static app_err_t multisig_session_open(multisig_crypto_t* m) {
  uint8_t path_bytes[MULTISIG_EIP1581_PATH_LEN * 4];
  uint8_t root[MULTISIG_ROOT_LEN];

  for (int i = 0; i < MULTISIG_EIP1581_PATH_LEN; i++) {
    uint32_t v = MULTISIG_EIP1581_PATH[i];
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

static multisig_entry_t* multisig_pick_entry(multisig_crypto_t* m) {
  multisig_entry_t* refs[MULTISIG_REF_MAX];
  uint8_t ser[MULTISIG_SER_MAX];
  char names[MULTISIG_REF_MAX][MULTISIG_MAX_NAME_LEN];
  const char* name_ptrs[MULTISIG_REF_MAX];
  uint8_t menu_buf[sizeof(menu_t) + MULTISIG_REF_MAX * sizeof(menu_entry_t)];
  menu_t* menu = (menu_t*) menu_buf;

  size_t count = multisig_store_list(m, refs, MULTISIG_REF_MAX);
  if (count > MULTISIG_REF_MAX) count = MULTISIG_REF_MAX;

  if (count == 0) {
    ui_info(ICON_INFO_ERROR, LSTR(MULTISIG_NO_DESCRIPTORS_MSG), LSTR(MULTISIG_NO_DESCRIPTORS_SUB), 0);
    return NULL;
  }

  for (size_t i = 0; i < count; i++) {
    size_t ser_len;
    if (multisig_store_read(m, refs[i], ser, sizeof(ser), &ser_len) != ERR_OK) {
      return NULL;
    }

    size_t name_len = 0;
    if (ser_len >= 5) {
      name_len = ser[4];
    }
    if (name_len >= MULTISIG_MAX_NAME_LEN || ser_len < (5 + name_len)) {
      names[i][0] = '\0';
    } else {
      memcpy(names[i], &ser[5], name_len);
      names[i][name_len] = '\0';
    }
    name_ptrs[i] = names[i];
  }

  /* Build a dynamic list menu over the names (label_id = index into it). */
  menu->len = (uint8_t) count;
  for (size_t i = 0; i < count; i++) {
    menu->entries[i].label_id = (i18n_str_id_t) i;
    menu->entries[i].submenu = NULL;
  }

  const char* const* saved = *i18n_strings;
  i18n_set_strings(name_ptrs);

  i18n_str_id_t sel = 0;
  core_evt_t evt = ui_menu(LSTR(MULTISIG_PICK_TITLE), menu, &sel, -1, 0, 0, 0, 0);

  i18n_set_strings(saved);

  if (evt != CORE_EVT_UI_OK || sel >= count) {
    return NULL;
  }
  return refs[sel];
}

static bool multisig_pick(multisig_crypto_t* m, multisig_t* out) {
  multisig_entry_t* entry = multisig_pick_entry(m);
  if (entry == NULL) return false;

  uint8_t ser[MULTISIG_SER_MAX];
  size_t ser_len;
  if (multisig_store_read(m, entry, ser, sizeof(ser), &ser_len) != ERR_OK) return false;
  if (multisig_deserialize(ser, ser_len, out) != ERR_OK) return false;
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
  uint8_t ser[MULTISIG_SER_MAX];
  app_err_t err = multisig_serialize(&d, ser, sizeof(ser), &ser_len);
  if (err == ERR_OK) {
    err = multisig_store_save(&m, ser, ser_len);
  }
  memzero(ser, sizeof(ser));
  multisig_crypto_wipe(&m);

  if (err != ERR_OK) {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_MALFORMED_DATA_MSG), LSTR(INFO_MALFORMED_DATA_SUB), 0);
    return;
  }

  ui_info(ICON_INFO_SUCCESS, LSTR(MULTISIG_IMPORT_OK_MSG), LSTR(MULTISIG_IMPORT_OK_SUB), 0);
}

void core_multisig_browse() {
  multisig_crypto_t m;
  multisig_t desc;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  if (!multisig_pick(&m, &desc)) {
    multisig_crypto_wipe(&m);
    return;
  }

  uint32_t index = 0;
  do {
    char addr[MAX_ADDR_LEN];

    if (multisig_derive_address(&desc, 0, index, addr) != ERR_OK) {
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
  multisig_t desc;
  char* txt = (char*) g_mem_heap;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  if (!multisig_pick(&m, &desc)) {
    multisig_crypto_wipe(&m);
    return;
  }

  multisig_to_text(&desc, txt, MEM_HEAP_SIZE);
  struct zcbor_string qr_out;
  qr_out.value = (const uint8_t*) txt;
  qr_out.len = strlen(txt);
  size_t out_len;

  uint8_t *out_buf = &g_mem_heap[qr_out.len];
  cbor_encode_psbt(out_buf, MEM_HEAP_SIZE - qr_out.len, &qr_out, &out_len);

  ui_display_ur_qr(LSTR(MULTISIG_ADDR_TITLE), out_buf, out_len, BYTES);

  multisig_crypto_wipe(&m);
}

void core_multisig_delete() {
  multisig_crypto_t m;

  if (multisig_session_open(&m) != ERR_OK) {
    ui_card_transport_error();
    return;
  }

  multisig_entry_t* entry = multisig_pick_entry(&m);
  if (entry == NULL) {
    multisig_crypto_wipe(&m);
    return;
  }

  if (ui_prompt(LSTR(MULTISIG_TITLE), LSTR(MULTISIG_DELETE_CONFIRM), UI_INFO_DANGEROUS) != CORE_EVT_UI_OK) {
    multisig_crypto_wipe(&m);
    return;
  }

  multisig_store_delete(&m, entry);
  multisig_crypto_wipe(&m);

  ui_info(ICON_INFO_SUCCESS, LSTR(MULTISIG_DELETE_OK_MSG), LSTR(MULTISIG_DELETE_OK_SUB), 0);
}
