#ifndef __MENU__
#define __MENU__

#include <stdint.h>
#include "i18n.h"
#include "error.h"

struct _menu;

typedef struct {
  i18n_str_id_t label_id;
  const struct _menu* submenu;
} menu_entry_t;

typedef struct _menu {
  uint8_t len;
  menu_entry_t entries[];
} menu_t;

extern const menu_t menu_mainmenu;
extern const menu_t menu_mnemonic;
extern const menu_t menu_mnemonic_import;
extern const menu_t menu_mnemonic_generate;
extern const menu_t menu_autooff;
extern const menu_t menu_onoff;
extern const menu_t menu_keycard_blocked;
extern const menu_t menu_keycard_pair;

app_err_t menu_run();

#endif
