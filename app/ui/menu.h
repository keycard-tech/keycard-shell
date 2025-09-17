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

typedef enum {
  UI_MENU_NOCANCEL = 1,
  UI_MENU_PAGED = 2
} ui_menu_opt_t;

extern const menu_t menu_mainmenu;
extern const menu_t menu_connect;
extern const menu_t menu_mnemonic;
extern const menu_t menu_mnemonic_length;
extern const menu_t menu_mnemonic_has_pass;
extern const menu_t menu_autooff;
extern const menu_t menu_onoff;
extern const menu_t menu_showhide;
extern const menu_t menu_keycard_blocked;
extern const menu_t menu_keycard_pair;

app_err_t menu_run();

#endif
