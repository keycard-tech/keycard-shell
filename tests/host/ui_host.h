#ifndef _UI_HOST_H_
#define _UI_HOST_H_

#include <stdbool.h>
#include <stdint.h>

#include "ui/i18n.h"
#include "ui/ui.h"

/*
 * The human-facing side of the device, scripted. Menus and prompts answer what the test says and
 * remember what they were asked; the setters -- backlight, inactivity timer, USB power, reboot --
 * record their argument and do nothing else, because there is nothing else to do. Reboot returns,
 * which is the one thing a test has to know rather than feel.
 *
 * Whatever is not scripted answers CORE_EVT_UI_CANCELLED, so a test that forgot to script a menu gets
 * the user declining rather than an approval nobody asked for.
 */

void host_ui_reset(void);

/* The last UR the shell put on screen. Unlike the other screens this one's argument is the protocol
 * itself -- the bytes a wallet scans -- so the seam keeps them, copied because the caller hands over a
 * pool it reuses for the next item. NULL when nothing has been shown since the reset. */
const uint8_t* host_ui_ur_qr(uint32_t* len, ur_type_t* type);

void host_ui_answer_menu(core_evt_t answer, i18n_str_id_t chosen);
void host_ui_answer_prompt(core_evt_t answer);
void host_ui_answer_brightness(core_evt_t answer, uint8_t value);
void host_ui_vusb_connected(bool connected);

unsigned host_ui_menu_calls(void);
unsigned host_ui_info_calls(void);
unsigned host_ui_prompt_calls(void);
unsigned host_ui_brightness_calls(void);
unsigned host_ui_pwm_calls(void);
unsigned host_ui_inactivity_calls(void);
unsigned host_ui_usb_plugged_calls(void);
unsigned host_ui_usb_unplugged_calls(void);
unsigned host_ui_reboot_calls(void);

/* The keycard-facing calls: notices are recorded under the name the code called, in order, and the
 * few that wait for the user answer what is scripted here -- CORE_EVT_UI_CANCELLED otherwise. */
unsigned host_ui_call_count(const char* name);
const char* host_ui_call_at(unsigned i);
void host_ui_answer_call(const char* name, core_evt_t answer);
/* What the seam hands back for a named call: what was scripted, or a refusal. The seam files consult
 * it; a test scripts with host_ui_answer_call(). */
core_evt_t host_ui_answer_for(const char* name);
void host_ui_script_pin(const uint8_t pin[6]);
void host_ui_script_puk(const uint8_t puk[12]);
/* The first PUK prompt answered with this, later ones with the scripted PUK. */
void host_ui_script_wrong_puk(const uint8_t puk[12]);
void host_ui_script_pairing(uint8_t idx);
/* What the mnemonic menu answers: generate or import, how many words, and whether a passphrase is
 * asked for. The length is what tells the shell BIP-39 from SLIP-39. */
void host_ui_script_mnemonic(i18n_str_id_t mode, uint32_t len, bool has_pass);
/* What a text field is answered with -- the BIP-39 passphrase, for one. */
void host_ui_script_string(const char* text);
/* The word indexes an importer or a QR scan returns, as indexes rather than words: the conversion
 * belongs to the caller, which has the wordlist's library in its link and the seam does not. */
void host_ui_script_indexes(const uint16_t* indexes, uint32_t count);
/* An imported SLIP-39 group: the shards, and the encrypted master secret they combine to -- which
 * is what the screen hands back, not what any single mnemonic carries. */
void host_ui_script_slip39(const slip39_shard_t* shards, uint8_t count,
                           const uint8_t ems[SLIP39_SEED_STRENGTH]);
uint8_t host_ui_wrong_pin_retries(void);
uint8_t host_ui_wrong_puk_retries(void);

void host_ui_keycard_reset(void);

/* The call log above, shared by every file of the seam. `host_ui_record` is what a seam function calls
 * on its way to `host_ui_answer_for`; `host_ui_record_progress` is the progress bar, whose reading a
 * test reads back with `host_ui_progress_at`, oldest first. */
void host_ui_record(const char* name);
void host_ui_record_progress(const char* name, uint8_t progress);
/* The payload of ui_display_ur_qr, which the accessor above hands back. */
void host_ui_record_ur_qr(const uint8_t* data, uint32_t len, ur_type_t type);
unsigned host_ui_calls(void);
uint8_t host_ui_progress_at(unsigned i);

i18n_str_id_t host_ui_menu_marked(void);
uint8_t host_ui_pwm_dutycycle(void);
uint32_t host_ui_inactivity_timeout(void);

#endif /* _UI_HOST_H_ */
