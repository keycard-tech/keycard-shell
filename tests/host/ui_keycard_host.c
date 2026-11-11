#include "ui_host.h"

#include <string.h>

#include "core/settings.h"

/*
 * The keycard-facing calls, scripted. A notice records the name it was called under and returns;
 * which notices appeared, and in what order, is what a test asserts, because on this path the
 * screen is the only thing the card activation says.
 *
 * Whatever waits for the user answers what host_ui_answer_call() scripted, and CORE_EVT_UI_CANCELLED
 * if nothing did, so a test that forgot to script a prompt gets a user who declined. The PIN and
 * PUK are copied from a scripted secret rather than typed, and the copy is wiped afterwards: what
 * the caller does with its own buffer is the thing under test.
 */

#define MAX_CALLS 64
#define MAX_ANSWERS 8

static const char* calls[MAX_CALLS];
static unsigned call_count;

static struct {
  const char* name;
  core_evt_t answer;
} answers[MAX_ANSWERS];
static unsigned answer_count;

static uint8_t script_pin[6] = {'1', '2', '3', '4', '5', '6'};
static uint8_t script_puk[12] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};
static uint8_t shown_pin_retries, shown_puk_retries;
static uint8_t pairing_idx = 1;

static void record(const char* name) {
  if (call_count < MAX_CALLS) {
    calls[call_count++] = name;
  }
}

static core_evt_t answer_for(const char* name) {
  for (unsigned i = 0; i < answer_count; i++) {
    if (strcmp(answers[i].name, name) == 0) {
      return answers[i].answer;
    }
  }

  return CORE_EVT_UI_CANCELLED;
}

void host_ui_keycard_reset(void) {
  memset(calls, 0, sizeof(calls));
  memset(answers, 0, sizeof(answers));
  shown_pin_retries = 0;
  shown_puk_retries = 0;
  call_count = 0;
  answer_count = 0;
}

unsigned host_ui_call_count(const char* name) {
  unsigned n = 0;
  for (unsigned i = 0; i < call_count; i++) {
    if (strcmp(calls[i], name) == 0) {
      n++;
    }
  }

  return n;
}

const char* host_ui_call_at(unsigned i) { return (i < call_count) ? calls[i] : ""; }

unsigned host_ui_call_total(void) { return call_count; }

void host_ui_answer_call(const char* name, core_evt_t answer) {
  if (answer_count < MAX_ANSWERS) {
    answers[answer_count].name = name;
    answers[answer_count++].answer = answer;
  }
}

void host_ui_script_pin(const uint8_t pin[6]) { memcpy(script_pin, pin, 6); }

void host_ui_script_puk(const uint8_t puk[12]) { memcpy(script_puk, puk, 12); }

void host_ui_script_pairing(uint8_t idx) { pairing_idx = idx; }

uint8_t host_ui_wrong_pin_retries(void) { return shown_pin_retries; }

uint8_t host_ui_wrong_puk_retries(void) { return shown_puk_retries; }

/* Nothing to answer, so the call itself is the whole of it. */
#define NOTICE(__FN__) \
  void __FN__(void) { record(#__FN__); }

NOTICE(ui_card_accepted)
NOTICE(ui_card_activation_error)
NOTICE(ui_card_inserted)
NOTICE(ui_card_removed)
NOTICE(ui_card_transport_error)
NOTICE(ui_keycard_already_paired)
NOTICE(ui_keycard_flash_failed)
NOTICE(ui_keycard_init_failed)
NOTICE(ui_keycard_no_keys)
NOTICE(ui_keycard_not_initialized)
NOTICE(ui_keycard_old_card)
NOTICE(ui_keycard_pin_ok)
NOTICE(ui_keycard_puk_ok)
NOTICE(ui_keycard_ready)
NOTICE(ui_keycard_secure_channel_failed)
NOTICE(ui_keycard_secure_channel_ok)
NOTICE(ui_keycard_wrong_card)
NOTICE(ui_seed_loaded)

void ui_keycard_init_ok(bool has_duress) { record("ui_keycard_init_ok"); (void)has_duress; }

void ui_keycard_paired(bool default_pass) {
  record("ui_keycard_paired");
  (void)default_pass;
}

void ui_keycard_wrong_pin(uint8_t retries) {
  record("ui_keycard_wrong_pin");
  shown_pin_retries = retries;
}

void ui_keycard_wrong_puk(uint8_t retries) {
  record("ui_keycard_wrong_puk");
  shown_puk_retries = retries;
}

core_evt_t ui_confirm_factory_reset(void) {
  record("ui_confirm_factory_reset");
  return answer_for("ui_confirm_factory_reset");
}

core_evt_t ui_keycard_no_pairing_slots(void) {
  record("ui_keycard_no_pairing_slots");
  return answer_for("ui_keycard_no_pairing_slots");
}

core_evt_t ui_keycard_not_genuine(void) {
  record("ui_keycard_not_genuine");
  return answer_for("ui_keycard_not_genuine");
}

core_evt_t ui_keycard_pairing_failed(const char* card_name, bool default_pass) {
  record("ui_keycard_pairing_failed");
  (void)card_name;
  (void)default_pass;
  return answer_for("ui_keycard_pairing_failed");
}

core_evt_t ui_prompt_try_puk(void) {
  record("ui_prompt_try_puk");
  return answer_for("ui_prompt_try_puk");
}

core_evt_t ui_read_pin(uint8_t* out, int8_t retries, uint8_t dismissable) {
  record("ui_read_pin");
  (void)dismissable;

  if (retries >= 0) {
    shown_pin_retries = (uint8_t)retries;
  }

  memcpy(out, script_pin, sizeof(script_pin));
  return answer_for("ui_read_pin");
}

core_evt_t ui_read_puk(uint8_t* out, int8_t retries, uint8_t dismissable) {
  record("ui_read_puk");
  (void)dismissable;

  if (retries >= 0) {
    shown_puk_retries = (uint8_t)retries;
  }

  memcpy(out, script_puk, sizeof(script_puk));
  return answer_for("ui_read_puk");
}

core_evt_t ui_read_duress_pin(uint8_t* out) {
  record("ui_read_duress_pin");

  memcpy(out, "000000", 6);
  return answer_for("ui_read_duress_pin");
}

core_evt_t ui_read_pairing(uint8_t* pairing, uint8_t* len) {
  record("ui_read_pairing");

  pairing[0] = pairing_idx;
  *len = 1;
  return answer_for("ui_read_pairing");
}

core_evt_t ui_read_number(const char* title, uint32_t min, uint32_t max, uint32_t* num, bool show_max) {
  record("ui_read_number");
  (void)title;
  (void)show_max;

  *num = min;
  return answer_for("ui_read_number");
}

core_evt_t ui_read_string(const char* title, const char* prompt, char* out, uint8_t* len,
                          ui_read_string_opt_t opts) {
  record("ui_read_string");
  (void)title;
  (void)prompt;
  (void)opts;

  out[0] = '\0';
  *len = 0;
  return answer_for("ui_read_string");
}

/* The mnemonic and SLIP-39 readers belong to a key being loaded, which is a scenario of its own.
 * Refusing is the honest default here: a test that walks into one should say so explicitly. */
core_evt_t ui_read_bip39(uint16_t indexes[BIP39_MAX_MNEMONIC_LEN], size_t mnemo_len) {
  record("ui_read_bip39");
  (void)indexes;
  (void)mnemo_len;
  return answer_for("ui_read_bip39");
}

core_evt_t ui_read_slip39(slip39_shard_t shards[SLIP39_MAX_MEMBERS], uint16_t indexes[SLIP39_MNEMO_LEN],
                          uint8_t ems[SLIP39_SEED_STRENGTH]) {
  record("ui_read_slip39");
  (void)shards;
  (void)indexes;
  (void)ems;
  return answer_for("ui_read_slip39");
}

core_evt_t ui_scan_mnemonic(uint16_t* indexes, uint32_t* len) {
  record("ui_scan_mnemonic");
  (void)indexes;
  (void)len;
  return answer_for("ui_scan_mnemonic");
}

i18n_str_id_t ui_read_mnemonic_len(uint32_t* len, bool* has_pass) {
  record("ui_read_mnemonic_len");
  (void)len;
  (void)has_pass;
  return 0;
}

core_evt_t ui_backup_mnemonic(uint16_t* indexes, uint32_t len, const char* const* wordlist,
                              size_t wordcount, bool prompt_confirm) {
  record("ui_backup_mnemonic");
  (void)indexes;
  (void)len;
  (void)wordlist;
  (void)wordcount;
  (void)prompt_confirm;
  return answer_for("ui_backup_mnemonic");
}
