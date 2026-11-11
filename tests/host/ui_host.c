#include "ui_host.h"

#include <string.h>

#include "hal.h"
#include "pwr.h"
#include "ui/menu.h"

static struct {
  core_evt_t menu_answer;
  i18n_str_id_t menu_choice;
  core_evt_t prompt_answer;
  core_evt_t brightness_answer;
  uint8_t brightness_choice;
  hal_gpio_state_t vusb;
} answer;

static struct {
  unsigned menu, info, prompt, brightness, pwm, inactivity, plugged, unplugged, reboot;
  i18n_str_id_t marked;
  uint8_t dutycycle;
  uint32_t timeout;
} seen;

#define MAX_ANSWERS 8

/* Answers by the name of the call, shared by every file of the seam so that a test never has to know
 * which of them implements the prompt it is answering. A name scripted twice keeps the first answer.
 */
static struct {
  const char* name;
  core_evt_t answer;
} answers[MAX_ANSWERS];
static unsigned answer_count;

void host_ui_answer_call(const char* name, core_evt_t answer) {
  if (answer_count < MAX_ANSWERS) {
    answers[answer_count].name = name;
    answers[answer_count++].answer = answer;
  }
}

/* What the user was asked to decide. Whatever is not scripted is a refusal, so a test that forgot to
 * say who pressed the button gets a user who declined. */
core_evt_t host_ui_answer_for(const char* name) {
  for (unsigned i = 0; i < answer_count; i++) {
    if (strcmp(answers[i].name, name) == 0) {
      return answers[i].answer;
    }
  }

  return CORE_EVT_UI_CANCELLED;
}

/* LSTR() reads the translated strings through a pointer the firmware sets at boot, so a test that
 * walks a path handing one to the ui faults on a null dereference until it is pointed at a table.
 * English is what `core/settings.c` installs and what the suite already links, so it is what the seam
 * installs too -- the wording a test sees is the device's, whether or not it asserts on it. */
void host_ui_reset(void) {
  i18n_set_strings(i18n_english_strings);

  memset(&answer, 0, sizeof(answer));
  memset(&seen, 0, sizeof(seen));
  answer_count = 0;

  host_ui_keycard_reset();
  host_ui_display_reset();

  answer.menu_answer = CORE_EVT_UI_CANCELLED;
  answer.prompt_answer = CORE_EVT_UI_CANCELLED;
  answer.brightness_answer = CORE_EVT_UI_CANCELLED;
  answer.vusb = GPIO_SET;
}

void host_ui_answer_menu(core_evt_t ans, i18n_str_id_t chosen) {
  answer.menu_answer = ans;
  answer.menu_choice = chosen;
}

void host_ui_answer_prompt(core_evt_t ans) {
  answer.prompt_answer = ans;
}

void host_ui_answer_brightness(core_evt_t ans, uint8_t value) {
  answer.brightness_answer = ans;
  answer.brightness_choice = value;
}

void host_ui_vusb_connected(bool connected) {
  answer.vusb = connected ? GPIO_RESET : GPIO_SET;
}

core_evt_t ui_menu(const char* title, const menu_t* menu, i18n_str_id_t* selected, i18n_str_id_t marked,
                   uint8_t allow_usb, ui_menu_opt_t opts, uint8_t current_page, uint8_t last_page) {
  (void)title;
  (void)menu;
  (void)allow_usb;
  (void)opts;
  (void)current_page;
  (void)last_page;

  seen.menu++;
  seen.marked = marked;

  if ((selected != NULL) && (answer.menu_answer == CORE_EVT_UI_OK)) {
    *selected = answer.menu_choice;
  }

  return answer.menu_answer;
}

core_evt_t ui_info(info_icon_t icon, const char* msg, const char* subtext, ui_info_opt_t opts) {
  (void)icon;
  (void)msg;
  (void)subtext;
  (void)opts;

  seen.info++;

  return answer.prompt_answer;
}

core_evt_t ui_prompt(const char* title, const char* msg, ui_info_opt_t opts) {
  (void)title;
  (void)msg;
  (void)opts;

  seen.prompt++;

  return answer.prompt_answer;
}

core_evt_t ui_settings_brightness(uint8_t* brightness) {
  seen.brightness++;

  if ((brightness != NULL) && (answer.brightness_answer == CORE_EVT_UI_OK)) {
    *brightness = answer.brightness_choice;
  }

  return answer.brightness_answer;
}

hal_err_t hal_pwm_set_dutycycle(hal_pwm_output_t out, uint8_t cycle) {
  (void)out;

  seen.pwm++;
  seen.dutycycle = cycle;

  return HAL_SUCCESS;
}

void hal_inactivity_timer_set(uint32_t delay_ms) {
  seen.inactivity++;
  seen.timeout = delay_ms;
}

hal_gpio_state_t hal_gpio_get(hal_gpio_pin_t pin) {
  return pin == GPIO_VUSB_OK ? answer.vusb : GPIO_RESET;
}

void pwr_usb_plugged(bool from_isr) {
  (void)from_isr;
  seen.plugged++;
}

void pwr_usb_unplugged(bool from_isr) {
  (void)from_isr;
  seen.unplugged++;
}

void hal_reboot(void) {
  seen.reboot++;
}

unsigned host_ui_menu_calls(void) { return seen.menu; }
unsigned host_ui_info_calls(void) { return seen.info; }
unsigned host_ui_prompt_calls(void) { return seen.prompt; }
unsigned host_ui_brightness_calls(void) { return seen.brightness; }
unsigned host_ui_pwm_calls(void) { return seen.pwm; }
unsigned host_ui_inactivity_calls(void) { return seen.inactivity; }
unsigned host_ui_usb_plugged_calls(void) { return seen.plugged; }
unsigned host_ui_usb_unplugged_calls(void) { return seen.unplugged; }
unsigned host_ui_reboot_calls(void) { return seen.reboot; }

i18n_str_id_t host_ui_menu_marked(void) { return seen.marked; }
uint8_t host_ui_pwm_dutycycle(void) { return seen.dutycycle; }
uint32_t host_ui_inactivity_timeout(void) { return seen.timeout; }

/* Passed by address and never walked: the seam's ui_menu does not read a menu, and the device's own
 * menu.c needs FreeRTOS. */
const menu_t menu_autooff = { .len = 0 };
const menu_t menu_onoff = { .len = 0 };
const menu_t menu_showhide = { .len = 0 };
const menu_t menu_connect = { .len = 0 };
