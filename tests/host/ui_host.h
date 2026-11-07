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

void host_ui_answer_menu(core_evt_t answer, i18n_str_id_t chosen);
void host_ui_answer_prompt(core_evt_t answer);
void host_ui_set_info_observer(void (*observer)(void));
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

i18n_str_id_t host_ui_menu_marked(void);
uint8_t host_ui_pwm_dutycycle(void);
uint32_t host_ui_inactivity_timeout(void);

#endif /* _UI_HOST_H_ */
