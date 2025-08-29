#ifndef BOOTLOADER

#include "common.h"
#include "FreeRTOS.h"
#include "task.h"
#include "hal.h"

#include "core/settings.h"

#define USB_STACK_SIZE 800
#define USB_TASK_PRIO 1

#define CORE_STACK_SIZE 2048
#define CORE_TASK_PRIO 2

#define UI_STACK_SIZE 6000
#define UI_TASK_PRIO 3

APP_DEF_TASK(usb, USB_STACK_SIZE);
APP_DEF_TASK(core, CORE_STACK_SIZE);
APP_DEF_TASK(ui, UI_STACK_SIZE);

#define FW_MAJOR 0
#define FW_MINOR 10
#define FW_PATCH 3

__attribute__((section(".fw_signature"))) __attribute__((__used__)) const uint8_t FW_SIGNATURE[64];
__attribute__((section(".fw_version"))) __attribute__((__used__)) const uint8_t FW_VERSION[4] = { FW_MAJOR, FW_MINOR, FW_PATCH, 0};

int main(void) {
  hal_init();
  settings_load();

  APP_CREATE_TASK(usb, USB_TASK_PRIO);
  APP_CREATE_TASK(core, CORE_TASK_PRIO);
  APP_CREATE_TASK(ui, UI_TASK_PRIO);

  vTaskStartScheduler();

  while(1) {
    __asm volatile ("nop");
  }
}
#endif
