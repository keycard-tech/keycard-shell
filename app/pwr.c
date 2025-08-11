#include "FreeRTOS.h"
#include "task.h"
#include "app_tasks.h"

#include "core/core.h"
#include "core/settings.h"
#include "hal.h"
#include "pwr.h"
#include "usb/usb.h"

static void pwr_graceful_shutdown() {
  while(hal_flash_busy()) {
    ;
  }

  settings_commit();
}

void pwr_reboot() {
  pwr_graceful_shutdown();
  hal_reboot();
}

void pwr_shutdown() {
#ifndef TEST_APP
  pwr_graceful_shutdown();
  hal_gpio_set(GPIO_PWR_KILL, GPIO_SET);
#endif
}

void pwr_usb_plugged(bool from_isr) {
  if (g_settings.enable_usb && g_core.ready) {
    hal_usb_start();
  }

  if (from_isr) {
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    BaseType_t xHigherPriorityTaskWoken2 = pdFALSE;

    vTaskNotifyGiveIndexedFromISR(APP_TASK(usb), USB_NOTIFICATION_IDX, &xHigherPriorityTaskWoken);
    xTaskNotifyIndexedFromISR(APP_TASK(ui), UI_NOTIFICATION_IDX, UI_USB_PLUG_EVT, eSetBits, &xHigherPriorityTaskWoken2);

    portYIELD_FROM_ISR(xHigherPriorityTaskWoken || xHigherPriorityTaskWoken2);
  } else {
    xTaskNotifyGiveIndexed(APP_TASK(usb), USB_NOTIFICATION_IDX);
  }
}

void pwr_usb_unplugged(bool from_isr) {
  hal_usb_stop();
  if (from_isr) {
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xTaskNotifyIndexedFromISR(APP_TASK(ui), UI_NOTIFICATION_IDX, UI_USB_PLUG_EVT, eSetBits, &xHigherPriorityTaskWoken);
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
  }
}

void pwr_smartcard_inserted() {
#ifndef TEST_APP
  pwr_reboot();
#endif
}

void pwr_smartcard_removed() {
#ifndef TEST_APP
  pwr_shutdown();
#endif
}

void pwr_inactivity_timer_elapsed() {
  pwr_shutdown();
}

uint8_t pwr_battery_level() {
  if (usb_connected()) {
    return PWR_BATTERY_CHARGING;
  }

  uint32_t vbat;
  hal_adc_read(ADC_VBAT, &vbat);

  if (vbat > VBAT_MAX) {
    vbat = VBAT_MAX;
  } else if (vbat < VBAT_MIN) {
    vbat = VBAT_MIN;
  }

  return ((vbat - VBAT_MIN) * 100) / (VBAT_MAX - VBAT_MIN);
}
