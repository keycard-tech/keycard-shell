#include "FreeRTOS.h"
#include "task.h"

#include "app_tasks.h"
#include "core/core.h"
#include "core/settings.h"
#include "usb/usb.h"

void usb_task_entry(void* pvParameters) {
  while(1) {
    if (!(usb_connected() && g_settings.enable_usb)) {
      ulTaskNotifyTakeIndexed(USB_NOTIFICATION_IDX, pdTRUE, portMAX_DELAY);
    }

    if (g_core.usb_command.status == COMMAND_COMPLETE) {
      g_core.usb_command.status = COMMAND_PROCESSING;
      xTaskNotifyIndexed(APP_TASK(core), CORE_EVENT_IDX, CORE_USB_EVT, eSetBits);
    }

    if ((g_core.usb_command.status == COMMAND_OUTBOUND) && !usb_send_busy()) {
      usb_hid_send_rapdu();
    }

    vTaskDelay(pdMS_TO_TICKS(USB_POLL_INTERVAL_MS));
  }
}
