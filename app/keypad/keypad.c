#include "keypad.h"
#include "app_tasks.h"
#include "hal.h"
#include "ui/ui_internal.h"

#define KEYPAD_GPIO_ROW_OFF GPIO_KEYPAD_ROW_0
#define KEYPAD_GPIO_COL_OFF GPIO_KEYPAD_COL_0

#define KEYPAD_DEBOUNCE_THRESHOLD (10/KEYPAD_POLL_MS)
#define KEYPAD_LONG_PRESS_THRESHOLD (150/KEYPAD_POLL_MS)

static inline void keypad_report_key(keypad_key_t key, bool is_long) {
  g_ui_ctx.keypad.last_key = key;
  g_ui_ctx.keypad.last_key_long = is_long;
  g_ui_ctx.keypad.last_key_released = !is_long;

  hal_inactivity_timer_reset();

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xTaskNotifyIndexedFromISR(APP_TASK(ui), UI_NOTIFICATION_IDX, UI_KEY_EVT, eSetBits, &xHigherPriorityTaskWoken);
  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

void keypad_scan_tick() {
  for (int i = 0; i < KEYPAD_COLS; i++) {
    keypad_key_t key = (g_ui_ctx.keypad.current_row * KEYPAD_COLS) + i;

    if (hal_gpio_get(KEYPAD_GPIO_COL_OFF + i)) {
      uint32_t duration = g_ui_ctx.keypad.matrix_state[key];
      g_ui_ctx.keypad.matrix_state[key] = 0;

      if (duration > KEYPAD_DEBOUNCE_THRESHOLD) {
        if (duration < KEYPAD_LONG_PRESS_THRESHOLD) {
          keypad_report_key(key, false);
        } else {
          g_ui_ctx.keypad.last_key_released = true;
        }

        break;
      }
    } else {
      g_ui_ctx.keypad.matrix_state[key]++;
      if (g_ui_ctx.keypad.matrix_state[key] >= KEYPAD_LONG_PRESS_THRESHOLD && g_ui_ctx.keypad.matrix_state[key] < (KEYPAD_LONG_PRESS_THRESHOLD * 2)) {
        g_ui_ctx.keypad.matrix_state[key] = KEYPAD_LONG_PRESS_THRESHOLD * 2;
        keypad_report_key(key, true);
        break;
      }
    }
  }

  hal_gpio_set((KEYPAD_GPIO_ROW_OFF + g_ui_ctx.keypad.current_row), GPIO_SET);
  g_ui_ctx.keypad.current_row = (g_ui_ctx.keypad.current_row + 1) % KEYPAD_ROWS;
  hal_gpio_set((KEYPAD_GPIO_ROW_OFF + g_ui_ctx.keypad.current_row), GPIO_RESET);
}
