#ifndef TASK_H
#define TASK_H

#include "FreeRTOS.h"

/* Scripts in sc_host.c: the completion notification the smartcard peripheral raises after a
 * transfer, and the delay the block guard time asks for. */
BaseType_t xTaskNotifyWaitIndexed(uint32_t index_to_wait_on, uint32_t bits_to_clear_on_entry,
                                  uint32_t bits_to_clear_on_exit, uint32_t* notification_value,
                                  TickType_t ticks_to_wait);
void vTaskDelay(TickType_t ticks);

/* app/core/core.c blocks on its own notification with the primitive above, and app/ui/ui_internal.h
 * posts one with the call below. portMAX_DELAY is what both pass as their wait. */
#define portMAX_DELAY ((TickType_t)0xffffffffU)

typedef enum { eInvalidate, eIncrement, eSetBits, eClearBits } NotifyAction_t;

BaseType_t xTaskNotifyIndexed(TaskHandle_t task, uint32_t index, uint32_t value,
                              NotifyAction_t action);

#endif
