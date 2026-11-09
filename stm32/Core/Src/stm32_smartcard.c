#include "stm32_internal.h"

static TaskHandle_t g_smartcard_task = NULL;

static void hal_smartcard_complete(uint32_t err) {
  if (!g_smartcard_task) {
    return;
  }

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xTaskNotifyIndexedFromISR(g_smartcard_task, SMARTCARD_TASK_NOTIFICATION_IDX, err, eSetValueWithOverwrite, &xHigherPriorityTaskWoken);
  g_smartcard_task = NULL;
  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

void HAL_SMARTCARD_TxCpltCallback(SMARTCARD_HandleTypeDef *hsmartcard) {
  hal_smartcard_complete(HAL_SMARTCARD_GetError(hsmartcard));
}

void HAL_SMARTCARD_RxCpltCallback(SMARTCARD_HandleTypeDef *hsmartcard) {
  __HAL_SMARTCARD_DISABLE_IT(&hsmartcard6, SMARTCARD_IT_RTO);
  hal_smartcard_complete(HAL_SMARTCARD_GetError(hsmartcard));
}

void HAL_SMARTCARD_ErrorCallback(SMARTCARD_HandleTypeDef *hsmartcard) {
  hal_smartcard_complete(HAL_SMARTCARD_GetError(hsmartcard));
}

hal_err_t hal_smartcard_start() {
  __HAL_RCC_USART6_CLK_ENABLE();
  vTaskDelay(pdMS_TO_TICKS(CLOCK_STABLE_DELAY));

  HAL_GPIO_WritePin(GPIO_CARD_RST_GPIO_Port, GPIO_CARD_RST_Pin, GPIO_PIN_RESET);
  vTaskDelay(pdMS_TO_TICKS(SC_RESET_DELAY));
  HAL_GPIO_WritePin(GPIO_CARD_RST_GPIO_Port, GPIO_CARD_RST_Pin, GPIO_PIN_SET);

  __HAL_SMARTCARD_FLUSH_DRREGISTER(&hsmartcard6);

  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_stop() {
  HAL_GPIO_WritePin(GPIO_CARD_RST_GPIO_Port, GPIO_CARD_RST_Pin, GPIO_PIN_RESET);

  hsmartcard6.Init.StopBits = SMARTCARD_STOPBITS_1_5;
  hsmartcard6.Init.BaudRate = SC_DEFAULT_BAUD_RATE;
  hsmartcard6.Init.Prescaler = SC_DEFAULT_PSC;
  hsmartcard6.Init.GuardTime = 0;
  hsmartcard6.Init.NACKEnable = SMARTCARD_NACK_ENABLE;
  hsmartcard6.Init.AutoRetryCount = 3;

  hal_err_t err = HAL_SMARTCARD_Init(&hsmartcard6);
  __HAL_RCC_USART6_CLK_DISABLE();
  return err;
}

hal_err_t hal_smartcard_pps(smartcard_protocol_t protocol, uint32_t baud, uint32_t freq, uint8_t guard, uint32_t timeout) {
  hsmartcard6.Init.BaudRate = baud;
  hsmartcard6.Init.Prescaler = (SMARTCARD_CLOCK / freq / 2);

  if (protocol == SC_T1) {
    hsmartcard6.Init.StopBits = SMARTCARD_STOPBITS_1;
    hsmartcard6.Init.NACKEnable = SMARTCARD_NACK_DISABLE;
    hsmartcard6.Init.BlockLength = 255;
    hsmartcard6.Init.AutoRetryCount = 0;
  } else {
    hsmartcard6.Init.TimeOutValue = timeout;
  }

  hsmartcard6.Init.GuardTime = guard;

  return HAL_SMARTCARD_Init(&hsmartcard6);
}

hal_err_t hal_smartcard_set_timeout(uint32_t timeout) {
  HAL_SMARTCARDEx_TimeOut_Config(&hsmartcard6, timeout);
  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_set_blocklen(uint32_t len) {
  HAL_SMARTCARDEx_BlockLength_Config(&hsmartcard6, len);
  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_send(const uint8_t* data, size_t len) {
  configASSERT(g_smartcard_task == NULL);
  g_smartcard_task = xTaskGetCurrentTaskHandle();
  return HAL_SMARTCARD_Transmit_IT(&hsmartcard6, data, len);
}

hal_err_t hal_smarcard_recv(uint8_t* data, size_t len) {
  configASSERT(g_smartcard_task == NULL);
  g_smartcard_task = xTaskGetCurrentTaskHandle();
  __HAL_SMARTCARD_CLEAR_FLAG(&hsmartcard6, SMARTCARD_CLEAR_RTOF);
  __HAL_SMARTCARD_ENABLE_IT(&hsmartcard6, SMARTCARD_IT_RTO);
  return HAL_SMARTCARD_Receive_IT(&hsmartcard6, data, len);
}

uint32_t hal_smartcard_received(void) {
  return hsmartcard6.RxXferSize - hsmartcard6.RxXferCount;
}

void hal_smartcard_abort() {
  HAL_SMARTCARD_Abort_IT(&hsmartcard6);
}
