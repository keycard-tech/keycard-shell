#include "stm32_internal.h"

static TaskHandle_t g_dcmi_task = NULL;
static int8_t g_acquiring;
static struct dcmi_buf g_dcmi_bufs[CAMERA_FB_COUNT];

static void inline _hal_acquire(int8_t idx) {
  g_acquiring = idx;
  g_dcmi_bufs[idx].status = DCMI_ACQUIRING;

  hdcmi.pBuffPtr = (uint32_t) g_dcmi_bufs[idx].addr;

  __HAL_DMA_DISABLE(hdcmi.DMA_Handle);
  __HAL_DMA_CLEAR_FLAG(hdcmi.DMA_Handle, (DMA_FLAG_TC | DMA_FLAG_HT | DMA_FLAG_DTE | DMA_FLAG_ULE | DMA_FLAG_USE | DMA_FLAG_SUSP | DMA_FLAG_TO));
  hdcmi.DMA_Handle->Instance->CBR1 = 0U;
  Camera_DMA_Node1.LinkRegisters[NODE_CDAR_DEFAULT_OFFSET] = hdcmi.pBuffPtr;
  Camera_DMA_Node2.LinkRegisters[NODE_CDAR_DEFAULT_OFFSET] = hdcmi.pBuffPtr + hdcmi.XferSize;

  MODIFY_REG(hdcmi.DMA_Handle->Instance->CBR1, DMA_CBR1_BNDT, (hdcmi.XferSize & DMA_CBR1_BNDT));
  hdcmi.DMA_Handle->Instance->CDAR = hdcmi.pBuffPtr;

  __HAL_DMA_ENABLE(hdcmi.DMA_Handle);

  hdcmi.Instance->CR |= DCMI_CR_CAPTURE;
}

void HAL_DCMI_FrameEventCallback(DCMI_HandleTypeDef *hdcmi) {
  hdcmi->Instance->CR &= ~(DCMI_CR_CAPTURE);

  g_dcmi_bufs[g_acquiring].status = DCMI_ACQUIRED;
  g_acquiring = -1;

  if(g_dcmi_task == NULL) {
    return;
  }

  for (int i = 0; i < CAMERA_FB_COUNT; i++) {
    if (g_dcmi_bufs[i].status == DCMI_READY) {
      _hal_acquire(i);
      break;
    }
  }

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  vTaskNotifyGiveIndexedFromISR(g_dcmi_task, CAMERA_TASK_NOTIFICATION_IDX, &xHigherPriorityTaskWoken);
  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

hal_err_t hal_camera_init() {
  mco_on();
  vTaskDelay(pdMS_TO_TICKS(CLOCK_STABLE_DELAY));
  return HAL_SUCCESS;
}

hal_err_t hal_camera_start(uint8_t fb[CAMERA_FB_COUNT][CAMERA_FB_SIZE]) {
  configASSERT(g_dcmi_task == NULL);
  g_dcmi_task = xTaskGetCurrentTaskHandle();

  g_dcmi_bufs[0].status = DCMI_ACQUIRING;
  g_dcmi_bufs[0].addr = fb[0];
  g_acquiring = 0;

  for (int i = 1; i < CAMERA_FB_COUNT; i++) {
    g_dcmi_bufs[i].status = DCMI_READY;
    g_dcmi_bufs[i].addr = fb[i];
  }

  return HAL_DCMI_Start_DMA(&hdcmi, DCMI_MODE_CONTINUOUS, (uint32_t) g_dcmi_bufs[0].addr, (CAMERA_FB_SIZE/4));
}

hal_err_t hal_camera_stop() {
  g_dcmi_task = NULL;
  HAL_DCMI_Stop(&hdcmi);
  mco_off();
  return HAL_SUCCESS;
}

hal_err_t hal_camera_next_frame(uint8_t** fb) {
  int ready = -1;

  for (int i = 0; i < CAMERA_FB_COUNT; i++) {
    if (g_dcmi_bufs[i].status == DCMI_ACQUIRED) {
      g_dcmi_bufs[i].status = DCMI_PROCESSING;
      *fb = g_dcmi_bufs[i].addr;
      return HAL_SUCCESS;
    } else if (g_dcmi_bufs[i].status == DCMI_READY) {
      ready = i;
    }
  }

  if (g_acquiring == -1 && ready != -1) {
    _hal_acquire(ready);
  }

  return HAL_FAIL;
}

hal_err_t hal_camera_submit(uint8_t* fb) {
  for (int i = 0; i < CAMERA_FB_COUNT; i++) {
    if (g_dcmi_bufs[i].addr == fb) {
      if (g_acquiring == -1) {
        _hal_acquire(i);
        return HAL_SUCCESS;
      } else {
        g_dcmi_bufs[i].status = DCMI_READY;
        return HAL_SUCCESS;
      }
    }
  }
  return HAL_FAIL;
}
