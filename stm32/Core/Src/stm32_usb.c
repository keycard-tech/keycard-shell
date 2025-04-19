#include "stm32_internal.h"

void HAL_PCD_SetupStageCallback(PCD_HandleTypeDef *hpcd) {
  hal_usb_setup_cb((uint8_t*) hpcd->Setup);
}

void HAL_PCD_DataOutStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum) {
  hal_usb_data_out_cb(epnum);
}

void HAL_PCD_DataInStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum) {
  hal_usb_data_in_cb(epnum);
}

static void _hal_usb_close_ep() {
  HAL_PCD_EP_Close(&hpcd_USB_DRD_FS, HAL_USB_EPIN_ADDR);
  HAL_PCD_EP_Close(&hpcd_USB_DRD_FS, HAL_USB_EPOUT_ADDR);
}

static void _hal_usb_open_ep() {
  HAL_PCD_EP_Open(&hpcd_USB_DRD_FS, HAL_USB_EPIN_ADDR, HAL_USB_MPS, EP_TYPE_INTR);
  HAL_PCD_EP_Open(&hpcd_USB_DRD_FS, HAL_USB_EPOUT_ADDR, HAL_USB_MPS, EP_TYPE_INTR);
}

void HAL_PCD_ResetCallback(PCD_HandleTypeDef *hpcd) {
  _hal_usb_close_ep();

  HAL_PCD_EP_Open(&hpcd_USB_DRD_FS, 0x00, HAL_USB_MPS, EP_TYPE_CTRL);
  HAL_PCD_EP_Open(&hpcd_USB_DRD_FS, 0x80, HAL_USB_MPS, EP_TYPE_CTRL);

  _hal_usb_open_ep();
}

static inline void _hal_start_usb_monitor() {
  HAL_TIM_Base_Stop_IT(&htim7);
  __HAL_TIM_SET_COUNTER(&htim7, 0);
  __HAL_TIM_CLEAR_IT(&htim7, TIM_IT_UPDATE);
  HAL_TIM_Base_Start_IT(&htim7);
}

static inline void _hal_stop_usb_monitor() {
  HAL_TIM_Base_Stop_IT(&htim7);
}

hal_err_t hal_usb_start() {
  HAL_PWREx_EnableVddUSB();

  MX_USB_PCD_Init();
  HAL_PCDEx_PMAConfig(&hpcd_USB_DRD_FS, 0x00, PCD_SNG_BUF, 0x18);
  HAL_PCDEx_PMAConfig(&hpcd_USB_DRD_FS, 0x80, PCD_SNG_BUF, 0x58);
  HAL_PCDEx_PMAConfig(&hpcd_USB_DRD_FS, HAL_USB_EPIN_ADDR, PCD_SNG_BUF, 0x98);
  HAL_PCDEx_PMAConfig(&hpcd_USB_DRD_FS, HAL_USB_EPOUT_ADDR, PCD_SNG_BUF, 0xD8);

  USB_DevConnect(hpcd_USB_DRD_FS.Instance);

  hpcd_USB_DRD_FS.Instance->ISTR = 0U;
  hpcd_USB_DRD_FS.Instance->CNTR = USB_CNTR_CTRM  | USB_CNTR_WKUPM | USB_CNTR_SUSPM | USB_CNTR_ERRM | USB_CNTR_RESETM | USB_CNTR_L1REQM;

  _hal_start_usb_monitor();
  return HAL_OK;
}

hal_err_t hal_usb_stop() {
  if (READ_BIT(PWR->USBSCR, PWR_USBSCR_USB33SV)) {
    _hal_usb_close_ep();
    HAL_PCD_Stop(&hpcd_USB_DRD_FS);
    HAL_PCD_DeInit(&hpcd_USB_DRD_FS);
    HAL_PWREx_DisableVddUSB();
  }

  _hal_stop_usb_monitor();
  return HAL_OK;
}

hal_err_t hal_usb_send(uint8_t epaddr, const uint8_t* data, size_t len) {
  return HAL_PCD_EP_Transmit(&hpcd_USB_DRD_FS, epaddr, (uint8_t *) data, len);
}

hal_err_t hal_usb_set_stall(uint8_t epaddr, uint8_t stall) {
  if (stall) {
    return HAL_PCD_EP_SetStall(&hpcd_USB_DRD_FS, epaddr);
  } else {
    return HAL_PCD_EP_ClrStall(&hpcd_USB_DRD_FS, epaddr);
  }
}

uint8_t hal_usb_get_stall(uint8_t epaddr) {
  if (epaddr & 0x80) {
    return hpcd_USB_DRD_FS.IN_ep[epaddr & 0x7].is_stall;
  } else {
    return hpcd_USB_DRD_FS.OUT_ep[epaddr & 0x7].is_stall;
  }
}

hal_err_t hal_usb_set_address(uint8_t addr) {
  return HAL_PCD_SetAddress(&hpcd_USB_DRD_FS, addr);
}

hal_err_t hal_usb_next_recv(uint8_t epaddr, uint8_t* data, size_t len) {
  return HAL_PCD_EP_Receive(&hpcd_USB_DRD_FS, epaddr, data, len);
}

