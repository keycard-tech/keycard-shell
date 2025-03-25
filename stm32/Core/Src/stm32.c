#include "stm32_internal.h"

const struct gpio_pin_spec STM32_PIN_MAP[] = {
  {GPIO_CAMERA_PWDN_GPIO_Port, GPIO_CAMERA_PWDN_Pin},
  {GPIO_CAM_EN_GPIO_Port, GPIO_CAM_EN_Pin},
  {GPIO_CAMERA_RST_GPIO_Port, GPIO_CAMERA_RST_Pin},
  {GPIO_LCD_CD_GPIO_Port, GPIO_LCD_CD_Pin},
  {GPIO_LCD_RST_GPIO_Port, GPIO_LCD_RST_Pin},
  {GPIO_KEYPAD_ROW_0_GPIO_Port, GPIO_KEYPAD_ROW_0_Pin},
  {GPIO_KEYPAD_ROW_1_GPIO_Port, GPIO_KEYPAD_ROW_1_Pin},
  {GPIO_KEYPAD_ROW_2_GPIO_Port, GPIO_KEYPAD_ROW_2_Pin},
  {GPIO_KEYPAD_ROW_3_GPIO_Port, GPIO_KEYPAD_ROW_3_Pin},
  {GPIO_KEYPAD_COL_0_GPIO_Port, GPIO_KEYPAD_COL_0_Pin},
  {GPIO_KEYPAD_COL_1_GPIO_Port, GPIO_KEYPAD_COL_1_Pin},
  {GPIO_KEYPAD_COL_2_GPIO_Port, GPIO_KEYPAD_COL_2_Pin},
  {GPIO_VUSB_OK_GPIO_Port, GPIO_VUSB_OK_Pin},
  {GPIO_SC_PRES_GPIO_Port, GPIO_SC_PRES_Pin},
  {GPIO_HALT_REQ_GPIO_Port, GPIO_HALT_REQ_Pin},
  {GPIO_PWR_KILL_GPIO_Port, GPIO_PWR_KILL_Pin},
};

static void (*g_spi_callback)();
static uint8_t g_uid[HAL_DEVICE_UID_LEN] __attribute__((aligned(4)));
static uint32_t g_adc_calibration;
static uint32_t g_adc_vref;

#ifdef BOOTLOADER
void SysTick_Handler(void) {
  HAL_IncTick();
}
#endif

void HAL_SPI_TxCpltCallback(SPI_HandleTypeDef *hspi) {
  if (g_spi_callback) {
    g_spi_callback();
  }
}

void HAL_GPIO_EXTI_Rising_Callback(uint16_t gpio_pin) {
  switch(gpio_pin) {
  case GPIO_HALT_REQ_Pin:
    HAL_TIM_Base_Stop_IT(&htim3);
    break;
  case GPIO_SC_PRES_Pin:
    pwr_smartcard_inserted();
    break;
  case GPIO_VUSB_OK_Pin:
    pwr_usb_unplugged(true);
    break;
  }
}

void HAL_GPIO_EXTI_Falling_Callback(uint16_t gpio_pin) {
  switch(gpio_pin) {
  case GPIO_HALT_REQ_Pin:
    HAL_TIM_Base_Stop_IT(&htim3);
    __HAL_TIM_SET_COUNTER(&htim3, 0);
    __HAL_TIM_CLEAR_IT(&htim3, TIM_IT_UPDATE);
    HAL_TIM_Base_Start_IT(&htim3);
    break;
  case GPIO_SC_PRES_Pin:
    pwr_smartcard_removed();
    break;
  case GPIO_VUSB_OK_Pin:
    pwr_usb_plugged(true);
    break;
  }
}

static void _hal_check_usb() {
  uint32_t v;
  hal_adc_read(ADC_VBAT, &v);
  if (v < VBAT_USB) {
    HAL_PCD_Stop(&hpcd_USB_DRD_FS);
  }
}

void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim) {
  if (htim == &htim2) {
    keypad_scan_tick();
  } else if (htim == &htim3) {
    pwr_shutdown();
  } else if (htim == &htim5) {
    pwr_inactivity_timer_elapsed();
  } else if (htim == &htim7) {
    _hal_check_usb();
  }
}

static void _hal_aes_enable() {
  __HAL_RCC_SAES_CLK_ENABLE();
}

hal_err_t hal_init() {
  // Copies UID, Flash size, package info before it becomes privileged
  memcpy(g_uid, (uint32_t*) UID_BASE, HAL_DEVICE_UID_LEN);
  uint16_t vrefint_cal = *VREFINT_CAL_ADDR;

  HAL_Init();
  SystemClock_Config();

  MX_RNG_Init();
  MX_HASH_Init();
  MX_CRC_Init();
  _hal_aes_enable();
  MX_PKA_Init();

  MX_GPIO_Init();
  MX_TIM6_Init();
  MX_TIM2_Init();
  MX_TIM3_Init();
  MX_TIM5_Init();
  MX_TIM7_Init();

  MX_GPDMA2_Init();
  MX_GPDMA1_Init();

  MX_SPI6_Init();
  MX_I2C2_Init();
  MX_USART6_SMARTCARD_Init();
  __HAL_RCC_USART6_CLK_DISABLE();

  MX_DCMI_Init();

  mco_off();
  __HAL_DCMI_DISABLE_IT(&hdcmi, DCMI_IT_LINE | DCMI_IT_VSYNC);

  MX_Camera_DMA_LL_Config();

  __HAL_LINKDMA(&hdcmi, DMA_Handle, handle_GPDMA2_Channel5);
  HAL_DMAEx_List_LinkQ(&handle_GPDMA2_Channel5, &Camera_DMA_LL);

  MX_ICACHE_Init();

  __HAL_TIM_ENABLE_IT(&htim2, TIM_IT_UPDATE);
  HAL_TIM_PWM_Start(&htim2, TIM_CHANNEL_1);

  MX_ADC1_Init();
  HAL_ADCEx_Calibration_Start(&hadc1, ADC_SINGLE_ENDED);
  HAL_ADC_Start(&hadc1);

  if (HAL_ADC_PollForConversion(&hadc1, HAL_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  g_adc_vref = (VREFINT_CAL_VREF * vrefint_cal) / HAL_ADC_GetValue(&hadc1);
  HAL_ADCEx_EnterADCDeepPowerDownMode(&hadc1);

  MX_ADC2_Init();
  HAL_ADCEx_Calibration_Start(&hadc2, ADC_SINGLE_ENDED);
  g_adc_calibration = HAL_ADCEx_Calibration_GetValue(&hadc2, ADC_SINGLE_ENDED);
  HAL_ADCEx_EnterADCDeepPowerDownMode(&hadc2);

  return HAL_SUCCESS;
}

hal_err_t hal_init_bootloader() {
  HAL_Init();
  SystemClock_Config();

  MX_RNG_Init();
  MX_HASH_Init();
  MX_PKA_Init();

  return HAL_SUCCESS;
}

hal_err_t hal_teardown_bootloader() {
  HAL_PKA_DeInit(&hpka);
  HAL_HASH_DeInit(&hhash);
  HAL_RNG_DeInit(&hrng);
  HAL_RCC_DeInit();

  return HAL_SUCCESS;
}

hal_err_t hal_device_uid(uint8_t out[HAL_DEVICE_UID_LEN]) {
  memcpy(out, g_uid, HAL_DEVICE_UID_LEN);
  return HAL_SUCCESS;
}

hal_boot_t hal_boot_type() {
  return __HAL_RCC_GET_FLAG(RCC_FLAG_SFTRST) ? BOOT_HOT : BOOT_COLD;
}

void hal_gpio_set(hal_gpio_pin_t pin, hal_gpio_state_t state) {
  HAL_GPIO_WritePin(STM32_PIN_MAP[pin].base, STM32_PIN_MAP[pin].pin, state);
}

hal_gpio_state_t hal_gpio_get(hal_gpio_pin_t pin) {
  return HAL_GPIO_ReadPin(STM32_PIN_MAP[pin].base, STM32_PIN_MAP[pin].pin);
}

hal_err_t hal_i2c_send(hal_i2c_port_t port, uint8_t addr, const uint8_t* data, size_t len) {
  assert(port == I2C_CAMERA);
  return HAL_I2C_Master_Transmit(&hi2c2, (addr << 1), (uint8_t*) data, len, HAL_TIMEOUT);
}

hal_err_t hal_spi_send(hal_spi_port_t port, const uint8_t* data, size_t len) {
  assert(port == SPI_LCD);
  return HAL_SPI_Transmit(&hspi6, (uint8_t*) data, len, HAL_TIMEOUT);
}

hal_err_t hal_spi_send_dma(hal_spi_port_t port, const uint8_t* data, size_t len, void (*cb)()) {
  assert(port == SPI_LCD);
  g_spi_callback = cb;
  return HAL_SPI_Transmit_DMA(&hspi6, (uint8_t*) data, len);
}

hal_err_t hal_delay_us(uint32_t usec) {
  __HAL_TIM_SET_COUNTER(&htim6, 0);
  HAL_TIM_Base_Start(&htim6);
  while(__HAL_TIM_GET_COUNTER(&htim6) < usec) {}
  HAL_TIM_Base_Stop(&htim6);
  return HAL_FAIL;
}

void hal_tick() {
  HAL_IncTick();
}

hal_err_t hal_pwm_set_dutycycle(hal_pwm_output_t out, uint8_t cycle) {
  assert(out == PWM_BACKLIGHT);
  assert(cycle <= 100);
  __HAL_TIM_SET_COMPARE(&htim2, TIM_CHANNEL_1, (cycle * 5));
  return HAL_SUCCESS;
}

void hal_inactivity_timer_set(uint32_t delay_ms) {
  HAL_TIM_Base_Stop_IT(&htim5);
  __HAL_TIM_SET_COUNTER(&htim5, 0);
  __HAL_TIM_SET_AUTORELOAD(&htim5, delay_ms * 4);
  __HAL_TIM_CLEAR_IT(&htim5, TIM_IT_UPDATE);
  HAL_TIM_Base_Start_IT(&htim5);
}

void hal_inactivity_timer_reset() {
  __HAL_TIM_SET_COUNTER(&htim5, 0);
}

hal_err_t hal_adc_read(hal_adc_channel_t ch, uint32_t* val) {
  assert(ch == ADC_VBAT);

  MX_ADC2_Init();
  HAL_ADCEx_Calibration_SetValue(&hadc2, ADC_SINGLE_ENDED, g_adc_calibration);
  HAL_ADC_Start(&hadc2);

  if (HAL_ADC_PollForConversion(&hadc2, HAL_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  *val = VBAT_OFFSET + (((HAL_ADC_GetValue(&hadc2) * g_adc_vref)) / ANALOG_DIV);

  HAL_ADC_Stop(&hadc2);
  HAL_ADCEx_EnterADCDeepPowerDownMode(&hadc2);

  return HAL_SUCCESS;
}
