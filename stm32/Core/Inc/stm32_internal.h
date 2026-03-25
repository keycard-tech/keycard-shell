#include <string.h>

#include "main.h"
#include "hal.h"
#include "keypad/keypad.h"
#include "linked_list.h"
#include "FreeRTOS.h"
#include "task.h"
#include "pwr.h"

#define HAL_TIMEOUT 250
#define PKA_TIMEOUT 500
#define SC_RESET_DELAY 10
#define CLOCK_STABLE_DELAY 5
#define SMARTCARD_STOPBITS_1 0x00000000U
#define ANALOG_DIV 4095
#define VBAT_OFFSET 1660

#define FLASH_BANK_SWAPPED() (FLASH->OPTSR_CUR & FLASH_OPTSR_SWAP_BANK)

#define HAL_WAIT(__PREDICATE__) { \
  uint32_t base = HAL_GetTick(); \
\
  while (__PREDICATE__) {\
    if ((HAL_GetTick() - base) > HAL_TIMEOUT) {\
      return HAL_FAIL;\
    }\
  }\
}

#define __PKA_RAM_PARAM_END(TAB,INDEX) { TAB[INDEX] = 0UL; TAB[INDEX + 1U] = 0UL;}

HAL_StatusTypeDef PKA_Process(PKA_HandleTypeDef *hpka, uint32_t mode, uint32_t Timeout);
void PKA_Memcpy_u8_to_u32(__IO uint32_t dst[], const uint8_t src[], size_t n);
void PKA_Memcpy_u32_to_u8(uint8_t dst[], __IO const uint32_t src[], size_t n);
void PKA_Memcpy_u32_to_u32(__IO uint32_t dst[], __IO const uint32_t src[], size_t n);

extern DMA_QListTypeDef Camera_DMA_LL;
extern DMA_NodeTypeDef Camera_DMA_Node1;
extern DMA_NodeTypeDef Camera_DMA_Node2;

struct gpio_pin_spec {
  GPIO_TypeDef* base;
  uint16_t pin;
};

enum dcmi_buf_status {
  DCMI_READY,
  DCMI_ACQUIRING,
  DCMI_ACQUIRED,
  DCMI_PROCESSING
};

struct dcmi_buf {
  enum dcmi_buf_status status;
  uint8_t* addr;
};

static inline void mco_off() {
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  GPIO_InitStruct.Pin = GPIO_PIN_8;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}

static inline void mco_on() {
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  GPIO_InitStruct.Pin = GPIO_PIN_8;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_MEDIUM;
  GPIO_InitStruct.Alternate = GPIO_AF0_MCO;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}
