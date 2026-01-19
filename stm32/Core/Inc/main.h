/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32h5xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */
extern DCMI_HandleTypeDef hdcmi;
extern HASH_HandleTypeDef hhash;
extern I2C_HandleTypeDef hi2c2;
extern PKA_HandleTypeDef hpka;
extern RNG_HandleTypeDef hrng;
extern SPI_HandleTypeDef hspi6;
extern SMARTCARD_HandleTypeDef hsmartcard6;
extern PCD_HandleTypeDef hpcd_USB_DRD_FS;
extern TIM_HandleTypeDef htim6;
extern TIM_HandleTypeDef htim2;
extern TIM_HandleTypeDef htim3;
extern TIM_HandleTypeDef htim5;
extern DMA_HandleTypeDef handle_GPDMA2_Channel5;
extern CRC_HandleTypeDef hcrc;
extern ADC_HandleTypeDef hadc1;
extern ADC_HandleTypeDef hadc2;
/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

void HAL_TIM_MspPostInit(TIM_HandleTypeDef *htim);

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);
void MX_GPIO_Init(void);
void MX_GPDMA1_Init(void);
void MX_GPDMA2_Init(void);
void MX_I2C2_Init(void);
void MX_RNG_Init(void);
void MX_SPI6_Init(void);
void MX_TIM2_Init(void);
void MX_TIM6_Init(void);
void MX_USART6_SMARTCARD_Init(void);
void MX_DCMI_Init(void);
void MX_CRC_Init(void);
void MX_HASH_Init(void);
void MX_USB_PCD_Init(void);
void MX_ICACHE_Init(void);
void MX_ADC2_Init(void);
void MX_TIM5_Init(void);
void MX_ADC1_Init(void);
void MX_TIM3_Init(void);
void MX_PKA_Init(void);

/* USER CODE BEGIN EFP */
void SystemClock_Config(void);
void MPU_Config(void);
/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define KEYPAD_POLL_MS 5
#define SC_DEFAULT_PSC 25
#define SC_DEFAULT_BAUD_RATE 10752
#define HALT_REQ_MS 10
#define GPIO_VUSB_OK_Pin GPIO_PIN_13
#define GPIO_VUSB_OK_GPIO_Port GPIOC
#define GPIO_VUSB_OK_EXTI_IRQn EXTI13_IRQn
#define GPIO_KEYPAD_COL_2_Pin GPIO_PIN_0
#define GPIO_KEYPAD_COL_2_GPIO_Port GPIOC
#define GPIO_KEYPAD_COL_1_Pin GPIO_PIN_1
#define GPIO_KEYPAD_COL_1_GPIO_Port GPIOC
#define GPIO_KEYPAD_COL_0_Pin GPIO_PIN_2
#define GPIO_KEYPAD_COL_0_GPIO_Port GPIOC
#define GPIO_LCD_CD_Pin GPIO_PIN_0
#define GPIO_LCD_CD_GPIO_Port GPIOA
#define GPIO_LCD_RST_Pin GPIO_PIN_1
#define GPIO_LCD_RST_GPIO_Port GPIOA
#define GPIO_CAMERA_RST_Pin GPIO_PIN_2
#define GPIO_CAMERA_RST_GPIO_Port GPIOA
#define GPIO_CAMERA_PWDN_Pin GPIO_PIN_3
#define GPIO_CAMERA_PWDN_GPIO_Port GPIOA
#define PWM_LCD_BL_Pin GPIO_PIN_5
#define PWM_LCD_BL_GPIO_Port GPIOA
#define GPIO_HALT_REQ_Pin GPIO_PIN_4
#define GPIO_HALT_REQ_GPIO_Port GPIOC
#define GPIO_HALT_REQ_EXTI_IRQn EXTI4_IRQn
#define GPIO_KEYPAD_ROW_0_Pin GPIO_PIN_5
#define GPIO_KEYPAD_ROW_0_GPIO_Port GPIOC
#define GPIO_KEYPAD_ROW_1_Pin GPIO_PIN_0
#define GPIO_KEYPAD_ROW_1_GPIO_Port GPIOB
#define GPIO_KEYPAD_ROW_2_Pin GPIO_PIN_1
#define GPIO_KEYPAD_ROW_2_GPIO_Port GPIOB
#define GPIO_KEYPAD_ROW_3_Pin GPIO_PIN_2
#define GPIO_KEYPAD_ROW_3_GPIO_Port GPIOB
#define GPIO_PWR_KILL_Pin GPIO_PIN_14
#define GPIO_PWR_KILL_GPIO_Port GPIOB
#define CAM_XCLK_Pin GPIO_PIN_8
#define CAM_XCLK_GPIO_Port GPIOA
#define GPIO_CARD_RST_Pin GPIO_PIN_10
#define GPIO_CARD_RST_GPIO_Port GPIOA
#define SWDIO_Pin GPIO_PIN_13
#define SWDIO_GPIO_Port GPIOA
#define SWCLK_Pin GPIO_PIN_14
#define SWCLK_GPIO_Port GPIOA
#define GPIO_SC_PRES_Pin GPIO_PIN_10
#define GPIO_SC_PRES_GPIO_Port GPIOC
#define GPIO_SC_PRES_EXTI_IRQn EXTI10_IRQn
#define GPIO_CAM_EN_Pin GPIO_PIN_2
#define GPIO_CAM_EN_GPIO_Port GPIOD
#define SWO_Pin GPIO_PIN_3
#define SWO_GPIO_Port GPIOB

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
