/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32h5xx_it.c
  * @brief   Interrupt Service Routines.
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

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32h5xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/
extern DCMI_HandleTypeDef hdcmi;
extern DMA_HandleTypeDef handle_GPDMA2_Channel5;
extern DMA_HandleTypeDef handle_GPDMA1_Channel0;
extern SPI_HandleTypeDef hspi6;
extern TIM_HandleTypeDef htim2;
extern TIM_HandleTypeDef htim3;
extern TIM_HandleTypeDef htim5;
extern TIM_HandleTypeDef htim7;
extern SMARTCARD_HandleTypeDef hsmartcard6;
extern PCD_HandleTypeDef hpcd_USB_DRD_FS;
/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
  while (1)
  {
  }
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/**
  * @brief This function handles Hard fault interrupt.
  */
void HardFault_Handler(void)
{
  /* USER CODE BEGIN HardFault_IRQn 0 */

  /* USER CODE END HardFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_HardFault_IRQn 0 */
    /* USER CODE END W1_HardFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Memory management fault.
  */
void MemManage_Handler(void)
{
  /* USER CODE BEGIN MemoryManagement_IRQn 0 */

  /* USER CODE END MemoryManagement_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_MemoryManagement_IRQn 0 */
    /* USER CODE END W1_MemoryManagement_IRQn 0 */
  }
}

/**
  * @brief This function handles Pre-fetch fault, memory access fault.
  */
void BusFault_Handler(void)
{
  /* USER CODE BEGIN BusFault_IRQn 0 */

  /* USER CODE END BusFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_BusFault_IRQn 0 */
    /* USER CODE END W1_BusFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Undefined instruction or illegal state.
  */
void UsageFault_Handler(void)
{
  /* USER CODE BEGIN UsageFault_IRQn 0 */

  /* USER CODE END UsageFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_UsageFault_IRQn 0 */
    /* USER CODE END W1_UsageFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/******************************************************************************/
/* STM32H5xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32h5xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles EXTI Line4 interrupt.
  */
void EXTI4_IRQHandler(void)
{
  /* USER CODE BEGIN EXTI4_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END EXTI4_IRQn 0 */
  HAL_GPIO_EXTI_IRQHandler(GPIO_HALT_REQ_Pin);
  /* USER CODE BEGIN EXTI4_IRQn 1 */
#endif
  /* USER CODE END EXTI4_IRQn 1 */
}

/**
  * @brief This function handles EXTI Line10 interrupt.
  */
void EXTI10_IRQHandler(void)
{
  /* USER CODE BEGIN EXTI10_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END EXTI10_IRQn 0 */
  HAL_GPIO_EXTI_IRQHandler(GPIO_SC_PRES_Pin);
  /* USER CODE BEGIN EXTI10_IRQn 1 */
#endif
  /* USER CODE END EXTI10_IRQn 1 */
}

/**
  * @brief This function handles EXTI Line13 interrupt.
  */
void EXTI13_IRQHandler(void)
{
  /* USER CODE BEGIN EXTI13_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END EXTI13_IRQn 0 */
  HAL_GPIO_EXTI_IRQHandler(GPIO_VUSB_OK_Pin);
  /* USER CODE BEGIN EXTI13_IRQn 1 */
#endif
  /* USER CODE END EXTI13_IRQn 1 */
}

/**
  * @brief This function handles GPDMA1 Channel 0 global interrupt.
  */
void GPDMA1_Channel0_IRQHandler(void)
{
  /* USER CODE BEGIN GPDMA1_Channel0_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END GPDMA1_Channel0_IRQn 0 */
  HAL_DMA_IRQHandler(&handle_GPDMA1_Channel0);
  /* USER CODE BEGIN GPDMA1_Channel0_IRQn 1 */
#endif
  /* USER CODE END GPDMA1_Channel0_IRQn 1 */
}

/**
  * @brief This function handles TIM2 global interrupt.
  */
void TIM2_IRQHandler(void)
{
  /* USER CODE BEGIN TIM2_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END TIM2_IRQn 0 */
  HAL_TIM_IRQHandler(&htim2);
  /* USER CODE BEGIN TIM2_IRQn 1 */
#endif
  /* USER CODE END TIM2_IRQn 1 */
}

/**
  * @brief This function handles TIM3 global interrupt.
  */
void TIM3_IRQHandler(void)
{
  /* USER CODE BEGIN TIM3_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END TIM3_IRQn 0 */
  HAL_TIM_IRQHandler(&htim3);
  /* USER CODE BEGIN TIM3_IRQn 1 */
#endif
  /* USER CODE END TIM3_IRQn 1 */
}

/**
  * @brief This function handles TIM5 global interrupt.
  */
void TIM5_IRQHandler(void)
{
  /* USER CODE BEGIN TIM5_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END TIM5_IRQn 0 */
  HAL_TIM_IRQHandler(&htim5);
  /* USER CODE BEGIN TIM5_IRQn 1 */
#endif
  /* USER CODE END TIM5_IRQn 1 */
}

/**
  * @brief This function handles TIM7 global interrupt.
  */
void TIM7_IRQHandler(void)
{
  /* USER CODE BEGIN TIM7_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END TIM7_IRQn 0 */
  HAL_TIM_IRQHandler(&htim7);
  /* USER CODE BEGIN TIM7_IRQn 1 */
#endif
  /* USER CODE END TIM7_IRQn 1 */
}

/**
  * @brief This function handles USB FS global interrupt.
  */
void USB_DRD_FS_IRQHandler(void)
{
  /* USER CODE BEGIN USB_DRD_FS_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END USB_DRD_FS_IRQn 0 */
  HAL_PCD_IRQHandler(&hpcd_USB_DRD_FS);
  /* USER CODE BEGIN USB_DRD_FS_IRQn 1 */
#endif
  /* USER CODE END USB_DRD_FS_IRQn 1 */
}

/**
  * @brief This function handles SPI6 global interrupt.
  */
void SPI6_IRQHandler(void)
{
  /* USER CODE BEGIN SPI6_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END SPI6_IRQn 0 */
  HAL_SPI_IRQHandler(&hspi6);
  /* USER CODE BEGIN SPI6_IRQn 1 */
#endif
  /* USER CODE END SPI6_IRQn 1 */
}

/**
  * @brief This function handles USART6 global interrupt.
  */
void USART6_IRQHandler(void)
{
  /* USER CODE BEGIN USART6_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END USART6_IRQn 0 */
  HAL_SMARTCARD_IRQHandler(&hsmartcard6);
  /* USER CODE BEGIN USART6_IRQn 1 */
#endif
  /* USER CODE END USART6_IRQn 1 */
}

/**
  * @brief This function handles GPDMA2 Channel 5 global interrupt.
  */
void GPDMA2_Channel5_IRQHandler(void)
{
  /* USER CODE BEGIN GPDMA2_Channel5_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END GPDMA2_Channel5_IRQn 0 */
  HAL_DMA_IRQHandler(&handle_GPDMA2_Channel5);
  /* USER CODE BEGIN GPDMA2_Channel5_IRQn 1 */
#endif
  /* USER CODE END GPDMA2_Channel5_IRQn 1 */
}

/**
  * @brief This function handles DCMI/PSSI global interrupt.
  */
void DCMI_PSSI_IRQHandler(void)
{
  /* USER CODE BEGIN DCMI_PSSI_IRQn 0 */
#ifndef BOOTLOADER
  /* USER CODE END DCMI_PSSI_IRQn 0 */
  HAL_DCMI_IRQHandler(&hdcmi);
  /* USER CODE BEGIN DCMI_PSSI_IRQn 1 */
#endif
  /* USER CODE END DCMI_PSSI_IRQn 1 */
}

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */
