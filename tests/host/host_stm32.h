#ifndef __HAL_HOST_PLATFORM__
#define __HAL_HOST_PLATFORM__

/*
 * Platform definition for the native test build (HOST_TEST). It replaces
 * stm32/Core/Inc/stm32.h and keeps the hardware-facing macros and geometry that the
 * application code expects, while dropping every register access. Peripheral values
 * mirror the STM32H573VI so that tests of flash consumers exercise the real layout.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common.h"

typedef struct {
  uint32_t len;
  uint32_t buf;
} hal_sha256_ctx_t;
typedef uint32_t hal_crc32_ctx_t;

#define APP_NOCACHE
#define APP_RAMFUNC
#define CAMERA_BUFFER_ALIGN 4

#define VBAT_MIN 3100
#define VBAT_MAX 4100

#define HAL_FLASH_SIZE 0x200000
#define HAL_FLASH_BLOCK_SIZE 0x2000
#define HAL_FLASH_WORD_SIZE 16
#define HAL_FLASH_BLOCK_COUNT 256
#define HAL_FLASH_ADDR 0x8000000UL

#define HAL_FLASH_BL_BLOCK_COUNT 4

#define HAL_FLASH_DATA_BLOCK_COUNT 96

#define HAL_FLASH_FW_START_ADDR (HAL_FLASH_ADDR + ((HAL_FLASH_BLOCK_SIZE * HAL_FLASH_BL_BLOCK_COUNT)))

#define HAL_FLASH_FW_UPGRADE_AREA (HAL_FLASH_ADDR + (HAL_FLASH_BLOCK_SIZE * HAL_FLASH_BL_BLOCK_COUNT) + (HAL_FLASH_BLOCK_SIZE * 128))
#define HAL_FLASH_FW_BLOCK_COUNT 76

#define HAL_FW_HEADER_OFFSET 588

#endif
