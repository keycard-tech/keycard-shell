#ifndef __HAL_STM32__
#define __HAL_STM32__

#include "stm32h573xx.h"

typedef struct {
  uint32_t len;
  uint32_t buf;
} hal_sha256_ctx_t;
typedef uint32_t hal_crc32_ctx_t;

#define APP_NOCACHE APP_ALIGNED
#define APP_RAMFUNC
#define CAMERA_BUFFER_ALIGN 4

#define VBAT_MIN 3100
#define VBAT_MAX 4100
#define VBAT_USB 4600

#define HAL_FLASH_SIZE FLASH_SIZE
#define HAL_FLASH_BLOCK_SIZE FLASH_SECTOR_SIZE
#define HAL_FLASH_WORD_SIZE 16
#define HAL_FLASH_BLOCK_COUNT (FLASH_SECTOR_NB << 1)
#define HAL_FLASH_ADDR FLASH_BASE

#define HAL_FLASH_BL_BLOCK_COUNT 4

#define HAL_FLASH_DATA_BLOCK_COUNT 96

#define HAL_FLASH_FW_START_ADDR (HAL_FLASH_ADDR + ((HAL_FLASH_BLOCK_SIZE * HAL_FLASH_BL_BLOCK_COUNT)))

#define HAL_FLASH_FW_UPGRADE_AREA (HAL_FLASH_ADDR + (HAL_FLASH_BLOCK_SIZE * HAL_FLASH_BL_BLOCK_COUNT) + (HAL_FLASH_BLOCK_SIZE * FLASH_SECTOR_NB))
#define HAL_FLASH_FW_BLOCK_COUNT 76

#define HAL_FW_HEADER_OFFSET 588

static inline void hal_reboot() {
  NVIC_SystemReset();
}

static inline bool hal_flash_busy() {
  return FLASH_NS->NSSR & FLASH_SR_BSY;
}

#endif
