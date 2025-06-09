#ifndef _MEM_H_
#define _MEM_H_

#include <stdint.h>
#include "hal.h"

#define MEM_HEAP_SIZE (128 * 1024)

#define BOOTCMD_SWITCH_FW 0x83578007

extern const uint8_t ZERO32[32];

extern uint8_t g_mem_heap[MEM_HEAP_SIZE];
extern uint8_t g_flash_swap[HAL_FLASH_BLOCK_SIZE];
extern uint8_t g_camera_fb[CAMERA_FB_COUNT][CAMERA_FB_SIZE];

extern uint32_t g_bootcmd;

#endif
