#include <stdint.h>
#include "mem.h"

/*
 * Data that lives in app/mem.c on the target, which cannot be compiled off-target: it places
 * objects in linker-script sections (%nobits@) the host assembler rejects. The host build only
 * needs the constant, whose value is fully determined by its declaration in mem.h.
 */
const uint8_t ZERO32[32] __attribute__((aligned(4))) = {0};

/* The one block buffer fs.c stages a block in while it rewrites it, so it has to be exactly one block
 * for an overflow of it to mean what it means on the device. */
APP_ALIGNED(uint8_t g_flash_swap[HAL_FLASH_BLOCK_SIZE], 4);
