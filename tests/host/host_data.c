#include <stdint.h>
#include "mem.h"
#include "common.h"
#include "ui/ui_internal.h"

/*
 * Data that lives in app/mem.c on the target, which cannot be compiled off-target: it places
 * objects in linker-script sections (%nobits@) the host assembler rejects. The host build only
 * needs the constant, whose value is fully determined by its declaration in mem.h.
 */
const uint8_t ZERO32[32] __attribute__((aligned(4))) = {0};

/* The one block buffer fs.c stages a block in while it rewrites it, so it has to be exactly one block
 * for an overflow of it to mean what it means on the device. */
APP_ALIGNED(uint8_t g_flash_swap[HAL_FLASH_BLOCK_SIZE], 4);

/* The two raw arenas the firmware indexes by hand -- a transaction context is laid over a camera frame
 * and read past its end -- so both have to be exactly the size mem.h declares them. Nothing here
 * allocates from them. */
uint8_t g_mem_heap[MEM_HEAP_SIZE];
uint8_t g_camera_fb[CAMERA_FB_COUNT][CAMERA_FB_SIZE];

/* Set to BOOTCMD_SWITCH_FW by an upgrade that asks the bootloader to come up in the other bank. The
 * reboot itself is scripted in hal_host.c, so this is the half a test reads back. */
uint32_t g_bootcmd;

/* Whatever build this image pretends to be. Distinct bytes, so a reply that carried the version can be
 * told from one that carried the buffer that held it. Tests read this rather than restating it. */
const uint8_t FW_VERSION[4] = { 0x01, 0x02, 0x03, 0x00 };

/* The command the ui task fills in when a prompt is answered over USB, and whose result the core's own
 * wait reads. Prompts are answered directly here, so only a test that walks that wait writes it. */
struct ui_cmd g_ui_cmd;
