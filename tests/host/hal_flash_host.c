#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hal.h"
#include "hal_host.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/*
 * NOR flash for the host build, modelled at the hal_flash_* boundary.
 *
 * Geometry comes from host_stm32.h, which mirrors the STM32H573VI. The data-segment map is the one
 * in stm32/Core/Src/stm32_flash.c and it is duplicated here in both bank orientations because
 * app/storage/fs.c walks that map to find its pages, and the walk visits the same blocks in a
 * different order after a firmware swap.
 *
 * This models silicon, not the driver. stm32_flash.c's own bookkeeping -- the PG bit, the head, bulk
 * and tail split it applies to an unaligned address -- is not reproduced and cannot be: on a host
 * every store the driver makes is an ordinary store, so there is nothing here that could tell a write
 * the controller would have accepted from one it would have ignored. What this model does see is
 * every byte fs.c asks to be written and where, which is the half that has never been pinned.
 *
 * The rules are the device's, taken strictly:
 *   - programming may only clear bits, so a byte must be 0xFF where a write lands;
 *   - erase takes a whole block and erases the whole block;
 *   - begin_program and end_program bracket every write, and blocks are erased between them.
 * A broken rule is recorded and printed rather than returned as an error: the device reports a
 * programming failure as little as this model does, because hal_flash_program returns whatever
 * hal_flash_wait_program returned, which is always success. A test therefore asserts
 * hal_host_flash_violations() == 0 and reads hal_host_flash_last_violation() when it is not.
 *
 * Writes are AND-ed into the array even with the 0xFF rule in force, so a test that relaxes the rule
 * sees the corrupted result the hardware would give rather than a clean overwrite.
 *
 * The array is mapped at the device's own base address because fs.c dereferences flash pointers
 * directly and this model reads a device address back out of the pointer it is handed, so the host has
 * to make that address real and low. ASan cannot
 * see an overrun inside an mmap'd region, which is why the range checks below are here; g_flash_swap,
 * which is where fs.c stages a block before rewriting it, is an ordinary array and ASan does watch it.
 */

static uint8_t* flash;
static bool unlocked;
static bool swapped;
static size_t violations;
static char last_violation[256];
static size_t programs_done;
static size_t programs_unaligned;
static size_t erases_done;
static bool switch_requested;
static bool refuse_unlock;
static int program_budget = -1;
static int erase_budget = -1;

static const hal_flash_data_segment_t segments[] = {
  { .addr = HAL_FLASH_BLOCK_ADDR(80), .count = 48 },
  { .addr = HAL_FLASH_BLOCK_ADDR(208), .count = 48 },
};

static const hal_flash_data_segment_t segments_swapped[] = {
  { .addr = HAL_FLASH_BLOCK_ADDR(208), .count = 48 },
  { .addr = HAL_FLASH_BLOCK_ADDR(80), .count = 48 },
};

static void flash_init(void) {
  if (flash) {
    return;
  }

  void* at = mmap((void*)HAL_FLASH_ADDR, HAL_FLASH_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

  if (at != (void*)HAL_FLASH_ADDR) {
    fprintf(stderr, "flash model: cannot map %u bytes at 0x%08lx, which is where the code under test "
                    "expects flash to be\n", (unsigned)HAL_FLASH_SIZE, (unsigned long)HAL_FLASH_ADDR);
    abort();
  }

  flash = at;
  memset(flash, 0xff, HAL_FLASH_SIZE);
}

static uint8_t* cell(uint32_t addr) {
  return flash + (addr - (uint32_t)HAL_FLASH_ADDR);
}

static void report(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(last_violation, sizeof(last_violation), fmt, ap);
  va_end(ap);

  violations++;
  fprintf(stderr, "flash model: %s\n", last_violation);
}

/* --- controls --- */

void hal_host_flash_reset(void) {
  flash_init();

  memset(flash, 0xff, HAL_FLASH_SIZE);
  unlocked = false;
  swapped = false;
  refuse_unlock = false;
  violations = 0;
  last_violation[0] = '\0';
  programs_done = 0;
  programs_unaligned = 0;
  erases_done = 0;
  switch_requested = false;
  program_budget = -1;
  erase_budget = -1;
}

size_t hal_host_flash_violations(void) {
  return violations;
}

const char* hal_host_flash_last_violation(void) {
  return last_violation;
}

uint8_t* hal_host_flash_block(uint32_t block) {
  flash_init();

  if (block >= HAL_FLASH_BLOCK_COUNT) {
    return NULL;
  }

  return cell(HAL_FLASH_BLOCK_ADDR(block));
}

void hal_host_flash_bank_swapped(bool now_swapped) {
  swapped = now_swapped;
}

size_t hal_host_flash_programs(void) {
  return programs_done;
}

size_t hal_host_flash_unaligned_programs(void) {
  return programs_unaligned;
}

size_t hal_host_flash_erases(void) {
  return erases_done;
}

void hal_host_flash_interrupt_after(int programs, int erases) {
  program_budget = programs;
  erase_budget = erases;
}

void hal_host_flash_refuse_unlock(bool refuse) {
  refuse_unlock = refuse;
}

bool hal_host_flash_switch_requested(void) {
  return switch_requested;
}

/* --- the hal interface --- */

const hal_flash_data_segment_t* hal_flash_get_data_segments() {
  return swapped ? segments_swapped : segments;
}

hal_err_t hal_flash_begin_program() {
  flash_init();

  if (unlocked) {
    report("begin_program while a program is still open");
  }

  if (refuse_unlock) {
    return HAL_FAIL;
  }

  unlocked = true;
  return HAL_SUCCESS;
}

hal_err_t hal_flash_end_program() {
  flash_init();

  if (!unlocked) {
    report("end_program without a begin_program");
  }

  unlocked = false;
  return HAL_SUCCESS;
}

hal_err_t hal_flash_program(const uint8_t* data, uint8_t* addr, size_t len) {
  flash_init();

  uint32_t at = (uint32_t)(uintptr_t)addr;

  if (!unlocked) {
    report("program of %zu bytes at 0x%08x with the flash locked", len, at);
  }

  if (program_budget == 0) {
    program_budget = -1;
    return HAL_FAIL;
  }

  if (program_budget > 0) {
    program_budget--;
  }

  if (!len) {
    return HAL_SUCCESS;
  }

  if (at < (uint32_t)HAL_FLASH_ADDR || (uint64_t)at + len > (uint64_t)HAL_FLASH_ADDR + HAL_FLASH_SIZE) {
    report("program of %zu bytes at 0x%08x is outside the flash", len, at);
    return HAL_SUCCESS;
  }

  size_t over = 0;
  uint32_t first_at = 0;
  uint8_t first_was = 0;

  for (size_t i = 0; i < len; i++) {
    uint8_t* to = cell(at + i);

    if (*to != 0xff) {
      if (!over) {
        first_at = at + i;
        first_was = *to;
      }
      over++;
    }

    *to &= data[i];
  }

  if (over) {
    report("program of %zu bytes at 0x%08x writes over %zu bytes that are not erased; the first is "
           "0x%08x, which held 0x%02x and was written 0x%02x", len, at, over, first_at, first_was,
           data[first_at - at]);
  }

  if ((at & (HAL_FLASH_WORD_SIZE - 1)) || (len & (HAL_FLASH_WORD_SIZE - 1))) {
    programs_unaligned++;
  }

  programs_done++;
  return HAL_SUCCESS;
}

hal_err_t hal_flash_erase(uint32_t block) {
  flash_init();

  if (!unlocked) {
    report("erase of block %u with the flash locked", block);
  }

  if (block >= HAL_FLASH_BLOCK_COUNT) {
    report("erase of block %u, which the device does not have", block);
    return HAL_SUCCESS;
  }

  if (erase_budget == 0) {
    erase_budget = -1;
    return HAL_FAIL;
  }

  if (erase_budget > 0) {
    erase_budget--;
  }

  /* An erase interrupted on hardware leaves some cells still programmed; that is not modelled, so a
   * test that fails an erase sees a block that is untouched rather than one half gone. */
  memset(cell(HAL_FLASH_BLOCK_ADDR(block)), 0xff, HAL_FLASH_BLOCK_SIZE);
  erases_done++;
  return HAL_SUCCESS;
}

bool hal_flash_busy() {
  return false;
}

void hal_flash_switch_firmware() {
  /* Neither the option bytes nor the reset that follows are modelled. A test that wants the other
   * bank orientation asks for it directly; this records that the code asked to reboot. */
  switch_requested = true;
}
