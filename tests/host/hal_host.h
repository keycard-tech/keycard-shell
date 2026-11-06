#ifndef HAL_HOST_H
#define HAL_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Controls for the host implementation of the hal_ interface. Tests that reach a function
 * which needs silicon abort with the function's name instead of returning a value that
 * would look like a pass.
 */

/* Seed for the deterministic byte source behind hal_rng_next(). Set before the code under
 * test draws random bytes; two runs with the same seed must take the same path. */
void hal_host_rng_seed(uint64_t seed);

/* Bytes drawn so far, so a test can assert that a code path consumed randomness at all. */
size_t hal_host_rng_count(void);

/* Memory below 4 GB, for anything handed to code that casts pointers to uint32_t -- which the device,
 * a 32-bit machine, can do freely and fs.c does for the entry buffer it is writing, not only for the
 * flash addresses. A normal static array on a 64-bit host truncates and the code lands in the weeds.
 * Aborts if the region runs out. It is mmap'd, so ASan has no redzones around what it returns. */
void* hal_host_low_mem(size_t size);

/* Flash, modelled at the hal_flash_* boundary in host/hal_flash_host.c: NOR semantics, the device's
 * geometry, and its data-segment map in both bank orientations. */

/* All of flash back to 0xFF and every counter and record cleared. Call it in setUp(). */
void hal_host_flash_reset(void);

/* Times the code wrote where the target was not erased, erased a block that does not exist, or wrote
 * outside the begin_program/end_program bracket. The device notices none of this, so neither does the
 * code under test: assert the count is zero and take the message below as the explanation. */
size_t hal_host_flash_violations(void);
const char* hal_host_flash_last_violation(void);

/* Raw bytes of a block, for asserting what is really in the store rather than what an API returns. */
uint8_t* hal_host_flash_block(uint32_t block);

/* Which bank the code sees first, the way the option byte does. fs.c reads its pages through this map,
 * so the two orientations are two orders over the same blocks. */
void hal_host_flash_bank_swapped(bool swapped);

size_t hal_host_flash_programs(void);
size_t hal_host_flash_erases(void);

/* Writes whose address or length is not a multiple of the device's 16 byte program width. On the
 * target these are the writes that stm32_flash.c splits into head, bulk and tail, so the count says how
 * much of the store depends on the flash controller assembling a doubleword across separate calls --
 * which no host can answer for. */
size_t hal_host_flash_unaligned_programs(void);

/* The next N writes and erases succeed, then the following one fails and the budget resets. Give
 * -1 to leave an operation unhurried. An erase that fails leaves the block untouched, which hardware
 * would not. */
void hal_host_flash_interrupt_after(int programs, int erases);

/* Make begin_program fail, the way HAL_FLASH_Unlock() can. The four store entry points all have an arm
 * for it, and nothing else reaches them. */
void hal_host_flash_refuse_unlock(bool refuse);

/* Whether the code asked to boot the other bank. The reset is not modelled. */
bool hal_host_flash_switch_requested(void);

#endif
