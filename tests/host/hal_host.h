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
void hal_host_rng_refuse_next(void);

/* Bytes drawn so far, so a test can assert that a code path consumed randomness at all. */
size_t hal_host_rng_count(void);

/* Memory below 4 GB, for anything handed to code that casts pointers to uint32_t -- which the device,
 * a 32-bit machine, can do freely and fs.c does for the entry buffer it is writing, not only for the
 * flash addresses. A normal static array on a 64-bit host truncates and the code lands in the weeds.
 * Aborts if the region runs out. It is mmap'd, so ASan has no redzones around what it returns. */
void* hal_host_low_mem(size_t size);

/* AES, modelled at the hal_aes256_* and hal_aes128_ccm_* boundary in host/hal_aes_host.c, from FIPS-197
 * and SP 800-38C rather than from how app/crypto/aes*.c drives them. A call the model cannot honour (a B0
 * announcing associated data, a tag longer than CCM_TAG_SIZE, a payload that does not match the length B0
 * declared) returns HAL_FAIL and is counted. Reset in setUp(). */
void hal_host_aes_reset(void);

/* hal_derive_device_unique_secret(), modelled in host/hal_derive_host.c the way the driver does it: a
 * two-block chain under a device secret, then SHA-256 over the wrapped bytes. The fused key that
 * AES_CR_KEYSEL_0 selects cannot be modelled, so the test supplies one -- setting it is how a test says
 * "a different device". Reset in setUp(). */
void hal_host_derive_reset(void);
void hal_host_device_secret_set(const uint8_t secret[32]);
size_t hal_host_derive_calls(void);
size_t hal_host_aes_rejections(void);

/* Make the next `jobs` AES jobs refuse to start, CBC or CCM, as silicon refusing would: HAL_FAIL and
 * nothing written to the output. Counted per hal_aes*_init(), so a caller that derives a key first --
 * key_read_private() does, and hal_derive_device_unique_secret() is itself a CBC job here -- needs one
 * more than the encrypt call it is targeting. */
void hal_host_aes_refuse_next(size_t jobs);
size_t hal_host_aes_cbc_blocks(void);
size_t hal_host_aes_ccm_bytes(void);

/* Associated data for the next CCM message, folded into the MAC after B0 and before the payload. Call it
 * between hal_aes128_ccm_init() and the first payload byte. Reachable only through a B0 with the Adata
 * bit set, which app/crypto/aes_ccm.c never builds: this exists so the published SP 800-38C vectors, all
 * of which carry associated data, exercise the model. */
void hal_host_aes_ccm_aad(const uint8_t* data, size_t len);

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
