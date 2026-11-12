#ifndef KEYS_HOST_H
#define KEYS_HOST_H

#include <stdint.h>

#include "storage/keys.h"

/*
 * Installing a public key the device is expected to trust.
 *
 * The keys the firmware embeds are each in their own elf section -- .keycard_ca_key, .db_auth_key --
 * because the release tool substitutes them into an image after the rest of it is hashed.
 * host_key_set() does the same thing to the running test binary's copy of those bytes:
 * nothing in the firmware is changed and nothing about the check is faked, so a key that was not
 * installed is still refused and the signature path is the firmware's own.
 *
 * FW_VERIFICATION_KEY is not one of them: the firmware reads it out of the running image's header at
 * HAL_FLASH_ADDR + HAL_FW_HEADER_OFFSET, which the flash model maps. Ask for hal_host_flash_block().
 */
void host_key_set(key_type_t type, const uint8_t public_key[33]);

/* Every installed key back to what the binary was built with. */
void host_key_reset(void);

#endif /* KEYS_HOST_H */
