/*!
 * \file CM7.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m7
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 17 Jun 2018
 */

#ifndef AES_CM7_H
#define AES_CM7_H

#include <stdint.h>
#include <stddef.h>
#include "hal.h"

APP_RAMFUNC void CM7_1T_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
APP_RAMFUNC void CM7_1T_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
APP_RAMFUNC void CM7_1T_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

APP_RAMFUNC void CM7_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);

APP_RAMFUNC void CM7_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
APP_RAMFUNC void CM7_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#endif // AES_CM7_H
