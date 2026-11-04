/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

/**
 * @brief Utilities for an Ethereum Hardware Wallet logic
 * @file ethUtils.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 8th of March 2016
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ethUtils.h"

bool rlpCanDecode(uint8_t *buffer, uint32_t bufferLength, bool *valid) {
	if (*buffer <= 0x7f) {
	} else if (*buffer <= 0xb7) {
	} else if (*buffer <= 0xbf) {
		if (bufferLength < (1 + (*buffer - 0xb7))) {
			return false;
		}
		if (*buffer > 0xbb) {
			*valid = false;  // arbitrary 32 bits length limitation
			return true;
		}
	} else if (*buffer <= 0xf7) {
	} else {
		if (bufferLength < (1 + (*buffer - 0xf7))) {
			return false;
		}
		if (*buffer > 0xfb) {
			*valid = false;  // arbitrary 32 bits length limitation
			return true;
		}
	}
	*valid = true;
	return true;
}

bool rlpDecodeLength(uint8_t *buffer, uint32_t *fieldLength, uint32_t *offset, bool *list) {
	if (*buffer <= 0x7f) {
		*offset = 0;
		*fieldLength = 1;
		*list = false;
	} else if (*buffer <= 0xb7) {
		*offset = 1;
		*fieldLength = *buffer - 0x80;
		*list = false;
	} else if (*buffer <= 0xbf) {
		*offset = 1 + (*buffer - 0xb7);
		*list = false;
		switch (*buffer) {
			case 0xb8:
				*fieldLength = *(buffer + 1);
				break;
			case 0xb9:
				*fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
				break;
			case 0xba:
				*fieldLength = (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
				break;
			case 0xbb:
				*fieldLength = ((uint32_t) *(buffer + 1) << 24) + ((uint32_t) *(buffer + 2) << 16) +
							   ((uint32_t) *(buffer + 3) << 8) + *(buffer + 4);
				break;
			default:
				return false;  // arbitrary 32 bits length limitation
		}
	} else if (*buffer <= 0xf7) {
		*offset = 1;
		*fieldLength = *buffer - 0xc0;
		*list = true;
	} else {
		*offset = 1 + (*buffer - 0xf7);
		*list = true;
		switch (*buffer) {
			case 0xf8:
				*fieldLength = *(buffer + 1);
				break;
			case 0xf9:
				*fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
				break;
			case 0xfa:
				*fieldLength = (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
				break;
			case 0xfb:
				*fieldLength = ((uint32_t) *(buffer + 1) << 24) + ((uint32_t) *(buffer + 2) << 16) +
							   ((uint32_t) *(buffer + 3) << 8) + *(buffer + 4);
				break;
			default:
				return false;  // arbitrary 32 bits length limitation
		}
	}

	return true;
}

bool adjustDecimals(const char *src, size_t srcLength, char *target, size_t targetLength, uint8_t decimals) {
	uint32_t startOffset;
	uint32_t lastZeroOffset = 0;
	uint32_t offset = 0;
	
  if ((srcLength == 1) && (*src == '0')) {
		if (targetLength < 2) {
			return false;
		}
		target[0] = '0';
		target[1] = '\0';
		return true;
	}

	if (srcLength <= decimals) {
		uint32_t delta = decimals - srcLength;
		if (targetLength < srcLength + 1 + 2 + delta) {
			return false;
		}
		target[offset++] = '0';
		target[offset++] = '.';
		for (uint32_t i = 0; i < delta; i++) {
			target[offset++] = '0';
		}
		startOffset = offset;
		for (uint32_t i = 0; i < srcLength; i++) {
			target[offset++] = src[i];
		}
		target[offset] = '\0';
	} else {
		uint32_t sourceOffset = 0;
		uint32_t delta = srcLength - decimals;
		if (targetLength < srcLength + 1 + 1) {
			return false;
		}
		while (offset < delta) {
			target[offset++] = src[sourceOffset++];
		}
		if (decimals != 0) {
			target[offset++] = '.';
		}
		startOffset = offset;
		while (sourceOffset < srcLength) {
			target[offset++] = src[sourceOffset++];
		}
		target[offset] = '\0';
	}

	for (uint32_t i = startOffset; i < offset; i++) {
		if (target[i] == '0') {
			if (lastZeroOffset == 0) {
				lastZeroOffset = i;
			}
		} else {
			lastZeroOffset = 0;
		}
	}

	if (lastZeroOffset != 0) {
		target[lastZeroOffset] = '\0';
		if (target[lastZeroOffset - 1] == '.') {
			target[lastZeroOffset - 1] = '\0';
		}
	}
	return true;
}

uint32_t u32_from_BE(const uint8_t *in, uint8_t size) {
    uint8_t i = 0;
    uint32_t res = 0;

    while (i < size && i < sizeof(res)) {
        res <<= 8;
        res |= in[i];
        i++;
    }

    return res;
}
