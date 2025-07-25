#ifndef __SLIP39_H__
#define __SLIP39_H__

#define SLIP39_WORDS_COUNT 1024

extern const char* const slip39_wordlist[SLIP39_WORDS_COUNT];

#include <stdint.h>

void slip39_encrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output);
void slip39_decrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output);

#endif
