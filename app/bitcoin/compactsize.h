
#ifndef PSBT_COMPACTSIZE_H
#define PSBT_COMPACTSIZE_H

#include "psbt_tx.h"

uint64_t compactsize_read(uint8_t *data, psbt_result_t *err);
uint32_t compactsize_length(uint64_t data);
void compactsize_write(uint8_t *dest, uint64_t size);
uint32_t compactsize_peek_length(uint8_t chsize);

#endif /* PSBT_COMPACTSIZE_H */
