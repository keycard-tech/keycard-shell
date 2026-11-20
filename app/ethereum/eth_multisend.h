#ifndef ETH_MULTISEND_H
#define ETH_MULTISEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  ETH_MULTISEND_COMPLETE, ETH_MULTISEND_MALFORMED,
  ETH_MULTISEND_EMPTY
} eth_multisend_result_t;

typedef struct {
  uint8_t operation;
  const uint8_t *to, *value, *data;
  size_t data_len;
} eth_multisend_call_t;

typedef struct {
  const uint8_t* payload;
  size_t length, offset, count;
} eth_multisend_t;

/* Packed transactions extracted from multiSend(bytes) by the ABI reader.
 * Validate every record before exposing an iterator. No allocation or copying. */
eth_multisend_result_t eth_multisend_init(eth_multisend_t* out, const uint8_t* payload, size_t length);
bool eth_multisend_next(eth_multisend_t* batch, eth_multisend_call_t* call);

#endif
