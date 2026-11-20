#include "eth_multisend.h"
#include "eth_data.h"
#include <string.h>

/* Packed record layout:
 * https://github.com/safe-fndn/safe-smart-account/blob/v1.5.0/contracts/libraries/MultiSend.sol#L41-L55
 */
#define ETH_MULTISEND_OPERATION_OFFSET 0
#define ETH_MULTISEND_TO_OFFSET (ETH_MULTISEND_OPERATION_OFFSET + sizeof(uint8_t))
#define ETH_MULTISEND_VALUE_OFFSET (ETH_MULTISEND_TO_OFFSET + ADDRESS_LENGTH)
#define ETH_MULTISEND_DATA_LEN_OFFSET (ETH_MULTISEND_VALUE_OFFSET + ETH_ABI_WORD_LEN)
#define ETH_MULTISEND_HEADER_LEN (ETH_MULTISEND_DATA_LEN_OFFSET + ETH_ABI_WORD_LEN)

bool eth_multisend_next(eth_multisend_t* b, eth_multisend_call_t* c) {
  if (b->offset > b->length || b->length - b->offset < ETH_MULTISEND_HEADER_LEN) {
    return false;
  }

  const uint8_t* p = b->payload + b->offset;
  uint16_t data_len = eth_data_read_short(p + ETH_MULTISEND_DATA_LEN_OFFSET);

  if (data_len == UINT16_MAX || data_len > b->length - b->offset - ETH_MULTISEND_HEADER_LEN) {
    return false;
  }

  c->operation = p[ETH_MULTISEND_OPERATION_OFFSET];
  c->to = p + ETH_MULTISEND_TO_OFFSET;
  c->value = p + ETH_MULTISEND_VALUE_OFFSET;
  c->data = p + ETH_MULTISEND_HEADER_LEN;
  c->data_len = data_len;
  b->offset += ETH_MULTISEND_HEADER_LEN + data_len;

  return true;
}
eth_multisend_result_t eth_multisend_init(eth_multisend_t* out, const uint8_t* payload, size_t length) {
  memset(out, 0, sizeof(*out));
  eth_multisend_t b = {.payload = payload, .length = length};
  while (b.offset < b.length) {
    eth_multisend_call_t c;
    
    if (!eth_multisend_next(&b, &c) || c.operation > 1) {
      return ETH_MULTISEND_MALFORMED;
    }

    b.count++;
  }

  if (!b.count) {
    return ETH_MULTISEND_EMPTY;
  }

  b.offset = 0;
  *out = b;

  return ETH_MULTISEND_COMPLETE;
}
