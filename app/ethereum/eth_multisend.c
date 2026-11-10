#include "eth_multisend.h"
#include <string.h>

static int read_size(const uint8_t* p, size_t* value) {
  *value = 0;
  for (size_t i = 0; i < 32; i++) {
    if (*value > (SIZE_MAX - p[i]) / 256) return 0;
    *value = *value * 256 + p[i];
  }
  return 1;
}
int eth_multisend_next(eth_multisend_t* b, eth_multisend_call_t* c) {
  if (b->offset > b->length || b->length - b->offset < 85) return 0;
  const uint8_t* p = b->payload + b->offset;
  if (!read_size(p + 53, &c->data_len) || c->data_len > b->length - b->offset - 85) return 0;
  c->operation = p[0]; c->to = p + 1; c->value = p + 21; c->data = p + 85;
  b->offset += 85 + c->data_len;
  return 1;
}
eth_multisend_result_t eth_multisend_init(eth_multisend_t* out, const uint8_t* payload, size_t length) {
  memset(out, 0, sizeof(*out));
  eth_multisend_t b = {.payload = payload, .length = length};
  while (b.offset < b.length) {
    eth_multisend_call_t c;
    if (!eth_multisend_next(&b, &c) || c.operation > 1) return ETH_MULTISEND_MALFORMED;
    b.count++;
  }
  if (!b.count) return ETH_MULTISEND_EMPTY;
  b.offset = 0;
  *out = b;
  return ETH_MULTISEND_COMPLETE;
}
