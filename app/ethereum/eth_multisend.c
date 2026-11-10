#include "eth_multisend.h"
#include <string.h>

/* Canonical addresses, recognized independently of chain:
 * https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.3.0
 * https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1
 * https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.5.0
 * Entries: multi_send.json and multi_send_call_only.json.
 */
static const struct { uint8_t address[20]; eth_multisend_variant_t variant; } deployments[] = {
  {{0xa2,0x38,0xcb,0xeb,0x14,0x2c,0x10,0xef,0x7a,0xd8,0x44,0x2c,0x6d,0x1f,0x9e,0x89,0xe0,0x7e,0x77,0x61}, ETH_MULTISEND_V130},
  {{0x40,0xa2,0xac,0xcb,0xd9,0x2b,0xca,0x93,0x8b,0x02,0x01,0x0e,0x17,0xa5,0xb8,0x92,0x9b,0x49,0x13,0x0d}, ETH_MULTISEND_CALL_ONLY_V130},
  {{0x38,0x86,0x9b,0xf6,0x6a,0x61,0xcf,0x6b,0xdb,0x99,0x6a,0x6a,0xe4,0x0d,0x58,0x53,0xfd,0x43,0xb5,0x26}, ETH_MULTISEND_V141},
  {{0x96,0x41,0xd7,0x64,0xfc,0x13,0xc8,0xb6,0x24,0xc0,0x44,0x30,0xc7,0x35,0x6c,0x1c,0x7c,0x81,0x02,0xe2}, ETH_MULTISEND_CALL_ONLY_V141},
  {{0x21,0x85,0x43,0x28,0x80,0x04,0xcd,0x07,0x83,0x24,0x72,0xd4,0x64,0x64,0x81,0x73,0xc7,0x7d,0x7e,0xb7}, ETH_MULTISEND_V150},
  {{0xa8,0x3c,0x33,0x6b,0x20,0x40,0x1a,0xf7,0x73,0xb6,0x21,0x9b,0xa5,0x02,0x71,0x74,0x33,0x8d,0x18,0x36}, ETH_MULTISEND_CALL_ONLY_V150},
};
eth_multisend_variant_t eth_multisend_classify(const uint8_t to[20]) {
  for (size_t i = 0; i < sizeof(deployments) / sizeof(deployments[0]); i++) {
    if (!memcmp(to, deployments[i].address, 20)) return deployments[i].variant;
  }
  return ETH_MULTISEND_NONE;
}
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
eth_multisend_result_t eth_multisend_init(eth_multisend_t* out, const uint8_t* data,
    size_t len, eth_multisend_variant_t variant) {
  memset(out, 0, sizeof(*out));
  size_t offset, length;
  if (variant < ETH_MULTISEND_V130 || variant > ETH_MULTISEND_CALL_ONLY_V150)
    return ETH_MULTISEND_UNSUPPORTED;
  if (len < 68 || memcmp(data, "\x8d\x80\xff\x0a", 4) ||
      !read_size(data + 4, &offset) || offset != 32 ||
      !read_size(data + 36, &length) || length > len - 68)
    return ETH_MULTISEND_MALFORMED;
  size_t padding = (32 - length % 32) % 32;
  if (len - 68 - length != padding) return ETH_MULTISEND_MALFORMED;
  for (size_t i = len - padding; i < len; i++)
    if (data[i]) return ETH_MULTISEND_MALFORMED;
  eth_multisend_t b = {.payload = data + 68, .length = length};
  while (b.offset < b.length) {
    eth_multisend_call_t c;
    if (!eth_multisend_next(&b, &c) || c.operation > 1) return ETH_MULTISEND_MALFORMED;
    if (c.operation == 1) {
      if (variant == ETH_MULTISEND_CALL_ONLY_V130 || variant == ETH_MULTISEND_CALL_ONLY_V141 ||
          variant == ETH_MULTISEND_CALL_ONLY_V150)
        return ETH_MULTISEND_MALFORMED;
    }
    if (++b.count > ETH_MULTISEND_MAX_CALLS) return ETH_MULTISEND_LIMIT;
  }
  if (!b.count) return ETH_MULTISEND_EMPTY;
  b.offset = 0;
  *out = b;
  return ETH_MULTISEND_COMPLETE;
}
