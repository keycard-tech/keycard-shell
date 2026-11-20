#include "unity.h"
#include "ethereum/eth_multisend.h"
#include "ethereum/eth_data.h"
#include "crypto/util.h"
#include "storage/fs.h"
#include "hal_host.h"
#include "ui/i18n.h"
#include <string.h>

static uint8_t data[4096];
void setUp(void) { memset(data, 0, sizeof(data)); hal_host_flash_reset(); i18n_set_strings(i18n_english_strings); }
void tearDown(void) {}

static void word(uint8_t* p, size_t v) {
  for (int i = 31; i >= 0; i--) { p[i] = v & 255; v >>= 8; }
}

/* Independent encoder for the packed records inside multiSend(bytes). */
static size_t fixture(unsigned count, size_t child_len) {
  memset(data, 0, sizeof(data));
  for (unsigned i = 0; i < count; i++) {
    uint8_t* p = data + i * (85 + child_len);
    memset(p + 1, i + 1, 20);
    p[21] = 0x80; p[52] = i;
    word(p + 53, child_len);
    memset(p + 85, 0xab, child_len);
  }
  return count * (85 + child_len);
}

static void valid(void) {
  for (unsigned count = 1; count <= 32; count++) {
    for (size_t child_len = 0; child_len < 5; child_len++) {
      size_t len = fixture(count, child_len);
      eth_multisend_t b;
      TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len));
      TEST_ASSERT_EQUAL(count, b.count);
      for (unsigned i = 0; i < count; i++) {
        eth_multisend_call_t c;
        TEST_ASSERT_TRUE(eth_multisend_next(&b, &c));
        TEST_ASSERT_EQUAL(0, c.operation);
        TEST_ASSERT_EQUAL(i + 1, c.to[0]);
        TEST_ASSERT_EQUAL(0x80, c.value[0]);
        TEST_ASSERT_EQUAL(i, c.value[31]);
        TEST_ASSERT_EQUAL(child_len, c.data_len);
        if (child_len) {
          TEST_ASSERT_EQUAL(0xab, c.data[child_len - 1]);
        }
      }
      eth_multisend_call_t c;
      TEST_ASSERT_FALSE(eth_multisend_next(&b, &c));
    }
  }
}

static void invalid(void) {
  eth_multisend_t b;
  size_t len = fixture(2, 0);
  data[85] = 2;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len));
  TEST_ASSERT_EQUAL(0, b.count); /* Do not expose the valid prefix. */
  data[85] = 1;
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len));
  data[53] = 1; /* Full-width uint256 length cannot fit. */
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len));
  word(data + 53, UINT16_MAX); /* Existing reader's error sentinel. */
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len));
  word(data + 53, (size_t)UINT16_MAX + 1);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, len));
  fixture(1, 0);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, 86));
}

static void limits(void) {
  eth_multisend_t b;
  size_t len = fixture(17, 0);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_COMPLETE, eth_multisend_init(&b, data, len));
  TEST_ASSERT_EQUAL(17, b.count);
  TEST_ASSERT_EQUAL(ETH_MULTISEND_EMPTY, eth_multisend_init(&b, data, 0));
  len = fixture(1, 3);
  for (size_t truncated = 1; truncated < len; truncated++)
    TEST_ASSERT_EQUAL(ETH_MULTISEND_MALFORMED, eth_multisend_init(&b, data, truncated));
}

static void random_inputs(void) {
  uint32_t seed = 1234567;
  eth_multisend_t b;
  for (unsigned i = 0; i < 10000; i++) {
    seed = seed * 1664525 + 1013904223;
    size_t len = seed % sizeof(data);
    for (size_t j = 0; j < len; j++) {
      seed = seed * 1664525 + 1013904223; data[j] = seed >> 24;
    }
    eth_multisend_init(&b, data, len);
  }
}

/* One packed record as it appears inside multiSend(bytes). */
static size_t record(uint8_t* p, uint8_t operation, uint8_t to, const uint8_t* child, size_t child_len) {
  memset(p, 0, 85 + child_len);
  p[0] = operation;
  memset(p + 1, to, 20);
  word(p + 53, child_len);
  memcpy(p + 85, child, child_len);
  return 85 + child_len;
}

/* multiSend(bytes) calldata carrying a batch. */
static size_t multi_send(uint8_t* out, const uint8_t* batch, size_t batch_len) {
  const uint32_t selector = ETH_DATA_MULTISEND_SELECTOR;
  memcpy(out, &selector, 4);
  word(out + 4, 32);
  word(out + 36, batch_len);
  memcpy(out + 68, batch, batch_len);
  return 68 + ((batch_len + 31) / 32) * 32;
}

/* Installed ABI records, in the relative-offset representation of the real database. */
static void install_multisend_abi(void) {
  static struct {
    fs_entry_t entry;
    eth_abi_function_t function;
    eth_abi_argument_t arg;
    char name[10];
  } multisend;
  memset(&multisend, 0, sizeof(multisend));
  multisend.entry.magic = FS_ABI_MAGIC;
  multisend.entry.len = sizeof(multisend) - sizeof(fs_entry_t);
  multisend.function.selector = ETH_DATA_MULTISEND_SELECTOR;
  multisend.function.ext_selector = ETH_DATA_MULTISEND_EXT_SELECTOR;
  multisend.function.attrs = ETH_FUNC_PAYABLE;
  multisend.function.first_arg = (uint8_t*)&multisend.arg - (uint8_t*)&multisend.function;
  multisend.function.name = (uint8_t*)multisend.name - (uint8_t*)&multisend.function;
  multisend.arg.type = ETH_ABI_VARBYTES;
  strcpy(multisend.name, "multiSend");
  TEST_ASSERT_EQUAL(ERR_OK, fs_write(&multisend.entry, sizeof(multisend)));
}

static void install_transfer_abi(void) {
  static struct {
    fs_entry_t entry;
    eth_abi_function_t function;
    eth_abi_argument_t args[2];
    char name[9];
  } transfer;
  memset(&transfer, 0, sizeof(transfer));
  transfer.entry.magic = FS_ABI_MAGIC;
  transfer.entry.len = sizeof(transfer) - sizeof(fs_entry_t);
  transfer.function.selector = ETH_DATA_ERC20_TRANSFER;
  transfer.function.ext_selector = ETH_DATA_ERC20_TRANFER_EXT_SELECTOR;
  transfer.function.first_arg = (uint8_t*)&transfer.args - (uint8_t*)&transfer.function;
  transfer.function.name = (uint8_t*)transfer.name - (uint8_t*)&transfer.function;
  transfer.args[0].type = ETH_ABI_BITSIZED_TYPE(ETH_ABI_ADDRESS, 160);
  transfer.args[0].next = (uint8_t*)&transfer.args[1] - (uint8_t*)&transfer.args[0];
  transfer.args[1].type = ETH_ABI_BITSIZED_TYPE(ETH_ABI_UINT, 256);
  strcpy(transfer.name, "transfer");
  TEST_ASSERT_EQUAL(ERR_OK, fs_write(&transfer.entry, sizeof(transfer)));
}

static void formatting(void) {
  static uint8_t encoded[512], out[1024];
  memset(encoded, 0, sizeof(encoded));
  size_t length = fixture(2, 1);
  memcpy(encoded, "\x8d\x80\xff\x0a", 4);
  word(encoded + 4, 32);
  word(encoded + 36, length);
  word(data + 21, 1000000000);
  data[86] = 1; /* The second record uses DELEGATECALL. */
  memcpy(encoded + 68, data, length);
  size_t encoded_len = 68 + ((length + 31) / 32) * 32;
  TEST_ASSERT_NULL(eth_data_recognize(encoded, encoded_len, false));
  size_t out_len;
  uint8_t num[11];
  chain_desc_t unknown, polygon;
  eth_lookup_chain(1, &unknown, num);
  TEST_ASSERT_EQUAL_STRING("???", unknown.ticker);
  TEST_ASSERT_EQUAL_STRING("1", unknown.name);
  eth_data_context_t context = {.chain = &unknown};
  eth_data_format(NULL, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_EQUAL_HEX8('8', out[0]); /* No ABI: raw calldata. */
  install_multisend_abi();
  const eth_abi_function_t* found = eth_data_recognize(encoded, encoded_len, false);
  TEST_ASSERT_NOT_NULL(found);
  static struct __attribute__((packed)) {
    fs_entry_t entry;
    uint32_t chain_id;
    char strings[30];
  } chain = {
    .entry = {.magic = 0x4348, .len = sizeof(chain) - sizeof(fs_entry_t)},
    .chain_id = 137,
    .strings = "POL\0Polygon\0Polygon",
  };
  TEST_ASSERT_EQUAL(ERR_OK, fs_write(&chain.entry, sizeof(chain)));
  eth_lookup_chain(137, &polygon, num);
  TEST_ASSERT_EQUAL_STRING("POL", polygon.ticker);
  TEST_ASSERT_EQUAL_STRING("Polygon", polygon.name);
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Value: 0.000000001 ???\n"));
  context.chain = &polygon;
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Call 1/2\nTo: 0x0101010101010101010101010101010101010101\n"));
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Call 2/2\nWarning: nested delegatecall\nTo: 0x0202020202020202020202020202020202020202\n"));
  TEST_ASSERT_EQUAL_HEX8('b', out[out_len - 1]); /* No trailing blank pages. */
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Value: 0.000000001 POL\n"));
  word(encoded + 68 + 21, 1);
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Value: A bit of POL\n"));
  word(encoded + 68 + 21, 1000000000);
  /* The unit is the chain under review's, not a property of the payload. */
  context.chain = &unknown;
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Value: 0.000000001 ???\n"));
  context.chain = &polygon;
  /* Payable recognition must also allow the batch expansion. */
  found = eth_data_recognize(encoded, encoded_len, true);
  TEST_ASSERT_NOT_NULL(found);
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "Call 1/2"));
  /* A malformed last record must discard the valid first call's expansion. */
  encoded[68 + 86] = 2;
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);
  TEST_ASSERT_NULL(strstr((char*)out, "Call 1/2"));
  eth_data_format(found, encoded, encoded_len, out, 4, &out_len, &context);
  TEST_ASSERT_EQUAL(0, out_len);
}

/* A child call is decoded with the same machinery as a top-level calldata. */
/* How a stored selector looks once base16_encode has run over it, as the formatter does. */
static const char* selector_hex(uint32_t stored, char out[9]) {
  base16_encode((const uint8_t*)&stored, out, 4);
  return out;
}

static void child_call(void) {
  install_multisend_abi();
  install_transfer_abi();

  const uint32_t transfer_selector = ETH_DATA_ERC20_TRANSFER;
  uint8_t transfer_call[68];
  memset(transfer_call, 0, sizeof(transfer_call));
  memcpy(transfer_call, &transfer_selector, 4);
  memset(transfer_call + 16, 0xab, 20);
  word(transfer_call + 36, 12345);

  uint8_t inner[85];
  memset(inner, 0, sizeof(inner));
  memset(inner + 1, 0x09, 20);
  uint8_t nested[68 + 96];
  size_t nested_len = multi_send(nested, inner, sizeof(inner));

  uint8_t batch[2 * (85 + sizeof(nested))];
  size_t batch_len = record(batch, 0, 1, transfer_call, sizeof(transfer_call));
  batch_len += record(batch + batch_len, 0, 2, nested, nested_len);

  uint8_t encoded[1024];
  size_t encoded_len = multi_send(encoded, batch, batch_len);
  const eth_abi_function_t* found = eth_data_recognize(encoded, encoded_len, false);
  TEST_ASSERT_NOT_NULL(found);

  chain_desc_t chain;
  uint8_t num[11];
  eth_lookup_chain(1, &chain, num);
  eth_data_context_t context = {.chain = &chain};
  uint8_t out[2048];
  size_t out_len;
  eth_data_format(found, encoded, encoded_len, out, sizeof(out), &out_len, &context);

  char transfer_hex[9], nested_hex[9];
  selector_hex(transfer_selector, transfer_hex);
  selector_hex(ETH_DATA_MULTISEND_SELECTOR, nested_hex);
  /* The recognized child is named with its arguments, not dumped. */
  TEST_ASSERT_NOT_NULL(strstr((char*)out, "transfer(0x"));
  TEST_ASSERT_NOT_NULL(strstr((char*)out, ", 12345)"));
  TEST_ASSERT_NULL(strstr((char*)out, transfer_hex));
  /* A nested batch keeps the depth limit: named by its calldata, not expanded again. */
  TEST_ASSERT_NOT_NULL(strstr((char*)out, nested_hex));
  TEST_ASSERT_NULL(strstr((char*)out, "Call 1/1"));
  TEST_ASSERT_NULL(strstr((char*)out, "To: 0x0909090909090909090909090909090909090909"));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(valid); RUN_TEST(invalid); RUN_TEST(limits); RUN_TEST(random_inputs); RUN_TEST(formatting);
  RUN_TEST(child_call);
  return UNITY_END();
}
