#ifndef __ETH_DATA__
#define __ETH_DATA__

#include <stddef.h>

#include "crypto/bignum.h"
#include "eip712.h"
#include "eth_db.h"
#include "ethUstream.h"

#define EIP712_MAX_NAME_LEN 40

#define ETH_ABI_NUM_SIGNED (1 << 8)
#define ETH_ABI_NUM_ADDR (1 << 9)
#define ETH_ABI_NUM_BOOL (1 << 10)
#define ETH_ABI_NUM_FIXED (1 << 11)

#define ETH_ABI_DYN_ALPHA (1 << 8)

#define ETH_ABI_COMP_VARLEN (1 << 8)
#define ETH_ABI_COMP_TUPLE (1 << 9)

#define ETH_ABI_NUMERIC (1 << 12)
#define ETH_ABI_DYNAMIC (1 << 13)
#define ETH_ABI_COMPOSITE (1 << 14)

#define ETH_ABI_WORD_LEN 32
#define ETH_ABI_WORD_ADDR_OFF (ETH_ABI_WORD_LEN - ADDRESS_LENGTH)

#define ETH_ABI_SIZED_TYPE(__TYPE__, __SIZE__) (__TYPE__ | (__SIZE__ & 0xff))
#define ETH_ABI_BITSIZED_TYPE(__TYPE__, __SIZE__) ETH_ABI_SIZED_TYPE(__TYPE__, (__SIZE__/8))
#define ETH_ABI_TYPE_SIZE(__SIZED_TYPE__) (__SIZED_TYPE__ & 0xff)
#define ETH_ABI_TUPLE_SIZE(__SIZED_TYPE__) (ETH_ABI_TYPE_SIZE(__SIZED_TYPE__) * ETH_ABI_WORD_LEN)

#define ETH_ABI_DEREF(__TYPE__, __STRUCT__, __FIELD__) ((__STRUCT__->__FIELD__) == 0 ? NULL : (__TYPE__)(((uint32_t) __STRUCT__) + (__STRUCT__->__FIELD__)))

#define ETH_DATA_ERC20_TRANFER_EXT_SELECTOR 0x2432e06e
#define ETH_DATA_ERC20_APPROVE_EXT_SELECTOR 0x502291f4

#define ETH_DATA_EXECUTE_DEADLINE_SELECTOR 0x4c569335
#define ETH_DATA_EXECUTE_DEADLINE_EXT_SELECTOR 0x45cef3fa

#define ETH_DATA_EXECUTE_SELECTOR 0xc36b8524
#define ETH_DATA_EXECUTE_EXT_SELECTOR 0xdb20e9a6

#define ETH_EXECUTE_V3_SWAP_EXACT_IN 0x00
#define ETH_EXECUTE_V3_SWAP_EXACT_OUT 0x01
#define ETH_EXECUTE_PERMIT2_TRANSFER_FROM 0x02
#define ETH_EXECUTE_PERMIT2_PERMIT_BATCH 0x03
#define ETH_EXECUTE_SWEEP 0x04
#define ETH_EXECUTE_TRANSFER 0x05
#define ETH_EXECUTE_PAY_PORTION 0x06
#define ETH_EXECUTE_V2_SWAP_EXACT_IN 0x08
#define ETH_EXECUTE_V2_SWAP_EXACT_OUT 0x09
#define ETH_EXECUTE_PERMIT2_PERMIT 0x0a
#define ETH_EXECUTE_WRAP_ETH 0x0b
#define ETH_EXECUTE_UNWRAP_WETH 0x0c
#define ETH_EXECUTE_PERMIT2_TRANSFER_FROM_BATCH 0x0d
#define ETH_EXECUTE_BALANCE_CHECK_ERC20 0x0e
#define ETH_EXECUTE_V4_SWAP 0x10
#define ETH_EXECUTE_V3_POSITION_MANAGER_PERMIT 0x11
#define ETH_EXECUTE_V3_POSITION_MANAGER_CALL 0x12
#define ETH_EXECUTE_V4_INITIALIZE_POOL 0x13
#define ETH_EXECUTE_V4_POSITION_MANAGER_CALL 0x14
#define ETH_EXECUTE_EXECUTE_SUB_PLAN 0x21

typedef enum {
  ETH_ABI_UINT = ETH_ABI_NUMERIC,
  ETH_ABI_INT = (ETH_ABI_NUMERIC | ETH_ABI_NUM_SIGNED),
  ETH_ABI_BOOL = (ETH_ABI_NUMERIC | ETH_ABI_NUM_BOOL),
  ETH_ABI_FIXED = (ETH_ABI_NUMERIC | ETH_ABI_NUM_FIXED | ETH_ABI_NUM_SIGNED),
  ETH_ABI_UFIXED = (ETH_ABI_NUMERIC | ETH_ABI_NUM_FIXED),
  ETH_ABI_ADDRESS = (ETH_ABI_NUMERIC | ETH_ABI_NUM_ADDR),
  ETH_ABI_BYTES = 0,
  ETH_ABI_VARBYTES = ETH_ABI_DYNAMIC,
  ETH_ABI_STRING = (ETH_ABI_DYNAMIC | ETH_ABI_DYN_ALPHA),
  ETH_ABI_TUPLE = (ETH_ABI_COMPOSITE | ETH_ABI_COMP_TUPLE),
  ETH_ABI_ARRAY = ETH_ABI_COMPOSITE,
  ETH_ABI_VARARRAY = (ETH_ABI_COMPOSITE | ETH_ABI_COMP_VARLEN),
} eth_abi_type_t;

typedef enum {
  ETH_FUNC_PAYABLE = 1
} eth_func_attr_t;

typedef enum {
  ETH_DATA_ERC20_TRANSFER = 0xbb9c05a9,
  ETH_DATA_ERC20_APPROVE = 0xb3a75e09,
} eth_data_type_t;

typedef enum {
  EIP712_UNKNOWN,
  EIP712_PERMIT,
  EIP712_PERMIT_SINGLE,
  EIP712_SAFE_TX
} eip712_data_type_t;

typedef struct __attribute__((packed)) {
  eth_abi_type_t type;
  uint16_t next;
  uint16_t child;
} eth_abi_argument_t;

typedef struct __attribute__((packed)) {
  uint32_t selector;
  uint32_t ext_selector;
  uint16_t name;
  uint16_t first_arg;
  eth_func_attr_t attrs;
} eth_abi_function_t;

typedef struct {
  uint8_t address[32];
  char name[EIP712_MAX_NAME_LEN];
  uint32_t chainID;
} eip712_domain_t;

typedef struct {
  chain_desc_t chain;
  erc20_desc_t token;
  uint8_t* data_str;
  size_t data_str_len;
  const uint8_t* to;
  bignum256 value;
  bignum256 fees;
  uint8_t _chain_num[11];
} eth_transfer_info_t;

typedef struct {
  eip712_domain_t domain;
  chain_desc_t chain;
  erc20_desc_t token;
  const uint8_t* spender;
  bignum256 value;
  bignum256 fees;
  uint8_t _addr[32];
  uint8_t _chain_num[11];
} eth_approve_info_t;

typedef struct {
  eip712_domain_t domain;
  chain_desc_t chain;
  const uint8_t* safeAddr;
  const uint8_t* to;
  uint8_t* data;
  uint32_t data_len;
  bignum256 value;
  uint8_t operation;
  bignum256 safeTxGas;
  bignum256 baseGas;
  bignum256 gasPrice;
  const uint8_t* gasToken;
  const uint8_t* refundReceiver;
  bignum256 nonce;
} eth_safe_tx_t;

const eth_abi_function_t* eth_data_recognize(const uint8_t* data, uint32_t data_len, bool has_value);
void eth_data_format(const eth_abi_function_t* abi, const uint8_t* data, size_t data_len, uint8_t* out, size_t* out_len);
eip712_data_type_t eip712_recognize(const eip712_ctx_t* ctx);

app_err_t eip712_extract_domain(const eip712_ctx_t* ctx, eip712_domain_t* out);

app_err_t eth_extract_transfer_info(const txContent_t* tx, const eth_abi_function_t* abi, eth_transfer_info_t* info);
app_err_t eth_extract_approve_info(const txContent_t* tx, const eth_abi_function_t* abi, eth_approve_info_t* info);

app_err_t eip712_extract_permit(const eip712_ctx_t* ctx, eth_approve_info_t* info);
app_err_t eip712_extract_permit_single(const eip712_ctx_t* ctx, eth_approve_info_t* info);
app_err_t eip712_extract_safe_tx(const eip712_ctx_t* ctx, eth_safe_tx_t* info);

app_err_t eth_data_tuple_get_elem(eth_abi_type_t type, uint8_t idx, const uint8_t* data, size_t data_len, const uint8_t** out, size_t* out_len);

#endif
