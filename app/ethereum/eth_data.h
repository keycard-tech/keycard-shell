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

#ifdef __ETH_ABI_FS_STORAGE
#define ETH_ABI_DEREF(__TYPE__, __STRUCT__, __FIELD__) ((__STRUCT__->__FIELD__) == 0 ? NULL : (__TYPE__)(((uint32_t) __STRUCT__) + (__STRUCT__->__FIELD__)))
#else
#define ETH_ABI_DEREF(__TYPE__, __STRUCT__, __FIELD__) (__STRUCT__->__FIELD__)
#endif

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
  ETH_DATA_PLAIN,
  ETH_DATA_ERC20_TRANSFER,
  ETH_DATA_ERC20_APPROVE,
} eth_data_type_t;

typedef enum {
  EIP712_UNKNOWN,
  EIP712_PERMIT,
  EIP712_PERMIT_SINGLE
} eip712_data_type_t;

typedef struct _eth_abi_argument {
  eth_abi_type_t type;
  const struct _eth_abi_argument* next;
  const struct _eth_abi_argument* child;
} eth_abi_argument_t;

typedef struct {
  uint32_t selector;
  const char* name;
  const eth_abi_argument_t* first_arg;
  eth_data_type_t data_type;
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
} eth_transfer_info;

typedef struct {
  eip712_domain_t domain;
  chain_desc_t chain;
  erc20_desc_t token;
  const uint8_t* spender;
  bignum256 value;
  bignum256 fees;
  uint8_t _addr[32];
  uint8_t _chain_num[11];
} eth_approve_info;

const eth_abi_function_t* eth_data_recognize(const txContent_t* tx);
eip712_data_type_t eip712_recognize(const eip712_ctx_t* ctx);

app_err_t eip712_extract_domain(const eip712_ctx_t* ctx, eip712_domain_t* out);

app_err_t eth_extract_transfer_info(const txContent_t* tx, const eth_abi_function_t* abi, eth_transfer_info* info);
app_err_t eth_extract_approve_info(const txContent_t* tx, const eth_abi_function_t* abi, eth_approve_info* info);

app_err_t eip712_extract_permit(const eip712_ctx_t* ctx, eth_approve_info* info);
app_err_t eip712_extract_permit_single(const eip712_ctx_t* ctx, eth_approve_info* info);

app_err_t eth_data_tuple_get_elem(eth_abi_type_t type, uint8_t idx, const uint8_t* data, size_t data_len, const uint8_t** out, size_t* out_len);

#endif
