#include <string.h>

#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "eth_data.h"

#define ETH_ERC20_TRANSFER_ADDR_OFF 16
#define ETH_ERC20_TRANSFER_VALUE_OFF 36

#define ETH_ERC20_APPROVE_ADDR_OFF 16
#define ETH_ERC20_APPROVE_VALUE_OFF 36

const eth_abi_argument_t ETH_ERC20_TRANSFER_ARG1 = { .type = ETH_ABI_BITSIZED_TYPE(ETH_ABI_UINT, 256), .field_id = 1, .next = NULL, .child = NULL };
const eth_abi_argument_t ETH_ERC20_TRANSFER_ARG0 = { .type = ETH_ABI_ADDRESS, .field_id = 0, .next = &ETH_ERC20_TRANSFER_ARG1, .child = NULL };

const eth_abi_function_t ETH_ABI_DB[] = {
    { .selector = 0xbb9c05a9, .first_arg = &ETH_ERC20_TRANSFER_ARG0, .data_type = ETH_DATA_ERC20_TRANSFER, .attrs = 0 },
    // since the arguments are the same we don't duplicate the definition, either way this will move to the data area
    { .selector = 0xb3a75e09, .first_arg = &ETH_ERC20_TRANSFER_ARG0, .data_type = ETH_DATA_ERC20_APPROVE, .attrs = 0 },
    { .selector = 0 }
};

struct eth_func_search_ctx {
  uint32_t selector;
  const uint8_t* args;
  size_t args_len;
  bool has_value;
};

static inline bool eth_data_check_padding(const uint8_t word[ETH_ABI_WORD_LEN], uint8_t val, uint8_t start, uint8_t end) {
  while (start < end) {
    if (word[start++] != val) {
      return false;
    }
  }

  return true;
}

static bool eth_data_validate_numeric_size(const uint8_t word[ETH_ABI_WORD_LEN], bool is_signed, uint8_t byte_size) {
  uint8_t pad;

  if (is_signed) {
    pad = (word[ETH_ABI_WORD_LEN - byte_size] & 0x80) ? 0xff : 0x00;
  } else {
    pad = 0;
  }

  return eth_data_check_padding(word, pad, 0, (ETH_ABI_WORD_LEN - byte_size));
}

static bool eth_data_validate_bytes_size(const uint8_t word[ETH_ABI_WORD_LEN], uint8_t byte_size) {
  return eth_data_check_padding(word, 0, byte_size, ETH_ABI_WORD_LEN);
}

static uint16_t eth_data_read_short(const uint8_t val[ETH_ABI_WORD_LEN]) {
  if (!eth_data_validate_numeric_size(val, false, sizeof(uint16_t))) {
    return UINT16_MAX;
  }

  return (val[ETH_ABI_WORD_LEN - 2] << 8) | val[ETH_ABI_WORD_LEN - 1];
}

app_err_t eth_data_tuple_get_elem(eth_abi_type_t type, uint8_t idx, const uint8_t* data, size_t data_len, const uint8_t** out, size_t* out_len) {
  size_t off = (idx * ETH_ABI_WORD_LEN);

  if ((data_len < ETH_ABI_WORD_LEN) || (off > (data_len - ETH_ABI_WORD_LEN))) {
    return ERR_DATA;
  }

  if (type & ETH_ABI_COMPOSITE) {
    uint16_t content_off = eth_data_read_short(&data[off]);

    if (type & ETH_ABI_DYNAMIC) {
      if (content_off > (data_len - ETH_ABI_WORD_LEN)) {
        return ERR_DATA;
      }

      *out_len = eth_data_read_short(&data[content_off]);
      if (content_off + ETH_ABI_WORD_LEN + ETH_ABI_TUPLE_SIZE(*out_len) > data_len) {
        return ERR_DATA;
      }

      *out = &data[content_off + ETH_ABI_WORD_LEN];
    } else {
      if (content_off + ETH_ABI_WORD_LEN + ETH_ABI_TUPLE_SIZE(type) > data_len) {
        return ERR_DATA;
      }

      *out = &data[content_off + ETH_ABI_WORD_LEN];
      *out_len = ETH_ABI_TYPE_SIZE(type);
    }
  } if (type & ETH_ABI_DYNAMIC) {
    uint16_t content_off = eth_data_read_short(&data[off]);
    if (content_off > (data_len - ETH_ABI_WORD_LEN)) {
      return ERR_DATA;
    }

    *out_len = eth_data_read_short(&data[content_off]);

    if ((content_off + ETH_ABI_WORD_LEN + *out_len) > data_len) {
      return ERR_DATA;
    }

    *out = &data[content_off + ETH_ABI_WORD_LEN];
  } else {
    *out = &data[off];
    *out_len = ETH_ABI_TYPE_SIZE(type);

    if (type & ETH_ABI_NUMERIC) {
      if (!eth_data_validate_numeric_size(*out, (type & ETH_ABI_NUM_SIGNED) == ETH_ABI_NUM_SIGNED, *out_len)) {
        return ERR_DATA;
      }

      *out_len = ETH_ABI_WORD_LEN;
    } else {
      if (!eth_data_validate_bytes_size(*out, *out_len)) {
        return ERR_DATA;
      }
    }
  }

  return ERR_OK;
}

fs_action_t eth_data_find_function(struct eth_func_search_ctx* search_ctx, const eth_abi_function_t* func) {
  if ((func->selector != search_ctx->selector) || (search_ctx->has_value && !(func->attrs & ETH_FUNC_PAYABLE))) {
    return FS_REJECT;
  }

  size_t args = 0;
  bool strict_size = true;

  const eth_abi_argument_t* arg = ETH_ABI_DEREF(eth_abi_argument_t*, func, first_arg);
  while(arg != NULL) {
    const uint8_t* out;
    size_t out_len;

    if (eth_data_tuple_get_elem(arg->type, args, search_ctx->args, search_ctx->args_len, &out, &out_len) != ERR_OK) {
      return FS_REJECT;
    }

    if ((arg->type & (ETH_ABI_COMPOSITE | ETH_ABI_DYNAMIC)) != 0) {
      strict_size = false;
    }

    arg = ETH_ABI_DEREF(eth_abi_argument_t*, arg, next);
    args++;
  }

  if (strict_size && (ETH_ABI_TUPLE_SIZE(args) != search_ctx->args_len)) {
    return FS_REJECT;
  }

  return FS_ACCEPT;
}

eth_data_type_t eth_data_recognize(const txContent_t* tx) {
  if (tx->dataLength < sizeof(uint32_t)) {
    return ETH_DATA_UNKNOWN;
  }

  struct eth_func_search_ctx search_ctx;
  memcpy(&search_ctx.selector, tx->data, sizeof(uint32_t));
  search_ctx.args = &tx->data[sizeof(uint32_t)];
  search_ctx.args_len = tx->dataLength - sizeof(uint32_t);
  search_ctx.has_value = tx->value.length > 0;

  int i = 0;

  while(ETH_ABI_DB[i].selector != 0) {
    if (eth_data_find_function(&search_ctx, &ETH_ABI_DB[i]) == FS_ACCEPT) {
      return ETH_ABI_DB[i].data_type;
    }

    i++;
  }

  return ETH_DATA_UNKNOWN;
}

eip712_data_type_t eip712_recognize(const eip712_ctx_t* ctx) {
  if (eip712_field_eq(ctx, ctx->index.primary_type, "Permit")) {
    return EIP712_PERMIT;
  } else if (eip712_field_eq(ctx, ctx->index.primary_type, "PermitSingle")) {
    return EIP712_PERMIT_SINGLE;
  }

  return EIP712_UNKNOWN;
}

app_err_t eip712_extract_domain(const eip712_ctx_t* ctx, eip712_domain_t* out) {
  if (eip712_extract_uint256(ctx, ctx->index.domain, "verifyingContract", out->address) != ERR_OK) {
    return ERR_DATA;
  }

  if (eip712_extract_string(ctx, ctx->index.domain, "name", out->name, EIP712_MAX_NAME_LEN) != ERR_OK) {
    out->name[0] = '\0';
  }

  uint8_t chain_bytes[32];

  if (eip712_extract_uint256(ctx, ctx->index.domain, "chainId", chain_bytes) != ERR_OK) {
    return ERR_DATA;
  }

  out->chainID = (chain_bytes[28] << 24) | (chain_bytes[29] << 16) | (chain_bytes[30] << 8) | chain_bytes[31];

  return ERR_OK;
}

static void eth_calculate_fees(const txContent_t* tx, bignum256* fees) {
  bignum256 gas_amount;
  bignum256 prime;
  bn_read_be(secp256k1.prime, &prime);
  bn_read_compact_be(tx->startgas.value, tx->startgas.length, &gas_amount);
  bn_read_compact_be(tx->gasprice.value, tx->gasprice.length, fees);
  bn_multiply(&gas_amount, fees, &prime);
}

static void eth_lookup_chain(uint32_t chain_id, chain_desc_t* chain, uint8_t* chain_num) {
  chain->chain_id = chain_id;

  if (eth_db_lookup_chain(chain) != ERR_OK) {
    chain->name = (char*) u32toa(chain->chain_id, chain_num, 11);
    chain->ticker = "???";
  }
}

static void eth_lookup_token(uint32_t chain_id, const uint8_t* addr, erc20_desc_t* token) {
  token->chain = chain_id;
  token->addr = addr;

  if (eth_db_lookup_erc20(token) != ERR_OK) {
    token->ticker = "???";
    token->decimals = 18;
  }
}

void eth_extract_transfer_info(const txContent_t* tx, eth_transfer_info* info) {
  info->data_str_len = 0;

  eth_lookup_chain(tx->chainID, &info->chain, info->_chain_num);

  const uint8_t* value;
  uint8_t value_len;

  if (info->data_type == ETH_DATA_ERC20_TRANSFER) {
    eth_lookup_token(info->chain.chain_id, tx->destination, &info->token);

    value = &tx->data[ETH_ERC20_TRANSFER_VALUE_OFF];
    value_len = INT256_LENGTH;

    info->to = &tx->data[ETH_ERC20_TRANSFER_ADDR_OFF];
  } else {
    info->token.ticker = info->chain.ticker;
    info->token.decimals = 18;

    value = tx->value.value;
    value_len = tx->value.length;

    info->to = tx->destination;

    if (tx->dataLength) {
      base16_encode(tx->data, (char *) info->data_str, tx->dataLength);
      info->data_str_len = tx->dataLength * 2;
    }
  }

  bn_read_compact_be(value, value_len, &info->value);
  eth_calculate_fees(tx, &info->fees);
}

void eth_extract_approve_info(const txContent_t* tx, eth_approve_info* info) {
  eth_lookup_chain(tx->chainID, &info->chain, info->_chain_num);
  eth_lookup_token(info->chain.chain_id, tx->destination, &info->token);
  bn_read_compact_be(&tx->data[ETH_ERC20_APPROVE_VALUE_OFF], INT256_LENGTH, &info->value);
  info->spender = &tx->data[ETH_ERC20_APPROVE_ADDR_OFF];

  eth_calculate_fees(tx, &info->fees);
}

app_err_t eip712_extract_permit(const eip712_ctx_t* ctx, eth_approve_info* info) {
  if (eip712_extract_domain(ctx, &info->domain) != ERR_OK) {
    return ERR_DATA;
  }

  eth_lookup_chain(info->domain.chainID, &info->chain, info->_chain_num);
  eth_lookup_token(info->chain.chain_id, &info->domain.address[EIP712_ADDR_OFF], &info->token);

  if (eip712_extract_uint256(ctx, ctx->index.message, "spender", info->_addr) != ERR_OK) {
    return ERR_DATA;
  }

  info->spender = &info->_addr[EIP712_ADDR_OFF];

  uint8_t value[INT256_LENGTH];

  if (eip712_extract_uint256(ctx, ctx->index.message, "value", value) != ERR_OK) {
    return ERR_DATA;
  }

  bn_read_be(value, &info->value);
  bn_zero(&info->fees);

  return ERR_OK;
}

app_err_t eip712_extract_permit_single(const eip712_ctx_t* ctx, eth_approve_info* info) {
  if (eip712_extract_domain(ctx, &info->domain) != ERR_OK) {
    return ERR_DATA;
  }

  eth_lookup_chain(info->domain.chainID, &info->chain, info->_chain_num);

  if (eip712_extract_uint256(ctx, ctx->index.message, "spender", info->_addr) != ERR_OK) {
    return ERR_DATA;
  }

  info->spender = &info->_addr[EIP712_ADDR_OFF];

  int details = eip712_find_field(ctx, ctx->index.message, "details");

  if (details == -1) {
    return ERR_DATA;
  }

  if (eip712_extract_uint256(ctx, details, "token", info->domain.address) != ERR_OK) {
    return ERR_DATA;
  }

  eth_lookup_token(info->chain.chain_id, &info->domain.address[EIP712_ADDR_OFF], &info->token);

  uint8_t value[INT256_LENGTH];

  if (eip712_extract_uint256(ctx, details, "amount", value) != ERR_OK) {
    return ERR_DATA;
  }

  bn_read_be(value, &info->value);
  bn_zero(&info->fees);

  return ERR_OK;
}

