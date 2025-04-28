#include <string.h>

#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "eth_data.h"

#define ETH_ERC20_TRANSFER_SIGNATURE_LEN 16
#define ETH_ERC20_TRANSFER_LEN 68

#define ETH_ERC20_TRANSFER_ADDR_OFF 16
#define ETH_ERC20_TRANSFER_VALUE_OFF 36

const uint8_t ETH_ERC20_TRANSFER_SIGNATURE[] = {
    0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define ETH_ERC20_APPROVE_SIGNATURE_LEN 16
#define ETH_ERC20_APPROVE_LEN 68

#define ETH_ERC20_APPROVE_ADDR_OFF 16
#define ETH_ERC20_APPROVE_VALUE_OFF 36

const uint8_t ETH_ERC20_APPROVE_SIGNATURE[] = {
    0x09, 0x5e, 0xa7, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

eth_data_type_t eth_data_recognize(const txContent_t* tx) {
  if (tx->value.length == 0) {
    if ((tx->dataLength == ETH_ERC20_TRANSFER_LEN) && !memcmp(tx->data, ETH_ERC20_TRANSFER_SIGNATURE, ETH_ERC20_TRANSFER_SIGNATURE_LEN)) {
      return ETH_DATA_ERC20_TRANSFER;
    } else if ((tx->dataLength == ETH_ERC20_APPROVE_LEN) && !memcmp(tx->data, ETH_ERC20_APPROVE_SIGNATURE, ETH_ERC20_APPROVE_SIGNATURE_LEN)) {
      return ETH_DATA_ERC20_APPROVE;
    }
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

