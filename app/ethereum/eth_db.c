#include "eth_db.h"
#include <string.h>

#define FS_CHAIN_MAGIC 0x4348
#define FS_ERC20_MAGIC 0x3020
#define FS_VERSION_MAGIC 0x4532
#define FS_DELTA_MAGIC 0x444c

#define ERC20_NET_LEN 24

struct __attribute__((packed)) chain_raw_desc {
  fs_entry_t _entry;
  uint32_t chain_id;
  char data[];
};

struct __attribute__((packed)) erc20_raw_desc {
  fs_entry_t _entry;
  uint8_t net_count;
  uint8_t data[];
};

struct __attribute__((packed)) abi_raw_desc {
  fs_entry_t _entry;
  uint64_t full_selector;
  uint8_t data[];
};

struct __attribute__((packed)) version_desc {
  fs_entry_t _entry;
  uint32_t version;
};

struct __attribute__((packed)) delta_desc {
  uint16_t magic;
  uint32_t old_version;
  uint16_t erase_chain_len;
  uint16_t erase_token_len;
  uint16_t erase_abi_len;
  uint8_t data[];
};

struct delta_erase_ctx {
  uint8_t* erase_chain;
  uint8_t* erase_token;
  uint8_t* erase_abi;
  uint16_t erase_chain_len;
  uint16_t erase_token_len;
  uint16_t erase_abi_len;
};

fs_action_t _eth_db_match_chain(void* ctx, fs_entry_t* entry) {
  if (entry->magic != FS_CHAIN_MAGIC) {
    return FS_REJECT;
  }

  chain_desc_t* chain = (chain_desc_t*) ctx;
  struct chain_raw_desc* chain_data = (struct chain_raw_desc*) entry;

  return chain_data->chain_id == chain->chain_id ? FS_ACCEPT : FS_REJECT;
}

fs_action_t _eth_db_match_erc20(void* ctx, fs_entry_t* entry) {
  if (entry->magic != FS_ERC20_MAGIC) {
    return FS_REJECT;
  }

  erc20_desc_t* erc20 = (erc20_desc_t*) ctx;
  struct erc20_raw_desc* erc20_data = (struct erc20_raw_desc*) entry;

  int count = erc20_data->net_count;
  uint8_t* data = erc20_data->data;

  while (count--) {
    if (!memcmp(&erc20->chain, data, 4) && !memcmp(erc20->addr, &data[4], 20)) {
      return FS_ACCEPT;
    }

    data += ERC20_NET_LEN;
  }

  return FS_REJECT;
}

fs_action_t _eth_db_match_version(void* ctx, fs_entry_t* entry) {
  return entry->magic == FS_VERSION_MAGIC ? FS_ACCEPT : FS_REJECT;
}

fs_action_t _eth_db_match_all(void* ctx, fs_entry_t* entry) {
  return ((entry->magic == FS_CHAIN_MAGIC) || (entry->magic == FS_ERC20_MAGIC) || (entry->magic == FS_VERSION_MAGIC) || (entry->magic == FS_ABI_MAGIC)) ? FS_REJECT : FS_ACCEPT;
}

static inline fs_action_t _eth_db_match_erase_chain(struct delta_erase_ctx* ctx, struct chain_raw_desc* entry) {
  for (int i = 0; i < ctx->erase_chain_len; i += 4) {
    if (!memcmp(&entry->chain_id, &ctx->erase_chain[i], 4)) {
      return FS_REJECT;
    }
  }

  return FS_ACCEPT;
}

static inline fs_action_t _eth_db_match_erase_token(struct delta_erase_ctx* ctx, struct erc20_raw_desc* entry) {
  uint8_t* ticker = entry->data + (entry->net_count * ERC20_NET_LEN) + 1;
  size_t off = 0;

  while (off < ctx->erase_token_len) {
    size_t ticker_off = 0;

    while(1) {
      if (ticker[ticker_off] != ctx->erase_token[off]) {
        while(ctx->erase_token[off++] != '\0') {
          continue;
        }

        break;
      }

      if (ticker[ticker_off] == '\0') {
        return FS_REJECT;
      }

      ticker_off++;
      off++;
    }
  }

  return FS_ACCEPT;
}

static inline fs_action_t _eth_db_match_erase_abi(struct delta_erase_ctx* ctx, struct abi_raw_desc* entry) {
  for (int i = 0; i < ctx->erase_abi_len; i += 8) {
    if (!memcmp(&entry->full_selector, &ctx->erase_abi[i], 8)) {
      return FS_REJECT;
    }
  }

  return FS_ACCEPT;
}

fs_action_t _eth_db_match_delta(void* ctx, fs_entry_t* entry) {
  switch(entry->magic) {
  case FS_VERSION_MAGIC:
    return FS_REJECT;
  case FS_CHAIN_MAGIC:
    return _eth_db_match_erase_chain((struct delta_erase_ctx*) ctx, (struct chain_raw_desc*) entry);
  case FS_ERC20_MAGIC:
    return _eth_db_match_erase_token((struct delta_erase_ctx*) ctx, (struct erc20_raw_desc*) entry);
  case FS_ABI_MAGIC:
    return _eth_db_match_erase_abi((struct delta_erase_ctx*) ctx, (struct abi_raw_desc*) entry);
  default:
    return FS_ACCEPT;
  }
}

app_err_t eth_db_lookup_chain(chain_desc_t* chain) {
  struct chain_raw_desc* chain_data = (struct chain_raw_desc*) fs_find(_eth_db_match_chain, chain);

  if (!chain_data) {
    return ERR_DATA;
  }

  chain->ticker = chain_data->data;
  chain->name = chain->ticker + strlen(chain->ticker) + 1;
  chain->short_name = chain->name + strlen(chain->name) + 1;

  return ERR_OK;
}

app_err_t eth_db_lookup_erc20(erc20_desc_t* erc20) {
  struct erc20_raw_desc* erc20_data = (struct erc20_raw_desc*) fs_find(_eth_db_match_erc20, erc20);

  if (!erc20_data) {
    return ERR_DATA;
  }

  uint8_t* data = erc20_data->data + (erc20_data->net_count * ERC20_NET_LEN);
  erc20->decimals = *(data++);
  erc20->ticker = (char *) data;

  return ERR_OK;
}

app_err_t eth_db_lookup_version(uint32_t* version) {
  struct version_desc* version_data = (struct version_desc*) fs_find(_eth_db_match_version, NULL);

  if (!version_data) {
    return ERR_DATA;
  }

  *version = version_data->version;

  return ERR_OK;
}

static app_err_t eth_full_db_rewrite(fs_entry_t* entries, size_t len) {
  app_err_t err = fs_erase_all(_eth_db_match_all, NULL);

  // since our matcher doesn't know when it has reached completion, if everything went OK the error code
  // will be ERR_DATA on success.
  if (err != ERR_DATA) {
    return err;
  }

  return fs_write(entries, len);
}

__attribute__((unused)) static app_err_t eth_delta_db_update(struct delta_desc* delta, size_t len) {
  uint32_t version;
  if (eth_db_lookup_version(&version) != ERR_OK) {
    return ERR_HW;
  }

  if (delta->old_version != version) {
    return ERR_VERSION;
  }

  struct delta_erase_ctx erase_ctx = {
      .erase_chain = &delta->data[0],
      .erase_token = &delta->data[delta->erase_chain_len],
      .erase_abi = &delta->data[delta->erase_chain_len + delta->erase_token_len],
      .erase_chain_len = delta->erase_chain_len,
      .erase_token_len = delta->erase_token_len,
      .erase_abi_len = delta->erase_abi_len
  };

  fs_entry_t* entries = (fs_entry_t*) &delta->data[delta->erase_chain_len + delta->erase_token_len + delta->erase_abi_len];

  size_t off = sizeof(struct delta_desc) + delta->erase_chain_len + delta->erase_token_len + delta->erase_abi_len;

  if (off > len) {
    return ERR_DATA;
  }

  app_err_t err = fs_erase_all(_eth_db_match_delta, &erase_ctx);

  // since our matcher doesn't know when it has reached completion, if everything went OK the error code
  // will be ERR_DATA on success. This could be optimized if noticeable delays are observed.
  if (err != ERR_DATA) {
    return err;
  }

  return fs_write(entries, (len - off));
}

static inline uint16_t eth_db_get_magic(uint8_t* data) {
  return data[0] | (data[1] << 8);
}

app_err_t eth_db_update(uint8_t* data, size_t len) {
  switch(eth_db_get_magic(data)) {
  case FS_VERSION_MAGIC:
    return eth_full_db_rewrite((fs_entry_t*) data, len);
  default:
    return ERR_UNSUPPORTED;
  }
}

app_err_t eth_db_extract_version(uint8_t* data, uint32_t* version) {
  struct version_desc* ver_data;
  struct delta_desc* delta;

  switch(eth_db_get_magic(data)) {
  case FS_VERSION_MAGIC:
    ver_data = (struct version_desc*) data;
    break;
  case FS_DELTA_MAGIC:
    delta = (struct delta_desc*) data;
    ver_data = (struct version_desc*) (&delta->data[delta->erase_chain_len + delta->erase_token_len + delta->erase_abi_len]);
    break;
  default:
    return ERR_UNSUPPORTED;
  }

  *version = ver_data->version;
  return ERR_OK;
}
