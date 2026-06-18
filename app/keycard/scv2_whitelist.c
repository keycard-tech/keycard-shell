#include "scv2_whitelist.h"
#include "storage/fs.h"
#include <string.h>

#define FS_SCV2_WHITELIST_MAGIC 0x5343

typedef struct __attribute__ ((packed)) {
  fs_entry_t _fs_data;
  uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN];
} scv2_whitelist_entry_t;

struct scv2_whitelist_match_ctx {
  const uint8_t* pubkey;
  fs_action_t match_action;
  fs_action_t mismatch_action;
};

static fs_action_t _scv2_whitelist_match_pubkey(void* ctx, fs_entry_t* entry) {
  if (entry->magic != FS_SCV2_WHITELIST_MAGIC) {
    return FS_REJECT;
  }

  scv2_whitelist_entry_t* wh_entry = (scv2_whitelist_entry_t*) entry;
  struct scv2_whitelist_match_ctx* match_ctx = (struct scv2_whitelist_match_ctx*) ctx;

  return memcmp(wh_entry->pubkey, match_ctx->pubkey, SCV2_WHITELIST_PUBKEY_LEN)
         ? match_ctx->mismatch_action
         : match_ctx->match_action;
}

app_err_t scv2_whitelist_check(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]) {
  struct scv2_whitelist_match_ctx match_ctx = {
    .pubkey = pubkey,
    .match_action = FS_ACCEPT,
    .mismatch_action = FS_REJECT,
  };

  fs_entry_t* entry = fs_find(_scv2_whitelist_match_pubkey, &match_ctx);

  return entry ? ERR_OK : ERR_DATA;
}

app_err_t scv2_whitelist_add(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]) {
  /* Check if already present */
  if (scv2_whitelist_check(pubkey) == ERR_OK) {
    return ERR_OK;
  }

  scv2_whitelist_entry_t entry;
  entry._fs_data.magic = FS_SCV2_WHITELIST_MAGIC;
  entry._fs_data.len = SCV2_WHITELIST_PUBKEY_LEN;
  memcpy(entry.pubkey, pubkey, SCV2_WHITELIST_PUBKEY_LEN);

  return fs_write(&entry._fs_data, sizeof(scv2_whitelist_entry_t));
}

app_err_t scv2_whitelist_remove(const uint8_t pubkey[SCV2_WHITELIST_PUBKEY_LEN]) {
  struct scv2_whitelist_match_ctx match_ctx = {
    .pubkey = pubkey,
    .match_action = FS_STOP,
    .mismatch_action = FS_ACCEPT,
  };

  return fs_erase_all(_scv2_whitelist_match_pubkey, &match_ctx);
}
