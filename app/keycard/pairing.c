#include "pairing.h"
#include "storage/keys.h"
#include "crypto/aes.h"
#include "crypto/memzero.h"
#include <string.h>

#define FS_PAIRING_MAGIC 0x5041

struct pairing_match_ctx {
  const uint8_t* instance_uid;
  fs_action_t match_action;
  fs_action_t mismatch_action;
};

fs_action_t _pairing_match_uid(void* ctx, fs_entry_t* entry) {
  if (entry->magic != FS_PAIRING_MAGIC) {
    return FS_REJECT;
  }

  pairing_t* pairing = (pairing_t*) entry;
  struct pairing_match_ctx* match_ctx = (struct pairing_match_ctx*) ctx;

  return memcmp(pairing->instance_uid, match_ctx->instance_uid, APP_INFO_INSTANCE_UID_LEN) ? match_ctx->mismatch_action : match_ctx->match_action;
}

app_err_t pairing_read(pairing_t* out) {
  struct pairing_match_ctx match_ctx = {.instance_uid = out->instance_uid, .match_action = FS_ACCEPT, .mismatch_action = FS_REJECT};
  pairing_t* entry = (pairing_t*) fs_find(_pairing_match_uid, &match_ctx);

  if (!entry) {
    return ERR_DATA;
  }

  uint8_t pairing_enc_key[AES_256_KEY_SIZE];
  key_read_private(PAIRING_ENC_PRIV_KEY, pairing_enc_key);
  aes_decrypt_cbc(pairing_enc_key, entry->instance_uid, entry->key, SHA256_DIGEST_LENGTH, out->key);
  memzero(pairing_enc_key, AES_256_KEY_SIZE);

  out->idx = entry->idx;

  return ERR_OK;
}

app_err_t pairing_write(const pairing_t* in) {
  pairing_t write;
  write._fs_data.magic = FS_PAIRING_MAGIC;
  write._fs_data.len = APP_INFO_INSTANCE_UID_LEN + SHA256_DIGEST_LENGTH + 1;
  write.idx = in->idx;
  memcpy(write.instance_uid, in->instance_uid, APP_INFO_INSTANCE_UID_LEN);

  uint8_t pairing_enc_key[AES_256_KEY_SIZE];
  key_read_private(PAIRING_ENC_PRIV_KEY, pairing_enc_key);
  aes_encrypt_cbc(pairing_enc_key, in->instance_uid, in->key, SHA256_DIGEST_LENGTH, write.key);
  memzero(pairing_enc_key, AES_256_KEY_SIZE);

  return fs_write((fs_entry_t*) &write, sizeof(pairing_t));
}

app_err_t pairing_erase(const pairing_t* in) {
  struct pairing_match_ctx match_ctx = {.instance_uid = in->instance_uid, .match_action = FS_STOP, .mismatch_action = FS_ACCEPT};
  return fs_erase_all(_pairing_match_uid, &match_ctx);
}
