#include "multisig_store.h"

#include <string.h>

#include "crypto/memzero.h"
#include "crypto/rand.h"

#define MULTISIG_ENTRY_FIXED (MULTISIG_FP_BLOB_LEN + CCM_NONCE_SIZE)

struct multisig_list_ctx {
  const uint8_t* blob;
  multisig_entry_t** out;
  size_t max;
  size_t count;
};

static fs_action_t multisig_store_match(void* ctx, fs_entry_t* entry) {
  if (entry->magic != MULTISIG_STORE_MAGIC) {
    return FS_REJECT;
  }

  struct multisig_list_ctx* c = (struct multisig_list_ctx*) ctx;
  multisig_entry_t* me = (multisig_entry_t*) entry;

  if (memcmp(me->blob, c->blob, MULTISIG_FP_BLOB_LEN) != 0) {
    return FS_REJECT;
  }

  if (c->count < c->max) {
    c->out[c->count] = me;
  }
  c->count++;

  return FS_ACCEPT;
}

app_err_t multisig_store_save(const multisig_crypto_t* m,
                              const uint8_t* plaintext, size_t len) {
  uint8_t save_buf[MULTISIG_MAX_ENTRY_SIZE];
  size_t data_len = len + CCM_TAG_SIZE;
  size_t total = sizeof(fs_entry_t) + MULTISIG_ENTRY_FIXED + data_len;

  if (total > sizeof(save_buf)) {
    return ERR_FULL;
  }

  multisig_entry_t* e = (multisig_entry_t*) save_buf;
  e->_fs_data.magic = MULTISIG_STORE_MAGIC;
  e->_fs_data.len = MULTISIG_ENTRY_FIXED + data_len;
  memcpy(e->blob, m->blob, MULTISIG_FP_BLOB_LEN);
  random_buffer(e->nonce, CCM_NONCE_SIZE);

  if (multisig_crypto_encrypt(m, e->nonce, plaintext, len, e->data) != ERR_OK) {
    memzero(save_buf, sizeof(save_buf));
    return ERR_CRYPTO;
  }

  app_err_t err = fs_write((fs_entry_t*) e, total);
  memzero(save_buf, sizeof(save_buf));

  return err;
}

size_t multisig_store_list(const multisig_crypto_t* m,
                           multisig_entry_t* out[], size_t max) {
  struct multisig_list_ctx ctx = {
    .blob = m->blob,
    .out = out,
    .max = max,
    .count = 0,
  };

  fs_iterate(multisig_store_match, &ctx);

  return ctx.count;
}

app_err_t multisig_store_read(const multisig_crypto_t* m,
                              const multisig_entry_t* entry,
                              uint8_t* out, size_t out_cap, size_t* out_len) {
  if (entry->_fs_data.magic != MULTISIG_STORE_MAGIC) {
    return ERR_DATA;
  }

  size_t data_len = entry->_fs_data.len - MULTISIG_ENTRY_FIXED;
  if (data_len <= CCM_TAG_SIZE) {
    return ERR_DATA;
  }

  size_t pt_len = data_len - CCM_TAG_SIZE;
  if (pt_len > out_cap) {
    return ERR_FULL;
  }

  *out_len = pt_len;

  return multisig_crypto_decrypt(m, entry->nonce, entry->data, data_len, out);
}

app_err_t multisig_store_delete(const multisig_crypto_t* m,
                                const multisig_entry_t* entry) {
  (void) m;

  if (entry->_fs_data.magic != MULTISIG_STORE_MAGIC) {
    return ERR_DATA;
  }

  return fs_erase((fs_entry_t*) entry);
}
