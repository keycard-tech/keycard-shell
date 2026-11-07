#include "core_privacy_pools_v1.h"

#include <stdbool.h>
#include <stdint.h>

#include "crypto/memzero.h"
#include "crypto/privacy_pools_v1.h"
#include "keycard/keycard_cmdset.h"

static bool overlaps_keycard(
    const keycard_t* kc, const void* ptr, size_t len) {
  if (ptr == NULL || len == 0) return false;

  uintptr_t a = (uintptr_t)kc;
  uintptr_t b = (uintptr_t)ptr;

  return a <= b ? b - a < sizeof(*kc) : a - b < len;
}

app_err_t core_privacy_pools_v1_derive_at(
    keycard_t* kc,
    const char* path,
    size_t path_len,
    uint8_t out[32]) {
  if (kc == NULL || out == NULL) return ERR_DATA;

  bool out_alias = overlaps_keycard(kc, out, 32);

  if (path == NULL || out_alias ||
      overlaps_keycard(kc, path, path_len) ||
      !privacy_pools_v1_valid_path(path, path_len)) {
    if (!out_alias) memzero(out, 32);
    memzero(&kc->apdu, sizeof(kc->apdu));
    return ERR_DATA;
  }

  app_err_t err = keycard_cmd_export_bip85_root(kc);

  if (err == ERR_OK) {
    if (kc->apdu.lr != 34 ||
        APDU_SW(&kc->apdu) != SW_OK) {
      err = ERR_DATA;
    } else {
      err = privacy_pools_v1_derive_at(
          APDU_RESP(&kc->apdu), path, path_len, out);
    }
  }

  if (err != ERR_OK) {
    memzero(out, 32);
  }

  /* Decrypted root, response status and transport residue. */
  memzero(&kc->apdu, sizeof(kc->apdu));

  return err;
}
