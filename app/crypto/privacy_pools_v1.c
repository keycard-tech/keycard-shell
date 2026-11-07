#include "privacy_pools_v1.h"

#include <stdbool.h>
#include <string.h>

#include "crypto/hmac.h"
#include "crypto/memzero.h"

static const char DERIVATION_DOMAIN[] =
    "kohaku-key/v3-r3/privacy-pools-v1/deriveAt";

bool privacy_pools_v1_valid_path(const char *path, size_t len) {
  static const char PATH_PREFIX[] = "m/28784'/1'";
  size_t i = sizeof(PATH_PREFIX) - 1;

  if (path == NULL || len <= i ||
      memcmp(path, PATH_PREFIX, i) != 0) {
    return false;
  }

  while (i < len) {
    if (path[i++] != '/' || i == len) return false;

    if (path[i] == '0') {
      i++;
      if (i < len && path[i] >= '0' && path[i] <= '9') {
        return false;
      }
    } else {
      if (path[i] < '1' || path[i] > '9') return false;
      do {
        i++;
      } while (i < len && path[i] >= '0' && path[i] <= '9');
    }

    if (i == len || path[i++] != '\'') return false;
  }

  return true;
}

app_err_t privacy_pools_v1_derive_at(
    const uint8_t root[32],
    const char *path,
    size_t path_len,
    uint8_t out[32]) {
  if (out == NULL) return ERR_DATA;

  /* Reject overlapping secret buffers without modifying the root. */
  if (root != NULL) {
    uintptr_t a = (uintptr_t)root;
    uintptr_t b = (uintptr_t)out;
    if ((a <= b && b - a < 32) ||
        (b < a && a - b < 32)) {
      return ERR_DATA;
    }
  }

  if (root == NULL || path_len > UINT32_MAX ||
      !privacy_pools_v1_valid_path(path, path_len)) {
    memzero(out, 32);
    return ERR_DATA;
  }

  HMAC_SHA256_CTX ctx;
  const uint8_t SEPARATOR = 0;

  hmac_sha256_Init(&ctx, root, 32);
  hmac_sha256_Update(&ctx, (const uint8_t *)DERIVATION_DOMAIN,
                     sizeof(DERIVATION_DOMAIN) - 1);
  hmac_sha256_Update(&ctx, &SEPARATOR, 1);
  hmac_sha256_Update(&ctx, (const uint8_t *)path,
                     (uint32_t)path_len);
  hmac_sha256_Final(&ctx, out);

  return ERR_OK;
}
