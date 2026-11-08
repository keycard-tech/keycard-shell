#include "core_kohaku_key_batch.h"

#include <stdbool.h>
#include <string.h>

#include "core_privacy_pools_v1.h"
#include "crypto/aes.h"
#include "crypto/ecdsa.h"
#include "crypto/hkdf.h"
#include "crypto/memzero.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "crypto/util.h"
#include "hal.h"
#include "ui/i18n.h"
#include "ui/ui.h"
#include "ur/ur.h"
#include "ur/ur_encode.h"

#define REQUEST_MAX 196
#define PATH_MAX 96
#define PATH_COUNT_MAX 2
#define RESPONSE_MAX 172

typedef struct {
  const uint8_t* value;
  size_t len;
} batch_path_t;

static bool valid_index(
    const uint8_t* path, size_t len,
    size_t* pos, uint32_t* value) {
  if (*pos >= len) return false;

  uint32_t number = 0;
  size_t start = *pos;

  if (path[*pos] == '0') {
    (*pos)++;
    if (*pos < len && path[*pos] >= '0' &&
        path[*pos] <= '9') return false;
  } else {
    if (path[*pos] < '1' || path[*pos] > '9')
      return false;

    while (*pos < len &&
           path[*pos] >= '0' && path[*pos] <= '9') {
      uint32_t digit = path[*pos] - '0';
      if (number > (0x7fffffffU - digit) / 10)
        return false;
      number = number * 10 + digit;
      (*pos)++;
    }
  }

  if (*pos == start || *pos >= len ||
      path[(*pos)++] != '\'') return false;

  *value = number;
  return true;
}

static bool valid_export_path(
    const uint8_t* path, size_t len) {
  static const char PREFIX[] = "m/28784'/1'/";

  if (len == 0 || len > PATH_MAX ||
      len < sizeof(PREFIX) ||
      memcmp(path, PREFIX, sizeof(PREFIX) - 1))
    return false;

  size_t pos = sizeof(PREFIX) - 1;

  for (unsigned i = 0; i < 4; i++) {
    uint32_t index;

    if (!valid_index(path, len, &pos, &index))
      return false;

    if (i == 1 && index > 2) return false;

    if (i != 3) {
      if (pos >= len || path[pos++] != '/')
        return false;
    }
  }

  return pos == len;
}

static bool parse_request(
    const uint8_t* request, size_t len,
    batch_path_t paths[PATH_COUNT_MAX],
    size_t* count) {
  static const uint8_t MAGIC[5] = {
      'K', 'K', 'Q', '3', 3};

  if (len < 89 || len > REQUEST_MAX ||
      memcmp(request, MAGIC, sizeof(MAGIC)) ||
      request[21] != 0x04)
    return false;

  *count = request[86];

  if (*count < 1 || *count > PATH_COUNT_MAX)
    return false;

  size_t pos = 87;

  for (size_t i = 0; i < *count; i++) {
    if (pos >= len) return false;

    size_t path_len = request[pos++];

    if (path_len == 0 || path_len > len - pos ||
        !valid_export_path(request + pos, path_len))
      return false;

    paths[i].value = request + pos;
    paths[i].len = path_len;
    pos += path_len;

    if (i && paths[i].len == paths[0].len &&
        !memcmp(paths[i].value, paths[0].value,
                paths[i].len))
      return false;
  }

  return pos == len;
}

app_err_t core_kohaku_key_run_batch(
    keycard_t* kc, const uint8_t* request,
    size_t request_len) {
  if (kc == NULL || request == NULL ||
      request_len > REQUEST_MAX)
    return ERR_DATA;

  if (kc->sc.state != SC_READY ||
      kc->app_version < 0x0400 ||
      kc->ch.version != SC_V2 ||
      !kc->ch.open)
    return ERR_CRYPTO;

  uint8_t request_copy[REQUEST_MAX] = {0};
  memcpy(request_copy, request, request_len);

  batch_path_t paths[PATH_COUNT_MAX] = {0};
  size_t count = 0;

  if (!parse_request(request_copy, request_len,
                     paths, &count)) {
    memzero(request_copy, sizeof(request_copy));
    ui_info(ICON_INFO_ERROR, LSTR(KOHAKU_PP_V1_ERROR),
            LSTR(KOHAKU_PP_V1_ERROR_SUB), 0);
    return ERR_DATA;
  }

  app_err_t status = ERR_CRYPTO;
  uint8_t digest[32] = {0};
  uint8_t private_key[32] = {0};
  uint8_t public_key[65] = {0};
  uint8_t shared_secret[65] = {0};
  uint8_t salt[32] = {0};
  uint8_t key[16] = {0};
  uint8_t plaintext[65] = {0};
  uint8_t response[RESPONSE_MAX] = {0};
  uint8_t encoded[190] = {0};

  char fingerprint[17] = {0};
  char review[360] = {0};

  sha256_Raw(request_copy + 21, 65, digest);
  base16_encode(digest, fingerprint, 8);

  static const char FINGERPRINT_LABEL[] =
      "Verify Mac fingerprint:\n";
  static const char PATH_LABEL[] =
      "\nPrivate credentials requested:\n";

  size_t used = 0;

  if (sizeof(FINGERPRINT_LABEL) - 1 +
      16 + sizeof(PATH_LABEL) - 1 > sizeof(review)) {
    status = ERR_DATA;
    goto cleanup;
  }

  memcpy(review + used, FINGERPRINT_LABEL,
         sizeof(FINGERPRINT_LABEL) - 1);
  used += sizeof(FINGERPRINT_LABEL) - 1;

  memcpy(review + used, fingerprint, 16);
  used += 16;

  memcpy(review + used, PATH_LABEL,
         sizeof(PATH_LABEL) - 1);
  used += sizeof(PATH_LABEL) - 1;

  for (size_t i = 0; i < count; i++) {
    if (paths[i].len >= sizeof(review) - used) {
      status = ERR_DATA;
      goto cleanup;
    }

    memcpy(review + used, paths[i].value,
           paths[i].len);
    used += paths[i].len;
    review[used++] = '\n';
  }

  if (ui_display_paged_text(
          LSTR(MENU_PRIVACY_POOLS_V1),
          review, (uint32_t)used) != CORE_EVT_UI_OK) {
    status = ERR_CANCEL;
    goto cleanup;
  }

  if (ui_prompt(
          LSTR(MENU_PRIVACY_POOLS_V1),
          "Export these private credentials to the verified Mac?",
          UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    status = ERR_CANCEL;
    goto cleanup;
  }

  bool key_valid = false;

  for (unsigned attempt = 0; attempt < 8; attempt++) {
    if (hal_rng_next(private_key,
                     sizeof(private_key)) != HAL_SUCCESS) {
      status = ERR_CRYPTO;
      goto cleanup;
    }

    if (ecdsa_get_public_key65(
            &secp256k1, private_key, public_key) == 0) {
      key_valid = true;
      break;
    }
  }

  if (!key_valid) {
    status = ERR_CRYPTO;
    goto cleanup;
  }

  if (ecdh_multiply(
          &secp256k1, private_key,
          request_copy + 21, shared_secret) != 0) {
    status = ERR_CRYPTO;
    goto cleanup;
  }

  memzero(private_key, sizeof(private_key));

  memcpy(response, "KKR3", 4);
  response[4] = 3;
  memcpy(response + 5, request_copy + 5, 16);
  memcpy(response + 21, public_key, 65);

  if (hal_rng_next(response + 86, CCM_NONCE_SIZE)
      != HAL_SUCCESS) {
    status = ERR_CRYPTO;
    goto cleanup;
  }

  static const uint8_t SALT_DOMAIN[] =
      "kohaku-key/v4-qr-derive-v1/salt";

  static const uint8_t KEY_DOMAIN[] =
      "kohaku-key/v4-qr-derive-v1/aes128-ccm";

  SHA256_CTX hash = {0};
  sha256_Init(&hash);
  sha256_Update(&hash, SALT_DOMAIN, sizeof(SALT_DOMAIN));
  sha256_Update(&hash, request_copy, request_len);
  sha256_Update(&hash, public_key, sizeof(public_key));
  sha256_Update(&hash, response + 86, CCM_NONCE_SIZE);
  sha256_Final(&hash, salt);
  memzero(&hash, sizeof(hash));

  if (hkdf_sha256(
          salt, sizeof(salt),
          shared_secret + 1, 32,
          KEY_DOMAIN, sizeof(KEY_DOMAIN) - 1,
          key, sizeof(key)) != 0) {
    status = ERR_CRYPTO;
    goto cleanup;
  }

  memzero(shared_secret, sizeof(shared_secret));

  plaintext[0] = (uint8_t)count;
  size_t plaintext_len = 1 + count * 32;

  for (size_t i = 0; i < count; i++) {
    status = core_privacy_pools_v1_derive_at(
        kc, (const char*)paths[i].value,
        paths[i].len, plaintext + 1 + i * 32);

    if (status != ERR_OK) goto cleanup;
  }

  if (!aes128_ccm_encrypt(
          key, response + 86,
          plaintext, (uint32_t)plaintext_len,
          response + 99)) {
    status = ERR_CRYPTO;
    goto cleanup;
  }

  memzero(plaintext, sizeof(plaintext));
  memzero(key, sizeof(key));
  memzero(salt, sizeof(salt));
  memzero(request_copy, sizeof(request_copy));

  size_t response_len =
      99 + plaintext_len + CCM_TAG_SIZE;

  struct zcbor_string qr_response = {
      .value = response,
      .len = response_len,
  };

  size_t encoded_len = 0;

  if (cbor_encode_psbt(
          encoded, sizeof(encoded),
          &qr_response, &encoded_len) != ZCBOR_SUCCESS) {
    status = ERR_DATA;
    goto cleanup;
  }

  status = ui_display_ur_qr(
      NULL, encoded, (uint32_t)encoded_len, BYTES)
      == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;

cleanup:
  memzero(digest, sizeof(digest));
  memzero(private_key, sizeof(private_key));
  memzero(public_key, sizeof(public_key));
  memzero(shared_secret, sizeof(shared_secret));
  memzero(salt, sizeof(salt));
  memzero(key, sizeof(key));
  memzero(plaintext, sizeof(plaintext));
  memzero(response, sizeof(response));
  memzero(encoded, sizeof(encoded));
  memzero(request_copy, sizeof(request_copy));
  memzero(review, sizeof(review));
  memzero(fingerprint, sizeof(fingerprint));

  return status;
}
