#include <string.h>

#include "bitcoin/tx.h"
#include "bitcoin/compactsize.h"
#include "bitcoin/psbt_tx.h"
#include "crypto/sha2.h"
#include "crypto/sha2_soft.h"

static bool btc_is_segwit(const uint8_t* tx) {
  return (tx[4] == 0) && (tx[5] == SEGREGATED_WITNESS_FLAG);
}

static bool btc_txid_read_size(SHA256_CTX* ctx, const uint8_t** cursor, const uint8_t* end, uint64_t* size) {
  if (*cursor >= end) {
    return false;
  }

  uint32_t encoding_len = compactsize_peek_length(**cursor);
  if ((size_t)(end - *cursor) < encoding_len) {
    return false;
  }

  psbt_result_t err = PSBT_OK;
  uint64_t value = compactsize_read(*cursor, &err);
  if (err != PSBT_OK) {
    return false;
  }

  sha256_Update(ctx, *cursor, encoding_len);
  *cursor += encoding_len;
  *size = value;

  return true;
}

#define BTC_TXID_TAKE(ctx, cursor, end, len) \
  { \
    if ((size_t)((end) - (cursor)) < (size_t)(len)) { \
      return false; \
    } \
    sha256_Update((ctx), (cursor), (len)); \
    (cursor) += (len); \
  }

static bool btc_generate_txid(const uint8_t* tx, size_t tx_len, uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  if (tx_len < sizeof(uint32_t) + sizeof(uint16_t)) {
    return false;
  }

  if (btc_is_segwit(tx)) {
    const uint8_t* p = tx;
    const uint8_t* end = tx + tx_len;
    uint64_t count;
    uint64_t script_len;

    sha256_Update(&ctx, p, sizeof(uint32_t));     /* version */
    p += sizeof(uint32_t) + sizeof(uint16_t);     /* marker and flag, not serialized in the txid */

    if (!btc_txid_read_size(&ctx, &p, end, &count)) {
      return false;
    }

    for (uint64_t i = 0; i < count; i++) {
      BTC_TXID_TAKE(&ctx, p, end, SHA256_DIGEST_LENGTH + sizeof(uint32_t)); /* outpoint */
      if (!btc_txid_read_size(&ctx, &p, end, &script_len)) {
        return false;
      }
      BTC_TXID_TAKE(&ctx, p, end, script_len + sizeof(uint32_t)); /* scriptSig and sequence */
    }

    if (!btc_txid_read_size(&ctx, &p, end, &count)) {
      return false;
    }

    for (uint64_t i = 0; i < count; i++) {
      BTC_TXID_TAKE(&ctx, p, end, sizeof(uint64_t)); /* amount */
      if (!btc_txid_read_size(&ctx, &p, end, &script_len)) {
        return false;
      }
      BTC_TXID_TAKE(&ctx, p, end, script_len); /* scriptPubKey */
    }

    const uint8_t* locktime = end - sizeof(uint32_t);
    sha256_Update(&ctx, locktime, sizeof(uint32_t));
  } else {
    sha256_Update(&ctx, tx, tx_len);
  }

  sha256_Final(&ctx, out);
  sha256_Raw(out, SHA256_DIGEST_LENGTH, out);

  return true;
}

#undef BTC_TXID_TAKE

bool btc_validate_tx_hash(const uint8_t* tx, size_t tx_len, const uint8_t expected_hash[SHA256_DIGEST_LENGTH]) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  return btc_generate_txid(tx, tx_len, digest) &&
         (memcmp(expected_hash, digest, SHA256_DIGEST_LENGTH) == 0);
}
