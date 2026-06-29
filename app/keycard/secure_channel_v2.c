#include <string.h>

#include "secure_channel_v2.h"
#include "crypto/ecdsa.h"
#include "crypto/sha2.h"
#include "crypto/hkdf.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/memzero.h"
#include "error.h"
#include "iso7816/smartcard.h"

#define SECP256K1_KEYLEN 32
#define SECP256K1_PUBLEN 65

#define SCV2_TAG_SIZE CCM_TAG_SIZE
#define SCV2_IDENT_PUB_SIZE 33
#define SCV2_PROTOCOL_LABEL_LEN 9
#define SCV2_INS_SECURED_APDU 0x18

const uint8_t *const SCV2_PROTOCOL_LABEL = (uint8_t *) "sc_v2_ccm";

/*
 * Build the V2 transcript hash:
 *   SHA-256("sc_v2_ccm" || salt || client_eph_pub || card_eph_pub)
 */
static void _scv2_build_transcript(const uint8_t salt[SCV2_SALT_SIZE],
                                    const uint8_t client_pub[SCV2_PUBKEY_SIZE],
                                    const uint8_t card_pub[SCV2_PUBKEY_SIZE],
                                    uint8_t hash[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  sha256_Update(&ctx, SCV2_PROTOCOL_LABEL, SCV2_PROTOCOL_LABEL_LEN);
  sha256_Update(&ctx, salt, SCV2_SALT_SIZE);
  sha256_Update(&ctx, client_pub, SCV2_PUBKEY_SIZE);
  sha256_Update(&ctx, card_pub, SCV2_PUBKEY_SIZE);
  sha256_Final(&ctx, hash);
}

/*
 * Increment the 13-byte big-endian nonce counter.
 * Returns 1 on overflow (should never happen in practice: 2^104).
 */
static uint8_t _scv2_nonce_inc(uint8_t nonce[SCV2_NONCE_SIZE]) {
  for (int i = SCV2_NONCE_SIZE - 1; i >= 0; i--) {
    nonce[i]++;
    if (nonce[i] != 0) {
      return 0; /* no overflow */
    }
  }
  return 1; /* overflow */
}

app_err_t securechannel_v2_open(secure_channel_v2_t* sc, smartcard_t* card, apdu_t* apdu, const uint8_t cert[SCV2_CERT_SIZE]) {
  /* 1. Generate random salt */
  uint8_t salt[SCV2_SALT_SIZE];
  random_buffer(salt, SCV2_SALT_SIZE);

  /* 2. Generate ephemeral secp256k1 key pair */
  uint8_t client_priv[SECP256K1_KEYLEN];
  random_buffer(client_priv, SECP256K1_KEYLEN);

  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  if (ecdsa_get_public_key65(&secp256k1, client_priv, client_pub) != 0) {
    memzero(client_priv, SECP256K1_KEYLEN);
    return ERR_CRYPTO;
  }

  /* 3. Send OPEN_SECURE_CHANNEL (INS=0x10, P1=0, P2=0) with salt || client_pub */
  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = 0x10;
  APDU_P1(apdu) = 0;
  APDU_P2(apdu) = 0;

  uint8_t* req_data = APDU_DATA(apdu);
  memcpy(req_data, salt, SCV2_SALT_SIZE);
  memcpy(&req_data[SCV2_SALT_SIZE], client_pub, SCV2_PUBKEY_SIZE);
  APDU_SET_LC(apdu, SCV2_SALT_SIZE + SCV2_PUBKEY_SIZE);
  APDU_SET_LE(apdu, 0);

  if (smartcard_send_apdu(card, apdu) != ERR_OK) {
    memzero(client_priv, SECP256K1_KEYLEN);
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(apdu);

  /* 4. Parse response: card_eph_pub(65) || signature(DER) */
  uint8_t* resp = APDU_RESP(apdu);
  uint16_t resp_len = apdu->lr;

  if (resp_len < SCV2_PUBKEY_SIZE + 2) {
    memzero(client_priv, SECP256K1_KEYLEN);
    return ERR_DATA;
  }

  uint8_t* card_pub = resp;
  uint8_t* sig_der = &resp[SCV2_PUBKEY_SIZE];
  uint16_t sig_der_len = resp_len - SCV2_PUBKEY_SIZE;

  /* 5. Compute ECDHE shared secret */
  uint8_t shared_secret[SECP256K1_PUBLEN];
  int res = ecdh_multiply(&secp256k1, client_priv, card_pub, shared_secret);
  memzero(client_priv, SECP256K1_KEYLEN);

  if (res != 0) {
    return ERR_CRYPTO;
  }

  /* 6. Derive session keys: HKDF-SHA256(salt, shared_secret, "sc_v2_ccm") -> key_h2c || key_c2h */
  uint8_t okm[SCV2_OKM_SIZE];
  if (hkdf_sha256(salt, SCV2_SALT_SIZE, &shared_secret[1], SECP256K1_KEYLEN,
                   SCV2_PROTOCOL_LABEL, SCV2_PROTOCOL_LABEL_LEN,
                   okm, SCV2_OKM_SIZE) != 0) {
    memzero(shared_secret, SECP256K1_PUBLEN);
    return ERR_CRYPTO;
  }

  memcpy(sc->key_h2c, okm, AES_128_KEY_SIZE);
  memcpy(sc->key_c2h, &okm[AES_128_KEY_SIZE], AES_128_KEY_SIZE);

  memzero(shared_secret, SECP256K1_KEYLEN);
  memzero(okm, SCV2_OKM_SIZE);

  /* 7. Verify card signature over transcript */
  uint8_t transcript[SHA256_DIGEST_LENGTH];
  _scv2_build_transcript(salt, client_pub, card_pub, transcript);
  memzero(salt, SCV2_SALT_SIZE);

  /* Parse DER signature to raw r||s (64 bytes) */
  uint8_t sig_raw[64];
  if (ecdsa_sig_from_der(sig_der, sig_der_len, sig_raw) != 0) {
    memzero(transcript, sizeof(transcript));
    memzero(sig_raw, sizeof(sig_raw));
    return ERR_DATA;
  }

  /* Verify against card identity public key */
  if (ecdsa_verify(&secp256k1, cert, sig_raw, transcript) != 0) {
    memzero(transcript, sizeof(transcript));
    memzero(sig_raw, sizeof(sig_raw));
    return ERR_CRYPTO;
  }

  memzero(transcript, sizeof(transcript));
  memzero(sig_raw, sizeof(sig_raw));

  /* 8. Initialize nonce counter to zero */
  memset(sc->nonce_counter, 0, SCV2_NONCE_SIZE);

  return ERR_OK;
}

app_err_t securechannel_v2_init(smartcard_t* card, secure_channel_v2_t* sc, apdu_t* apdu, uint8_t* data, uint32_t len) {
  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = 0xfe;
  APDU_P1(apdu) = 0;
  APDU_P2(apdu) = 0;
  
  if (securechannel_v2_send_apdu(card, sc, apdu, data, len) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(apdu);

  return ERR_OK;
}

app_err_t securechannel_v2_send_apdu(smartcard_t* card, secure_channel_v2_t* sc, apdu_t* apdu, uint8_t* data, uint32_t len) {
  uint8_t* apdu_data = APDU_DATA(apdu);
  memcpy(apdu_data, &APDU_CLA(apdu), 4);
  apdu_data[4] = len;
  memcpy(&apdu_data[5], data, len);

  memzero(data, len);

  /* Encrypt with AES-128-CCM using key_h2c and current nonce */
  if (!aes128_ccm_encrypt(sc->key_h2c, sc->nonce_counter, apdu_data, (len + 5), apdu_data)) {
    memzero(apdu_data, len + 5);
    return ERR_CRYPTO;
  }

  /* Send as SECURED_APDU: INS=0x18, P1=0, P2=0 */
  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = SCV2_INS_SECURED_APDU;
  APDU_P1(apdu) = 0;
  APDU_P2(apdu) = 0;

  APDU_SET_LC(apdu, len + 5 + SCV2_TAG_SIZE);
  APDU_SET_LE(apdu, 0);

  if (smartcard_send_apdu(card, apdu) != ERR_OK) {
    return ERR_TXRX;
  }

  if (APDU_SW(apdu) == 0x6982) {
    return ERR_CRYPTO;
  }

  APDU_ASSERT_OK(apdu);
  apdu->lr -= 2;

  /* Decrypt response with AES-128-CCM using key_c2h and current nonce */
  if (apdu->lr < SCV2_TAG_SIZE) {
    return ERR_CRYPTO;
  }

  if (!aes128_ccm_decrypt(sc->key_c2h, sc->nonce_counter, APDU_RESP(apdu), apdu->lr, APDU_RESP(apdu))) {
    return ERR_CRYPTO;
  }

  apdu->lr -= SCV2_TAG_SIZE;

  /* Increment nonce counter */
  if (_scv2_nonce_inc(sc->nonce_counter)) {
    /* Nonce overflow — close session */
    return ERR_CRYPTO;
  }

  return ERR_OK;
}

void securechannel_v2_close(secure_channel_v2_t* sc) {
  memzero(sc->key_h2c, AES_128_KEY_SIZE);
  memzero(sc->key_c2h, AES_128_KEY_SIZE);
  memzero(sc->nonce_counter, SCV2_NONCE_SIZE);
}
