#include <string.h>

#include "secure_channel.h"
#include "crypto/ecdsa.h"
#include "crypto/sha2.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "crypto/memzero.h"
#include "error.h"

#define SECP256K1_KEYLEN 32
#define SECP256K1_PUBLEN 65

static app_err_t securechannel_mutual_authenticate(secure_channel_t* sc, smartcard_t* card, apdu_t* apdu) {
  SC_BUF(data, 32);
  random_buffer(data, 32);
  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = 0x11;
  APDU_P1(apdu) = 0;
  APDU_P2(apdu) = 0;
  
  if (securechannel_protect_apdu(sc, apdu, data, 32) != ERR_OK) {
    return ERR_CRYPTO;
  }

  if (smartcard_send_apdu(card, apdu) != ERR_OK) {
    return ERR_TXRX;
  }

  if (securechannel_decrypt_apdu(sc, apdu) != ERR_OK) {
    return ERR_CRYPTO;
  }

  APDU_ASSERT_OK(apdu);

  return ERR_OK;
}

app_err_t securechannel_open(secure_channel_t* sc, smartcard_t* card, apdu_t* apdu, pairing_t* pairing, uint8_t* sc_pub) {
  uint8_t priv[SECP256K1_KEYLEN];
  random_buffer(priv, SECP256K1_KEYLEN);
  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = 0x10;
  APDU_P1(apdu) = pairing->idx;
  APDU_P2(apdu) = 0;
  if (ecdsa_get_public_key65(&secp256k1, priv, APDU_DATA(apdu)) != 0) {
    memzero(priv, SECP256K1_KEYLEN);
    return ERR_CRYPTO;
  }
  APDU_SET_LC(apdu, SECP256K1_PUBLEN);
  APDU_SET_LE(apdu, 0);
  
  if (smartcard_send_apdu(card, apdu) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(apdu);

  uint8_t secret[SECP256K1_PUBLEN];

  uint8_t res = ecdh_multiply(&secp256k1, priv, sc_pub, secret);
  memzero(priv, SECP256K1_KEYLEN);

  if (res != 0) {
    return ERR_CRYPTO;
  }

  uint8_t* apduData = APDU_RESP(apdu);

  SHA512_CTX sha512 = {0};
  sha512_Init(&sha512);
  sha512_Update(&sha512, &secret[1], SHA256_DIGEST_LENGTH);
  sha512_Update(&sha512, pairing->key, SHA256_DIGEST_LENGTH);
  sha512_Update(&sha512, apduData, SHA256_DIGEST_LENGTH);
  sha512_Final(&sha512, (uint8_t*) sc);

  memcpy(sc->iv, &apduData[SHA256_DIGEST_LENGTH], AES_IV_SIZE);
  sc->open = 1;

  memzero(secret, SECP256K1_PUBLEN);
  return securechannel_mutual_authenticate(sc, card, apdu);
}

app_err_t securechannel_protect_apdu(secure_channel_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len) {
  len = pad_iso9797_m1(data, SC_PAD, len);
  uint8_t* apduData = APDU_DATA(apdu);

  if (!aes_encrypt_cbc(sc->enc_key, sc->iv, data, len, &apduData[AES_IV_SIZE])) {
    memset(data, 0, len);
    return ERR_CRYPTO;
  }

  memset(data, 0, len);

  len += 16;
  APDU_SET_LC(apdu, len);
  APDU_SET_LE(apdu, 0);

  memset(apduData, 0, AES_IV_SIZE);
  apduData[0] = APDU_CLA(apdu);
  apduData[1] = APDU_INS(apdu);
  apduData[2] = APDU_P1(apdu);
  apduData[3] = APDU_P2(apdu);
  apduData[4] = len;

  if (!aes_cbc_mac(sc->mac_key, apduData, len, apduData)) {
    return ERR_CRYPTO;
  }

  memcpy(sc->iv, apduData, AES_IV_SIZE);
  return ERR_OK;
}

app_err_t securechannel_decrypt_apdu(secure_channel_t *sc, apdu_t* apdu) {
  if (APDU_SW(apdu) == 0x6982) {
    sc->open = 0;
    return ERR_CRYPTO;
  }

  APDU_ASSERT_OK(apdu);
  apdu->lr -= 2;

  uint8_t cmac[AES_IV_SIZE] __attribute__((aligned(4)));
  uint8_t new_iv[AES_IV_SIZE] __attribute__((aligned(4)));
  uint8_t* data = APDU_RESP(apdu);

  memcpy(cmac, data, AES_IV_SIZE);
  memset(data, 0, AES_IV_SIZE);
  data[0] = apdu->lr;

  if (!aes_cbc_mac(sc->mac_key, data, apdu->lr, new_iv)) {
    sc->open = 0;
    return ERR_CRYPTO;    
  }

  if (memcmp_ct(new_iv, cmac, AES_IV_SIZE) != 0) {
    sc->open = 0;
    return ERR_CRYPTO;
  }

  if (!aes_decrypt_cbc(sc->enc_key, sc->iv, &data[AES_IV_SIZE], (apdu->lr - AES_IV_SIZE), data)) {
    sc->open = 0;
    return ERR_CRYPTO;
  }

  apdu->lr = unpad_iso9797_m1(data, (apdu->lr - AES_IV_SIZE));

  memcpy(sc->iv, new_iv, AES_IV_SIZE);

  return ERR_OK;
}

app_err_t securechannel_init(smartcard_t* card, apdu_t* apdu, uint8_t* sc_pub, uint8_t* data, uint32_t len) {
  uint8_t priv[SECP256K1_KEYLEN];
  random_buffer(priv, SECP256K1_KEYLEN);

  uint8_t secret[SECP256K1_PUBLEN+3] __attribute__((aligned(4)));

  uint8_t res = ecdh_multiply(&secp256k1, priv, sc_pub, &secret[3]);
  memmove(secret, &secret[4], AES_256_KEY_SIZE);

  uint8_t* apduData = APDU_DATA(apdu);
  apduData[0] = SECP256K1_PUBLEN;
  res |= ecdsa_get_public_key65(&secp256k1, priv, &apduData[1]);

  memzero(priv, SECP256K1_KEYLEN);

  if (res != 0) {
    return ERR_CRYPTO;
  }

  uint8_t iv[AES_IV_SIZE] __attribute__((aligned(4)));
  random_buffer(iv, AES_IV_SIZE);
  memcpy(&apduData[SECP256K1_PUBLEN+1], iv, AES_IV_SIZE);

  len = pad_iso9797_m1(data, SC_PAD, len);
  res = aes_encrypt_cbc(secret, iv, data, len, data);

  memzero(secret, SECP256K1_KEYLEN+3);

  if (!res) {
    memzero(data, len);
    return ERR_CRYPTO;
  }

  memcpy(&apduData[SECP256K1_PUBLEN + 1 + AES_IV_SIZE], data, len);

  APDU_RESET(apdu);
  APDU_CLA(apdu) = 0x80;
  APDU_INS(apdu) = 0xfe;
  APDU_P1(apdu) = 0;
  APDU_P2(apdu) = 0;
  APDU_SET_LC(apdu, (1 + SECP256K1_PUBLEN + AES_IV_SIZE + len));
  APDU_SET_LE(apdu, 0);

  if(smartcard_send_apdu(card, apdu) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(apdu);

  return ERR_OK;
}

app_err_t securechannel_send_apdu(smartcard_t* card, secure_channel_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len) {
  uint16_t err;
  if ((err = securechannel_protect_apdu(sc, apdu, data, len)) != ERR_OK) {
    return err;
  }

  if (smartcard_send_apdu(card, apdu) != ERR_OK) {
    return ERR_TXRX;
  }

  return securechannel_decrypt_apdu(sc, apdu);
}

void securechannel_close(secure_channel_t* sc) {
  memzero(sc->enc_key, AES_256_KEY_SIZE);
  memzero(sc->mac_key, AES_256_KEY_SIZE);
  memzero(sc->iv, AES_IV_SIZE);
  sc->open = 0;
}
