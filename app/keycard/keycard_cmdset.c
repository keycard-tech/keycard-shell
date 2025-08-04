#include <string.h>

#include "keycard_cmdset.h"
#include "error.h"
#include "crypto/rand.h"
#include "crypto/sha2.h"
#include "crypto/util.h"

const extern uint8_t KEYCARD_DEFAULT_PSK[];

#define KEYCARD_INIT_CMD_LEN (KEYCARD_PIN_LEN + KEYCARD_PUK_LEN + SHA256_DIGEST_LENGTH + 2 + KEYCARD_PIN_LEN)

app_err_t keycard_cmd_select(keycard_t* kc, const uint8_t* aid, uint32_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0;
  APDU_INS(&kc->apdu) = 0xa4;
  APDU_P1(&kc->apdu) = 4;
  APDU_P2(&kc->apdu) = 0;
  memcpy(APDU_DATA(&kc->apdu), aid, len);
  APDU_SET_LC(&kc->apdu, len);
  APDU_SET_LE(&kc->apdu, 0);

  return smartcard_send_apdu(&kc->sc, &kc->apdu);
}

app_err_t keycard_cmd_pair(keycard_t* kc, uint8_t step, uint8_t* data) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x12;
  APDU_P1(&kc->apdu) = step;
  APDU_P2(&kc->apdu) = 0;
  memcpy(APDU_DATA(&kc->apdu), data, 32);  
  APDU_SET_LC(&kc->apdu, 32);
  APDU_SET_LE(&kc->apdu, 0);  

  return smartcard_send_apdu(&kc->sc, &kc->apdu);
}

app_err_t keycard_cmd_autopair(keycard_t* kc, const uint8_t* psk, pairing_t* pairing) {
  uint8_t buf[SHA256_DIGEST_LENGTH];
  random_buffer(buf, SHA256_DIGEST_LENGTH);

  if (keycard_cmd_pair(kc, 0, buf) != ERR_OK) {
    return ERR_TXRX;
  }

  uint16_t sw = APDU_SW(&kc->apdu);
  if (sw == 0x6a84) {
    return ERR_FULL;
  } else if (sw != SW_OK) {
    return sw;
  }

  uint8_t* card_cryptogram = APDU_RESP(&kc->apdu);
  uint8_t* card_challenge = &card_cryptogram[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256 = {0};
  sha256_Init(&sha256);
  sha256_Update(&sha256, psk, SHA256_DIGEST_LENGTH);
  sha256_Update(&sha256, buf, SHA256_DIGEST_LENGTH);
  sha256_Final(&sha256, buf);

  if (memcmp_ct(card_cryptogram, buf, SHA256_DIGEST_LENGTH) != 0) {
    return ERR_CRYPTO;
  }

  sha256_Init(&sha256);
  sha256_Update(&sha256, psk, SHA256_DIGEST_LENGTH);
  sha256_Update(&sha256, card_challenge, SHA256_DIGEST_LENGTH);
  sha256_Final(&sha256, buf);

  if (keycard_cmd_pair(kc, 1, buf) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(&kc->apdu);

  pairing->idx = APDU_RESP(&kc->apdu)[0];
  uint8_t *salt = APDU_RESP(&kc->apdu) + 1;

	sha256_Init(&sha256);
  sha256_Update(&sha256, psk, SHA256_DIGEST_LENGTH);
  sha256_Update(&sha256, salt, SHA256_DIGEST_LENGTH);
  sha256_Final(&sha256, pairing->key);

  return ERR_OK;
}

app_err_t keycard_cmd_unpair(keycard_t* kc, uint8_t idx) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x13;
  APDU_P1(&kc->apdu) = idx;
  APDU_P2(&kc->apdu) = 0;

  SC_BUF(data, 0);

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, 0);
}

app_err_t keycard_cmd_verify_pin(keycard_t* kc, uint8_t* pin) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x20;
  APDU_P1(&kc->apdu) = 0;
  APDU_P2(&kc->apdu) = 0;
  
  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, pin, KEYCARD_PIN_LEN);
}

app_err_t keycard_cmd_change_credential(keycard_t* kc, keycard_credentials_t type, uint8_t* credentials, uint8_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x21;
  APDU_P1(&kc->apdu) = type;
  APDU_P2(&kc->apdu) = 0;

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, credentials, len);
}

app_err_t keycard_cmd_unblock_pin(keycard_t* kc, uint8_t* pin, uint8_t* puk) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x22;
  APDU_P1(&kc->apdu) = 0;
  APDU_P2(&kc->apdu) = 0;

  SC_BUF(data, (KEYCARD_PUK_LEN + KEYCARD_PIN_LEN));
  memcpy(data, puk, KEYCARD_PUK_LEN);
  memcpy(&data[KEYCARD_PUK_LEN], pin, KEYCARD_PIN_LEN);

  memset(puk, 0, KEYCARD_PUK_LEN);
  memset(pin, 0, KEYCARD_PIN_LEN);
  
  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, (KEYCARD_PUK_LEN + KEYCARD_PIN_LEN));
}

app_err_t keycard_cmd_get_status(keycard_t* kc) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xf2;
  APDU_P1(&kc->apdu) = 0;
  APDU_P2(&kc->apdu) = 0;

  SC_BUF(data, 0);
  
  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, 0);
}

app_err_t keycard_cmd_init(keycard_t* kc, uint8_t* sc_pub, uint8_t* pin, uint8_t* puk, uint8_t* psk, uint8_t pin_retries, uint8_t puk_retries, uint8_t* duress_pin) {
  SC_BUF(data, KEYCARD_INIT_CMD_LEN);
  memcpy(data, pin, KEYCARD_PIN_LEN);
  memcpy(&data[KEYCARD_PIN_LEN], puk, KEYCARD_PUK_LEN);
  memcpy(&data[KEYCARD_PIN_LEN+KEYCARD_PUK_LEN], psk, SHA256_DIGEST_LENGTH);
  data[KEYCARD_PIN_LEN+KEYCARD_PUK_LEN+SHA256_DIGEST_LENGTH] = pin_retries;
  data[KEYCARD_PIN_LEN+KEYCARD_PUK_LEN+SHA256_DIGEST_LENGTH + 1] = puk_retries;
  memcpy(&data[KEYCARD_PIN_LEN+KEYCARD_PUK_LEN+SHA256_DIGEST_LENGTH + 2], duress_pin, KEYCARD_PIN_LEN);

  if (psk != KEYCARD_DEFAULT_PSK) {
    memset(psk, 0, SHA256_DIGEST_LENGTH);
  }

  return securechannel_init(&kc->sc, &kc->apdu, sc_pub, data, KEYCARD_INIT_CMD_LEN);
}

app_err_t keycard_cmd_generate_mnemonic(keycard_t* kc, uint8_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xd2;
  APDU_P1(&kc->apdu) = (len / 3);
  APDU_P2(&kc->apdu) = 0;

  SC_BUF(data, 0);
  
  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, 0);
}

app_err_t keycard_cmd_load_seed(keycard_t* kc, uint8_t* seed) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xd0;
  APDU_P1(&kc->apdu) = 3;
  APDU_P2(&kc->apdu) = 0;
  
  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, seed, 64);
}

app_err_t keycard_cmd_load_key(keycard_t* kc, uint8_t* key_template, uint8_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xd0;
  APDU_P1(&kc->apdu) = 2;
  APDU_P2(&kc->apdu) = 0;

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, key_template, len);
}

app_err_t keycard_cmd_export_key(keycard_t* kc, uint8_t export_type, uint8_t* path, uint8_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xc2;
  APDU_P1(&kc->apdu) = 1;
  APDU_P2(&kc->apdu) = export_type;

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, path, len);
}

app_err_t keycard_cmd_sign(keycard_t* kc, uint8_t* path, uint8_t path_len, uint8_t* hash) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xc0;
  APDU_P1(&kc->apdu) = 1;
  APDU_P2(&kc->apdu) = 0;

  SC_BUF(data, 72);

  memcpy(data, hash, 32);
  memcpy(&data[32], path, path_len);

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, (32 + path_len));
}

app_err_t keycard_cmd_factory_reset(keycard_t* kc) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xfd;
  APDU_P1(&kc->apdu) = 0xaa;
  APDU_P2(&kc->apdu) = 0x55;

  return smartcard_send_apdu(&kc->sc, &kc->apdu);
}

app_err_t keycard_cmd_get_data(keycard_t* kc) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xca;
  APDU_P1(&kc->apdu) = 0x00;
  APDU_P2(&kc->apdu) = 0x00;

  if (kc->ch.open) {
    SC_BUF(data, 0);
    return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, 0);
  } else {
    return smartcard_send_apdu(&kc->sc, &kc->apdu);
  }
}

app_err_t keycard_cmd_set_data(keycard_t* kc, uint8_t* data, int8_t len) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xe2;
  APDU_P1(&kc->apdu) = 0x00;
  APDU_P2(&kc->apdu) = 0x00;

  return securechannel_send_apdu(&kc->sc, &kc->ch, &kc->apdu, data, len);
}

app_err_t keycard_cmd_identify(keycard_t* kc, const uint8_t challenge[SHA256_DIGEST_LENGTH]) {
  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0x14;
  APDU_P1(&kc->apdu) = 0x00;
  APDU_P2(&kc->apdu) = 0x00;
  memcpy(APDU_DATA(&kc->apdu), challenge, SHA256_DIGEST_LENGTH);
  APDU_SET_LC(&kc->apdu, SHA256_DIGEST_LENGTH);
  APDU_SET_LE(&kc->apdu, 0);

  return smartcard_send_apdu(&kc->sc, &kc->apdu);
}

