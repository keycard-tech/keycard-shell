#ifndef __SECURE_CHANNEL_V1
#define __SECURE_CHANNEL_V1

#include "pairing.h"
#include "iso7816/smartcard.h"
#include "crypto/aes.h"
#include "error.h"

#define SC_PAD AES_IV_SIZE

extern const uint8_t KEYCARD_DEFAULT_PSK[];

typedef struct __attribute__((packed, aligned(4))) {
  uint8_t enc_key[AES_256_KEY_SIZE];
  uint8_t mac_key[AES_256_KEY_SIZE];
  uint8_t iv[AES_IV_SIZE];
} secure_channel_v1_t;

/* What follows are the protocol steps of this version, private to secure_channel.c: call the
 * securechannel_*() wrappers, which own the open state and wipe the keys when an exchange fails. */

app_err_t securechannel_v1_open(secure_channel_v1_t* sc, smartcard_t* card, apdu_t* apdu, pairing_t* pairing, uint8_t* sc_pub);
app_err_t securechannel_v1_init(smartcard_t* card, apdu_t* apdu, uint8_t* sc_pub, uint8_t* data, uint32_t len);
app_err_t securechannel_v1_protect_apdu(secure_channel_v1_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len);
app_err_t securechannel_v1_decrypt_apdu(secure_channel_v1_t *sc, apdu_t* apdu);
app_err_t securechannel_v1_send_apdu(smartcard_t* card, secure_channel_v1_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len);
void securechannel_v1_close(secure_channel_v1_t* sc);

#endif
