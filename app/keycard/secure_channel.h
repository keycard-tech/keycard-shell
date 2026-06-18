#ifndef __SECURE_CHANNEL
#define __SECURE_CHANNEL

#include "pairing.h"
#include "iso7816/smartcard.h"
#include "crypto/aes.h"
#include "error.h"
#include "secure_channel_v1.h"
#include "secure_channel_v2.h"

#define SC_PAD AES_IV_SIZE

#define SC_BUF(__NAME__, __LEN__) uint8_t __NAME__[__LEN__+SC_PAD] __attribute__((aligned(4)))

/* Secure channel protocol version */
typedef enum {
  SC_V1,  /* AES-256-CBC + CBC-MAC + ECDH (firmware < 0x0400) */
  SC_V2,  /* AES-128-CCM + ECDHE (firmware >= 0x0400) */
} sc_version_t;

/* Unified secure channel: version + variant state */
typedef struct {
  sc_version_t version;
  uint8_t open;
  union {
    secure_channel_v1_t v1;
    secure_channel_v2_t v2;
  };
} secure_channel_t;

typedef struct __attribute__((packed, aligned(4))) {
  pairing_t* pairing;
  uint8_t* sc_pub;
} sc_v1_open_t;

app_err_t securechannel_open(secure_channel_t* sc, smartcard_t* card, apdu_t* apdu, sc_version_t version, void* context_data);
app_err_t securechannel_init(smartcard_t* card, apdu_t* apdu, uint8_t* sc_pub, uint8_t* data, uint32_t len);
app_err_t securechannel_send_apdu(smartcard_t* card, secure_channel_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len);
void securechannel_close(secure_channel_t* sc);

#endif
