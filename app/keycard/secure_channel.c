#include "secure_channel.h"
#include "keycard/secure_channel_v1.h"
#include "secure_channel_v2.h"
#include "error.h"

app_err_t securechannel_open(secure_channel_t* sc, smartcard_t* card, apdu_t* apdu, sc_version_t version, void* context_data) {
  app_err_t err;

  if (version == SC_V2) {
    err = securechannel_v2_open(&sc->v2, card, apdu, (const uint8_t*) context_data);
  } else if (version == SC_V1) {
    sc_v1_open_t* params = (sc_v1_open_t *) context_data;
    err = securechannel_v1_open(&sc->v1, card, apdu, params->pairing, params->sc_pub);
  } else {
    return ERR_CRYPTO;
  }

  sc->version = version;
  sc->open = err == ERR_OK ? 1 : 0;

  return err;
}

app_err_t securechannel_init(smartcard_t* card, apdu_t* apdu, uint8_t* sc_pub, uint8_t* data, uint32_t len) {
  return securechannel_v1_init(card, apdu, sc_pub, data, len);
}

app_err_t securechannel_send_apdu(smartcard_t* card, secure_channel_t *sc, apdu_t* apdu, uint8_t* data, uint32_t len) {
  if (!sc->open) {
    return ERR_CRYPTO;
  }
  
  app_err_t err;
  if (sc->version == SC_V2) {
    err = securechannel_v2_send_apdu(card, &sc->v2, apdu, data, len);
  } else if (sc->version == SC_V1) {
    err = securechannel_v1_send_apdu(card, &sc->v1, apdu, data, len);
  } else {
    return ERR_CRYPTO;
  }

  if (err != ERR_OK) {
    sc->open = 0;
  }

  return err;
}

void securechannel_close(secure_channel_t* sc) {
  if (sc->version == SC_V2) {
    securechannel_v2_close(&sc->v2);
  } else {
    securechannel_v1_close(&sc->v1);
  }
  sc->open = 0;
}
