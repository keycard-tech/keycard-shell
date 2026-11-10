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

  if (err != ERR_OK) {
    /* Both versions install the session keys before the card has proved anything -- v1 before the
     * mutual authenticate, v2 before the signature over the transcript is checked -- so clearing the
     * flag alone would leave keys for a session nobody completed. */
    securechannel_close(sc);
    return err;
  }

  sc->open = 1;

  return err;
}

app_err_t securechannel_init(smartcard_t* card, secure_channel_t* sc, apdu_t* apdu, sc_version_t version, uint8_t* sc_data, uint8_t* data, uint32_t len) {
    if (version == SC_V2) {
      app_err_t err = securechannel_v2_open(&sc->v2, card, apdu, sc_data);
      if (err != ERR_OK) {
        return err;
      }

      err = securechannel_v2_init(card, &sc->v2, apdu, data, len);
      if (err != ERR_OK) {
        /* The handshake succeeded a command ago, so there is something to wipe here. */
        securechannel_v2_close(&sc->v2);
      }

      return err;
    } else {
      return securechannel_v1_init(card, apdu, sc_data, data, len);
    }
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
    /* A sealed exchange that failed is not resumable -- the chain or nonce that failed is state, not
     * a retry -- so the keys go with the flag that was already being cleared. */
    securechannel_close(sc);
  }

  return err;
}

/* Also correct on a struct that was never opened, which is what the callers at boot and at card
 * removal rely on: it only zeroes, whatever half it picks. */
void securechannel_close(secure_channel_t* sc) {
  if (sc->version == SC_V2) {
    securechannel_v2_close(&sc->v2);
  } else {
    securechannel_v1_close(&sc->v1);
  }
  sc->open = 0;
}
