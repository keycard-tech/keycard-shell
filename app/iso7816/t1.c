#include "hal.h"
#include "iso7816/t1.h"
#include <stdlib.h>

#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif

#define T1_BGT 22

static inline uint8_t t1_lrc(uint8_t* header, uint8_t* data, uint32_t len) {
  uint8_t lrc = header[0] ^ header[1] ^ header[2];

  for (int i = 0; i < len; i++) {
    lrc ^= data[i];
  }

  return lrc;
}

static app_err_t t1_transmit_r(smartcard_t* sc, uint8_t err) {
  uint8_t block[4];
  block[0] = T1_NAD;
  block[1] = T1_R_BLOCK | err | T1_R_SEQ(sc->recv_seq);
  block[2] = 0;
  block[3] = t1_lrc(block, NULL, 0);
  
  return smartcard_transmit_sync(sc, block, 4);
}

static app_err_t t1_transmit_s(smartcard_t* sc, uint8_t type, uint8_t has_data, uint8_t data) {
  uint8_t block[5];
  block[0] = T1_NAD;
  block[1] = T1_S_BLOCK | type;
  block[2] = has_data;
  block[3] = data;
  block[3+has_data] = t1_lrc(block, &block[3], has_data);
  
  return smartcard_transmit_sync(sc, block, 4+has_data);
}

static app_err_t t1_handle_i(smartcard_t* sc, uint8_t pcb, uint8_t* more) {
  uint8_t errcode;

  if ((pcb & T1_I_SEQ_MSK) != T1_I_SEQ(sc->recv_seq)) {
    errcode = T1_R_OTHER;
  } else {
    errcode = T1_R_OK;
    sc->recv_seq = sc->recv_seq ^ 1;  
  }

  *more = ((pcb & T1_I_MORE) != 0) || (errcode != T1_R_OK);

  if (*more) {
    if (t1_transmit_r(sc, errcode) != ERR_OK) {
      return ERR_TXRX;
    }
  }

  return ERR_OK;
}

static uint8_t t1_handle_s(smartcard_t* sc, uint8_t pcb, uint8_t data, uint8_t* more) {
  uint8_t is_resp = (pcb & T1_S_RES) == T1_S_RES;

  uint8_t res = T1_S_RES;
  uint8_t len;
  app_err_t err = ERR_OK;
  *more = !is_resp;

  if ((pcb & T1_S_WTX) == T1_S_WTX) {
    sc->t1_bwt_factor = data;
    len = 1;
    res |= T1_S_WTX;
  } else if ((pcb & T1_S_ABORT) == T1_S_ABORT) {
    len = 0;
    res |= T1_S_ABORT;
    err = ERR_TXRX;
    *more = 0;
  } else if ((pcb & T1_S_IFS) == T1_S_IFS) {
    if (!is_resp) {
      sc->atr.t1_ifsc = data;
    }
    len = 1;
    res |= T1_S_IFS;
  } else {
    len = 0;
    res |= T1_S_RESYNCH;
    sc->recv_seq = 0;
    sc->send_seq = 0;
  }

  if (!is_resp) {
    if (t1_transmit_s(sc, res, len, data) != ERR_OK) {
      *more = 0;
      return ERR_TXRX;
    }
  }
 
  return err;
}

static app_err_t t1_handle_r(smartcard_t* sc, uint8_t pcb) {
  if (((pcb & T1_R_ERR_MSK) != T1_R_OK) || ((pcb & T1_R_SEQ_MSK) != (sc->send_seq ^ 1))) {
    return ERR_RETRY;
  }

  return ERR_OK;
}

static app_err_t t1_handle_resp(smartcard_t* sc, apdu_t* apdu) {
  uint8_t header[3];

  hal_smartcard_set_timeout(sc->t1_bwt * sc->t1_bwt_factor);
  sc->t1_bwt_factor = 1;
  if (smartcard_receive_sync(sc, header, 3) != ERR_OK) {
    return ERR_TXRX;
  }

  uint8_t blen = header[2];

  hal_smartcard_set_blocklen(blen);
  hal_smartcard_set_timeout(sc->t1_cwt);

  uint8_t *data;
  uint8_t s;

  if ((header[1] & T1_R_BLOCK) == 0) {
    data = &apdu->data[(apdu->lr+1)];
    apdu->lr += blen;
  } else if ((header[1] & T1_S_BLOCK) == T1_S_BLOCK) {
    data = &s;
  } else {
    data = NULL;
    blen = 0;
  }

  if (blen) {
    if (smartcard_receive_sync(sc, data, blen) != ERR_OK) {
      return ERR_TXRX;
    }    
  }

  uint8_t lrc;
  if (smartcard_receive_sync(sc, &lrc, 1) != ERR_OK) {
    return ERR_TXRX;
  }

  smartcard_delay(sc, T1_BGT);

  if (t1_lrc(header, data, blen) != lrc) {
    if (t1_transmit_r(sc, T1_R_PARITY) != ERR_OK) {
      return ERR_TXRX;
    }

    return t1_handle_resp(sc, apdu);
  }

  uint8_t more = 0;
  app_err_t err;

  if ((header[1] & T1_R_BLOCK) == 0) {
    err = t1_handle_i(sc, header[1], &more);
  } else if ((header[1] & T1_S_BLOCK) == T1_S_BLOCK) {
    err = t1_handle_s(sc, header[1], s, &more);    
  } else {
    err = t1_handle_r(sc, header[1]);
  }

  return more ? t1_handle_resp(sc, apdu) : err;
}

app_err_t t1_transmit(smartcard_t* sc, apdu_t* apdu) {
  uint8_t* data = apdu->data;
  uint8_t to_send = APDU_LEN(apdu);
  uint8_t resend = 0;

  while(to_send > 0 && (resend < 2)) {
    uint8_t header[3];
    uint8_t blen = MIN(to_send, sc->atr.t1_ifsc);

    header[0] = T1_NAD;
    header[1] = T1_I_BLOCK | T1_I_SEQ(sc->send_seq) | ((to_send > sc->atr.t1_ifsc) ? T1_I_MORE : T1_I_LAST);
    header[2] = blen;

    uint8_t lrc = t1_lrc(header, data, blen);

    if (smartcard_transmit_sync(sc, header, 3) != ERR_OK) {
      return ERR_TXRX;
    }
    
    if (smartcard_transmit_sync(sc, data, blen) != ERR_OK) {
      return ERR_TXRX;
    }

    if (smartcard_transmit_sync(sc, &lrc, 1) != ERR_OK) {
      return ERR_TXRX;
    }

    uint8_t res = t1_handle_resp(sc, apdu);

    switch(res) {
      case ERR_OK:
        sc->send_seq = sc->send_seq ^ 1;
        to_send -= blen;
        data += blen;
        resend = 0;
        break;
      case ERR_RETRY:
        resend++;
        break;
      default:
        return ERR_TXRX;
    }
  }

  return to_send == 0 ? ERR_OK : ERR_TXRX;
}

app_err_t t1_negotiate_ifsd(smartcard_t* sc, int retry) {
  smartcard_delay(sc, T1_BGT);
  
  if (t1_transmit_s(sc, T1_S_IFS, 1, T1_IFSD) != ERR_OK) {
    return ERR_TXRX;
  }

  if (t1_handle_resp(sc, NULL) == ERR_OK) {
    return ERR_OK;
  }

  if (!retry || (t1_transmit_s(sc, T1_S_RESYNCH, 0, 0) != ERR_OK)) {
    return ERR_TXRX;
  }

  if (t1_handle_resp(sc, NULL) != ERR_OK) {
    return ERR_TXRX;
  }

  return t1_negotiate_ifsd(sc, retry - 1);
}
