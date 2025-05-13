#include "iso7816/smartcard.h"
#include "iso7816/atr.h"
#include "iso7816/pps.h"
#include "iso7816/t1.h"
#include "FreeRTOS.h"
#include "task.h"
#include "hal.h"

#define SC_DEFAULT_ETU10NS 9300
#define SC_MAX_TIMEOUT_MS 1000

static inline void smartcard_state_reset(smartcard_t* sc) {
  sc->send_seq = 0;
  sc->recv_seq = 0;
  sc->etu_10ns = SC_DEFAULT_ETU10NS;
}

void smartcard_delay(smartcard_t* sc, uint32_t etu) {
  uint32_t usec = (sc->etu_10ns * etu)/100;

  if (usec > 4000) {
    vTaskDelay(pdMS_TO_TICKS(usec/1000));
  } else {
    hal_delay_us(usec);
  }
}


void smartcard_init(smartcard_t* sc) {
  smartcard_state_reset(sc);
  sc->state = SC_OFF;
}

void smartcard_activate(smartcard_t* sc) {
  hal_smartcard_start();

  if (atr_read(sc) != ERR_OK) {
    smartcard_deactivate(sc);
    return;
  }

  if (pps_negotiate(sc) != ERR_OK) {
    smartcard_deactivate(sc);
    return;
  }

  if (sc->atr.default_protocol == SC_T1) {
    if (t1_negotiate_ifsd(sc, 3) != ERR_OK) {
      smartcard_deactivate(sc);
      return;
    }
  }

  sc->state = SC_READY;
}

void smartcard_deactivate(smartcard_t* sc) {
  smartcard_state_reset(sc);
  hal_smartcard_stop();
  sc->state = SC_DEACTIVATED;
}

void smartcard_in(smartcard_t* sc) {
  sc->state = SC_OFF;
}

void smartcard_out(smartcard_t* sc) {
  smartcard_deactivate(sc);
  sc->state = SC_NOT_PRESENT;
}

static inline app_err_t smartcard_wait(smartcard_t* sc) {
  BaseType_t res = pdFAIL;
  uint32_t err;
  res = xTaskNotifyWaitIndexed(SMARTCARD_TASK_NOTIFICATION_IDX, 0, UINT32_MAX, &err, pdMS_TO_TICKS(SC_MAX_TIMEOUT_MS));

  if (res != pdPASS) {
    hal_smartcard_abort();
    return ERR_HW;
  }

  return err == HAL_SUCCESS ? ERR_OK : ERR_HW;
}

app_err_t smartcard_transmit(smartcard_t* sc, const uint8_t* buf, uint32_t len) {
  return hal_smartcard_send(buf, len) == HAL_SUCCESS ? ERR_OK : ERR_TXRX;
}

app_err_t smartcard_transmit_sync(smartcard_t* sc, const uint8_t* buf, uint32_t len) {
  if (smartcard_transmit(sc, buf, len) != ERR_OK) {
    return ERR_TXRX;
  }

  return smartcard_wait(sc);
}

app_err_t smartcard_receive(smartcard_t* sc, uint8_t* buf, uint32_t len) {
  return hal_smarcard_recv(buf, len) == HAL_SUCCESS ? ERR_OK : ERR_TXRX;
}

app_err_t smartcard_receive_sync(smartcard_t* sc, uint8_t* buf, uint32_t len) {
  if (smartcard_receive(sc, buf, len) != ERR_OK) {
    return ERR_TXRX;
  }

  return smartcard_wait(sc);
}

app_err_t smartcard_send_apdu(smartcard_t* sc, apdu_t* apdu) {
  if (sc->atr.default_protocol == SC_T1) {
    return t1_transmit(sc, apdu);
  } else {
    // T0 not implemented
    return ERR_UNSUPPORTED;
  }
}
