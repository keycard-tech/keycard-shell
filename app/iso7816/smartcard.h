#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include "atr_types.h"
#include "error.h"

#define SW_OK 0x9000

#define APDU_CLA(__APDU__) ((__APDU__)->data[0])
#define APDU_INS(__APDU__) ((__APDU__)->data[1])
#define APDU_P1(__APDU__) ((__APDU__)->data[2])
#define APDU_P2(__APDU__) ((__APDU__)->data[3])
#define APDU_LC(__APDU__) ((__APDU__)->has_lc ? (__APDU__)->data[4] : -1)
#define APDU_DATA(__APDU__)(&((__APDU__)->data[5]))
#define APDU_RESP(__APDU__)(&((__APDU__)->data[0]))
#define APDU_LE(__APDU__) ((__APDU__)->has_le ? (__APDU__)->data[(__APDU__)->has_lc ? 5 : 4] : -1)
#define APDU_SET_LC(__APDU__, __val__) {(__APDU__)->data[4] = __val__; (__APDU__)->has_lc = 1;}
#define APDU_SET_LE(__APDU__, __val__) {(__APDU__)->data[5 + APDU_LC(__APDU__)] = __val__; (__APDU__)->has_le = 1;}
#define APDU_RESET(__APDU__) {(__APDU__)->has_lc = 0; (__APDU__)->has_le = 0; (__APDU__)->lr = 0;}
#define APDU_LEN(__APDU__) (4 + (__APDU__)->has_le + ((__APDU__)->has_lc ? (1 + (__APDU__)->data[4]) : 0))
#define APDU_SW1(__APDU__) ((__APDU__)->data[(__APDU__)->lr - 2])
#define APDU_SW2(__APDU__) ((__APDU__)->data[(__APDU__)->lr - 1])
#define APDU_SW(__APDU__) ((APDU_SW1(__APDU__) << 8) | APDU_SW2(__APDU__))
#define APDU_BUF_LEN (255 + 6)

#define APDU_ASSERT_SW(__APDU__, __SW__) if (APDU_SW(__APDU__) != __SW__) return ERR_HW;
#define APDU_ASSERT_OK(__APDU__) APDU_ASSERT_SW(__APDU__, SW_OK)

typedef enum {
  SC_NOT_PRESENT,
  SC_OFF,
  SC_DEACTIVATED,
  SC_READY
} smartcard_state_t;

typedef enum {
  SC_T0,
  SC_T1
} smartcard_protocol_t;

typedef struct {
  smartcard_state_t state;
  atr_t atr;
  uint8_t send_seq;
  uint8_t recv_seq;
  uint32_t t1_bwt;
  uint32_t t1_cwt;
  uint8_t t1_bwt_factor;
  uint32_t etu_10ns;
} smartcard_t;

typedef struct __attribute__((packed,aligned(4))) {
  uint8_t has_lc;
  uint8_t has_le;
  uint16_t lr;
  uint8_t data[APDU_BUF_LEN];
} apdu_t;

#define SC_TRANSMIT_TO 25

void smartcard_delay(smartcard_t* sc, uint32_t etu);
void smartcard_init(smartcard_t* sc);
void smartcard_activate(smartcard_t* sc);
void smartcard_deactivate(smartcard_t* sc);
void smartcard_in(smartcard_t* sc);
void smartcard_out(smartcard_t* sc);
app_err_t smartcard_transmit(smartcard_t* sc, const uint8_t* buf, uint32_t len);
app_err_t smartcard_transmit_sync(smartcard_t* sc, const uint8_t* buf, uint32_t len);
app_err_t smartcard_receive(smartcard_t* sc, uint8_t* buf, uint32_t len);
app_err_t smartcard_receive_sync(smartcard_t* sc, uint8_t* buf, uint32_t len);
app_err_t smartcard_send_apdu(smartcard_t* sc, apdu_t* apdu);

#endif
