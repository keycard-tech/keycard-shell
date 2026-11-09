#ifndef _ATR_H
#define _ATR_H

#include "smartcard.h"
#include "error.h"

#define ATR_DEFAULT_FIDI 0x11
#define ATR_DEFAULT_N 0
#define ATR_DEFAULT_T0_WI 10

#define ATR_DEFAULT_T1_IFSC 32
#define ATR_DEFAULT_T1_CWI 13
#define ATR_DEFAULT_T1_BWI 4
/* 7816-3:11.4.4: LRC is both the code bit 1 of the first TC for T=1 selects when clear and the
 * default when that byte is absent. */
#define ATR_DEFAULT_T1_RC ATR_T1_LRC

#define ATR_DEFAULT_CLOCKSTOP 0
/* 8.3: with no T=15 in the ATR, the card supports class A and stops no clock. */
#define ATR_DEFAULT_CLASSES ATR_CLASS_A_5V

app_err_t atr_read(smartcard_t* sc);

#endif
