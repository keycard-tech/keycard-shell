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
#define ATR_DEFAULT_T1_RC 0

#define ATR_DEFAULT_CLOCKSTOP 0
#define ATR_DEFAULT_CLASSES 0

app_err_t atr_read(smartcard_t* sc);

#endif
