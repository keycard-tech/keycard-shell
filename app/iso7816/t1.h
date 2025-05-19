#ifndef __T1
#define __T1

#include "smartcard.h"
#include "error.h"

#define T1_NAD 0x00
#define T1_IFSD 254

#define T1_I_BLOCK 0x00
#define T1_R_BLOCK 0x80
#define T1_S_BLOCK 0xC0

#define T1_I_SEQ(__seq__) (__seq__ << 6)
#define T1_I_SEQ_MSK 0x40
#define T1_I_MORE 0x20
#define T1_I_LAST 0x00

#define T1_R_OK 0x00
#define T1_R_PARITY 0x01
#define T1_R_OTHER 0x02
#define T1_R_ERR_MSK 0x3
#define T1_R_SEQ(__seq__) (__seq__ << 5)
#define T1_R_SEQ_MSK 0x20

#define T1_S_RESYNCH 0x00
#define T1_S_IFS 0x01
#define T1_S_ABORT 0x02
#define T1_S_WTX 0x03

#define T1_S_RQS 0x00
#define T1_S_RES 0x20


app_err_t t1_transmit(smartcard_t* sc, apdu_t* apdu);
app_err_t t1_negotiate_ifsd(smartcard_t* sc, int retry);

#endif
