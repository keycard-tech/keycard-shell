#include "hal.h"
#include "iso7816/pps.h"
#include "iso7816/atr.h"

#define PPS_TIMEOUT 20

const static uint32_t F_Table[] = {372, 372, 558, 744, 1116, 1488, 1860, 0, 0, 512, 768, 1024, 1536, 2048, 0, 0};
const static uint32_t D_Table[] = {0, 1, 2, 4, 8, 16, 32, 0, 12, 20, 0, 0, 0, 0, 0, 0};

#if(SMARTCARD_CLOCK == 64000000)
const static uint32_t F_freq_Table[] = {4000000, 4533333, 5333333, 8000000, 10666666, 16000000, 16000000, 0, 0, 4533333, 6400000, 8000000, 10666666, 16000000, 0, 0};
#elif(SMARTCARD_CLOCK == 200000000)
const static uint32_t F_freq_Table[] = {4000000, 5000000, 5882352, 7692307, 11111111, 14285714, 20000000, 0, 0, 5000000, 7142857, 10000000, 14285714, 20000000, 0, 0};
#elif(SMARTCARD_CLOCK == 250000000)
const static uint32_t F_freq_Table[] = {3906250, 5000000, 5952380, 7812500, 11363636, 15625000, 17857142, 0, 0, 5000000, 7352941, 9615384, 13888888, 17857142, 0, 0};
#else
#error "Frequency table not found"
#endif

app_err_t pps_negotiate(smartcard_t* sc) {
  if (sc->atr.fi_di != ATR_DEFAULT_FIDI) {
    uint8_t pps[4] = {0xff, 0x10, 0x00, 0x00};
    uint8_t ppsr[4];
    pps[1] |= sc->atr.default_protocol;
    pps[2] = sc->atr.fi_di;
    pps[3] = pps[0] ^ pps[1] ^ pps[2];

    if (smartcard_transmit_sync(sc, pps, 4) != ERR_OK) {
      return ERR_TXRX;
    }

    if (smartcard_receive_sync(sc, ppsr, 4) != ERR_OK) {
      return ERR_TXRX;
    }

    if(!((pps[0] == ppsr[0]) && (pps[1] == ppsr[1]) && (pps[2] == ppsr[2]) && (pps[3] == ppsr[3]))) {
        return ERR_DATA;
    }
  }

  uint8_t fi = (sc->atr.fi_di >> 4);
  uint8_t di = (sc->atr.fi_di & 0x0f);
  
  uint32_t F = F_Table[fi];
  uint32_t D = D_Table[di];
  uint32_t freq = F_freq_Table[fi];

  if ((D == 0) || (F == 0)) {
    return ERR_DATA;
  }

  uint32_t fd = F/D;

  uint32_t baud = ((freq * D) / F);
  uint32_t timeout = 0;

  sc->etu_10ns = (100000000/freq) * fd;

  if (sc->atr.default_protocol == SC_T1) {
    sc->t1_cwt = (1 << sc->atr.t1_cwi);
    sc->t1_bwt = (((1 << sc->atr.t1_bwi) * 960 * 372 * D) / F);
    sc->t1_bwt_factor = 1;
  } else {
    timeout = sc->atr.t0_wi * D * 960;
  }

  uint8_t guard = (sc->atr.n == 0 || sc->atr.n == 255) ? 0 : (fd * sc->atr.n);

  return hal_smartcard_pps(sc->atr.default_protocol, baud, freq, guard, timeout) == HAL_SUCCESS ? ERR_OK : ERR_HW;
}
