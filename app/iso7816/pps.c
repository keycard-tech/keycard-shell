#include "hal.h"
#include "iso7816/pps.h"
#include "iso7816/atr.h"

#define PPS_SELECT 0xff
#define PPS_HAS_PPS1 0x10 /* 9.2: bit 5 says a PPS1 -- an Fi, Di proposal -- follows */
#define PPS_ANSWER_BITS 0xf0 /* 9.3: bits 5, 6 and 7 of the answer are the request's or 0; bit 8 is reserved */
#define PPS_TYPE 0x0f
#define PPS_GUARD_MAX 255

/* 8.3 Table 7 pairs Fi with f(max) in bits 8 to 5 of TA1. The frequency is the device's choice
 * under that bound: the kernel clock divided by 2 * Prescaler, of which hal_smartcard_pps programs
 * the Prescaler, so the fastest one at or below f(max). */
#if(SMARTCARD_CLOCK == 64000000)
static const uint32_t Freq_Table[] = {4000000, 4533333, 5333333, 8000000, 10666666, 16000000, 16000000, 0, 0, 4533333, 6400000, 8000000, 10666666, 16000000, 0, 0};
#elif(SMARTCARD_CLOCK == 200000000)
static const uint32_t Freq_Table[] = {4000000, 5000000, 5882352, 7692307, 11111111, 14285714, 20000000, 0, 0, 5000000, 7142857, 10000000, 14285714, 20000000, 0, 0};
#elif(SMARTCARD_CLOCK == 250000000)
static const uint32_t Freq_Table[] = {3906250, 5000000, 5952380, 7812500, 11363636, 15625000, 17857142, 0, 0, 5000000, 7352941, 9615384, 13888888, 17857142, 0, 0};
#else
#error "Frequency table not found"
#endif

/* 8.3 Table 7 again for Fi, and Table 8 for Di. A zero is a value the text leaves RFU. */
static const uint32_t F_Table[] = {372, 372, 558, 744, 1116, 1488, 1860, 0, 0, 512, 768, 1024, 1536, 2048, 0, 0};
static const uint32_t D_Table[] = {0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0};

app_err_t pps_negotiate(smartcard_t* sc) {
  const uint8_t fi_code = sc->atr.fi_di >> 4;
  const uint8_t di_code = sc->atr.fi_di & 0xf;

  /* 6.3.1: Fd and Dd, the parameters the exchange starts from and falls back to. They are the ones
   * atr.h carries as the default TA1, so that the two cannot drift apart. */
  const uint32_t fd = F_Table[ATR_DEFAULT_FIDI >> 4];
  const uint32_t dd = D_Table[ATR_DEFAULT_FIDI & 0xf];

  /* 8.3: bit 5 of TA2 says whether TA1's integers apply at all. With it set the implicit values --
   * Fd and Dd -- do, and a TA1 that carries no valid values is then not read. */
  const int implicit = (sc->atr.ta2 != ATR_INVALID_TA2) && (sc->atr.ta2 & 0x10);

  uint8_t rate = fi_code;
  if (implicit) {
    if ((F_Table[rate] == 0) || (D_Table[di_code] == 0)) {
      rate = ATR_DEFAULT_FIDI >> 4; /* the f(max) of 8.3's default, 5 MHz */
    }
  } else if ((F_Table[fi_code] == 0) || (D_Table[di_code] == 0)) {
    return ERR_DATA;
  }

  const uint32_t freq = Freq_Table[rate];

  uint32_t f = implicit ? fd : F_Table[fi_code];
  uint32_t d = implicit ? dd : D_Table[di_code];

  if (sc->atr.default_protocol == SC_T1) {
    /* 9.1: the request goes out whatever the rates are, because PPS0's type nibble is how the card
     * is told which protocol to run, at WT = 9600 etu -- the waiting time the ATR read already
     * armed, so nothing here reprograms it before the exchange. PPS1 is there only when there is
     * something to propose: a device that omits it proposes Fd and Dd (9.2). */
    const int propose = !implicit && ((f != fd) || (d != dd));

    uint8_t req[4];
    size_t len = 0;
    req[len++] = PPS_SELECT;
    req[len++] = sc->atr.default_protocol | (propose ? PPS_HAS_PPS1 : 0);
    if (propose) {
      req[len++] = sc->atr.fi_di;
    }
    req[len] = 0;
    for (size_t i = 0; i < len; i++) {
      req[len] ^= req[i]; /* 9.2: PPSS to PCK inclusive exclusive-ors to 00 */
    }
    len++;

    if (smartcard_transmit_sync(sc, req, len) != ERR_OK) {
      return ERR_TXRX;
    }

    uint8_t ans[4];
    const app_err_t rx = smartcard_receive_sync(sc, ans, sizeof(ans));
    const uint32_t got = hal_smartcard_received();

    if (got < 2) {
      return ERR_TXRX; /* 9.1: nothing that could be read as an answer */
    }

    /* 9.3: bits 4 to 1 identical, and each of bits 5, 6 and 7 either identical to the request's or 0
     * -- which is the answer not claiming a parameter byte the request never sent. Bit 8 is reserved
     * for future use, and this reader sends neither PPS2 nor PPS3, so bits 6 to 8 must read 0. */
    if ((ans[0] != PPS_SELECT) || ((ans[1] & PPS_TYPE) != (req[1] & PPS_TYPE)) ||
        (ans[1] & ~req[1] & PPS_ANSWER_BITS)) {
      return ERR_DATA;
    }

    /* 9.2 and 9.3: four bytes when the card echoes PPS1, three when it clears bit 5 to take Fd and
     * Dd. The three byte answer leaves the reception waiting for a PCK that never comes, which is
     * why a read that failed with exactly three bytes is that decline and nothing else is. */
    const uint32_t need = (ans[1] & PPS_HAS_PPS1) ? sizeof(ans) : 3;
    if ((got != need) || ((rx != ERR_OK) && (need != 3))) {
      return ERR_TXRX;
    }

    if (ans[1] & PPS_HAS_PPS1) {
      if (ans[2] != sc->atr.fi_di) {
        return ERR_DATA;
      }
    } else {
      /* 9.3: an answer that clears bit 5 is a success, and it means Fd and Dd are in force however
       * TA1 read. */
      f = fd;
      d = dd;
    }

    uint8_t pck = 0;
    for (uint32_t i = 0; i < need; i++) {
      pck ^= ans[i]; /* 9.2: PPSS to PCK inclusive exclusive-ors to 00 */
    }
    if (pck != 0) {
      return ERR_DATA;
    }

    /* 11.4.3, both of which carry an 11 etu term, and BWT with Fd over f rather than Fi. */
    sc->t1_cwt = 11 + (1u << sc->atr.t1_cwi);
    sc->t1_bwt = 11 + ((1u << sc->atr.t1_bwi) * 960 * fd * d / f);
  }

  /* 7.1: 1 etu = F / (D * f). The division is kept whole because Fi need not divide by Di: 558 over
   * 32 is a valid etu and truncating first loses a sixth of it. */
  sc->etu_10ns = (uint32_t)(((uint64_t)100000000 * f) / ((uint64_t)d * freq));

  /* GTPR.GT is in etu, counted after the stop bit, so it wants CGT minus the character this reader
   * sends: 11 etu with STOP = 00 in T=1, 11.5 otherwise, which is one etu short of the 12 that 8.3
   * counts either way. CGT is 12 etu + R * N / f, R being F / D or Fi / Di when T=15 is in the ATR,
   * except 11.2's 11 etu for N = 255 in T=1, which the frame spans by itself. Rounded up, since it is
   * the card that waits. */
  uint32_t extra = 0;
  if (sc->atr.n != 255) {
    const uint32_t r_num = (sc->atr.t15_present && !implicit) ? F_Table[fi_code] : f;
    const uint32_t r_den = (sc->atr.t15_present && !implicit) ? D_Table[di_code] : d;
    const uint32_t den = r_den * f;
    extra = (((uint64_t)r_num * sc->atr.n * d) + den - 1) / den;
  }
  const uint32_t want = (sc->atr.n == 255 && sc->atr.default_protocol == SC_T1) ? 0 : extra + 1;
  const uint8_t guard = want > PPS_GUARD_MAX ? PPS_GUARD_MAX : want;

  /* 10.2: WT = WI * 960 * Fi / f, which is WI * 960 * D once F is Fi, as it is with no exchange. */
  const uint32_t timeout = sc->atr.default_protocol == SC_T1 ? 0 : sc->atr.t0_wi * 960 * d;

  return hal_smartcard_pps(sc->atr.default_protocol, (uint32_t)((uint64_t)freq * d / f), freq, guard, timeout) == HAL_SUCCESS ? ERR_OK : ERR_HW;
}
