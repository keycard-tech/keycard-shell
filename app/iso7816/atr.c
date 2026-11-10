#include "atr.h"
#include "hal.h"

/* 8.1: the answer to reset is framed with GT = 12 etu and WT = 9600 etu, which a card is free to use
 * before its first character. The peripheral counts baud blocks, etu in smartcard mode. */
#define ATR_WT 9600
#define ATR_SIZE 2
#define ATR_DIRECT_CONVENTION 0x3b

#define ATR_READ_BYTE(v, mask, td, def) ((mask & td) ? v : def)

/* 7816-3:8.2.3 numbers the interface bytes of a type by occurrence, and 11.4.2, 11.4.3, 11.4.4 and
 * 8.3 then take only the first of each kind for their type: a later triple belongs to the next offer
 * of that protocol, not to the parameters in force. */
#define ATR_SEEN_T1_TA 0x1
#define ATR_SEEN_T1_TB 0x2
#define ATR_SEEN_T1_TC 0x4
#define ATR_SEEN_T15_TA 0x8

/* 8.2.3: T names a transmission protocol, except T=15, which only qualifies global interface bytes
 * and so offers nothing. */
static uint8_t atr_protocol_bit(uint8_t t) {
  switch (t) {
    case 0:
      return ATR_PROTOCOLS_T0;
    case 1:
      return ATR_PROTOCOLS_T1;
    default:
      return 0;
  }
}

static app_err_t atr_read_bytes(smartcard_t* sc, uint8_t* buf, uint8_t td, uint8_t *ck) {
  for (int i = 0; i < 4; i++) {
    if (td & 0x10) {
      if (smartcard_receive_sync(sc, &buf[i], 1) != ERR_OK) {
        return ERR_TXRX;
      }

      *ck ^= buf[i];
    } else {
      buf[i] = 0;
    }

    td >>= 1;
  }

  return ERR_OK;
}

static void atr_parse_bytes(smartcard_t* sc, uint8_t* buf, uint8_t td, uint8_t i, uint8_t* seen) {
  /* The timing group: TA1 is Fi, Di and f(max) and TC1 is N, both of 8.3. TB1 is deprecated and the
   * reader shall ignore it. */
  if (i == 1) {
    sc->atr.fi_di = ATR_READ_BYTE(buf[0], 0x10, td, ATR_DEFAULT_FIDI);
    sc->atr.n = ATR_READ_BYTE(buf[2], 0x40, td, ATR_DEFAULT_N);
    return;
  }

  /* The second group is qualified by TD1's T, but 8.2.3 makes TA2 and TB2 global and TC2 specific to
   * T=0 whatever that T was: TA2 is the specific mode byte of 8.3, not an IFSC. */
  if (i == 2) {
    sc->atr.ta2 = ATR_READ_BYTE(buf[0], 0x10, td, ATR_INVALID_TA2);
    sc->atr.t0_wi = ATR_READ_BYTE(buf[2], 0x40, td, ATR_DEFAULT_T0_WI);
    return;
  }

  switch (td & 0xf) {
    case 1:
      if ((td & 0x10) && !(*seen & ATR_SEEN_T1_TA)) {
        *seen |= ATR_SEEN_T1_TA;
        sc->atr.t1_ifsc = buf[0];
      }
      if ((td & 0x20) && !(*seen & ATR_SEEN_T1_TB)) {
        *seen |= ATR_SEEN_T1_TB;
        sc->atr.t1_cwi = buf[1] & 0xf;
        sc->atr.t1_bwi = (buf[1] & 0xf0) >> 4;
      }
      if ((td & 0x40) && !(*seen & ATR_SEEN_T1_TC)) {
        *seen |= ATR_SEEN_T1_TC;
        /* 11.4.4: bit 1 of the first TC for T=1 asks for CRC; clear, and an absent byte, is LRC. */
        sc->atr.t1_rc = (buf[2] & 0x1) ? ATR_T1_CRC : ATR_T1_LRC;
      }
      break;
    case 15:
      sc->atr.t15_present = 1;
      if ((td & 0x10) && !(*seen & ATR_SEEN_T15_TA)) {
        *seen |= ATR_SEEN_T15_TA;
        sc->atr.classes = buf[0] & 0x7;
        sc->atr.clockstop = buf[0] & 0xc0;
      }
      break;
  }
}

static void atr_reset(smartcard_t* sc) {
  sc->atr.valid = 0;
  sc->atr.t15_present = 0;
  sc->atr.default_protocol = SC_T0;
  sc->atr.protocols = ATR_PROTOCOLS_T0;

  sc->atr.fi_di = ATR_DEFAULT_FIDI;
  sc->atr.n = ATR_DEFAULT_N;
  sc->atr.ta2 = ATR_INVALID_TA2;
  sc->atr.t0_wi = ATR_DEFAULT_T0_WI;
  sc->atr.t1_ifsc = ATR_DEFAULT_T1_IFSC;
  sc->atr.t1_cwi = ATR_DEFAULT_T1_CWI;
  sc->atr.t1_bwi = ATR_DEFAULT_T1_BWI;
  sc->atr.t1_rc = ATR_DEFAULT_T1_RC;
  sc->atr.clockstop = ATR_DEFAULT_CLOCKSTOP;
  sc->atr.classes = ATR_DEFAULT_CLASSES;
  sc->atr.hist_len = 0;
}

app_err_t atr_read(smartcard_t* sc) {
  atr_reset(sc);

  uint8_t buf[4];

  hal_smartcard_set_timeout(ATR_WT);
  if (smartcard_receive_sync(sc, buf, 2) != ERR_OK) {
    return ERR_TXRX;
  }

  if (buf[0] != ATR_DIRECT_CONVENTION) {
    return ERR_DATA;
  }

  uint8_t td = buf[1];
  uint8_t ck = td;
  uint8_t seen = 0;
  /* 8.2.5: the check byte is absent when only T=0 is indicated, possibly by default, and present in
   * every other case -- including an ATR that adds only T=15, which offers no protocol at all. */
  int saw_t15 = 0;
  int saw_other_than_t0 = 0;

  sc->atr.hist_len = td & 0x0f;

  int i = 1;
  int more = 1;

  /* 8.2.3: a group follows only when the byte before it carries a TD, and that TD's value -- even a
   * byte with no indicator bits set -- is what qualifies the group. Ending the chain on a TD of 00
   * would hide an offer, and the offers are what the check byte and the order are judged on. */
  while(more) {
    if (atr_read_bytes(sc, buf, td, &ck) != ERR_OK) {
      return ERR_TXRX;
    }

    if (i >= 2) {
      const uint8_t t = td & 0xf;

      /* 8.2.3: if present, T=0 shall be first and T=15 shall be last. The types are not checked for
       * ascending order, because a card that offers no T=0 puts its first T=1 triple after a TD2
       * repeating the T=1 of TD1, which is how 8.2.3 itself describes it. */
      if (saw_t15 || ((t == 0) && saw_other_than_t0)) {
        return ERR_DATA;
      }

      if (i == 2) {
        /* 8.2.3: TD1 encodes the first offered protocol, and T=15 is invalid in it. */
        if (t == 15) {
          return ERR_DATA;
        }
        sc->atr.default_protocol = t;
        sc->atr.protocols = atr_protocol_bit(t);
      } else {
        sc->atr.protocols |= atr_protocol_bit(t);
      }

      saw_t15 |= (t == 15);
      saw_other_than_t0 |= (t != 0);
    }

    atr_parse_bytes(sc, buf, td, i, &seen);
    more = (td & 0x80) != 0;
    td = buf[3];
    i++;
  }

  /* 6.3.1 with 8.3: in specific mode the protocol is the type TA2 encodes. A type we cannot run is the
   * deactivation 8.3's NOTE asks for. */
  if (sc->atr.ta2 != ATR_INVALID_TA2) {
    const uint8_t t = sc->atr.ta2 & 0x0f;

    if ((t != SC_T0) && (t != SC_T1)) {
      return ERR_DATA;
    }

    sc->atr.default_protocol = t;
  }

  if (smartcard_receive_sync(sc, sc->atr.hist, sc->atr.hist_len) != ERR_OK) {
    return ERR_TXRX;
  }

  for (int i = 0; i < sc->atr.hist_len; i++) {
    ck ^= sc->atr.hist[i];
  }

  if (saw_other_than_t0) {
    if (smartcard_receive_sync(sc, buf, 1) != ERR_OK) {
      return ERR_TXRX;
    }

    sc->atr.valid = (buf[0] ^ ck) == 0;
  } else {
    sc->atr.valid = 1;
  }

  return sc->atr.valid ? ERR_OK : ERR_DATA;
}
