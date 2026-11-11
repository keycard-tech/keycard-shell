#ifndef SC_CARD_H
#define SC_CARD_H

#include <stddef.h>
#include <stdint.h>

#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "sc_host.h"
#include "unity.h"

/*
 * Scripting a card on the T=1 wire: the answers a test queues and the blocks it reads back. The
 * card has no state beyond its send-sequence, which counts I-blocks modulo 2 -- N(S) is a single
 * bit (T1_I_SEQ_MSK is 0x40), so an exchange's third block goes back to 0, and a 2 written in that
 * field is the top bit of an R-block, which the reader then reads as one.
 *
 * A card's reply over a secure channel carries its own status word inside the seal and lr counts
 * it, which is why the APDU macros read a channel reply the same way they read a bare one.
 */

#define SC_CARD_ATR "3BFA1300FF910131FE000031C173C84000009000D2" /* specific mode, T=1, LRC */
#define SC_CARD_IFS_ANSWER "00E101FE1E"                          /* the card's answer to S(IFS) */

static inline void sc_card_answer(const uint8_t* info, size_t len, uint8_t seq) {
  const uint8_t hdr[3] = {0x00, (uint8_t)((seq & 1) << 6), (uint8_t)len};

  uint8_t lrc = hdr[0] ^ hdr[1] ^ hdr[2];
  for (size_t i = 0; i < len; i++) {
    lrc ^= info[i];
  }

  hal_host_sc_reply(hdr, sizeof(hdr));
  hal_host_sc_reply(info, len);
  hal_host_sc_reply(&lrc, 1);
}

/* A reply that is nothing but a status word. */
static inline void sc_card_status(uint16_t sw, uint8_t seq) {
  const uint8_t bytes[2] = {(uint8_t)(sw >> 8), (uint8_t)sw};
  sc_card_answer(bytes, sizeof(bytes), seq);
}

/* A card switched on and negotiated with, which is where every exchange with the shell starts. */
static inline void sc_card_activate(smartcard_t* sc) {
  hal_host_sc_reply_hex(SC_CARD_ATR);
  hal_host_sc_reply_hex(SC_CARD_IFS_ANSWER);
  smartcard_activate(sc);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_READY, sc->state, "activation");

  /* Counted from nothing afterwards, so an exchange cannot inherit the activation's block. */
  hal_host_sc_sent_clear();
}

/* The nth block the shell put on the wire, as an APDU. Not hal_host_sc_send_calls(), which counts
 * the three writes t1.c makes per block. */
static inline size_t sc_card_apdu(unsigned n, uint8_t* out, size_t maxlen) {
  const size_t len = hal_host_sc_apdu_at(n, out, maxlen);
  TEST_ASSERT_TRUE_MESSAGE(len != 0, "block is not an I-block");
  return len;
}

/* No (index)th I-block: the exchange ended where the test says it ended. */
static inline void sc_card_assert_no_apdu(unsigned index) {
  uint8_t got[128];
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, (unsigned)hal_host_sc_apdu_at(index, got, sizeof(got)),
                                 "another command went out");
}

/* The one block the shell sent since the last clear, byte for byte. */
static inline void sc_card_assert_apdu(const uint8_t* want, size_t len) {
  uint8_t got[128];

  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)(len + 4), (unsigned)hal_host_sc_sent_len(), "one block");
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(got), (unsigned)len, "want");

  const size_t sent = hal_host_sc_apdu(got, sizeof(got));
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)len, (unsigned)sent, "apdu length");
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, got, (unsigned)((len < sent) ? len : sent), "apdu");
}

#endif
