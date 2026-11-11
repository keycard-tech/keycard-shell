#ifndef SC_CARD_H
#define SC_CARD_H

#include <stddef.h>
#include <stdint.h>

#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/application_info.h"
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

/* ------------------------------------------------------------------ what a card answers

   Replies in the applet's own wire format. Every suite that drives a card needs the same handful --
   what SELECT returns, what the two status commands return, the name -- so they are written once
   here. The trailing 90 00 of each is the T=1 status word, which belongs to no TLV. */

#define SC_CARD_NAME "card" /* what a test then asserts the shell read */

/* A card switched on: the ATR, and the answer to the S(IFS) the shell sends back to it. This only
 * queues the two; sc_card_activate() below runs the module over them. */
static inline void sc_card_present(void) {
  hal_host_sc_reply_hex(SC_CARD_ATR);
  hal_host_sc_reply_hex(SC_CARD_IFS_ANSWER);
}

/* What a v4 applet answers SELECT with: its version, an initialised status, a key uid (whose length
 * is what reports a card that carries a key), the capabilities, and the device certificate. The
 * certificate's first 33 bytes are the identity key on its own, which is what a CA signs -- the rest
 * is that signature and the recovery id to read the CA out of it. */
static inline size_t sc_card_app_info_v4(uint8_t* out, size_t max, uint16_t version, const uint8_t* cert) {
  uint8_t inner[192];
  size_t n = 0;

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(inner),
                                         (unsigned)(4 + 3 + 2 + APP_INFO_KEY_UID_LEN + 3 + 2 +
                                                    APP_INFO_CERT_SIZE),
                                         "inner tlv");

  inner[n++] = 0x02;
  inner[n++] = 2;
  inner[n++] = (uint8_t)(version >> 8);
  inner[n++] = (uint8_t)version;

  inner[n++] = 0x8c;
  inner[n++] = 1;
  inner[n++] = APP_STATUS_INITIALIZED;

  inner[n++] = 0x8e;
  inner[n++] = APP_INFO_KEY_UID_LEN;
  memset(&inner[n], 0x5a, APP_INFO_KEY_UID_LEN);
  n += APP_INFO_KEY_UID_LEN;

  inner[n++] = 0x8d;
  inner[n++] = 1;
  inner[n++] = 0x00;

  inner[n++] = 0x8a;
  inner[n++] = APP_INFO_CERT_SIZE;
  memcpy(&inner[n], cert, APP_INFO_CERT_SIZE);
  n += APP_INFO_CERT_SIZE;

  /* A template this long needs the two-octet form of the length, which is what a real applet sends
   * and what the reader accepts. */
  const size_t hdr = (n >= 0x80) ? 3 : 2;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)max, (unsigned)(n + hdr + 2), "out");

  size_t o = 0;
  out[o++] = 0xa4;
  if (hdr == 3) {
    out[o++] = 0x81;
  }
  out[o++] = (uint8_t)n;
  memcpy(&out[o], inner, n);
  o += n;

  out[o++] = 0x90;
  out[o++] = 0x00;
  return o;
}

/* The application status: how many PIN and PUK retries the card has left, and a key present. */
static inline size_t sc_card_status_plain(uint8_t* plain, uint8_t pin_retries, uint8_t puk_retries) {
  plain[0] = 0xa3;
  plain[1] = 0x09;
  plain[2] = 0x02;
  plain[3] = 0x01;
  plain[4] = pin_retries;
  plain[5] = 0x02;
  plain[6] = 0x01;
  plain[7] = puk_retries;
  plain[8] = 0x01;
  plain[9] = 0x01;
  plain[10] = 0x01;
  plain[11] = 0x90;
  plain[12] = 0x00;

  return 13;
}

/* The card's name as the shell reads it: a length under the 0x20 flag, then the bytes. */
static inline size_t sc_card_name_plain(uint8_t* plain) {
  plain[0] = (uint8_t)(0x20 | (sizeof(SC_CARD_NAME) - 1));
  memcpy(&plain[1], SC_CARD_NAME, sizeof(SC_CARD_NAME) - 1);
  plain[sizeof(SC_CARD_NAME)] = 0x90;
  plain[sizeof(SC_CARD_NAME) + 1] = 0x00;

  return sizeof(SC_CARD_NAME) + 2;
}

#endif
