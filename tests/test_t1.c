#include <stdint.h>
#include <string.h>

#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "iso7816/atr.h"
#include "iso7816/pps.h"
#include "iso7816/smartcard.h"
#include "iso7816/t1.h"
#include "sc_host.h"
#include "unity.h"
#include "vectors/vectors_t1.h"

/*
 * t1.c is where the shell spends everything PPS negotiated: blocks are framed with the LRC the
 * card chose to need, awaited with the CWT and BWT it implied, and acknowledged by the sequence
 * numbers of 11.6. It is asserted as an exchange, not as a function: the card's blocks are queued
 * behind the ATR and its PPS answer, one call runs the exchange, and what is compared is every
 * byte the reader put on the wire, the timeouts it programmed between them, and the sequences and
 * parameters it was left with.
 *
 * The expectations come from the text, derived in pps_expect()/t1_expect() of
 * tests/vectors/generate.py; the note above each row names the clause or the rule.
 */

static smartcard_t sc;
static apdu_t apdu;

void setUp(void) {
  hal_host_sc_reset();
  smartcard_init(&sc);
}

void tearDown(void) {}

static size_t queue(const char* hex) {
  uint8_t bytes[512];
  const size_t len = test_unhex(hex, bytes, sizeof(bytes));
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(bytes), (unsigned)len, "vector too long");
  hal_host_sc_reply(bytes, len);
  return len;
}

static void assert_wire(const t1_kat_t* v) {
  uint8_t want[2048];
  const size_t want_len = test_unhex(v->wire_hex, want, sizeof(want));

  TEST_ASSERT_EQUAL_UINT32_MESSAGE((uint32_t)want_len, (uint32_t)hal_host_sc_sent_len(), v->name);
  if (want_len != hal_host_sc_sent_len()) {
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(want, hal_host_sc_sent(), (unsigned)want_len, v->name);
  }
}

static void run_row(const t1_kat_t* v) {
  queue(v->atr_hex);
  queue(v->pps_answer_hex);
  queue(v->card_hex);

  TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_OK, atr_read(&sc), v->name);
  TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_OK, pps_negotiate(&sc), v->name);

  /* Everything after here is the exchange: the wire, the reads and the timeouts are counted from
   * nothing, so a row cannot pass by inheriting what PPS did. */
  hal_host_sc_phase();
  hal_host_sc_refuse_send(v->refuse_sends);

  apdu.has_lc = v->has_lc;
  apdu.has_le = v->has_le;
  const size_t cmd_len = test_unhex(v->apdu_hex, apdu.data, sizeof(apdu.data));
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(APDU_BUF_LEN, (unsigned)cmd_len, v->name);
  /* The command goes in at data[0] and the answer is appended at data[lr], which is where lr has
   * to start: what is overwritten is a chunk that has already been transmitted. */
  apdu.lr = 0;

  const app_err_t res = v->entry == T1_ENTRY_NEGOTIATE ? t1_negotiate_ifsd(&sc, v->retry)
                                                       : t1_transmit(&sc, &apdu);

  TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->result, res, v->name);
  assert_wire(v);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->send_seq, sc.send_seq, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->recv_seq, sc.recv_seq, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->ifsc, sc.atr.t1_ifsc, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->bwt_factor, sc.t1_bwt_factor, v->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->unread, (uint32_t)hal_host_sc_unread(), v->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->delay_us, hal_host_sc_delayed_us(), v->name);

  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(T1_TIMEOUTS_MAX, v->timeout_count, v->name);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(v->timeout_count, hal_host_sc_timeout_count(), v->name);
  for (unsigned i = 0; i < v->timeout_count; i++) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->timeouts[i], hal_host_sc_timeout(i), v->name);
  }
}

void test_t1_rows(void) {
  for (unsigned i = 0; i < T1_KAT_COUNT; i++) {
    setUp();
    run_row(&T1_KAT[i]);
  }
}

/* A card that asks for a CRC of 11.4.4 gets no traffic whatever: the refusal has to come before
 * the first block, because a block with the wrong epilogue is a block the card will reject. */
void test_a_card_asking_for_crc_is_refused_before_the_first_block(void) {
  smartcard_init(&sc);
  hal_host_sc_reset();

  uint8_t bytes[64];
  size_t len = test_unhex("3B901881712045011C", bytes, sizeof(bytes));
  hal_host_sc_reply(bytes, len);
  len = test_unhex("FF1118F6", bytes, sizeof(bytes));
  hal_host_sc_reply(bytes, len);

  TEST_ASSERT_EQUAL_UINT16(ERR_OK, atr_read(&sc));
  TEST_ASSERT_EQUAL_UINT16(ERR_OK, pps_negotiate(&sc));
  TEST_ASSERT_EQUAL_UINT8(ATR_T1_CRC, sc.atr.t1_rc);

  hal_host_sc_phase();
  TEST_ASSERT_EQUAL_UINT16(ERR_UNSUPPORTED, t1_negotiate_ifsd(&sc, 1));
  TEST_ASSERT_EQUAL_UINT16(ERR_UNSUPPORTED, t1_transmit(&sc, &apdu));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_send_calls(), "a CRC card must not be talked at");
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_t1_rows);
  RUN_TEST(test_a_card_asking_for_crc_is_refused_before_the_first_block);

  return UNITY_END();
}
