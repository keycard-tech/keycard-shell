#include <stdint.h>
#include <string.h>

#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "iso7816/smartcard.h"
#include "sc_host.h"
#include "unity.h"

/*
 * smartcard.c is the order of an activation and the reading of what the peripheral says back: the
 * answer to reset, the parameters, the T=1 IFSD offer, and then SC_READY or a deactivation. No other
 * module sees that order, and an activation that stops halfway is only diagnosable if the step that
 * stopped it is named somewhere.
 *
 * The card is scripted rather than emulated: the ATR and the card's answers are queued in the order
 * they arrive, and what is asserted is the state, the peripheral events, and the bytes the shell put
 * on the wire.
 */

#define ATR_T1 "3BFA1300FF910131FE000031C173C84000009000D2" /* specific mode of 6.3.1, T=1, LRC */
#define ATR_T0 "3B69000241434F534A76313031"                 /* nothing offered but T=0 */

/* S(IFS request) offering the shell's IFSD of 254, with the LRC of 11.4.4: the one block activation
 * sends and the first thing a T=1 card is met with. */
#define IFS_REQUEST "00C101FE3E"

/* A card's answer to it, taken from the ifs rows of the T=1 vectors. */
#define CARD_ANSWER "00E101FE1E"

static smartcard_t sc;
static apdu_t apdu;

void setUp(void) {
  hal_host_sc_reset();
  smartcard_init(&sc);
}

void tearDown(void) {}

static void assert_wire_starts_with(const char* hex) {
  uint8_t want[64];
  const size_t len = test_unhex(hex, want, sizeof(want));

  TEST_ASSERT_GREATER_OR_EQUAL_UINT_MESSAGE((unsigned)len, (unsigned)hal_host_sc_sent_len(), "wire");
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, hal_host_sc_sent(), (unsigned)len, "wire");
}

static void assert_wire(const char* hex) {
  uint8_t want[64];
  const size_t len = test_unhex(hex, want, sizeof(want));

  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)len, (unsigned)hal_host_sc_sent_len(), "wire length");
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, hal_host_sc_sent(), (unsigned)len, "wire");
}

/* 6.3.1, 9.1 and 11.6.2 in one pass: the ATR is read at the parameters of the reset, the ones the
 * card asked for are applied, and a T=1 card is offered the IFSD before the shell calls itself
 * ready. */
void test_activation_reads_the_atr_applies_the_parameters_and_offers_the_ifsd(void) {
  hal_host_sc_reply_hex(ATR_T1);
  hal_host_sc_reply_hex(CARD_ANSWER);

  smartcard_activate(&sc);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_READY, sc.state, "state");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, hal_host_sc_starts(), "clock started once");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_stops(), "not deactivated");
  TEST_ASSERT_TRUE_MESSAGE(hal_host_sc_pps_called(), "parameters applied");
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_T1, hal_host_sc_pps_protocol(), "protocol");
  assert_wire(IFS_REQUEST);
}

/* 8.2.5: without a check byte that covers the answer to reset there is nothing for pps.c to work
 * from, and the card is deactivated before the peripheral is reprogrammed. */
void test_a_bad_answer_to_reset_deactivates_before_the_parameters(void) {
  uint8_t atr[64];
  const size_t len = test_unhex(ATR_T1, atr, sizeof(atr));
  atr[len - 1] ^= 0xff;

  hal_host_sc_reply(atr, len);

  smartcard_activate(&sc);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_DEACTIVATED, sc.state, "state");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, hal_host_sc_stops(), "peripheral stopped");
  TEST_ASSERT_FALSE_MESSAGE(hal_host_sc_pps_called(), "no parameters applied");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_sent_len(), "nothing transmitted");
}

/* 9.1: an exchange the peripheral refuses leaves the card at the parameters the exchange would have
 * established, which is nowhere. */
void test_a_refused_pps_deactivates(void) {
  hal_host_sc_reply_hex(ATR_T1);
  hal_host_sc_pps_refuse(true);

  smartcard_activate(&sc);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_DEACTIVATED, sc.state, "state");
  TEST_ASSERT_TRUE_MESSAGE(hal_host_sc_pps_called(), "parameters attempted");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, hal_host_sc_stops(), "peripheral stopped");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_sent_len(), "no IFSD offer followed");
}

/* 11.6.2 with the retries t1_negotiate_ifsd is given: the request and the resynchronization that
 * follows it are all the card said nothing to, and the activation ends as a failed ATR would. */
void test_a_card_silent_at_the_ifsd_offer_deactivates(void) {
  hal_host_sc_reply_hex(ATR_T1);

  smartcard_activate(&sc);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_DEACTIVATED, sc.state, "state");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, hal_host_sc_stops(), "peripheral stopped");
  assert_wire_starts_with(IFS_REQUEST);
}

/* The protocol of the answer to reset decides what activation does next: the IFSD offer is T=1's,
 * so a T=0 card is activated with nothing on the wire. */
void test_a_t0_card_is_activated_without_a_t1_block(void) {
  hal_host_sc_reply_hex(ATR_T0);

  smartcard_activate(&sc);

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_READY, sc.state, "state");
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_T0, hal_host_sc_pps_protocol(), "protocol");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_sent_len(), "no block transmitted");
}

/* Where that card's story ends, since the shell speaks T=1 only: refused by name, before any byte
 * goes out. */
void test_an_apdu_to_a_t0_card_is_unsupported(void) {
  hal_host_sc_reply_hex(ATR_T0);
  smartcard_activate(&sc);

  APDU_RESET(&apdu);
  apdu.data[0] = 0x00;
  apdu.data[1] = 0xa4;
  apdu.data[2] = 0x04;
  apdu.data[3] = 0x00;

  TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_UNSUPPORTED, smartcard_send_apdu(&sc, &apdu), "result");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_sent_len(), "nothing transmitted");
}

/* The sync wrappers read the notification rather than the call: a transfer whose completion carries
 * anything but HAL_SUCCESS is ERR_HW, and there is nothing to abort -- it is finished. */
void test_a_peripheral_error_is_hw(void) {
  hal_host_sc_notify_value(HAL_FAIL);

  const uint8_t byte = 0x00;
  TEST_ASSERT_EQUAL_UINT16(ERR_HW, smartcard_transmit_sync(&sc, &byte, 1));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_aborts());
}

/* The case the abort exists for: no notification at all. The wait gives up and abandons the
 * transfer, because nothing else will clear the peripheral. */
void test_a_transfer_that_never_answers_aborts(void) {
  hal_host_sc_fail_notify_after(0);

  const uint8_t byte = 0x00;
  TEST_ASSERT_EQUAL_UINT16(ERR_HW, smartcard_transmit_sync(&sc, &byte, 1));
  TEST_ASSERT_EQUAL_UINT(1, hal_host_sc_aborts());
}

/* A write the peripheral refuses is not a wait: nothing was armed, so nothing is abandoned. */
void test_a_refused_write_is_txrx(void) {
  hal_host_sc_refuse_send(1);

  const uint8_t byte = 0x00;
  TEST_ASSERT_EQUAL_UINT16(ERR_TXRX, smartcard_transmit(&sc, &byte, 1));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_aborts());
}

/* 7.1 with the etu of the reset, and where a delay stops being a busy wait: 43 etu is 3999 us, and
 * 44 is 4092, which is the scheduler's. The guard times of 11.2 are counted this way. */
void test_the_delay_follows_the_etu_and_yields_past_four_milliseconds(void) {
  smartcard_delay(&sc, 43);
  TEST_ASSERT_EQUAL_UINT32(3999, hal_host_sc_delayed_us());

  smartcard_delay(&sc, 44);
  TEST_ASSERT_EQUAL_UINT32(3999 + 4000, hal_host_sc_delayed_us());
}

/* The next card is a different card: deactivation drops the negotiated etu and the block sequences,
 * which is what an activation at other parameters would otherwise inherit. */
void test_deactivation_returns_to_the_reset_parameters(void) {
  hal_host_sc_reply_hex(ATR_T1);
  hal_host_sc_reply_hex(CARD_ANSWER);
  smartcard_activate(&sc);
  TEST_ASSERT_EQUAL_UINT32(1860, sc.etu_10ns);

  sc.send_seq = 3;
  sc.recv_seq = 2;

  smartcard_deactivate(&sc);

  TEST_ASSERT_EQUAL_UINT32(9300, sc.etu_10ns);
  TEST_ASSERT_EQUAL_UINT8(0, sc.send_seq);
  TEST_ASSERT_EQUAL_UINT8(0, sc.recv_seq);
  TEST_ASSERT_EQUAL_UINT8(1, sc.t1_bwt_factor);
}

/* Removal is a state and a deactivation; insertion is a state and nothing else, because the
 * peripheral is started by the activation. */
void test_out_deactivates_and_marks_the_card_absent(void) {
  smartcard_out(&sc);

  TEST_ASSERT_EQUAL_UINT8(SC_NOT_PRESENT, sc.state);
  TEST_ASSERT_EQUAL_UINT(1, hal_host_sc_stops());
}

void test_in_moves_the_state_only(void) {
  smartcard_in(&sc);

  TEST_ASSERT_EQUAL_UINT8(SC_OFF, sc.state);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_stops());
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_starts());
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_activation_reads_the_atr_applies_the_parameters_and_offers_the_ifsd);
  RUN_TEST(test_a_bad_answer_to_reset_deactivates_before_the_parameters);
  RUN_TEST(test_a_refused_pps_deactivates);
  RUN_TEST(test_a_card_silent_at_the_ifsd_offer_deactivates);
  RUN_TEST(test_a_t0_card_is_activated_without_a_t1_block);
  RUN_TEST(test_an_apdu_to_a_t0_card_is_unsupported);
  RUN_TEST(test_a_peripheral_error_is_hw);
  RUN_TEST(test_a_transfer_that_never_answers_aborts);
  RUN_TEST(test_a_refused_write_is_txrx);
  RUN_TEST(test_the_delay_follows_the_etu_and_yields_past_four_milliseconds);
  RUN_TEST(test_deactivation_returns_to_the_reset_parameters);
  RUN_TEST(test_out_deactivates_and_marks_the_card_absent);
  RUN_TEST(test_in_moves_the_state_only);

  return UNITY_END();
}
