#include <stdint.h>
#include <string.h>

#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "iso7816/atr.h"
#include "iso7816/pps.h"
#include "iso7816/smartcard.h"
#include "sc_host.h"
#include "unity.h"
#include "vectors/vectors_pps.h"

/*
 * pps.c turns the ATR into the two things every later transmission is timed against: the rate the
 * card is asked to run at, and the waiting times the peripheral counts out in etu. It is also the
 * last place where the card gets a vote -- 9.3 lets the answer refuse a proposed Fi and Di and
 * settle for Fd and Dd, which changes every number the module then computes.
 *
 * Each row is run as a card would be: the ATR goes on the wire and is read by atr_read, the row's
 * answer follows it, and what is asserted is the request that leaves, the answer consumed, and the
 * arguments handed to hal_smartcard_pps together with the etu, CWT and BWT that t1.c times blocks
 * with. The expectations come from the text; see the header of vectors_pps.h for the clauses and
 * pps_vectors() for the arithmetic.
 */

static smartcard_t sc;

void setUp(void) {
  hal_host_sc_reset();
  smartcard_init(&sc);
}

void tearDown(void) {}

static void feed(const pps_kat_t* v) {
  uint8_t bytes[64];

  const size_t atr_len = test_unhex(v->atr_hex, bytes, sizeof(bytes));
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(bytes), (unsigned)atr_len, v->name);
  hal_host_sc_reply(bytes, atr_len);

  if (v->pps_answer_hex != NULL) {
    const size_t answer_len = test_unhex(v->pps_answer_hex, bytes, sizeof(bytes));
    hal_host_sc_reply(bytes, answer_len);
  }

  TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_OK, atr_read(&sc), v->name);
}

static void run_case(const pps_kat_t* v) {
  feed(v);
  TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->result, pps_negotiate(&sc), v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->pps_called, hal_host_sc_pps_called() ? 1 : 0, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t1_bwt_factor, sc.t1_bwt_factor, v->name);

  if (!v->pps_called) {
    return;
  }

  uint8_t request[16];
  const size_t request_len = test_unhex(v->pps_request_hex, request, sizeof(request));
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)request_len, (unsigned)hal_host_sc_sent_len(), v->name);
  if (request_len > 0) {
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(request, hal_host_sc_sent(), request_len, v->name);
  }

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->protocol, (uint8_t)hal_host_sc_pps_protocol(), v->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->freq, hal_host_sc_pps_freq(), v->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->baud, hal_host_sc_pps_baud(), v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->guard, hal_host_sc_pps_guard(), v->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->t0_timeout, hal_host_sc_pps_timeout(), v->name);

  TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->etu_10ns, sc.etu_10ns, v->name);
  if (v->protocol == SC_T1) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->t1_cwt, sc.t1_cwt, v->name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->t1_bwt, sc.t1_bwt, v->name);
  }

  if (v->result == ERR_OK) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, (unsigned)hal_host_sc_unread(), v->name);
  }
}

void test_pps_rows(void) {
  for (unsigned i = 0; i < PPS_KAT_COUNT; i++) {
    hal_host_sc_reset();
    smartcard_init(&sc);
    run_case(&PPS_KAT[i]);
  }
}

/* f(max.) travels in the same nibble of TA1 as Fi (8.3, Table 7) and 5.2.3 forbids exceeding it,
 * so for every Fi a card may indicate, the clock handed to the peripheral is bounded by the figure
 * that came with it. The frequency itself is the device's choice, which is why the bound rather
 * than the value is what is pinned here. */
void test_no_clock_exceeds_the_frequency_the_card_allows(void) {
  for (unsigned i = 0; i < PPS_FMAX_COUNT; i++) {
    /* TA1 with an offered T=1 and no interface bytes, so the row says nothing but the nibble. */
    uint8_t atr[] = {0x3b, 0x90, (uint8_t)((PPS_FMAX[i].code << 4) | 0x1), 0x01, 0x00};
    atr[4] = (uint8_t)(atr[1] ^ atr[2] ^ atr[3]);

    hal_host_sc_reset();
    smartcard_init(&sc);
    hal_host_sc_reply(atr, sizeof(atr));
    const uint8_t answer[] = {0xff, 0x01, 0xfe}; /* accepts T=1 at Fd and Dd, as the request asked */
    hal_host_sc_reply(answer, sizeof(answer));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_OK, atr_read(&sc), PPS_FMAX[i].name);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(ERR_OK, pps_negotiate(&sc), PPS_FMAX[i].name);

    const uint32_t freq = hal_host_sc_pps_freq();
    TEST_ASSERT_TRUE_MESSAGE(freq > 0, PPS_FMAX[i].name);
    TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)PPS_FMAX[i].fmax_hz, (unsigned)freq,
                                           PPS_FMAX[i].name);
  }
}

/* A peripheral that will not take the parameters is the device failing, not the card: the caller has
 * to hear which of the two it is, since only one of them is worth retrying with another card. */
void test_a_peripheral_that_refuses_the_parameters_is_a_hardware_failure(void) {
  const pps_kat_t* v = &PPS_KAT[0];
  hal_host_sc_pps_refuse(true);
  feed(v);
  TEST_ASSERT_EQUAL_UINT16(ERR_HW, pps_negotiate(&sc));
}

/* Until a card is spoken to the shell runs at the reset parameters of 6.3.1 -- Fd = 372, Dd = 1 at
 * 4 MHz, so 93 us per etu by 7.1 -- and pps.c replaces that with what the ATR says. */
void test_the_etu_before_any_atr_is_the_reset_one(void) {
  TEST_ASSERT_EQUAL_UINT32(9300, sc.etu_10ns);
  TEST_ASSERT_EQUAL_UINT32((100000000UL / 4000000) * 372, sc.etu_10ns);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_pps_rows);
  RUN_TEST(test_no_clock_exceeds_the_frequency_the_card_allows);
  RUN_TEST(test_a_peripheral_that_refuses_the_parameters_is_a_hardware_failure);
  RUN_TEST(test_the_etu_before_any_atr_is_the_reset_one);

  return UNITY_END();
}
