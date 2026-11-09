#include <stdint.h>
#include <string.h>

#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "iso7816/atr.h"
#include "iso7816/smartcard.h"
#include "sc_host.h"
#include "unity.h"
#include "vectors/vectors_atr.h"

/*
 * atr.c is the first thing that speaks to a card and the only thing that decides what everything
 * else will mean: pps.c takes Fi/Di and N from the parsed ATR to work out the bit rate it proposes
 * and the guard it asks for, t1.c takes IFSC to size a block and CWI/BWI to time one, and
 * default_protocol decides whether the shell talks T=1 at all -- a T=0 answer is ERR_UNSUPPORTED.
 *
 * The rows are therefore asserted as what ISO/IEC 7816-3 requires, not as what this module has
 * historically produced: see the header of vectors_atr.h for the clauses and for where the rows come
 * from. Two of the properties that header lists are worth naming here because they are the ones a
 * reader would otherwise assume the module gets for free. The check byte exists unless the ATR
 * indicates nothing but T=0 (8.2.5), and it must be taken off the wire when it does exist -- the
 * next read is the PPS answer, and a byte nobody consumed offsets it by one. And the type in a TD
 * decides what the bytes after it mean (8.2.3), so a card that offers T=1 from TD1 does not get an
 * IFSC from TA2, which 8.3 reserves for the specific mode byte.
 */

static smartcard_t sc;

void setUp(void) {
  hal_host_sc_reset();
  smartcard_init(&sc);
}

void tearDown(void) {}

static size_t unhex_atr(const atr_kat_t* v, uint8_t* out, size_t max) {
  const size_t len = test_unhex(v->atr_hex, out, max);
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)max, (unsigned)len, v->name);
  return len;
}

static void assert_fields(const atr_kat_t* v) {
  const atr_t* a = &sc.atr;

  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->fi_di, a->fi_di, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->n, a->n, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->ta2, a->ta2, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t0_wi, a->t0_wi, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->default_protocol, a->default_protocol, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->protocols, a->protocols, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t1_ifsc, a->t1_ifsc, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t1_bwi, a->t1_bwi, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t1_cwi, a->t1_cwi, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t1_rc, a->t1_rc, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->t15_present, a->t15_present, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->classes, a->classes, v->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->clockstop, a->clockstop, v->name);
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)v->hist_len, (unsigned)a->hist_len, v->name);
  if (v->hist_len == 0) {
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", v->hist_hex, v->name);
  } else {
    TEST_ASSERT_HEX_MESSAGE(a->hist, a->hist_len, v->hist_hex, v->name);
  }
}

/* ATRs captured from real cards, and the synthetic ones built from the standard's tables, read as
 * the standard says they must be read -- and every byte the card sent consumed, because the PPS
 * exchange reads next. */
static void test_atrs_are_read_as_the_standard_reads_them(void) {
  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if (v->result != ERR_OK) {
      continue;
    }

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    hal_host_sc_reset();
    hal_host_sc_reply(bytes, len);

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->result, atr_read(&sc), v->name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, sc.atr.valid, v->name);
    assert_fields(v);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, (unsigned)hal_host_sc_unread(), v->name);
  }
}

/* 8.2.3 names cases invalid: T=15 in TD1, T=0 not first, T=15 not last. Feeding one of those on
 * would otherwise hand a protocol of 15 to pps_negotiate. */
static void test_atrs_the_standard_declares_invalid(void) {
  int rows = 0;

  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if (v->result == ERR_OK) {
      continue;
    }
    rows++;

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    hal_host_sc_reset();
    hal_host_sc_reply(bytes, len);

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->result, atr_read(&sc), v->name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, sc.atr.valid, v->name);
  }

  TEST_ASSERT_TRUE(rows > 0);
}

/* The check byte covers T0 through the historical bytes, so a card one bit off is a card this shell
 * refuses rather than one it talks to at a rate it misread. The parse itself is kept -- valid is the
 * only thing gating it -- so the fields are checked after the refusal too. */
static void test_a_card_that_does_not_check_out(void) {
  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if (!v->tck || (v->result != ERR_OK)) {
      continue;
    }

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    for (size_t bit = 0; bit < 8; bit++) {
      hal_host_sc_reset();

      bytes[len - 1] ^= (uint8_t)(1u << bit);
      hal_host_sc_reply(bytes, len);
      bytes[len - 1] ^= (uint8_t)(1u << bit);

      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, atr_read(&sc), v->name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, sc.atr.valid, v->name);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(0, (unsigned)hal_host_sc_unread(), v->name);
    }
  }
}

/* A bit flipped anywhere in the historical bytes has to show up at the check byte too: 8.2.5 covers
 * T0 through the end of the historical characters, so a corrupt answer is refused and not parsed. */
static void test_a_corrupted_historical_byte_is_caught(void) {
  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if ((v->hist_len == 0) || !v->tck || (v->result != ERR_OK)) {
      continue;
    }

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    for (size_t off = len - v->hist_len - 1; off < len - 1; off++) {
      hal_host_sc_reset();

      bytes[off] ^= 0x01;
      hal_host_sc_reply(bytes, len);
      bytes[off] ^= 0x01;

      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, atr_read(&sc), v->name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, sc.atr.valid, v->name);
    }
  }
}

/* A card pulled halfway through its answer, or one that stops early: every cut has to be a
 * transport error and not a truncated read the caller cannot tell from a complete one. */
static void test_a_card_that_stops_talking(void) {
  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if (v->result != ERR_OK) {
      continue;
    }

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    for (size_t cut = 0; cut < len; cut++) {
      hal_host_sc_reset();
      hal_host_sc_reply(bytes, cut);

      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_TXRX, atr_read(&sc), v->name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, sc.atr.valid, v->name);
      /* nothing pending in the peripheral: a short read is noticed by the receiver itself, so the
       * next card is not started with a transfer still in flight */
      TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_sc_aborts(), v->name);
    }
  }
}

/* A check byte is read when 8.2.5 says it is there and not when it is not, which is the difference
 * between an ATR that ends where the module stops and one that leaves a byte for the PPS answer to
 * trip over. One byte more than the standard allows the card to send is what tells the two apart from
 * the reader's side: a module that reads a check byte that does not exist swallows it, and one that
 * skips a check byte that does leaves two. */
static void test_only_the_bytes_that_exist_are_read(void) {
  const uint8_t surplus = 0x00;

  for (size_t i = 0; i < ATR_KAT_COUNT; i++) {
    const atr_kat_t* v = &ATR_KAT[i];

    if (v->result != ERR_OK) {
      continue;
    }

    uint8_t bytes[64];
    const size_t len = unhex_atr(v, bytes, sizeof(bytes));

    hal_host_sc_reset();
    hal_host_sc_reply(bytes, len);
    hal_host_sc_reply(&surplus, 1);

    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, atr_read(&sc), v->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, (unsigned)hal_host_sc_unread(), v->name);
  }
}

/* The peripheral reports completion through a task notification. If that never arrives the read is
 * abandoned with the transfer aborted, or the next smartcard user would be waiting on this card's
 * bytes. */
static void test_a_transfer_that_never_completes(void) {
  const atr_kat_t* v = &ATR_KAT[0]; /* any complete ATR */

  uint8_t bytes[64];
  const size_t len = unhex_atr(v, bytes, sizeof(bytes));
  hal_host_sc_reply(bytes, len);
  hal_host_sc_fail_notify_after(0);

  TEST_ASSERT_EQUAL_INT(ERR_TXRX, atr_read(&sc));
  TEST_ASSERT_EQUAL_UINT8(0, sc.atr.valid);
  TEST_ASSERT_EQUAL_UINT(1, hal_host_sc_aborts());

  /* The same for a completion that reports failure: an error the peripheral saw is not taken for the
   * byte it did not deliver. */
  hal_host_sc_reset();
  hal_host_sc_reply(bytes, len);
  hal_host_sc_notify_value(HAL_FAIL);

  TEST_ASSERT_EQUAL_INT(ERR_TXRX, atr_read(&sc));
  TEST_ASSERT_EQUAL_UINT8(0, sc.atr.valid);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_aborts());
}

/* Only the direct convention is driven: TS = 0x3F means the card is inverted relative to how the
 * peripheral is clocking, and the bytes that follow would be read as a complement nobody asked for. */
static void test_an_inverted_card_is_refused(void) {
  const atr_kat_t* v = &ATR_KAT[0]; /* any ATR longer than the TS and T0 that are read */

  uint8_t bytes[64];
  const size_t len = unhex_atr(v, bytes, sizeof(bytes));
  bytes[0] = 0x3f;
  hal_host_sc_reply(bytes, len);

  TEST_ASSERT_EQUAL_INT(ERR_DATA, atr_read(&sc));
  TEST_ASSERT_EQUAL_UINT8(0, sc.atr.valid);
  /* TS and T0 and nothing more: reading on would fill a picture of a card already rejected */
  TEST_ASSERT_EQUAL_UINT((unsigned)(len - 2), (unsigned)hal_host_sc_unread());
}

/* atr_read starts from a clean sheet, so a card that answers nothing cannot leave the previous
 * card's timing, protocol or buffer size behind as if they had just been negotiated. */
static void test_a_failed_read_claims_nothing(void) {
  memset(&sc.atr, 0xaa, sizeof(sc.atr));
  hal_host_sc_fail_read_after(0);

  TEST_ASSERT_EQUAL_INT(ERR_TXRX, atr_read(&sc));

  const atr_t* a = &sc.atr;
  TEST_ASSERT_EQUAL_UINT8(0, a->valid);
  TEST_ASSERT_EQUAL_UINT8(0, a->t15_present);
  TEST_ASSERT_EQUAL_UINT8(SC_T0, a->default_protocol);
  TEST_ASSERT_EQUAL_UINT8(ATR_PROTOCOLS_T0, a->protocols);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_FIDI, a->fi_di);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_N, a->n);
  TEST_ASSERT_EQUAL_UINT8(ATR_INVALID_TA2, a->ta2);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_T0_WI, a->t0_wi);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_T1_IFSC, a->t1_ifsc);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_T1_CWI, a->t1_cwi);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_T1_BWI, a->t1_bwi);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_T1_RC, a->t1_rc);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_CLASSES, a->classes);
  TEST_ASSERT_EQUAL_UINT8(ATR_DEFAULT_CLOCKSTOP, a->clockstop);
  TEST_ASSERT_EQUAL_UINT8(0, a->hist_len);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_atrs_are_read_as_the_standard_reads_them);
  RUN_TEST(test_atrs_the_standard_declares_invalid);
  RUN_TEST(test_a_card_that_does_not_check_out);
  RUN_TEST(test_a_corrupted_historical_byte_is_caught);
  RUN_TEST(test_a_card_that_stops_talking);
  RUN_TEST(test_only_the_bytes_that_exist_are_read);
  RUN_TEST(test_a_transfer_that_never_completes);
  RUN_TEST(test_an_inverted_card_is_refused);
  RUN_TEST(test_a_failed_read_claims_nothing);

  return UNITY_END();
}
