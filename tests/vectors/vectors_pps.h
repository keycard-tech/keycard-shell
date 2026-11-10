#ifndef VECTORS_PPS_H
#define VECTORS_PPS_H

/* What ISO/IEC 7816-3:2006 requires of a reader once it has read an ATR: the protocol and parameter
 * selection of clause 9 and the rates, guard and waiting times that follow from clauses 7, 8, 10
 * and 11. One row is one ATR and one card answer, and the fields are what pps.c must hand to
 * hal_smartcard_pps and to smartcard_t, derived from the text by tests/vectors/generate.py.
 *
 * The derivation is in pps_vectors() above; the short version is that Table 7 of 8.3 pairs Fi with
 * f(max) in the upper nibble of TA1 and Table 8 puts Di in the lower one, so the two are read from
 * different nibbles; that the clock fed to CLK is whatever the device can produce under f(max) --
 * kernel / (2 * Prescaler) here -- and that everything else is arithmetic on 7.1's etu, 8.3's guard
 * with its R taken from F/D or from Fi/Di depending on whether T=15 is in the ATR, 10.2's waiting
 * time, and 11.4.3's CWT and BWT, both of which carry an 11 etu term. Clause 9 is structural: the
 * request is always sent, PPS1 only when there is something to propose and only with bit 5 of PPS0
 * set, and a card may answer shorter than it was asked, in which case Fd and Dd are in force.
 */

#include "error.h"
#include "iso7816/smartcard.h"

typedef struct {
  const char* name;
  const char* atr_hex;
  const char* pps_answer_hex; /* NULL when the card never answers */
  app_err_t result;
  uint8_t pps_called;
  const char* pps_request_hex;
  uint8_t protocol;
  uint32_t freq;
  uint32_t baud;
  uint32_t etu_10ns;
  uint8_t guard;
  uint32_t t1_cwt;
  uint32_t t1_bwt;
  uint32_t t0_timeout;
  uint8_t t1_bwt_factor;
} pps_kat_t;

/* Table 7 of 8.3, as a bound a test can check the device's own frequency table against. */
typedef struct {
  uint8_t code;
  uint32_t fmax_hz;
  const char* name;
} pps_fmax_t;

static const pps_fmax_t PPS_FMAX[] = {
    { 0x0, 4000000, "TA1 0x" },
    { 0x1, 5000000, "TA1 1x" },
    { 0x2, 6000000, "TA1 2x" },
    { 0x3, 8000000, "TA1 3x" },
    { 0x4, 12000000, "TA1 4x" },
    { 0x5, 16000000, "TA1 5x" },
    { 0x6, 20000000, "TA1 6x" },
    { 0x9, 5000000, "TA1 9x" },
    { 0xA, 7500000, "TA1 Ax" },
    { 0xB, 10000000, "TA1 Bx" },
    { 0xC, 15000000, "TA1 Cx" },
    { 0xD, 20000000, "TA1 Dx" },
};

#define PPS_FMAX_COUNT (sizeof(PPS_FMAX) / sizeof(PPS_FMAX[0]))

static const pps_kat_t PPS_KAT[] = {
    /* Card ATR 3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 10 0A. Fi = 372 comes from the upper nibble of
     * TA1 and Di = 12 from the lower, so the proposal carries them, the bit rate is twelve per etu,
     * and N = 255 asks for no extra guard */
    {
        "comsign eid", "3BD518FF8191FE1FC38073C821100A", "FF1118F6", ERR_OK, 1,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 8203, 184331, 0, 1,
    },
    /* Card ATR 3B FA 13 00 FF 91 01 31 FE 00 00 31 C1 73 C8 40 00 00 90 00 D2. TB3 = 00: CWI = 0 is
     * legal, 11.4.3 says so, and puts CWT at its minimum of 12 etu -- one etu above the eleven this
     * reader's character spans -- while BWI = 0 puts BWT at 960 Fd/f plus the 11 etu. The card that
     * lights only the backlight */
    {
        "cryptnox fido2", "3BFA1300FF910131FE000031C173C84000009000D2", NULL, ERR_OK, 1,
        "", 1, 5000000, 53763, 1860,
        0, 12, 3851, 0, 1,
    },
    /* Card ATR 3B F0 11 00 FF 91 00 01 8E. 6.3.1 applies the specific values at once, so T=0 is
     * programmed with 10.2's waiting time and no request goes out */
    {
        "specific t0", "3BF01100FF9100018E", NULL, ERR_OK, 1,
        "", 0, 5000000, 13440, 7440,
        1, 0, 0, 9600, 1,
    },
    /* Card ATR 3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 10 0A. 9.3: an answer with bit 5 clear is a
     * successful exchange, and Fd = 372 with Dn = 1 are then in force even though TA1 indicated 372
     * over 12 -- the etu grows twelvefold, and so does CWT */
    {
        "comsign declined", "3BD518FF8191FE1FC38073C821100A", "FF01FE", ERR_OK, 1,
        "FF1118F6", 1, 5000000, 13440, 7440,
        0, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B EB 00 00 81 31 FE 45 00 31 C1 73 C8 40 00 00 90 00 7A 01. no TA1 at all, so Fi =
     * 372 and Di = 1 by default and there is nothing to propose in PPS1, yet 9.1 still requires the
     * request: PPS0's type nibble is how the card is told to run T=1 */
    {
        "jcop 2.4.1r3", "3BEB00008131FE450031C173C840000090007A01", "FF01FE", ERR_OK, 1,
        "FF01FE", 1, 5000000, 13440, 7440,
        1, 43, 15371, 0, 1,
    },
    /* Card ATR 3B 90 17 81 11 FE E9. Table 8 gives Di = 64 for bits 4 to 1 equal to 0111, a valid
     * value the reader may not refuse */
    {
        "di 64", "3B90178111FEE9", "FF1117F9", ERR_OK, 1,
        "FF1117F9", 1, 5000000, 860215, 116,
        1, 8203, 983051, 0, 1,
    },
    /* Card ATR 3B 90 71 81 11 FE 8F. Table 7 leaves bits 8 to 5 = 0111 without an Fi, so there is no
     * rate to run and no exchange to start */
    {
        "fi rfu", "3B90718111FE8F", NULL, ERR_DATA, 0,
        "", 1, 0, 0, 9300,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 77 91 11 11 FE 88. TA2 = 11 has bit 5 set, so 8.3 takes the implicit Fd and Dd,
     * and the RFU nibble of TA1 is none of the reader's business because nothing reads it */
    {
        "ta2 implicit", "3B9077911111FE88", NULL, ERR_OK, 1,
        "", 1, 5000000, 13440, 7440,
        1, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B 90 95 91 01 11 FE 7A. TA2 = 01 leaves bit 5 clear, so the Fi = 512 and Di = 1 of
     * TA1 apply and are what gets proposed */
    {
        "ta2 indicated", "3B9095910111FE7A", NULL, ERR_OK, 1,
        "", 1, 5000000, 156250, 640,
        1, 8203, 178571, 0, 1,
    },
    /* Card ATR 3B 90 11 81 21 00 21. 11.4.3 with CWI = 0 gives CWT = 11 + 1 = 12 etu, the minimum
     * the text states */
    {
        "cwt zero", "3B901181210021", "FF01FE", ERR_OK, 1,
        "FF01FE", 1, 5000000, 13440, 7440,
        1, 12, 971, 0, 1,
    },
    /* Card ATR 3B 90 11 81 21 45 64. CWI = 5 and BWI = 4: CWT = 11 + 32 etu and BWT = 11 + 16 * 960
     * etu at Fd and Dd */
    {
        "cwt five", "3B901181214564", "FF01FE", ERR_OK, 1,
        "FF01FE", 1, 5000000, 13440, 7440,
        1, 43, 15371, 0, 1,
    },
    /* Card ATR 3B 90 18 81 21 90 B8. BWI = 9 is the largest 11.4.3 defines, and Fd over f grows with
     * Di = 12 */
    {
        "bwt nine", "3B9018812190B8", "FF1118F6", ERR_OK, 1,
        "FF1118F6", 1, 5000000, 161290, 620,
        1, 12, 5898251, 0, 1,
    },
    /* Card ATR 3B D0 11 03 81 11 20 72. N = 3 with no T=15 in the ATR, so R = F / D and the extra
     * guard comes out as exactly N etu */
    {
        "guard n three", "3BD0110381112072", "FF01FE", ERR_OK, 1,
        "FF01FE", 1, 5000000, 13440, 7440,
        4, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B D0 91 03 81 91 20 1F 03 6E. with T=15 present 8.3 takes R from Fi / Di instead of
     * from what is in force, which does not divide: 512 * 3 over 372 is 4.13 etu and the card must
     * not be shortchanged, so 5 */
    {
        "guard n three t15", "3BD091038191201F036E", "FF01FE", ERR_OK, 1,
        "FF11917F", 1, 5000000, 13440, 7440,
        6, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B D0 D1 FE 81 91 20 1F 03 D3. Fi = 2048 over the Fd = 372 that is in force would ask
     * for 1400 etu of guard and the peripheral holds 255: the card wanted more than the reader can
     * give, so it gets the maximum, no error */
    {
        "guard clamped", "3BD0D1FE8191201F03D3", "FF01FE", ERR_OK, 1,
        "FF11D13F", 1, 20000000, 53763, 1860,
        255, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B D0 11 FF 81 11 20 8E. 8.3 defers N = 255 to the protocol and 11.2 answers 11 etu,
     * which the character frame spans by itself: no extra guard either way */
    {
        "n 255", "3BD011FF8111208E", "FF01FE", ERR_OK, 1,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 8203, 15371, 0, 1,
    },
    /* Card ATR 3B 90 26 81 11 FE D8. Fi = 558 with Di = 32: the etu is 558 over 32 times f, so
     * dividing F by D before multiplying by the clock loses a sixth of it */
    {
        "etu not divisible", "3B90268111FED8", "FF1126C8", ERR_OK, 1,
        "FF1126C8", 1, 5882352, 337339, 296,
        1, 8203, 327691, 0, 1,
    },
    /* Card ATR 3B 90 11 81 11 20 31. 9.3: bits 4 to 1 of the answer shall be identical to those of
     * the request */
    {
        "answer wrong type", "3B901181112031", "FF00FF", ERR_DATA, 0,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 11 81 11 20 31. 9.2: exclusive-oring PPSS to PCK inclusive shall give 00, and
     * 9.1 hands a device whose answer does not check to a deactivation */
    {
        "answer bad pck", "3B901181112031", "FF0101", ERR_DATA, 0,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 11 81 11 20 31. 9.3 lets bit 6 of the answer be what the request made it or 0,
     * and the request made it 0, so a card offering the SPU of 5.2.4 here is answering a different
     * request from the one it got */
    {
        "answer asks spu", "3B901181112031", "FF21DE", ERR_DATA, 0,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 11 81 11 20 31. 9.1: a card that stays silent after a correct request leaves
     * the reader to wait out WT and stop */
    {
        "no answer", "3B901181112031", NULL, ERR_TXRX, 0,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 18 81 11 20 38. the answer promises a PPS1 and then stops: two bytes are not an
     * exchange, and 9.1 leaves the reader with a waiting time rather than with what it half heard */
    {
        "answer truncated", "3B901881112038", "FF11", ERR_TXRX, 0,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 18 81 11 20 38. 9.2 puts PCK last, so an answer that ends before it says
     * nothing whatever it carried */
    {
        "answer without pck", "3B901881112038", "FF1118", ERR_TXRX, 0,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 11 81 11 20 31. the request asked for no PPS1, so 9.3 lets bit 5 of the answer
     * read only 0: a card that insists on proposing rates to a reader that did not ask is not
     * answering this request */
    {
        "answer unasked pps1", "3B901181112031", "FF1118F6", ERR_DATA, 0,
        "FF01FE", 1, 5000000, 13440, 7440,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 18 81 11 20 38. one byte is not the start of an answer either: 9.1 gives the
     * reader a waiting time and a deactivation, and nothing here reads meaning into a PPSS on its
     * own */
    {
        "answer one byte", "3B901881112038", "FF", ERR_TXRX, 0,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 18 81 11 20 38. 9.3: with bit 5 clear PPS1 of the answer shall be absent, so
     * the three bytes that do check are the whole answer and whatever followed it is not part of
     * this exchange */
    {
        "decline with a fourth byte", "3B901881112038", "FF01FE00", ERR_TXRX, 0,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 90 18 81 11 20 38. 9.3: PPS1 of the answer shall be identical to the request's, so
     * a card that agrees to T=1 while putting other integers in their place is refused rather than
     * run at a rate neither asked for */
    {
        "answer other rates", "3B901881112038", "FF1112ED", ERR_DATA, 0,
        "FF1118F6", 1, 5000000, 161290, 620,
        0, 0, 0, 0, 1,
    },
    /* Card ATR 3B 69 00 02 41 43 4F 53 4A 76 31 30 31. no TD anywhere, so the only offer is T=0,
     * which the shell refuses at the APDU layer; 10.2 still gives the waiting time to program, and N
     * = 2 the guard */
    {
        "t0 card", "3B69000241434F534A76313031", NULL, ERR_OK, 1,
        "", 0, 5000000, 13440, 7440,
        3, 0, 0, 9600, 1,
    },
};

#define PPS_KAT_COUNT (sizeof(PPS_KAT) / sizeof(PPS_KAT[0]))

#endif
