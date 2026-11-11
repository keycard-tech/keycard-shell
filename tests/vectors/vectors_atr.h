#ifndef VECTORS_ATR_H
#define VECTORS_ATR_H

/* What ISO/IEC 7816-3:2006 requires of a reader facing an ATR, row by row. Each row is one ATR --
 * captured from a real card, from pcsc-tools' smartcard_list.txt or from the cards at hand, or built
 * from the standard's own tables for a shape those collections do not contain -- and the fields are
 * the
 * answer in iso7816/atr.c's terms, derived from the text by tests/vectors/generate.py rather than
 * from that file.
 *
 * The clauses:
 *  - 8.2.3 structure. T0 conveys Y1 and K; each TD conveys which of TA, TB, TC, TD follow it and the
 *    type T that qualifies those bytes; an absent TD means the whole group after it is absent. TA1,
 *    TB1, TC1, TA2 and TB2 are global and TC2 is specific to T=0, so from the third group on the
 *    bytes mean what the preceding TD's T says they mean, and the k-th triple for a type follows the
 *    k-th occurrence of that type. T=0 first if offered, T=15 last and invalid in TD1.
 *  - 8.2.5 check byte. Absent if only T=0 is indicated, possibly by default; present otherwise.
 *    Exclusive-oring T0 to TCK inclusive gives 00, TS excluded.
 *  - 8.3 global bytes. TA1 is Fi, Di and f(max), default Fi = 372, Di = 1; TB1 and TB2 are
 *    deprecated and the reader shall ignore them; TC1 is N, default 0; TA2 is the specific mode byte
 *    and says nothing about IFSC. The first TA for T=15 is the clock stop indicator X in bits 8-7 and
 *    the classes in bits 6-1, default clock stop not supported and class A only.
 *  - 10.2 T=0. TC2 is WI over eight bits except 00, default 10, and WT = WI * 960 * Fi / f.
 *  - 11.4.2 to 11.4.4 T=1. The first TA for T=1 is IFSC, 01..FE encoding 1..254 with 00 and FF
 *    reserved, default 32. The first TB for T=1 is BWI in bits 8-5 (0..9, default 4) and CWI in bits
 *    4-1 (default 13). Bit 1 of the first TC for T=1 selects CRC, and clear selects LRC, which is
 *    also the default when the byte is absent.
 *
 * Two things the standard does not let this reader enforce, and the suite therefore does not claim.
 * The types in TD1, TD2 and so on "shall be in ascending numerical order", yet 1014 of the 2678
 * check-byte-valid ATRs in that collection repeat the first type, which is exactly how the clause
 * 8.2.3 note places the first T=1 triple after a TD2 indicating T=1 for a card that offers no T=0;
 * order is only checked where the text names a case invalid. And 11.4.2 reserves IFSC values 00 and
 * FF without saying what a reader does about them; 4 of those 2678 ATRs use one, so no row here asks
 * for a verdict.
 */

typedef struct {
  const char* name;
  const char* atr_hex;
  app_err_t result;
  uint8_t tck;
  uint8_t fi_di;
  uint8_t n;
  uint8_t ta2;
  uint8_t t0_wi;
  uint8_t default_protocol;
  uint8_t protocols;
  uint8_t t1_ifsc;
  uint8_t t1_bwi;
  uint8_t t1_cwi;
  uint8_t t1_rc;
  uint8_t t15_present;
  uint8_t classes;
  uint8_t clockstop;
  size_t hist_len;
  const char* hist_hex;
} atr_kat_t;

static const atr_kat_t ATR_KAT[] = {
    /* Card: timing only. T=0 offered first; TD2 then offers T=1, whose first triple is a lone TA =
     * IFSC 254 */
    {
        "timing only", "3B90958011FE6A", ERR_OK, 1,
        0x95, 0x00, 0xFF, 10, 0, 3,
        0xFE, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Card: staros s21. STARCOS S21 C: T=0 then T=1 with IFSC 112 and BWI 3 CWI 5, 15 historical
     * bytes */
    {
        "staros s21", "3BBF18008031703553544152434F5320533231204390009B", ERR_OK, 1,
        0x18, 0x00, 0xFF, 10, 0, 3,
        0x70, 3, 5, 0, 0, 0x01, 0x00,
        15, "53544152434f532053323120439000",
    },
    /* Card: three protocols. T=0, then T=1, then T=15, whose first TA is classes A+B+C with clock
     * stop both states */
    {
        "three protocols", "3B9F97C00AB1FE453FC6828031E073FE211B65D0023A14C9810F8B", ERR_OK, 1,
        0x97, 0x00, 0xFF, 10, 0, 3,
        0xFE, 4, 5, 0, 1, 0x06, 0xC0,
        15, "8031e073fe211b65d0023a14c9810f",
    },
    /* Card: second group TC. TC2 = FF is T=0's WI; the T=1 triple is split across TA3 (IFSC) and TB3
     * (BWI 3 CWI 5) */
    {
        "second group TC", "3B9711C0FFB1FE351F83A505010102A3015F", ERR_OK, 1,
        0x11, 0x00, 0xFF, 255, 0, 3,
        0xFE, 3, 5, 0, 1, 0x03, 0x80,
        7, "a505010102a301",
    },
    /* Card: t1 tb only. the T=1 triple offers only TB, so IFSC keeps its default while CWI 3 and BWI
     * 6 are read */
    {
        "t1 tb only", "3B85C0FA216380630101051B", ERR_OK, 1,
        0x11, 0x00, 0xFF, 250, 0, 3,
        0x20, 6, 3, 0, 0, 0x01, 0x00,
        5, "8063010105",
    },
    /* Card: t0 only. nothing offered but T=0, so 8.2.5 says there is no check byte and the last byte
     * is historical */
    {
        "t0 only", "3B151112CA0700DB", ERR_OK, 0,
        0x11, 0x00, 0xFF, 10, 0, 1,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        5, "12ca0700db",
    },
    /* Card: t1 no interface. TD1 = 01 offers T=1 and nothing else: no interface byte at all, check
     * byte still required */
    {
        "t1 no interface", "3B800181", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 1, 2,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Card: sse piv. TD1 offers T=1, TD2 = 01 repeats it with no bytes; the T=1 triple never arrives */
    {
        "sse piv", "3B9C958101505343502D53435356312E308E", ERR_OK, 1,
        0x95, 0x00, 0xFF, 10, 1, 2,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        12, "505343502d53435356312e30",
    },
    /* Card: didem v1.7. Didem Card V1.7: TD1 offers T=1 and TA2, which 8.3 makes the global specific
     * mode byte, not IFSC */
    {
        "didem v1.7", "3B97181181444944454D010758", ERR_OK, 1,
        0x18, 0x00, 0x81, 10, 1, 2,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        7, "444944454d0107",
    },
    /* Card: t15 in td1. the one card in that list that puts T=15 in TD1, which 8.2.3 declares
     * invalid */
    {
        "t15 in td1", "3B811F00CC52", ERR_DATA, 1,
        0x11, 0x00, 0x00, 10, 0, 0,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        1, "cc",
    },
    /* Synthetic: t1 crc. 8.2.3 puts the first T=1 triple after a TD2 indicating T=1: IFSC 129, BWI 5
     * CWI 9, and bit 1 of the first TC asks for CRC per 11.4.4 */
    {
        "t1 crc", "3B808171815901A9", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 1, 2,
        0x81, 5, 9, 1, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: t1 lrc. the same triple with bit 1 of the first TC clear, which 11.4.4 makes LRC --
     * the default when that byte is absent anyway */
    {
        "t1 lrc", "3B808171815900A8", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 1, 2,
        0x81, 5, 9, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: t1 first triple wins. two triples qualified for T=1: 8.2.3 numbers them by
     * occurrence and 11.4.1 lets only the first set IFSC, BWI and CWI, so IFSC is 33 and not 98 */
    {
        "t1 first triple wins", "3B8081B12144316266E0", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 1, 2,
        0x21, 4, 4, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: t0 and t15. T=0 then T=15, whose first TA is classes A+B+C with clock stop
     * preferred in state L. 8.2.3 says T=15 is not a protocol, so T=1 stays unoffered -- yet 8.2.5
     * still requires the check byte */
    {
        "t0 and t15", "3B80801F4758", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 0, 1,
        0x20, 4, 13, 0, 1, 0x07, 0x40,
        0, "",
    },
    /* Card: no interface byte. T0 sets no Y1 bit and offers no TD, so 8.2.3 leaves only T=0 by
     * default: 8.3 and 10.2 give every parameter and 8.2.5 wants no check byte. 93 of the list's
     * ATRs are shaped like this */
    {
        "no interface byte", "3B02141C", ERR_OK, 0,
        0x11, 0x00, 0xFF, 10, 0, 1,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        2, "141c",
    },
    /* Card: comsign eid. TD1 offers T=1 and TD2 repeats it with a lone TA3 = IFSC 254, so 11.4.3 and
     * 11.4.4 leave BWI at 4, CWI at 13 and the code at LRC; TD3 then brings T=15 last, classes A+C */
    {
        "comsign eid", "3BD518FF8191FE1FC38073C821100A", ERR_OK, 1,
        0x18, 0xFF, 0xFF, 10, 1, 2,
        0xFE, 4, 13, 0, 1, 0x03, 0xC0,
        5, "8073c82110",
    },
    /* Card: renap guatemala. the chain of comsign eid with a TB3 added to TD2's third group, and
     * 11.4.3 takes BWI 4 and CWI 5 out of it: the only difference between the two rows is which byte
     * TD2 indicates */
    {
        "renap guatemala", "3BD518FF81B1FE451FC38073C821106F", ERR_OK, 1,
        0x18, 0xFF, 0xFF, 10, 1, 2,
        0xFE, 4, 5, 0, 1, 0x03, 0xC0,
        5, "8073c82110",
    },
    /* Card: jcop3 p60. JCOP3 SecID P60: comsign eid's chain with 12 historical bytes, which 8.2.5
     * folds into the check byte like any other count */
    {
        "jcop3 p60", "3BDC18FF8191FE1FC38073C821136605036351000250", ERR_OK, 1,
        0x18, 0xFF, 0xFF, 10, 1, 2,
        0xFE, 4, 13, 0, 1, 0x03, 0xC0,
        12, "8073c8211366050363510002",
    },
    /* Card: jcop 2.4.1r3. Y1 sets TB1, TC1 and TD1 and no TA1, so 8.3 gives Fi = 372 and Di = 1 even
     * though a TB1 is there to be ignored, and TC1 = 00 is N = 0 rather than a missing byte */
    {
        "jcop 2.4.1r3", "3BEA00008131FE450031C173C840000090007A", ERR_OK, 1,
        0x11, 0x00, 0xFF, 10, 1, 2,
        0xFE, 4, 5, 0, 0, 0x01, 0x00,
        10, "0031c173c84000009000",
    },
    /* Card: cryptnox fido2. VPP not connected, TC1 = FF, T=1 offered by TD1 and again by TD2, whose
     * triple is IFSC 254 with TB3 = 00, asking for CWI 0 and BWI 0 */
    {
        "cryptnox fido2", "3BFA1300FF910131FE000031C173C84000009000D2", ERR_OK, 1,
        0x13, 0xFF, 0x01, 10, 1, 2,
        0xFE, 0, 0, 0, 0, 0x01, 0x00,
        10, "0031c173c84000009000",
    },
    /* Card: acosj 40k. TB1 and TC1 and no TD anywhere, so 8.2.3 leaves only T=0 by default and 8.2.5
     * wants no check byte: the ATR ends with the nine historical bytes spelling ACOSJv101 */
    {
        "acosj 40k", "3B69000241434F534A76313031", ERR_OK, 0,
        0x11, 0x02, 0xFF, 10, 0, 1,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        9, "41434f534a76313031",
    },
    /* Synthetic: t0 not first. TD1 offers T=1 and TD2 then offers T=0, which 8.2.3 forbids: if T=0
     * is present it shall be first */
    {
        "t0 not first", "3B80810001", ERR_DATA, 1,
        0x11, 0x00, 0xFF, 10, 1, 3,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: t15 not last. TD2 brings T=15 and TD3 repeats T=1 after it; 8.2.3 puts T=15 last,
     * so the offer is refused rather than handed to pps_negotiate as a protocol of 15 */
    {
        "t15 not last", "3B80809F11018F", ERR_DATA, 1,
        0x11, 0x00, 0xFF, 10, 0, 3,
        0x20, 4, 13, 0, 1, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: t0 offered, no t15. TD1 offers T=0 and TC2 = 0B is its WI. With no T=15, 8.3 gives
     * class A and clock stop not supported; with nothing but T=0 indicated, 8.2.5 gives no check
     * byte */
    {
        "t0 offered, no t15", "3B80400B", ERR_OK, 0,
        0x11, 0x00, 0xFF, 11, 0, 1,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: specific t0. TD1 offers T=1, but TA2 = 00 is specific mode with type 0, so 6.3.1
     * runs T=0 and bit 5 clear keeps TA1's Fi = 372 and Di = 1 */
    {
        "specific t0", "3BF01100FF9100018E", ERR_OK, 1,
        0x11, 0xFF, 0x00, 10, 0, 2,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
    /* Synthetic: specific unsupported type. 8.3's NOTE: a type the interface device cannot run is a
     * warm reset or a deactivation, so TA2 = 8F of specific mode and type 15 is refused */
    {
        "specific unsupported type", "3BF01100FF918F0101", ERR_DATA, 1,
        0x11, 0xFF, 0x8F, 10, 1, 2,
        0x20, 4, 13, 0, 0, 0x01, 0x00,
        0, "",
    },
};

#define ATR_KAT_COUNT (sizeof(ATR_KAT) / sizeof(ATR_KAT[0]))

#endif
