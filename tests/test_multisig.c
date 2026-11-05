/* Multisig setup files: what arrives from a QR scan, what goes to the store, and what goes back out
 * as a QR. The accepted files are the one printed on COLDCARD's format page and the exports
 * Sparrow keeps as its own parser's fixtures, so the meaning of each is somebody else's answer.
 *
 * multisig_derive_address is not here. It is the only function of the module that reaches silicon
 * (bip32_ckd_pub -> hal_ec_double_ladder), so every path through it ends in an aborting stub on a
 * host, including the paths that would merely fail. It belongs to the device-differential work. */
#include <stdlib.h>
#include <string.h>

#include "bitcoin/multisig.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_multisig.h"

/* Lowercase hex, the way the vectors spell fingerprints and xpubs. */
static void to_hex(const uint8_t* data, size_t len, char* out, size_t cap) {
  static const char digits[] = "0123456789abcdef";
  size_t off = 0;
  for (size_t i = 0; i < len && off + 2 < cap; i++) {
    out[off++] = digits[data[i] >> 4];
    out[off++] = digits[data[i] & 0x0f];
  }
  out[off] = '\0';
}

static multisig_t parsed;
static multisig_t revived;
static uint8_t blob[4096];
static char text[4096];

void setUp(void) {
  memset(&parsed, 0xA5, sizeof(parsed));
  memset(&revived, 0xA5, sizeof(revived));
  memset(blob, 0, sizeof(blob));
  memset(text, 0, sizeof(text));
}

void tearDown(void) {}

/* The descriptor a row says it holds, field by field. */
static void assert_descriptor(const multisig_t* d, const multisig_case_t* row) {
  TEST_ASSERT_EQUAL_STRING_MESSAGE(row->name, d->name, row->label);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->m, d->m, row->label);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->n, d->n, row->label);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->format, d->format, row->label);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->key_count, d->key_count, row->label);

  char hex[3 * MULTISIG_XPUB_LEN + 1];
  for (uint8_t i = 0; i < row->key_count; i++) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->path_len[i], d->keys[i].path_len, row->label);
    if (row->path_len[i] > 0) {
      TEST_ASSERT_EQUAL_UINT32_ARRAY_MESSAGE(row->path[i], d->keys[i].path, row->path_len[i],
                                             row->label);
    }
    /* The fingerprint is stored in the order the file spells it, which is the order a master
     * fingerprint is written everywhere else too -- not little-endian like the path. */
    to_hex(d->keys[i].fingerprint, MULTISIG_FP_LEN, hex, sizeof(hex));
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(&row->fingerprints[i * 2 * MULTISIG_FP_LEN], hex,
                                         2 * MULTISIG_FP_LEN, row->label);
    to_hex(d->keys[i].xpub, MULTISIG_XPUB_LEN, hex, sizeof(hex));
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(&row->xpubs[i * 2 * MULTISIG_XPUB_LEN], hex,
                                         2 * MULTISIG_XPUB_LEN, row->label);
  }
}

static void test_parse(void) {
  for (size_t i = 0; i < MULTISIG_CASE_COUNT; i++) {
    const multisig_case_t* row = &MULTISIG_CASES[i];

    /* A scanned QR carries a length and no terminator, so neither is added here: a reader that
     * looked for a NUL would read past the camera buffer. */
    char* file = malloc(row->text_len);
    TEST_ASSERT_NOT_NULL(file);
    memcpy(file, row->text, row->text_len);

    const app_err_t err = multisig_parse_text(file, row->text_len, &parsed);
    free(file);

    TEST_ASSERT_EQUAL_INT_MESSAGE(row->err, err, row->label);
    if (err == ERR_OK) {
      assert_descriptor(&parsed, row);
    }
  }
}

static void test_serialize_roundtrip(void) {
  for (size_t i = 0; i < MULTISIG_CASE_COUNT; i++) {
    const multisig_case_t* row = &MULTISIG_CASES[i];
    if (row->err != ERR_OK) {
      continue;
    }
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_parse_text(row->text, row->text_len, &parsed));

    memset(blob, 0x5A, sizeof(blob));
    size_t len = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, multisig_serialize(&parsed, blob, sizeof(blob), &len),
                                  row->label);
    /* No byte beyond what it reported. */
    for (size_t off = len; off < len + 8; off++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x5A, blob[off], row->label);
    }

    if (row->serialized != NULL) {
      TEST_ASSERT_HEX_MESSAGE(blob, len, row->serialized, row->label);
    }

    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_deserialize(blob, len, &revived));
    TEST_ASSERT_EQUAL_INT(0, memcmp(&parsed, &revived, sizeof(parsed)));

    /* One octet short of what it needs is refused rather than truncated. */
    size_t written = 12345;
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_FULL, multisig_serialize(&parsed, blob, len - 1, &written),
                                  row->label);

    /* Every truncation of the storage form is refused: the lengths inside it are not a hint. */
    for (size_t cut = 0; cut < len; cut++) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, multisig_deserialize(blob, cut, &revived),
                                    row->label);
    }
  }
}

/* Fields the store format takes verbatim, checked against the bounds the struct can hold. */
static void test_deserialize_refuses_impossible_shapes(void) {
  const multisig_case_t* row = &MULTISIG_CASES[0];
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_parse_text(row->text, row->text_len, &parsed));
  size_t len = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_serialize(&parsed, blob, sizeof(blob), &len));

  TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_deserialize(blob, 4, &revived));

  /* name length beyond the field, key count beyond the array, path length beyond a path. */
  for (uint8_t value = MULTISIG_MAX_NAME_LEN; value < MULTISIG_MAX_NAME_LEN + 3; value++) {
    uint8_t poisoned[sizeof(blob)];
    memcpy(poisoned, blob, 5);
    poisoned[4] = value;
    memcpy(poisoned + 5, parsed.name, strlen(parsed.name));
    TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_deserialize(poisoned, len, &revived));
  }

  uint8_t poisoned[sizeof(blob)];
  memcpy(poisoned, blob, 5);
  poisoned[3] = MULTISIG_MAX_KEYS + 1;
  TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_deserialize(poisoned, 64, &revived));

  /* The first key's path length, which sits right after the name. */
  const size_t path_len_at = 5 + strlen(parsed.name);
  for (uint8_t value = MULTISIG_MAX_PATH_LEN + 1; value < MULTISIG_MAX_PATH_LEN + 4; value++) {
    memcpy(poisoned, blob, sizeof(poisoned));
    poisoned[path_len_at] = value;
    TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_deserialize(poisoned, len, &revived));
  }

  /* A format byte outside the three known ones is stored as it arrived: the module that would act
   * on it is the address derivation, which has a default case that refuses. */
  memcpy(poisoned, blob, sizeof(poisoned));
  poisoned[0] = 7;
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_deserialize(poisoned, len, &revived));
  TEST_ASSERT_EQUAL_UINT8(7, revived.format);
}

static void assert_same_descriptor(const multisig_t* a, const multisig_t* b, const char* label) {
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, memcmp(a, b, sizeof(*a)), label);
}

static void test_reexport(void) {
  for (size_t i = 0; i < MULTISIG_CASE_COUNT; i++) {
    const multisig_case_t* row = &MULTISIG_CASES[i];
    if (row->err != ERR_OK) {
      continue;
    }
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_parse_text(row->text, row->text_len, &parsed));
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_to_text(&parsed, text, sizeof(text)));

    if (row->reexport != NULL) {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(row->reexport, text, row->label);
    }

    /* Whatever it writes has to mean the same wallet again. This is the only check available on the
     * emitted form: it is our layout, not a published one, so it is the round trip that gives it
     * content rather than a comparison against a document. */
    multisig_t again;
    if (parsed.keys[0].path_len == 0) {
      /* A descriptor whose keys carry no path is accepted on the way in and written back out as
       * "Derivation: m", which this parser refuses: an exported wallet with no path cannot be
       * scanned back. The store keeps the bytes either way, so only the QR round trip is affected. */
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(text, "Derivation: m\n"), row->label);
      TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_parse_text(text, strlen(text), &again));
      continue;
    }
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_parse_text(text, strlen(text), &again));
    assert_same_descriptor(&parsed, &again, row->label);

    /* A buffer that cannot hold the whole thing must not be written past. The text is truncated --
     * to_text reports no error for it, so the caller's cap is the only bound, and the rows below
     * are where that becomes visible. */
    for (size_t cap = 1; cap < 64; cap++) {
      char tight[96];
      memset(tight, 0x5A, sizeof(tight));
      multisig_to_text(&parsed, tight, cap);
      for (size_t off = cap; off < sizeof(tight); off++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x5A, tight[off], row->label);
      }
    }
  }
}

static void test_has_fingerprint(void) {
  for (size_t i = 0; i < MULTISIG_CASE_COUNT; i++) {
    const multisig_case_t* row = &MULTISIG_CASES[i];
    if (row->err != ERR_OK) {
      continue;
    }
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_parse_text(row->text, row->text_len, &parsed));

    for (uint8_t key = 0; key < parsed.key_count; key++) {
      /* The argument is a number, and the stored form is the four octets in the order the file
       * wrote them: 3E 43 D1 6E is 0x3E43D16E, not its byte reversal. */
      uint32_t mfp = 0;
      for (uint8_t off = 0; off < MULTISIG_FP_LEN; off++) {
        mfp = (mfp << 8) | parsed.keys[key].fingerprint[off];
      }
      TEST_ASSERT_TRUE_MESSAGE(multisig_has_fingerprint(&parsed, mfp), row->label);
      /* The same octets read the other way round belong to a different device. */
      uint32_t swapped = ((mfp & 0xffu) << 24) | ((mfp & 0xff00u) << 8) | ((mfp & 0xff0000u) >> 8) |
                         ((mfp >> 24) & 0xffu);
      if (swapped != mfp) {
        TEST_ASSERT_FALSE_MESSAGE(multisig_has_fingerprint(&parsed, swapped), row->label);
      }
    }

    TEST_ASSERT_FALSE(multisig_has_fingerprint(&parsed, 0x00000000u));
    TEST_ASSERT_FALSE(multisig_has_fingerprint(&parsed, 0xFFFFFFFFu));

    multisig_t none;
    memset(&none, 0, sizeof(none));
    TEST_ASSERT_FALSE(multisig_has_fingerprint(&none, 0x0F056943u));
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_parse);
  RUN_TEST(test_serialize_roundtrip);
  RUN_TEST(test_deserialize_refuses_impossible_shapes);
  RUN_TEST(test_reexport);
  RUN_TEST(test_has_fingerprint);
  return UNITY_END();
}
