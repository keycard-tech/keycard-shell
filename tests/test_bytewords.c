#include <ctype.h>
#include <string.h>
#include "crypto/crc32.h"
#include "framework/test_util.h"
#include "ur/bytewords.h"
#include "unity.h"
#include "vectors/vectors_bytewords.h"

#define MAX_PAYLOAD 512
#define MAX_ENCODED (2 * (MAX_PAYLOAD + 4))
#define CHECKSUM_CODES 4

static uint8_t payload[MAX_PAYLOAD];
static uint8_t out[MAX_ENCODED + 16];
static uint8_t back[MAX_PAYLOAD + 16];

void setUp(void) {
  memset(out, 0xa5, sizeof(out));
  memset(back, 0xa5, sizeof(back));
}

void tearDown(void) {}

static size_t encode(const char* payload_hex) {
  size_t len = test_unhex(payload_hex, payload, sizeof(payload));
  TEST_ASSERT_TRUE_MESSAGE(len < sizeof(payload), payload_hex);
  return bytewords_encode(payload, len, out, MAX_ENCODED);
}

static void assert_encoding(size_t len, const char* expected, const char* name) {
  TEST_ASSERT_EQUAL_MESSAGE(strlen(expected), len, name);

  char upper[strlen(expected) + 1];
  for (size_t i = 0; i < len; i++) {
    upper[i] = (char)toupper((unsigned char)expected[i]);
  }
  upper[len] = '\0';

  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(upper, (const char*)out, len, name);
}

/* The two letters a byte encodes to, straight out of Blockchain Commons' word list. */
static void code_of(uint8_t value, char code[2]) {
  code[0] = BYTEWORDS_MINIMAL[2 * value];
  code[1] = BYTEWORDS_MINIMAL[2 * value + 1];
}

static void test_encode_vectors(void) {
  for (size_t i = 0; i < BYTEWORDS_VECTOR_COUNT; i++) {
    size_t len = encode(BYTEWORDS_VECTORS[i].payload);
    assert_encoding(len, BYTEWORDS_VECTORS[i].encoded, BYTEWORDS_VECTORS[i].name);
  }
}

static void test_decode_vectors(void) {
  for (size_t i = 0; i < BYTEWORDS_VECTOR_COUNT; i++) {
    const bytewords_vector_t* v = &BYTEWORDS_VECTORS[i];
    size_t want = test_unhex(v->payload, payload, sizeof(payload));

    /* The vectors are BC's lowercase form; the encoder emits uppercase. A decoder has to take
     * both, because the case of a scanned QR is not ours to choose. */
    size_t text_len = strlen(v->encoded);
    char text[text_len + 1];

    for (size_t j = 0; j < text_len; j++) {
      text[j] = (char)toupper((unsigned char)v->encoded[j]);
    }
    text[text_len] = '\0';

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want, bytewords_decode((const uint8_t*)text, text_len, back, MAX_PAYLOAD),
                                      v->name);
    TEST_ASSERT_HEX_MESSAGE(back, want, v->payload, v->name);

    for (size_t j = 0; j < text_len; j++) {
      text[j] = (char)tolower((unsigned char)v->encoded[j]);
    }

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want, bytewords_decode((const uint8_t*)text, text_len, back, MAX_PAYLOAD),
                                      v->name);
    TEST_ASSERT_HEX_MESSAGE(back, want, v->payload, v->name);
  }
}

/* Every byte has exactly one code, and the encoder and decoder agree on it -- which pins both
 * lookup tables against the word list, since the vectors alone would let a wrong pair in one
 * direction pass if the other direction made the same mistake. */
static void test_every_byte_roundtrips_through_its_code(void) {
  for (size_t value = 0; value < 256; value++) {
    uint8_t in = (uint8_t)value;
    char code[2];
    code_of((uint8_t)value, code);

    memset(out, 0xa5, sizeof(out));
    size_t len = bytewords_encode(&in, 1, out, MAX_ENCODED);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(2 * (1 + CHECKSUM_CODES), len, "encoded length");
    TEST_ASSERT_EQUAL_CHAR_MESSAGE(code[0], (char)out[0], "first letter");
    TEST_ASSERT_EQUAL_CHAR_MESSAGE(code[1], (char)out[1], "second letter");

    memset(back, 0xa5, sizeof(back));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, bytewords_decode(out, len, back, MAX_PAYLOAD), "decoded");
    TEST_ASSERT_EQUAL_UINT8((uint8_t)value, back[0]);
  }
}

/* The four trailing codes are the CRC32 of the payload, most significant byte first. The
 * primitive itself is covered by test_hash; what is pinned here is where it goes. */
static void test_checksum_is_big_endian_crc32(void) {
  char wanted[8];
  uint8_t codes[CHECKSUM_CODES];

  for (size_t i = 0; i < BYTEWORDS_VECTOR_COUNT; i++) {
    size_t payload_len = test_unhex(BYTEWORDS_VECTORS[i].payload, payload, sizeof(payload));
    uint32_t crc = crc32(payload, payload_len);

    for (size_t byte = 0; byte < CHECKSUM_CODES; byte++) {
      codes[byte] = (uint8_t)(crc >> (8 * (CHECKSUM_CODES - 1 - byte)));
    }

    for (size_t byte = 0; byte < CHECKSUM_CODES; byte++) {
      wanted[2 * byte] = BYTEWORDS_MINIMAL[2 * codes[byte]];
      wanted[2 * byte + 1] = BYTEWORDS_MINIMAL[2 * codes[byte] + 1];
    }

    size_t len = encode(BYTEWORDS_VECTORS[i].payload);
    TEST_ASSERT_TRUE_MESSAGE(len >= 2 * CHECKSUM_CODES, "encoded shorter than its checksum");
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(
        wanted, (const char*)(out + len - 2 * CHECKSUM_CODES), 2 * CHECKSUM_CODES,
        BYTEWORDS_VECTORS[i].name);
  }
}

static void test_encode_needs_room_for_the_checksum(void) {
  size_t len = encode(BYTEWORDS_VECTORS[0].payload);
  TEST_ASSERT_TRUE(len > 0);

  memset(out, 0xa5, sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(0, bytewords_encode(payload, strlen(BYTEWORDS_VECTORS[0].payload) / 2,
                                               out, len - 1));

  /* An exact fit is enough, and nothing past it is written. */
  memset(out, 0xa5, sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(len, bytewords_encode(payload, strlen(BYTEWORDS_VECTORS[0].payload) / 2,
                                                 out, len));
  TEST_ASSERT_EQUAL_UINT8(0xa5, out[len]);
}

static void test_decode_needs_room_for_the_payload(void) {
  size_t len = encode(BYTEWORDS_VECTORS[0].payload);
  size_t want = strlen(BYTEWORDS_VECTORS[0].payload) / 2;

  TEST_ASSERT_EQUAL_UINT32(want, bytewords_decode(out, len, back, want));
  TEST_ASSERT_EQUAL_UINT32(0, bytewords_decode(out, len, back, want - 1));
}

static void test_truncations_rejected(void) {
  for (size_t i = 0; i < BYTEWORDS_VECTOR_COUNT; i++) {
    size_t len = encode(BYTEWORDS_VECTORS[i].payload);

    for (size_t cut = 0; cut < len; cut++) {
      memset(back, 0xa5, sizeof(back));
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, bytewords_decode(out, cut, back, MAX_PAYLOAD),
                                       BYTEWORDS_VECTORS[i].name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, back[MAX_PAYLOAD], "wrote past the output limit");
    }
  }
}

/* Whatever a scanner gets wrong in one letter, it must not come back as different data. Either
 * the checksum stops it, or the changed letter still means the same byte -- which is the one
 * thing a decoder built from a sparse table cannot tell apart. */
static void test_one_letter_worse_never_yields_other_data(void) {
  static const char substitutions[] = "amz1 -\t0Z";

  for (size_t i = 0; i < 2; i++) {
    size_t len = encode(BYTEWORDS_VECTORS[i].payload);
    size_t want = strlen(BYTEWORDS_VECTORS[i].payload) / 2;

    for (size_t pos = 0; pos < len; pos++) {
      for (size_t s = 0; s < sizeof(substitutions) - 1; s++) {
        char text[MAX_ENCODED + 1];
        memcpy(text, out, len);
        text[len] = '\0';

        if (text[pos] == (char)substitutions[s]) {
          continue;
        }
        text[pos] = substitutions[s];

        memset(back, 0xa5, sizeof(back));
        size_t got = bytewords_decode((const uint8_t*)text, len, back, MAX_PAYLOAD);

        if (got != 0) {
          TEST_ASSERT_EQUAL_UINT32_MESSAGE((unsigned)want, (unsigned)got,
                                           BYTEWORDS_VECTORS[i].name);
          TEST_ASSERT_HEX_MESSAGE(back, got, BYTEWORDS_VECTORS[i].payload,
                                  "a mutated code decoded to other data");
        }
      }
    }
  }
}

static void test_invalid_inputs_rejected(void) {
  for (size_t i = 0; i < BYTEWORDS_INVALID_COUNT; i++) {
    size_t len = test_unhex(BYTEWORDS_INVALID[i].encoded, out, MAX_ENCODED);
    TEST_ASSERT_TRUE_MESSAGE(len < MAX_ENCODED, BYTEWORDS_INVALID[i].name);

    memset(back, 0xa5, sizeof(back));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, bytewords_decode(out, len, back, MAX_PAYLOAD),
                                     BYTEWORDS_INVALID[i].name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa5, back[MAX_PAYLOAD], "wrote past the output limit");
  }
}

static bool is_word_pair(char first, char second) {
  for (size_t value = 0; value < 256; value++) {
    if ((BYTEWORDS_MINIMAL[2 * value] == first) &&
        (BYTEWORDS_MINIMAL[2 * value + 1] == second)) {
      return true;
    }
  }

  return false;
}

/* A pair of letters that is no word still selects a byte: the decode table is sparse and carries
 * a value wherever no word lives. Blockchain Commons' reference rejects such a code; this decoder
 * is stopped only by the checksum, which protects a payload but leaves an encoding non-unique --
 * Every such code therefore means at most one byte -- it never means two -- and the pairs whose
 * index falls past the end of the table mean nothing at all and are refused. Recorded as behaviour
 * rather than as a table of pairs, so that adding the rejection is a decision made here and not a
 * QR that quietly stops scanning. */
static void test_non_word_codes_mean_exactly_one_byte(void) {
  size_t non_words = 0;
  size_t refused = 0;

  for (size_t a = 0; a < 26; a++) {
    for (size_t b = 0; b < 26; b++) {
      char first = 'A' + (char)a;
      char second = 'A' + (char)b;

      if (is_word_pair(first, second)) {
        continue;
      }

      size_t meanings = 0;

      for (size_t value = 0; value < 256; value++) {
        uint8_t one = (uint8_t)value;
        uint8_t text[MAX_ENCODED];
        size_t len = bytewords_encode(&one, 1, text, MAX_ENCODED);

        text[0] = (uint8_t)first;
        text[1] = (uint8_t)second;

        memset(back, 0xa5, sizeof(back));
        size_t got = bytewords_decode(text, len, back, MAX_PAYLOAD);

        if (got != 0) {
          TEST_ASSERT_EQUAL_UINT32(1, got);
          TEST_ASSERT_EQUAL_UINT8((uint8_t)value, back[0]);
          meanings++;
        }
      }

      char pair[3] = { first, second, '\0' };
      TEST_ASSERT_TRUE_MESSAGE(meanings <= 1, pair);

      if (meanings == 0) {
        refused++;
      }

      non_words++;
    }
  }

  TEST_ASSERT_EQUAL_UINT32(26 * 26 - 256, non_words);
  TEST_ASSERT_TRUE(refused > 0);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_encode_vectors);
  RUN_TEST(test_decode_vectors);
  RUN_TEST(test_every_byte_roundtrips_through_its_code);
  RUN_TEST(test_checksum_is_big_endian_crc32);
  RUN_TEST(test_encode_needs_room_for_the_checksum);
  RUN_TEST(test_decode_needs_room_for_the_payload);
  RUN_TEST(test_truncations_rejected);
  RUN_TEST(test_one_letter_worse_never_yields_other_data);
  RUN_TEST(test_invalid_inputs_rejected);
  RUN_TEST(test_non_word_codes_mean_exactly_one_byte);
  return UNITY_END();
}
