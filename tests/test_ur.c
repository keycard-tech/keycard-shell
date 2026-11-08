#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/crc32.h"
#include "error.h"
#include "ur/bytewords.h"
#include "ur/ur.h"
#include "ur/ur_decode.h"
#include "ur/sampler.h"
#include "ur/ur_encode.h"
#include "unity.h"
#include "vectors/vectors_ur.h"
#include "vectors/vectors_kohaku_a8.h"

/* The receiver keeps one scratch buffer, MEM_HEAP_SIZE on the device, and lays the part being
 * decoded, the reassembly slots and the finished message inside it. Every buffer here is exactly
 * data_max_len so that a write past what the receiver owns lands in an ASan redzone. */
#define HEAP_SIZE (128 * 1024)
#define CBOR_HEADER_LEN 32
#define PART_STR_MAX (8 * 1024)

#define MAX_PARTS 128

static uint8_t heap[HEAP_SIZE];
static uint8_t small[2048];
static char part_str[PART_STR_MAX];
static uint8_t part_cbor[CBOR_HEADER_LEN + 4096];
static uint8_t message[8192];
static uint8_t first_msg[1000];
static uint8_t second_msg[1000];
static ur_t ur;

void setUp(void) {
  memset(&ur, 0, sizeof(ur));
  ur.buffer = heap;
  ur.data_max_len = sizeof(heap);
  memset(heap, 0, sizeof(heap));
}

void tearDown(void) {}

static void use_buffer(uint8_t* buffer, size_t size) {
  ur.buffer = buffer;
  ur.data_max_len = size;
}

static size_t part(uint32_t seq_num, uint32_t seq_len, uint32_t message_len, uint32_t checksum,
                   const uint8_t* data, size_t data_len, const char* label) {
  struct ur_part in = {
    .ur_part_seqNum = seq_num,
    .ur_part_seqLen = seq_len,
    .ur_part_messageLen = message_len,
    .ur_part_checksum = checksum,
    .ur_part_data.value = (uint8_t*)data,
    .ur_part_data.len = data_len,
  };

  size_t cbor_len = 0;
  TEST_ASSERT_EQUAL_INT(ZCBOR_SUCCESS,
                        cbor_encode_ur_part(part_cbor, sizeof(part_cbor), &in, &cbor_len));

  memcpy(part_str, "ur:", 3);
  size_t off = 3 + (size_t)sprintf(part_str + 3, "%s/", label + 3);

  if (seq_len > 1) {
    off += (size_t)sprintf(part_str + off, "%u-%u/", seq_num, seq_len);
  }

  size_t encoded = bytewords_encode(part_cbor, cbor_len, (uint8_t*)part_str + off,
                                    sizeof(part_str) - off - 1);
  TEST_ASSERT_TRUE(encoded > 0);
  part_str[off + encoded] = '\0';

  return off + encoded;
}

/* A part claiming the multi-part header whose payload is not a part at all. */
static size_t bogus_part(uint32_t seq_num, uint32_t seq_len, const uint8_t* payload, size_t len) {
  memcpy(part_str, "ur:", 3);
  size_t off = 3 + (size_t)sprintf(part_str + 3, "bytes/%u-%u/", seq_num, seq_len);
  size_t encoded = bytewords_encode(payload, len, (uint8_t*)part_str + off,
                                    sizeof(part_str) - off - 1);
  TEST_ASSERT_TRUE(encoded > 0);
  part_str[off + encoded] = '\0';
  return off + encoded;
}

/* A part with no CBOR structure: what a single-part UR carries. */
static size_t single(const uint8_t* payload, size_t len, const char* label) {
  memcpy(part_str, "ur:", 3);
  size_t off = 3 + (size_t)sprintf(part_str + 3, "%s/", label + 3);
  size_t encoded = bytewords_encode(payload, len, (uint8_t*)part_str + off,
                                    sizeof(part_str) - off - 1);
  TEST_ASSERT_TRUE(encoded > 0);
  part_str[off + encoded] = '\0';
  return off + encoded;
}

static void fill_into(uint8_t* dst, size_t len, unsigned seed) {
  for (size_t i = 0; i < len; i++) {
    seed = seed * 1103515245u + 12345u;
    dst[i] = (uint8_t)(seed >> 16);
  }
}

static void test_single_part(void) {
  fill_into(message, 64, 7);
  size_t len = single(message, 64, "ur:bytes");

  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_process_part(&ur, (const uint8_t*)part_str, len));
  TEST_ASSERT_EQUAL_INT(BYTES, ur.type);
  TEST_ASSERT_EQUAL_UINT32(64, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, 64);
}

/* The label is the only thing saying what a payload is, so it has to be one of the types the
 * firmware lists -- not something that merely hashes to one of them. */
static void test_type_labels(void) {
  static const struct {
    const char* label;
    int accepted;
    ur_type_t type;
  } cases[] = {
    {"ur:bytes", 1, BYTES},
    {"ur:BYTES", 1, BYTES},
    {"ur:ByTeS", 1, BYTES},
    {"ur:crypto-psbt", 1, CRYPTO_PSBT},
    {"ur:CRYPTO-PSBT", 1, CRYPTO_PSBT},
    {"ur:btc-sign-request", 1, BTC_SIGN_REQUEST},
    {"ur:crypto-output", 1, CRYPTO_OUTPUT},
    /* each of these hashed to a listed type */
    {"ur:any-tx", 0, BYTES},
    {"ur:ppke", 0, BYTES},
    {"ur:crypto-paycoin-psbt", 0, BYTES},
    {"ur:json", 0, BYTES},
    {"ur:pnx", 0, BYTES},
    {"ur:output-descriptor", 0, BYTES},
    /* nothing on either side of a real label */
    {"ur:byte", 0, BYTES},
    {"ur:bytes2", 0, BYTES},
    {"ur:bytes-x", 0, BYTES},
    {"ur:", 0, BYTES},
    {"ur:fw-update", 1, FW_UPDATE},
  };

  fill_into(message, 32, 11);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t len = single(message, 32, cases[i].label);
    app_err_t res = ur_process_part(&ur, (const uint8_t*)part_str, len);

    if (!cases[i].accepted) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, res, cases[i].label);
      continue;
    }

    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, res, cases[i].label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].type, (int)ur.type, cases[i].label);
    setUp();
  }
}

static void test_framing_rejected(void) {
  fill_into(message, 32, 13);
  size_t len = single(message, 32, "ur:bytes");
  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_process_part(&ur, (const uint8_t*)part_str, len));
  setUp();

  static const char* bad[] = {
    "",
    "bytes/abcdefghij",               /* no ur: prefix */
    "ur:bytes",                       /* too short overall */
    "ur:bytesabcdefg",                /* no separator after the type */
    "ur:/abcdefghij",                 /* empty type */
    "ur:bytes/",                      /* empty payload */
  };

  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    setUp();
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA,
                                  ur_process_part(&ur, (const uint8_t*)bad[i], strlen(bad[i])),
                                  bad[i]);
  }

  /* A payload whose own checksum no longer matches, one letter off. */
  setUp();
  len = single(message, 32, "ur:bytes");
  part_str[len - 1] = (part_str[len - 1] == 'a') ? 'b' : 'a';
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_process_part(&ur, (const uint8_t*)part_str, len));

  /* A sequence header that never ends, and one that carries something which is not a part. */
  setUp();
  len = single(message, 32, "ur:bytes");
  char headerless[PART_STR_MAX];
  size_t head = (size_t)sprintf(headerless, "ur:bytes/1-2");
  memcpy(headerless + head, part_str + 9, len - 9);
  TEST_ASSERT_EQUAL_INT(ERR_DATA,
                        ur_process_part(&ur, (const uint8_t*)headerless, head + len - 9));

  setUp();
  len = bogus_part(1, 2, message, 32);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_process_part(&ur, (const uint8_t*)part_str, len));

  /* A fountain part number further than the sampler is defined for: ignored, not refused. */
  setUp();
  len = part(UR_MAX_PART_COUNT + 2 + 1, 2, 64, 0x11223344, message, 32, "ur:bytes");
  TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, ur_process_part(&ur, (const uint8_t*)part_str, len));

  /* Truncations of a good part: a partial read is not a part. */
  for (size_t cut = 0; cut < len; cut++) {
    setUp();
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, ur_process_part(&ur, (const uint8_t*)part_str, cut),
                                  "truncated part accepted");
  }
}

/* Encoder and decoder against each other: the message that comes out is the message put in, so
 * the expectation does not depend on how either side lays out bytes. */
static void test_multipart_in_order(void) {
  fill_into(message, 1000, 17);

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 1000, 300);
  TEST_ASSERT_TRUE(out.part.ur_part_seqLen > 1);

  char text[PART_STR_MAX];

  for (uint32_t i = 0; i < out.part.ur_part_seqLen; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

    if (i + 1 < out.part.ur_part_seqLen) {
      TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA,
                            ur_process_part(&ur, (const uint8_t*)text, strlen(text)));
    } else {
      TEST_ASSERT_EQUAL_INT(ERR_OK, ur_process_part(&ur, (const uint8_t*)text, strlen(text)));
    }
  }

  TEST_ASSERT_EQUAL_UINT32(1000, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
}

static void test_multipart_order_and_repetition(void) {
  fill_into(message, 2000, 19);

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 2000, 250);
  uint32_t parts = out.part.ur_part_seqLen;
  TEST_ASSERT_TRUE(parts > 2);

  static char text[MAX_PARTS][PART_STR_MAX];
  TEST_ASSERT_TRUE(parts <= MAX_PARTS);

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text[i], PART_STR_MAX));
  }

  /* reversed */
  setUp();
  for (uint32_t i = parts; i-- > 0;) {
    ur_process_part(&ur, (const uint8_t*)text[i], strlen(text[i]));
  }
  TEST_ASSERT_EQUAL_UINT32(2000, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);

  /* each part twice */
  setUp();
  for (uint32_t i = 0; i < parts; i++) {
    ur_process_part(&ur, (const uint8_t*)text[i], strlen(text[i]));
    ur_process_part(&ur, (const uint8_t*)text[i], strlen(text[i]));
  }
  TEST_ASSERT_EQUAL_UINT32(2000, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);

  /* every part, in the order the encoder produces fountain parts after the sequence */
  setUp();
  for (uint32_t i = 0; i < parts * 3; i++) {
    char extra[PART_STR_MAX];
    ur_out_t again;
    ur_out_init(&again, BYTES, message, 2000, 250);

    for (uint32_t n = 0; n <= i; n++) {
      TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&again, extra, sizeof(extra)));
    }

    if (ur_process_part(&ur, (const uint8_t*)extra, strlen(extra)) == ERR_OK) {
      TEST_ASSERT_EQUAL_UINT32(2000, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
      return;
    }
  }

  TEST_FAIL_MESSAGE("fountain parts never completed the message");
}

/* A different checksum means a different message: whatever was buffered is useless. */
static void test_checksum_change_discards_buffered_parts(void) {
  fill_into(first_msg, sizeof(first_msg), 23);
  fill_into(second_msg, sizeof(second_msg), 29);

  ur_out_t out;
  char text[PART_STR_MAX];

  ur_out_init(&out, BYTES, first_msg, sizeof(first_msg), 500);
  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, ur_process_part(&ur, (const uint8_t*)text, strlen(text)));

  /* the last part of another message, carrying that message's checksum */
  ur_out_init(&out, BYTES, second_msg, sizeof(second_msg), 500);
  ur_encode_next(&out, text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, ur_process_part(&ur, (const uint8_t*)text, strlen(text)));
  TEST_ASSERT_NOT_EQUAL_UINT32(0, ur.crc);

  /* the other half of the first message no longer completes anything, because its buffered
   * part was discarded along with the previous checksum */
  ur_out_init(&out, BYTES, first_msg, sizeof(first_msg), 500);
  ur_encode_next(&out, text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, ur_process_part(&ur, (const uint8_t*)text, strlen(text)));
  TEST_ASSERT_EQUAL_UINT32(0, ur.data_len);

  /* and only sending the first message again from its start recovers it */
  ur_out_init(&out, BYTES, first_msg, sizeof(first_msg), 500);

  for (uint32_t i = 0; i < out.part.ur_part_seqLen; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    ur_process_part(&ur, (const uint8_t*)text, strlen(text));
  }

  TEST_ASSERT_EQUAL_UINT32(sizeof(first_msg), ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(first_msg, ur.data, ur.data_len);
}

/* What the fountain is for: parts that never arrived, recovered by combining the ones sent after
 * the sequence. This is the path that stores, XORs and replaces buffered parts. */
static void test_fountain_parts_recover_what_was_missed(void) {
  fill_into(message, 2000, 41);

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 2000, 250);
  uint32_t parts = out.part.ur_part_seqLen;
  char text[PART_STR_MAX];

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

    if ((i % 3) != 1) {
      ur_process_part(&ur, (const uint8_t*)text, strlen(text));
    }
  }

  TEST_ASSERT_NOT_EQUAL_UINT32(2000, ur.data_len);

  for (uint32_t sent = parts; (ur.data_len != 2000) && (sent < (parts * 20)); sent++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    ur_process_part(&ur, (const uint8_t*)text, strlen(text));
  }

  TEST_ASSERT_EQUAL_UINT32_MESSAGE(2000, ur.data_len, "fountain parts never finished");
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
}

/* A sender that keeps sending combinations: the receiver's slots fill up, and a part that cannot
 * be placed replaces the most mixed one already buffered. 100 byte parts in the full receiver
 * buffer leaves room for the 129 slots the bookkeeping has, so with a 64 part message and none of
 * its pieces sent, the extra slots get used long before anything can be assembled. */
static void test_fountain_parts_when_every_slot_is_full(void) {
  fill_into(message, 6400, 43);

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 6400, 100);
  uint32_t parts = out.part.ur_part_seqLen;
  TEST_ASSERT_EQUAL_UINT32(64, parts);

  char text[PART_STR_MAX];

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  }

  bool completed = false;

  for (uint32_t sent = 0; (sent < 1000) && !completed; sent++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

    if (ur_process_part(&ur, (const uint8_t*)text, strlen(text)) == ERR_OK) {
      TEST_ASSERT_EQUAL_UINT32(6400, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
      completed = true;
    } else {
      TEST_ASSERT_EQUAL_UINT32(0, ur.data_len);
    }
  }

  if (completed) {
    return;
  }

  /* and once the pieces themselves arrive, all that buffered mixing must not have cost anything */
  ur_out_init(&out, BYTES, message, 6400, 100);

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    ur_process_part(&ur, (const uint8_t*)text, strlen(text));
  }

  TEST_ASSERT_EQUAL_UINT32(6400, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
}

/* Three spare slots and a sender that only ever sends combinations of three pieces: nothing can
 * be reduced, nothing can be placed, and a part worse than everything buffered is dropped. */
static void test_fountain_parts_that_are_worse_than_the_buffered_ones(void) {
  fill_into(message, 1000, 47);
  use_buffer(small, sizeof(small));

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 1000, 250);
  uint32_t parts = out.part.ur_part_seqLen;
  TEST_ASSERT_EQUAL_UINT32(4, parts);

  char text[PART_STR_MAX];

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  }

  for (uint32_t sent = 0; sent < 300; sent++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

    if (ur_process_part(&ur, (const uint8_t*)text, strlen(text)) == ERR_OK) {
      TEST_ASSERT_EQUAL_UINT32(1000, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
      return;
    }
  }

}

/* A message that fills every slot has nowhere to put a combination: the part is dropped rather
 * than displacing anything, and nothing is claimed to have been assembled. */
static void test_fountain_part_with_no_room_left_at_all(void) {
  fill_into(message, 1750, 49);
  use_buffer(small, sizeof(small));

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 1750, 250);
  TEST_ASSERT_EQUAL_UINT32(7, out.part.ur_part_seqLen);

  char text[PART_STR_MAX];

  for (uint32_t i = 0; i < out.part.ur_part_seqLen; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
  }

  bool completed = false;

  for (uint32_t sent = 0; (sent < 100) && !completed; sent++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

    if (ur_process_part(&ur, (const uint8_t*)text, strlen(text)) == ERR_OK) {
      TEST_ASSERT_EQUAL_UINT32(1750, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
      completed = true;
    } else {
      TEST_ASSERT_EQUAL_UINT32(0, ur.data_len);
    }
  }
}

/* Frames do not go missing politely. Deterministic pseudo-random loss, several message sizes and
 * segment sizes, and the message must be exactly right whenever it comes together. */
static void test_fountain_parts_under_random_loss(void) {
  for (unsigned seed = 1; seed <= 16; seed++) {
    setUp();

    uint32_t rnd = 0x9e3779b9u * seed;
    size_t len = 400 + (size_t)(rnd ^ (rnd >> 7)) % 1600;
    size_t segment = 60 + (size_t)(rnd ^ (rnd >> 13)) % 200;

    fill_into(message, len, seed * 7 + 1);

    ur_out_t out;
    ur_out_init(&out, BYTES, message, len, segment);
    uint32_t parts = out.part.ur_part_seqLen;
    char text[PART_STR_MAX];
    bool completed = false;

    for (uint32_t sent = 0; (sent < (parts * 30)) && !completed; sent++) {
      TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));

      rnd ^= rnd << 13;
      rnd ^= rnd >> 17;
      rnd ^= rnd << 5;

      if ((rnd % 100) < 45) {
        continue;
      }

      if (ur_process_part(&ur, (const uint8_t*)text, strlen(text)) == ERR_OK) {
        TEST_ASSERT_EQUAL_UINT32((uint32_t)len, ur.data_len);
        TEST_ASSERT_EQUAL_MEMORY(message, ur.data, ur.data_len);
        completed = true;
      }
    }

    TEST_ASSERT_TRUE_MESSAGE(completed, "a lossy scan never assembled");
  }
}

/* ur_process_part ignores the seqNum-seqLen field, so only looking at the emitted text pins it.
 * The label, the two numbers and the separator are what a wallet reads off our screen. */
static void test_encoded_part_text(void) {
  fill_into(message, 1000, 53);

  ur_out_t out;
  char text[PART_STR_MAX];

  ur_out_init(&out, BYTES, message, 1000, 300);
  uint32_t parts = out.part.ur_part_seqLen;
  TEST_ASSERT_EQUAL_UINT32(4, parts);

  for (uint32_t i = 0; i < parts; i++) {
    char prefix[32];
    size_t prefix_len = (size_t)sprintf(prefix, "UR:BYTES/%u-%u/", i + 1, parts);

    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    TEST_ASSERT_EQUAL_MEMORY(prefix, text, prefix_len);

    uint8_t decoded[512];
    uint32_t decoded_len = bytewords_decode((const uint8_t*)text + prefix_len,
                                            strlen(text) - prefix_len, decoded, sizeof(decoded));
    TEST_ASSERT_TRUE(decoded_len > 0);

    struct ur_part part;
    TEST_ASSERT_EQUAL_INT(ZCBOR_SUCCESS, cbor_decode_ur_part(decoded, decoded_len, &part, NULL));
    TEST_ASSERT_EQUAL_UINT32(i + 1, part.ur_part_seqNum);
    TEST_ASSERT_EQUAL_UINT32(parts, part.ur_part_seqLen);
    TEST_ASSERT_EQUAL_UINT32(1000, part.ur_part_messageLen);
    TEST_ASSERT_EQUAL_UINT32(crc32(message, 1000), part.ur_part_checksum);
    TEST_ASSERT_EQUAL_UINT32(300, part.ur_part_data.len);

    size_t filled = APP_MIN((1000 - (i * 300)), 300);
    TEST_ASSERT_EQUAL_MEMORY(&message[i * 300], part.ur_part_data.value, filled);

    for (size_t off = filled; off < 300; off++) {
      TEST_ASSERT_EQUAL_UINT8(0, part.ur_part_data.value[off]);
    }
  }

  /* one part carries the message itself, with no sequence numbers to skip */
  ur_out_init(&out, BYTES, message, 1000, 4000);
  TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode(&out, text, sizeof(text)));
  TEST_ASSERT_EQUAL_MEMORY("UR:BYTES/", text, 9);

  uint8_t payload[1024];
  uint32_t payload_len = bytewords_decode((const uint8_t*)text + 9, strlen(text) - 9, payload,
                                          sizeof(payload));
  TEST_ASSERT_EQUAL_UINT32(1000, payload_len);
  TEST_ASSERT_EQUAL_MEMORY(message, payload, 1000);
}

static void test_progress_reported(void) {
  fill_into(message, 1000, 31);

  ur_out_t out;
  ur_out_init(&out, BYTES, message, 1000, 200);
  uint32_t parts = out.part.ur_part_seqLen;
  char text[PART_STR_MAX];
  uint8_t previous = 0;

  for (uint32_t i = 0; i < parts; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    ur_process_part(&ur, (const uint8_t*)text, strlen(text));
    TEST_ASSERT_TRUE_MESSAGE(ur.percent_done >= previous, "percent_done went backwards");
    previous = ur.percent_done;
  }

  TEST_ASSERT_EQUAL_UINT8(100, ur.percent_done);
}

/* Parts that describe a sequence this receiver cannot hold must be refused: the slots, the part
 * being decoded and the assembled message all share one buffer. */
static void test_part_sizes_within_the_receiver_buffer(void) {
  uint8_t data[4096];
  memset(data, 0x77, sizeof(data));

  static const struct {
    const char* name;
    uint32_t seq_num;
    uint32_t seq_len;
    uint32_t message_len;
    size_t data_len;
    size_t buffer_len;
    app_err_t expected;
  } cases[] = {
    /* part_len, the 32 bytes of header room, the slots and the message share the one buffer */
    {"sequence one slot too wide", 1, 128, 100, 1020, HEAP_SIZE, ERR_DATA},
    {"sequence exactly wide enough", 1, 128, 100, 1015, HEAP_SIZE, ERR_NEED_MORE_DATA},
    {"fountain part in a sequence with room to spare", 7, 2, 100, 1020, HEAP_SIZE,
     ERR_NEED_MORE_DATA},
    {"message longer than the buffer", 1, 4, HEAP_SIZE, 64, HEAP_SIZE, ERR_DATA},
    {"message that fills the slots", 1, 4, 1500, 500, 2048, ERR_DATA},
    {"slots past a small buffer", 1, 8, 900, 300, 2048, ERR_DATA},
    {"within every bound", 1, 4, 1200, 400, 2048, ERR_NEED_MORE_DATA},
    {"part needing more room than the buffer holds", 1, 2, 100, 2030, 2048, ERR_DATA},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    setUp();
    use_buffer(cases[i].buffer_len == sizeof(small) ? small : heap, cases[i].buffer_len);

    size_t len = part(cases[i].seq_num, cases[i].seq_len, cases[i].message_len, 0x89abcdef,
                      data, cases[i].data_len, "ur:bytes");
    app_err_t res = ur_process_part(&ur, (const uint8_t*)part_str, len);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].expected, res, cases[i].name);
  }
}

/* The part header is written before the payload length is known to fit. */
static void test_encode_refuses_too_small_a_buffer(void) {
  fill_into(message, 1000, 37);

  ur_out_t out;
  ur_out_init(&out, CRYPTO_MULTI_ACCOUNTS, message, 1000, 200);

  /* "UR:" + the longest type name + '/' + "1-5/" is 30 bytes, and the only check before those
   * writes is that max_len is at least MIN_ENCODED_LEN. */
  char text[24];
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_encode_next(&out, text, sizeof(text)));

  ur_out_init(&out, CRYPTO_MULTI_ACCOUNTS, message, 100, 1000);
  char flat[24];
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_encode(&out, flat, sizeof(flat)));

  /* room for the header but not for the payload */
  ur_out_init(&out, BYTES, message, 1000, 200);
  char tight[64];
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_encode_next(&out, tight, sizeof(tight)));

  /* UR_ANY_TX and NO_UR ask for a scan, they are not types a UR carries */
  ur_out_init(&out, UR_ANY_TX, message, 100, 1000);
  char not_a_type[512];
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_encode(&out, not_a_type, sizeof(not_a_type)));

  ur_out_init(&out, NO_UR, message, 100, 1000);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, ur_encode(&out, not_a_type, sizeof(not_a_type)));
}

/* ------------------------------------------------- BCR-2024-001, and the type papers' own examples */

static size_t part_body(const char* text, uint8_t* cbor, size_t max) {
  const char* body = strrchr(text, '/');
  TEST_ASSERT_NOT_NULL(body);
  size_t len = bytewords_decode((const uint8_t*)(body + 1), strlen(body + 1), cbor, max);
  TEST_ASSERT_TRUE(len > 0);
  return len;
}

static void expect_part_fields(const char* text, const ur_spec_part_t* want) {
  uint8_t cbor[128];
  size_t len = part_body(text, cbor, sizeof(cbor));

  struct ur_part got;
  TEST_ASSERT_EQUAL_INT(ZCBOR_SUCCESS, cbor_decode_ur_part(cbor, len, &got, NULL));
  TEST_ASSERT_EQUAL_UINT32(want->seq_num, got.ur_part_seqNum);
  TEST_ASSERT_EQUAL_UINT32(want->seq_len, got.ur_part_seqLen);
  TEST_ASSERT_EQUAL_UINT32(want->message_len, got.ur_part_messageLen);
  TEST_ASSERT_EQUAL_UINT32(want->checksum, got.ur_part_checksum);
  TEST_ASSERT_EQUAL_UINT32(UR_SPEC_FRAGMENT_LEN, got.ur_part_data.len);
  TEST_ASSERT_EQUAL_MEMORY(want->data, got.ur_part_data.value, UR_SPEC_FRAGMENT_LEN);
}

/* The receiver's checksum is the one field nothing but the message can produce. */
static void test_message_checksum_is_crc32(void) {
  TEST_ASSERT_EQUAL_UINT32(UR_SPEC_CHECKSUM, crc32(UR_SPEC_MESSAGE, UR_SPEC_MESSAGE_LEN));
}

static void test_encoder_emits_the_published_parts(void) {
  ur_out_t out;
  ur_out_init(&out, BYTES, UR_SPEC_MESSAGE, UR_SPEC_MESSAGE_LEN, UR_SPEC_FRAGMENT_LEN);
  TEST_ASSERT_EQUAL_UINT32(UR_SPEC_SEQ_LEN, out.part.ur_part_seqLen);
  TEST_ASSERT_EQUAL_UINT32(UR_SPEC_CHECKSUM, out.part.ur_part_checksum);

  char text[PART_STR_MAX];
  for (uint32_t i = 0; i < UR_SPEC_PARTS_COUNT; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, ur_encode_next(&out, text, sizeof(text)));
    expect_part_fields(text, &UR_SPEC_PARTS[i]);
  }
}

static size_t spec_part(uint32_t seq_num) {
  const ur_spec_part_t* p = &UR_SPEC_PARTS[seq_num - 1];
  return part(p->seq_num, p->seq_len, p->message_len, p->checksum, p->data,
              UR_SPEC_FRAGMENT_LEN, "ur:bytes");
}

static void test_published_parts_reassemble_the_message(void) {
  for (uint32_t i = 1; i <= UR_SPEC_PARTS_COUNT; i++) {
    size_t len = spec_part(i);
    app_err_t err = ur_process_part(&ur, (const uint8_t*)part_str, len);

    if (i < UR_SPEC_SEQ_LEN) {
      TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, err);
    } else if (i == UR_SPEC_SEQ_LEN) {
      TEST_ASSERT_EQUAL_INT(ERR_OK, err);
      TEST_ASSERT_EQUAL_UINT32(UR_SPEC_MESSAGE_LEN, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(UR_SPEC_MESSAGE, ur.data, ur.data_len);
    } else {
      /* the message is already whole: further parts of the same sequence change nothing */
      TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, err);
      TEST_ASSERT_EQUAL_UINT32(UR_SPEC_MESSAGE_LEN, ur.data_len);
      TEST_ASSERT_EQUAL_MEMORY(UR_SPEC_MESSAGE, ur.data, ur.data_len);
    }
  }
}

static void test_published_parts_in_reverse_order(void) {
  for (uint32_t i = UR_SPEC_SEQ_LEN; i-- > 0;) {
    size_t len = spec_part(i + 1);
    ur_process_part(&ur, (const uint8_t*)part_str, len);
  }

  TEST_ASSERT_EQUAL_UINT32(UR_SPEC_MESSAGE_LEN, ur.data_len);
  TEST_ASSERT_EQUAL_MEMORY(UR_SPEC_MESSAGE, ur.data, ur.data_len);
}

/* The published mixed parts have to stand in for the fragments that were never seen, which pins
 * both the mixing and the set of fragments a part is made of. */
static void test_published_mixed_parts_replace_a_missed_fragment(void) {
  for (uint32_t missed = 1; missed <= UR_SPEC_SEQ_LEN; missed++) {
    setUp();

    bool done = false;
    for (uint32_t i = 1; i <= UR_SPEC_PARTS_COUNT && !done; i++) {
      if (i == missed) {
        continue;
      }
      size_t len = spec_part(i);
      done = ur_process_part(&ur, (const uint8_t*)part_str, len) == ERR_OK;
    }

    TEST_ASSERT_TRUE_MESSAGE(done, "the published fountain parts never replaced the missed one");
    TEST_ASSERT_EQUAL_UINT32(UR_SPEC_MESSAGE_LEN, ur.data_len);
    TEST_ASSERT_EQUAL_MEMORY(UR_SPEC_MESSAGE, ur.data, ur.data_len);
  }
}

/* "Once the first part of a sequence is decoded, any subsequent parts with different seqLen,
 * messageLen, or checksum, or where data is a different length from the first received part MUST
 * be rejected." A refusal must not wedge the receiver: the sequence still completes afterwards. */
static void test_part_disagreeing_with_the_sequence_is_refused(void) {
  static const struct {
    const char* what;
    uint32_t seq_len;
    uint32_t message_len;
    size_t data_len;
  } variants[] = {
    {"seqLen", UR_SPEC_SEQ_LEN + 1, UR_SPEC_MESSAGE_LEN, UR_SPEC_FRAGMENT_LEN},
    {"messageLen", UR_SPEC_SEQ_LEN, UR_SPEC_MESSAGE_LEN + 1, UR_SPEC_FRAGMENT_LEN},
    {"data", UR_SPEC_SEQ_LEN, UR_SPEC_MESSAGE_LEN, UR_SPEC_FRAGMENT_LEN - 1},
  };

  const ur_spec_part_t* second = &UR_SPEC_PARTS[1];

  for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
    setUp();

    size_t len = spec_part(1);
    TEST_ASSERT_EQUAL_INT(ERR_NEED_MORE_DATA, ur_process_part(&ur, (const uint8_t*)part_str, len));

    len = part(second->seq_num, variants[i].seq_len, variants[i].message_len, second->checksum,
               second->data, variants[i].data_len, "ur:bytes");
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA,
                                  ur_process_part(&ur, (const uint8_t*)part_str, len), variants[i].what);

    for (uint32_t n = 2; n <= UR_SPEC_SEQ_LEN; n++) {
      len = spec_part(n);
      ur_process_part(&ur, (const uint8_t*)part_str, len);
    }

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(UR_SPEC_MESSAGE_LEN, ur.data_len, variants[i].what);
    TEST_ASSERT_EQUAL_MEMORY(UR_SPEC_MESSAGE, ur.data, ur.data_len);
  }
}

static void test_rateless_parts_mix_the_published_fragments(void) {
  double probs[UR_MAX_PART_COUNT];
  int aliases[UR_MAX_PART_COUNT];
  random_sampler_init(UR_FRAGMENT_SEQ_LEN, probs, aliases);

  for (size_t i = 0; i < UR_FRAGMENT_CHOICES_COUNT; i++) {
    ur_desc_t indexes;
    fountain_part_indexes(UR_FRAGMENT_CHOICES[i].seq_num, UR_FRAGMENT_CHECKSUM,
                          UR_FRAGMENT_SEQ_LEN, probs, aliases, &indexes);

    uint16_t fragments = 0;
    for (int f = 0; f < UR_FRAGMENT_SEQ_LEN; f++) {
      if (ur_desc_get_bit(&indexes, (uint32_t)f)) {
        fragments |= (uint16_t)(1u << f);
      }
    }
    TEST_ASSERT_EQUAL_UINT16(UR_FRAGMENT_CHOICES[i].fragments, fragments);
  }
}

static const char* const* registry_row_for(const char* label) {
  for (size_t r = 0; r < UR_REGISTRY_COUNT; r++) {
    for (size_t n = 0; n < 3; n++) {
      if (strcmp(UR_REGISTRY_LABELS[r][n], label) == 0) {
        return UR_REGISTRY_LABELS[r];
      }
    }
  }
  return NULL;
}

static size_t relabel(char* out, size_t max, const char* text, const char* label) {
  const char* body = strchr(text, '/');
  TEST_ASSERT_NOT_NULL(body);
  int written = snprintf(out, max, "ur:%s/%s", label, body + 1);
  TEST_ASSERT_TRUE((written > 0) && ((size_t)written < max));
  return (size_t)written;
}

/* The papers were written across a rename of these types, so an example's own label is not
 * necessarily the spelling this device registers. Either way the body is the published CBOR: the
 * label decides acceptance and nothing else.
 *
 * The body is compared as bytes rather than run through cbor_decode_hd_key or
 * cbor_decode_crypto_account: cddl/ur.cddl makes is-private, origin, parent-fingerprint and name
 * mandatory in hd-key, and crypto-output has no form for the tag 410 multi-key descriptors these
 * examples use, so the published bodies are not representable in this device's schema at all. */
static void test_published_ur_texts_decode_to_their_published_cbor(void) {
  for (size_t i = 0; i < UR_PUBLISHED_COUNT; i++) {
    const ur_published_t* row = &UR_PUBLISHED[i];
    const char* const* names = registry_row_for(row->label);
    TEST_ASSERT_NOT_NULL(names);

    int accepted = 0;
    for (size_t n = 0; (n < 3) && names[n][0]; n++) {
      size_t len = relabel(part_str, sizeof(part_str), row->ur, names[n]);
      app_err_t err = ur_process_part(&ur, (const uint8_t*)part_str, len);

      if (err == ERR_OK) {
        accepted++;
        TEST_ASSERT_EQUAL_UINT32(row->cbor_len, ur.data_len);
        TEST_ASSERT_EQUAL_MEMORY(row->cbor, ur.data, row->cbor_len);
      } else {
        TEST_ASSERT_EQUAL_INT(ERR_DATA, err);
      }
    }

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, accepted, row->ur);
  }
}


static void test_kohaku_a8_cli_interoperability(void) {
  static const struct {
    const char* text;
    const uint8_t* payload;
    size_t len;
  } fixtures[] = {
    {
      KOHAKU_A8_REQUEST_UR,
      KOHAKU_A8_REQUEST,
      sizeof(KOHAKU_A8_REQUEST),
    },
    {
      KOHAKU_A8_RESPONSE_UR,
      KOHAKU_A8_RESPONSE,
      sizeof(KOHAKU_A8_RESPONSE),
    },
  };

  for (size_t i = 0; i < 2; i++) {
    setUp();

    TEST_ASSERT_EQUAL_INT(
        ERR_OK,
        ur_process_part(
            &ur,
            (const uint8_t*)fixtures[i].text,
            strlen(fixtures[i].text)));

    TEST_ASSERT_EQUAL_INT(BYTES, ur.type);

    struct zcbor_string decoded = {0};
    TEST_ASSERT_EQUAL_INT(
        ZCBOR_SUCCESS,
        cbor_decode_psbt(
            ur.data, ur.data_len, &decoded, NULL));

    TEST_ASSERT_EQUAL_UINT(fixtures[i].len, decoded.len);
    TEST_ASSERT_EQUAL_MEMORY(
        fixtures[i].payload, decoded.value, decoded.len);

    ur_out_t encoder;
    ur_out_init(&encoder, BYTES, ur.data, ur.data_len, 200);

    char encoded[512] = {0};
    TEST_ASSERT_EQUAL_INT(
        ERR_OK, ur_encode(&encoder, encoded, sizeof(encoded)));

    TEST_ASSERT_EQUAL_UINT(
        strlen(fixtures[i].text), strlen(encoded));

    for (size_t j = 0; j < strlen(encoded); j++) {
      TEST_ASSERT_EQUAL_INT(
          tolower((unsigned char)fixtures[i].text[j]),
          tolower((unsigned char)encoded[j]));
    }
  }
}

int main(void) {
  /* a sanitizer abort must not cost the output of the assertions that ran before it */
  setvbuf(stdout, NULL, _IONBF, 0);

  UNITY_BEGIN();
  RUN_TEST(test_single_part);
  RUN_TEST(test_type_labels);
  RUN_TEST(test_framing_rejected);
  RUN_TEST(test_multipart_in_order);
  RUN_TEST(test_multipart_order_and_repetition);
  RUN_TEST(test_checksum_change_discards_buffered_parts);
  RUN_TEST(test_fountain_parts_recover_what_was_missed);
  RUN_TEST(test_fountain_parts_when_every_slot_is_full);
  RUN_TEST(test_fountain_parts_that_are_worse_than_the_buffered_ones);
  RUN_TEST(test_fountain_part_with_no_room_left_at_all);
  RUN_TEST(test_fountain_parts_under_random_loss);
  RUN_TEST(test_encoded_part_text);
  RUN_TEST(test_progress_reported);
  RUN_TEST(test_part_sizes_within_the_receiver_buffer);
  RUN_TEST(test_encode_refuses_too_small_a_buffer);
  RUN_TEST(test_message_checksum_is_crc32);
  RUN_TEST(test_encoder_emits_the_published_parts);
  RUN_TEST(test_published_parts_reassemble_the_message);
  RUN_TEST(test_published_parts_in_reverse_order);
  RUN_TEST(test_published_mixed_parts_replace_a_missed_fragment);
  RUN_TEST(test_part_disagreeing_with_the_sequence_is_refused);
  RUN_TEST(test_rateless_parts_mix_the_published_fragments);
  RUN_TEST(test_published_ur_texts_decode_to_their_published_cbor);
  RUN_TEST(test_kohaku_a8_cli_interoperability);
  return UNITY_END();
}
