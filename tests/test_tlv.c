#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "framework/test_util.h"
#include "keycard/application_info.h"
#include "unity.h"
#include "util/tlv.h"
#include "vectors/vectors_tlv.h"

/* tlv.c reads the bytes that come back from the secure element. It takes a cursor -- [p, end) --
 * because the response length is the one thing the caller knows and the card does not, and a
 * refusal leaves the cursor where it was. Tag numbers over two octets, indefinite lengths and
 * lengths over two octets are refused: Keycard sends none of them, and reading them anyway costs
 * the alignment of everything that follows.
 *
 * The vectors are the applet's own responses -- tags, field order and length form taken from its
 * source -- plus the BER forms a reader has to make sense of. Every input is parsed out of a buffer
 * of exactly its length, so a read past the response is a sanitizer report rather than a silent
 * read of whatever the allocator left there.
 *
 * The prefixes and the lying headers are rows here because that is where the unbounded reader this
 * parser replaced stopped being a reader: 355 of the 360 such rows ran past the response, and one
 * byte was enough. Its agreement with this one on every response a genuine card sends was measured
 * before the change and is not repeated -- the rows are what remains.
 */

#define CANARY 0xA5

static uint8_t* input;
static size_t input_len;

static uint8_t* load(const char* hex) {
  free(input);
  input_len = strlen(hex) / 2;
  input = malloc(input_len ? input_len : 1);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_MESSAGE(input_len, test_unhex(hex, input, input_len), "malformed vector");
  return input;
}

void setUp(void) {}

void tearDown(void) {
  free(input);
  input = NULL;
}

void test_header_forms(void) {
  for (size_t i = 0; i < TLV_HEADER_CASES_COUNT; i++) {
    const tlv_header_case_t* v = &TLV_HEADER_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->hex);
    tlv_t tlv;
    tlv_open(&tlv, buf, input_len);

    uint16_t tag = 0;
    const bool tag_read = tlv_read_tag(&tlv, &tag);
    if (v->tag_size == 0) {
      TEST_ASSERT_FALSE_MESSAGE(tag_read, label);
      TEST_ASSERT_EQUAL_PTR_MESSAGE(buf, tlv.p, label);
      continue;
    }
    TEST_ASSERT_TRUE_MESSAGE(tag_read, label);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->tag, tag, label);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->tag_size, tlv.p - buf, label);

    const uint8_t* before = tlv.p;
    uint16_t length = 0;
    const bool length_read = tlv_read_length(&tlv, &length);
    if (v->length_size == 0) {
      TEST_ASSERT_FALSE_MESSAGE(length_read, label);
      TEST_ASSERT_EQUAL_PTR_MESSAGE(before, tlv.p, label);
      continue;
    }
    TEST_ASSERT_TRUE_MESSAGE(length_read, label);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->length_size, tlv.p - before, label);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->length, length, label);
  }
}

void test_primitive_reads(void) {
  for (size_t i = 0; i < TLV_READ_CASES_COUNT; i++) {
    const tlv_read_case_t* v = &TLV_READ_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->hex);
    tlv_t tlv;
    tlv_open(&tlv, buf, input_len);

    uint8_t out[256];
    memset(out, CANARY, sizeof(out));
    uint16_t len = 0;

    const bool read = tlv_read_primitive(&tlv, v->tag, v->max_len, out, &len);
    if (v->out == NULL) {
      TEST_ASSERT_FALSE_MESSAGE(read, label);
      TEST_ASSERT_EQUAL_PTR_MESSAGE(buf, tlv.p, label);
      /* Every refusal -- a tag that is not the one expected, a value larger than the caller's
       * buffer, a length the response does not honour -- happens before anything is copied. */
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(CANARY, out[0], label);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(read, label);
      TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->consumed, tlv.p - buf, label);
      TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->out_len, len, label);
      if (v->out_len > 0) {
        TEST_ASSERT_HEX_MESSAGE(out, v->out_len, v->out, label);
      }
    }
  }
}

void test_fixed_reads(void) {
  for (size_t i = 0; i < TLV_FIXED_CASES_COUNT; i++) {
    const tlv_fixed_case_t* v = &TLV_FIXED_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->hex);
    tlv_t tlv;
    tlv_open(&tlv, buf, input_len);

    uint8_t out[256];
    memset(out, CANARY, sizeof(out));

    const bool read = tlv_read_fixed(&tlv, v->tag, v->want_len, out);
    if (v->consumed == 0) {
      TEST_ASSERT_FALSE_MESSAGE(read, label);
      TEST_ASSERT_EQUAL_PTR_MESSAGE(buf, tlv.p, label);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(CANARY, out[0], label);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(read, label);
      TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->consumed, tlv.p - buf, label);
    }
  }
}

void test_application_info(void) {
  for (size_t i = 0; i < APP_INFO_CASES_COUNT; i++) {
    const app_info_case_t* v = &APP_INFO_CASES[i];
    char label[160];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->response);
    /* Both sides of the call are exactly sized, so a parser that reads past the response or writes
     * past the struct is reported rather than absorbed by the stack. */
    app_info_t* const info = malloc(sizeof(app_info_t));
    TEST_ASSERT_NOT_NULL(info);
    memset(info, CANARY, sizeof(app_info_t));

    const app_err_t got = application_info_parse(buf, input_len, info);
    if (!v->ok) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, got, label);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, got, label);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(v->version, info->version, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(v->status, info->status, label);
    if (v->capabilities != 0xFFFF) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->capabilities, info->capabilities, label);
    }

    const size_t key_uid_len = strlen(v->key_uid) / 2;
    uint8_t key_uid[APP_INFO_KEY_UID_LEN];
    TEST_ASSERT_EQUAL(key_uid_len, test_unhex(v->key_uid, key_uid, sizeof(key_uid)));
    if (key_uid_len > 0) {
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(key_uid, info->key_uid, key_uid_len, label);
    }

    if (v->app_status >= 0) {
      /* v4: the certificate is the payload, and the status byte carries the PIN counters. */
      TEST_ASSERT_HEX_MESSAGE(info->v4.cert_data, strlen(v->primary) / 2, v->primary, label);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)v->app_status, info->v4.app_status, label);
    } else {
      TEST_ASSERT_HEX_MESSAGE(info->v3.sc_key, strlen(v->primary) / 2, v->primary, label);
      if (v->secondary != NULL) {
        TEST_ASSERT_HEX_MESSAGE(info->v3.instance_uid, strlen(v->secondary) / 2, v->secondary,
                                label);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)v->free_pairing, info->v3.free_pairing, label);
      }
    }
    free(info);
  }
}

void test_application_status(void) {
  for (size_t i = 0; i < APP_STATUS_CASES_COUNT; i++) {
    const app_status_case_t* v = &APP_STATUS_CASES[i];
    char label[128];
    snprintf(label, sizeof(label), "%zu: %s", i, v->comment);

    uint8_t* buf = load(v->response);
    app_status_t* const status = malloc(sizeof(app_status_t));
    TEST_ASSERT_NOT_NULL(status);
    memset(status, CANARY, sizeof(app_status_t));

    const app_err_t got = application_status_parse(buf, input_len, status);
    if (!v->ok) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, got, label);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, got, label);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->pin_retries, status->pin_retries, label);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->puk_retries, status->puk_retries, label);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->has_key, status->has_key, label);
    free(status);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_header_forms);
  RUN_TEST(test_primitive_reads);
  RUN_TEST(test_fixed_reads);
  RUN_TEST(test_application_info);
  RUN_TEST(test_application_status);
  return UNITY_END();
}
