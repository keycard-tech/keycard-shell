#include <stdint.h>
#include <string.h>

#include "ur/ur_encode.h"
#include "unity.h"
#include "vectors/vectors_ur_encode.h"
#include "zcbor_encode.h"

/*
 * The bytes the shell shows the wallet.
 *
 * Everything under test here ends its life as a QR code that something else has to parse: a
 * signature a broadcast depends on, an extended key a watch-only wallet imports, the psbt a wallet
 * continues, the parts of an animated QR. So the assertion is the whole encoded item, compared byte
 * for byte against CBOR that generate.py assembled on its own -- including canonical form, which is
 * the thing zcbor cannot check about itself: minimal length heads, map keys ascending, an absent
 * optional field simply not there rather than a null where the reader expected nothing.
 *
 * Each case also checks the length the encoder reported and one poisoned byte after the output, so
 * an encoder that wrote ahead of what it declared is caught here rather than by a wallet three steps
 * away. ASan watches the buffer ends.
 *
 * crypto-account and crypto-multi-accounts are reachable from core.c but not covered yet, and
 * hd-key's use-info is never set by the shell.
 */

/* Same convention as vectors_ur_decode.h: an index at or above 2^31 is not an index, so 0xffffffff
 * stands for a component that carried none. */
#define NO_INDEX 0xffffffffu

#define OUT_SIZE 512
#define FILL 0xa5
/* What the length out-parameter is set to before a call that is expected to fail, so that "the
 * encoder did not touch it" is an assertion rather than an absence of one. */
#define SENTINEL 0xdeadbeefu

static uint8_t out[OUT_SIZE];

static void start(void) {
  memset(out, FILL, sizeof(out));
}

static void done(const char* name, const uint8_t* expect, uint16_t expect_len, int res,
                 size_t written) {
  TEST_ASSERT_EQUAL_INT_MESSAGE(ZCBOR_SUCCESS, res, name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(expect_len, (uint32_t)written, name);
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expect, out, expect_len, name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(FILL, out[expect_len], name);
}

static void keypath(struct crypto_keypath* kp, const uint32_t* index, const uint8_t* hardened,
                    uint8_t count, uint32_t fingerprint, int has_fingerprint, uint32_t depth,
                    int has_depth) {
  memset(kp, 0, sizeof(*kp));
  kp->crypto_keypath_components_path_component_m_count = count;

  for (uint8_t i = 0; i < count; i++) {
    struct path_component* pc = &kp->crypto_keypath_components_path_component_m[i];
    pc->path_component_child_index_m_present = index[i] != NO_INDEX;
    pc->path_component_child_index_m = index[i];
    pc->path_component_is_hardened_m = hardened[i];
  }

  kp->crypto_keypath_source_fingerprint_present = has_fingerprint;
  kp->crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint = fingerprint;
  kp->crypto_keypath_depth_present = has_depth;
  kp->crypto_keypath_depth.crypto_keypath_depth = depth;
}

static void str_field(struct zcbor_string* s, const uint8_t* value, uint16_t len) {
  s->value = value;
  s->len = len;
}

/* One builder per family, so the short-buffer case offers the encoder exactly the item the byte
 * comparison case offers it, one byte less room and nothing else different. */

static void build_eth(const ur_encode_sig_case_t* c, struct eth_signature* sig) {
  memset(sig, 0, sizeof(*sig));
  sig->eth_signature_request_id_present = c->request_id != NULL;
  if (c->request_id != NULL) {
    str_field(&sig->eth_signature_request_id.eth_signature_request_id, c->request_id,
              c->request_id_len);
  }
  str_field(&sig->eth_signature_signature, c->signature, c->signature_len);
  sig->eth_signature_signature_origin_present = c->third != NULL;
  if (c->third != NULL) {
    str_field(&sig->eth_signature_signature_origin.eth_signature_signature_origin, c->third,
              c->third_len);
  }
}

static void build_btc(const ur_encode_sig_case_t* c, struct btc_signature* sig) {
  memset(sig, 0, sizeof(*sig));
  str_field(&sig->btc_signature_request_id, c->request_id, c->request_id_len);
  str_field(&sig->btc_signature_signature, c->signature, c->signature_len);
  str_field(&sig->btc_signature_public_key, c->third, c->third_len);
}

static void build_part(const ur_encode_part_case_t* c, struct ur_part* part) {
  memset(part, 0, sizeof(*part));
  part->ur_part_seqNum = c->seq_num;
  part->ur_part_seqLen = c->seq_len;
  part->ur_part_messageLen = c->message_len;
  part->ur_part_checksum = c->checksum;
  str_field(&part->ur_part_data, c->data, c->data_len);
}

static void build_dev(const ur_encode_dev_case_t* c, struct dev_auth* auth) {
  memset(auth, 0, sizeof(*auth));
  auth->dev_auth_step.dev_auth_step_type_choice = c->step;
  auth->dev_auth_dev_id_present = c->dev_id != NULL;
  if (c->dev_id != NULL) {
    str_field(&auth->dev_auth_dev_id.dev_auth_dev_id, c->dev_id, c->dev_id_len);
  }
  auth->dev_auth_first_auth_present = c->has_first_auth;
  auth->dev_auth_first_auth.dev_auth_first_auth = c->first_auth;
  auth->dev_auth_auth_time_present = c->has_auth_time;
  auth->dev_auth_auth_time.dev_auth_auth_time = c->auth_time;
  auth->dev_auth_auth_count_present = c->has_auth_count;
  auth->dev_auth_auth_count.dev_auth_auth_count = c->auth_count;
  auth->dev_auth_challenge_present = c->challenge != NULL;
  if (c->challenge != NULL) {
    str_field(&auth->dev_auth_challenge.dev_auth_challenge, c->challenge, c->challenge_len);
  }
  auth->dev_auth_auth_sig_present = c->auth_sig != NULL;
  if (c->auth_sig != NULL) {
    str_field(&auth->dev_auth_auth_sig.dev_auth_auth_sig, c->auth_sig, c->auth_sig_len);
  }
}

static void build_hdkey(const ur_encode_hdkey_case_t* c, struct hd_key* key) {
  memset(key, 0, sizeof(*key));
  key->hd_key_is_private = c->is_private;
  str_field(&key->hd_key_key_data, c->key_data, c->key_data_len);
  str_field(&key->hd_key_chain_code, c->chain_code, c->chain_code_len);
  keypath(&key->hd_key_origin, c->origin_index, c->origin_hardened, c->origin_count,
          c->source_fingerprint, c->has_fingerprint, c->depth, c->has_depth);
  key->hd_key_parent_fingerprint = c->parent_fingerprint;
  str_field(&key->hd_key_name, (const uint8_t*)c->key_name,
            c->key_name != NULL ? (uint16_t)strlen(c->key_name) : 0);
  key->hd_key_source_present = c->source != NULL;
  if (c->source != NULL) {
    str_field(&key->hd_key_source.hd_key_source, (const uint8_t*)c->source,
              (uint16_t)strlen(c->source));
  }
  key->hd_key_children_present = c->has_children;
  if (c->has_children) {
    keypath(&key->hd_key_children.hd_key_children, c->child_index, c->child_hardened,
            c->child_count, 0, 0, 0, 0);
  }
}

void setUp(void) {}

void tearDown(void) {}

void test_eth_signature_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_ETH_SIG_CASES) / sizeof(UR_ENCODE_ETH_SIG_CASES[0]); i++) {
    const ur_encode_sig_case_t* c = &UR_ENCODE_ETH_SIG_CASES[i];
    struct eth_signature sig;
    size_t written = 0;
    int res;

    build_eth(c, &sig);
    start();
    res = cbor_encode_eth_signature(out, OUT_SIZE, &sig, &written);
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

void test_btc_signature_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_BTC_SIG_CASES) / sizeof(UR_ENCODE_BTC_SIG_CASES[0]); i++) {
    const ur_encode_sig_case_t* c = &UR_ENCODE_BTC_SIG_CASES[i];
    struct btc_signature sig;
    size_t written = 0;
    int res;

    build_btc(c, &sig);
    start();
    res = cbor_encode_btc_signature(out, OUT_SIZE, &sig, &written);
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

void test_ur_part_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_PART_CASES) / sizeof(UR_ENCODE_PART_CASES[0]); i++) {
    const ur_encode_part_case_t* c = &UR_ENCODE_PART_CASES[i];
    struct ur_part part;
    size_t written = 0;
    int res;

    build_part(c, &part);
    start();
    res = cbor_encode_ur_part(out, OUT_SIZE, &part, &written);
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

void test_dev_auth_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_DEV_CASES) / sizeof(UR_ENCODE_DEV_CASES[0]); i++) {
    const ur_encode_dev_case_t* c = &UR_ENCODE_DEV_CASES[i];
    struct dev_auth auth;
    size_t written = 0;
    int res;

    build_dev(c, &auth);
    start();
    res = cbor_encode_dev_auth(out, OUT_SIZE, &auth, &written);

    if (!c->accept) {
      TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS, res, c->name);
      /* The refusal is not a rollback. A map header is written with the field count at the top of
       * the range and patched when the map closes, so what is left is a7 -- dev-auth has seven
       * fields -- where a closed map of the present ones would have read smaller. */
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa7, out[0], c->name);
      continue;
    }
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

void test_psbt_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_PSBT_CASES) / sizeof(UR_ENCODE_PSBT_CASES[0]); i++) {
    const ur_encode_psbt_case_t* c = &UR_ENCODE_PSBT_CASES[i];
    struct zcbor_string psbt;
    size_t written = 0;
    int res;

    str_field(&psbt, c->payload, c->payload_len);
    start();
    res = c->tagged ? cbor_encode_tagged_psbt(out, OUT_SIZE, &psbt, &written)
                    : cbor_encode_psbt(out, OUT_SIZE, &psbt, &written);
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

void test_hd_key_rows(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_HDKEY_CASES) / sizeof(UR_ENCODE_HDKEY_CASES[0]); i++) {
    const ur_encode_hdkey_case_t* c = &UR_ENCODE_HDKEY_CASES[i];
    struct hd_key key;
    size_t written = 0;
    int res;

    build_hdkey(c, &key);
    start();
    res = cbor_encode_hd_key(out, OUT_SIZE, &key, &written);

    if (!c->accept) {
      TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS, res, c->name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa9, out[0], c->name); /* hd-key has nine fields */
      continue;
    }
    done(c->name, c->expect, c->expect_len, res, written);
  }
}

/* The firmware sizes every destination by a worst case of its own -- CBOR_SIG_MAX_LEN,
 * CBOR_KEY_MAX_LEN, a slice of the heap pool -- and passes it straight in, so an encoder given less
 * room than the item needs has to refuse rather than write what fits. One byte less than each item
 * needs, into a poisoned buffer. What the refusal leaves behind is part of the contract: the length
 * out-parameter is untouched, so a caller that reused the buffer for the next signature would be
 * showing the length of the previous one. */
void test_one_byte_short_is_refused_rather_than_truncated(void) {
  for (size_t i = 0; i < sizeof(UR_ENCODE_ETH_SIG_CASES) / sizeof(UR_ENCODE_ETH_SIG_CASES[0]); i++) {
    const ur_encode_sig_case_t* c = &UR_ENCODE_ETH_SIG_CASES[i];
    struct eth_signature sig;
    size_t written = SENTINEL;

    build_eth(c, &sig);
    start();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_encode_eth_signature(out, c->expect_len - 1, &sig, &written),
                                  c->name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(SENTINEL, (uint32_t)written, c->name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa3, out[0], c->name);
  }

  for (size_t i = 0; i < sizeof(UR_ENCODE_BTC_SIG_CASES) / sizeof(UR_ENCODE_BTC_SIG_CASES[0]); i++) {
    const ur_encode_sig_case_t* c = &UR_ENCODE_BTC_SIG_CASES[i];
    struct btc_signature sig;
    size_t written = SENTINEL;

    build_btc(c, &sig);
    start();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_encode_btc_signature(out, c->expect_len - 1, &sig, &written),
                                  c->name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(SENTINEL, (uint32_t)written, c->name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xa3, out[0], c->name);
  }

  for (size_t i = 0; i < sizeof(UR_ENCODE_PART_CASES) / sizeof(UR_ENCODE_PART_CASES[0]); i++) {
    const ur_encode_part_case_t* c = &UR_ENCODE_PART_CASES[i];
    struct ur_part part;
    size_t written = SENTINEL;

    build_part(c, &part);
    start();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(ZCBOR_SUCCESS,
                                  cbor_encode_ur_part(out, c->expect_len - 1, &part, &written),
                                  c->name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(SENTINEL, (uint32_t)written, c->name);
  }

  for (size_t i = 0; i < sizeof(UR_ENCODE_PSBT_CASES) / sizeof(UR_ENCODE_PSBT_CASES[0]); i++) {
    const ur_encode_psbt_case_t* c = &UR_ENCODE_PSBT_CASES[i];
    struct zcbor_string psbt;
    size_t written = SENTINEL;

    if (c->tagged) {
      continue; /* its length includes the tag, which the untagged encoder would not write */
    }
    str_field(&psbt, c->payload, c->payload_len);
    start();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(
        ZCBOR_SUCCESS, cbor_encode_psbt(out, c->expect_len - 1, &psbt, &written), c->name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(SENTINEL, (uint32_t)written, c->name);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_eth_signature_rows);
  RUN_TEST(test_btc_signature_rows);
  RUN_TEST(test_ur_part_rows);
  RUN_TEST(test_dev_auth_rows);
  RUN_TEST(test_psbt_rows);
  RUN_TEST(test_hd_key_rows);
  RUN_TEST(test_one_byte_short_is_refused_rather_than_truncated);
  return UNITY_END();
}
