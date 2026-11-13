#include "unity.h"

#include <stddef.h>
#include <string.h>

#include "core/core.h"
#include "error.h"
#include "ur/ur_decode.h"
#include "ur/ur_types.h"
#include "vectors/vectors_ur_decode.h"
#include "zcbor_decode.h"

/*
 * What a scanned keypath becomes.
 *
 * core_set_derivation_path() is the one place the eth and btc UR families meet, and everything it
 * writes goes on to name a key inside the card. Two of its bounds are not enforced upstream: the
 * generated decoders drop the .lt on child-index and the .gt on source-fingerprint, and they leave an
 * absent optional field as they found it -- the decode buffer is a pool reused from one scan to the
 * next, so "found it" can mean the previous QR code. The tests below are written against those two
 * facts plus the arithmetic the function exists to do: a component's index, big-endian, with the
 * hardened bit owned by the shell and nobody else.
 *
 * The last case takes the payloads from vectors/vectors_ur_decode.h -- the same bytes a wallet would
 * send, and which test_ur_decode.c already established the decoder accepts -- and pushes each through
 * to this function, so the pair of suites covers the route from camera bytes to derivation bytes. The
 * verdict there is computed from the vector's own fields, not from what the code does.
 */

static void build(struct crypto_keypath* kp, const uint32_t* index, const uint8_t* present,
                  const uint8_t* hardened, uint8_t count, uint32_t fingerprint, int has_fingerprint) {
  memset(kp, 0, sizeof(*kp));
  kp->crypto_keypath_components_path_component_m_count = count;

  for (uint8_t i = 0; i < count; i++) {
    struct path_component* pc = &kp->crypto_keypath_components_path_component_m[i];
    pc->path_component_child_index_m_present = present == NULL || present[i];
    pc->path_component_child_index_m = index[i];
    pc->path_component_is_hardened_m = hardened[i];
  }

  kp->crypto_keypath_source_fingerprint_present = has_fingerprint;
  kp->crypto_keypath_source_fingerprint.crypto_keypath_source_fingerprint = fingerprint;
}

static void expect_bytes(const uint8_t* want, uint8_t len, const char* m) {
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(len, g_core.bip44_path_len, m);
  if (len > 0) {
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, g_core.bip44_path, len, m);
  }
}

/* Fills `want` the way BIP32 spells a path and returns the length, from the vector's own index and
 * hardened columns. */
static uint8_t expect_path(const uint32_t* index, const uint8_t* hardened, uint8_t count,
                           uint8_t* want) {
  for (uint8_t i = 0; i < count; i++) {
    uint32_t idx = index[i];
    if (hardened[i]) {
      idx |= 0x80000000;
    }
    want[i * 4] = idx >> 24;
    want[(i * 4) + 1] = (idx >> 16) & 0xff;
    want[(i * 4) + 2] = (idx >> 8) & 0xff;
    want[(i * 4) + 3] = idx & 0xff;
  }
  return count * 4;
}

void setUp(void) {
  memset(&g_core, 0, sizeof(g_core));
}

void tearDown(void) {}

void test_m_44h_60h_0h_0_0_is_stored_as_ten_big_endian_words_with_the_hardened_bit_set(void) {
  static const uint32_t index[5] = {44, 60, 0, 0, 0};
  static const uint8_t hardened[5] = {1, 1, 1, 0, 0};
  static const uint8_t want[20] = {0x80, 0x00, 0x00, 0x2c, 0x80, 0x00, 0x00, 0x3c, 0x80, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct crypto_keypath kp;

  build(&kp, index, NULL, hardened, 5, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, core_set_derivation_path(&kp));
  expect_bytes(want, 20, "m/44'/60'/0'/0/0");
}

void test_the_full_depth_the_struct_holds_is_stored(void) {
  static const uint32_t index[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  static const uint8_t hardened[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t want[BIP44_MAX_PATH_LEN];
  struct crypto_keypath kp;

  build(&kp, index, NULL, hardened, 10, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, core_set_derivation_path(&kp));
  expect_bytes(want, expect_path(index, hardened, 10, want), "ten components");
}

/* child-index is uint31, and 0x80000000 is the bit the shell ORs in for a hardened level: accepted,
 * an index of 2^31 unhardened would name m/0' while the sender meant 2147483648. */
void test_an_index_at_2_31_is_refused_because_it_is_the_hardened_bit_itself(void) {
  static const uint32_t index[1] = {0x80000000u};
  static const uint8_t hardened[1] = {0};
  struct crypto_keypath kp;

  build(&kp, index, NULL, hardened, 1, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(0, g_core.bip44_path_len);

  build(&kp, index, NULL, hardened, 1, 0, 0);
  kp.crypto_keypath_components_path_component_m[0].path_component_child_index_m = 0xffffffffu;
  TEST_ASSERT_EQUAL_INT(ERR_DATA, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(0, g_core.bip44_path_len);
}

/* One below the bound is a legal index, and it is the highest key the schema can name. */
void test_the_highest_index_the_schema_allows_is_stored(void) {
  static const uint32_t index[1] = {0x7fffffffu};
  static const uint8_t hardened[1] = {0};
  static const uint8_t want[4] = {0x7f, 0xff, 0xff, 0xff};
  struct crypto_keypath kp;

  build(&kp, index, NULL, hardened, 1, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, core_set_derivation_path(&kp));
  expect_bytes(want, 4, "2^31 - 1");
}

/* A component may carry is-hardened with no child index at all, which the schema permits and the
 * decoder reports as absent. The field then holds what the reused decode buffer already had, and
 * there is no derivation that a shell can honestly do with it. */
void test_a_component_without_a_child_index_is_refused_rather_than_reusing_the_last_scan(void) {
  static const uint32_t index[2] = {44, 0xa5a5a5a5};
  static const uint8_t present[2] = {1, 0};
  static const uint8_t hardened[2] = {1, 0};
  struct crypto_keypath kp;

  memset(g_core.bip44_path, 0xa5, sizeof(g_core.bip44_path));
  g_core.bip44_path_len = sizeof(g_core.bip44_path);

  build(&kp, index, present, hardened, 2, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(0, g_core.bip44_path_len);
}

void test_a_source_fingerprint_of_zero_is_refused_because_zero_means_none(void) {
  static const uint32_t index[1] = {44};
  static const uint8_t hardened[1] = {1};
  struct crypto_keypath kp;

  build(&kp, index, NULL, hardened, 1, 0, 1);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(0, g_core.bip44_path_len);

  build(&kp, index, NULL, hardened, 1, 0x12345678, 1);
  TEST_ASSERT_EQUAL_INT(ERR_OK, core_set_derivation_path(&kp));
}

/* A refusal partway through the loop leaves the previous path's bytes in the buffer, and that is
 * fine: bip44_path_len is what every consumer reads them with -- keycard_cmd_sign, core_export_key,
 * core_get_fingerprint, and core_task.c asks for the master fingerprint by passing a length of 0 --
 * so a length of 0 is the whole of "no path". */
void test_a_refusal_leaves_no_path_behind(void) {
  static const uint32_t good[5] = {44, 60, 0, 0, 0};
  static const uint8_t good_hardened[5] = {1, 1, 1, 0, 0};
  static const uint32_t bad[3] = {44, 0x80000000u, 0};
  static const uint8_t bad_hardened[3] = {1, 0, 0};
  struct crypto_keypath kp;

  build(&kp, good, NULL, good_hardened, 5, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_OK, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(20, g_core.bip44_path_len);

  build(&kp, bad, NULL, bad_hardened, 3, 0, 0);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, core_set_derivation_path(&kp));
  TEST_ASSERT_EQUAL_UINT8(0, g_core.bip44_path_len);
}

/* The route from camera bytes to derivation bytes, over the payloads test_ur_decode.c established
 * that the decoder accepts. The verdict comes from the vector's fields: a row whose path carries an
 * absent index, or an index at or above 2^31, or a fingerprint of 0, must be refused here -- and the
 * rest must land as the bytes BIP32 says, not one of them rearranged. */
void test_every_keypath_a_wallet_can_send_is_stored_whole_or_refused(void) {
  uint8_t want[BIP44_MAX_PATH_LEN];

  for (size_t i = 0; i < sizeof(UR_DECODE_ETH_CASES) / sizeof(UR_DECODE_ETH_CASES[0]); i++) {
    const ur_decode_eth_case_t* c = &UR_DECODE_ETH_CASES[i];
    if (!c->accept) {
      continue;
    }
    struct eth_sign_request out;
    memset(&out, 0, sizeof(out));
    if (cbor_decode_eth_sign_request(c->cbor, c->cbor_len, &out, NULL) != ZCBOR_SUCCESS) {
      TEST_FAIL_MESSAGE(c->name);
    }

    int refuses = c->has_fingerprint && c->source_fingerprint == 0;
    for (uint8_t n = 0; n < c->path_count; n++) {
      if (c->path_index[n] == UR_DECODE_PATH_NO_INDEX || c->path_index[n] & 0x80000000) {
        refuses = 1;
      }
    }

    char m[200];
    snprintf(m, sizeof(m), "%s", c->name);

    if (refuses) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, core_set_derivation_path(&out.eth_sign_request_derivation_path), m);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, g_core.bip44_path_len, m);
    } else {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, core_set_derivation_path(&out.eth_sign_request_derivation_path), m);
      expect_bytes(want, expect_path(c->path_index, c->path_hardened, c->path_count, want), m);
    }
  }

  for (size_t i = 0; i < sizeof(UR_DECODE_BTC_CASES) / sizeof(UR_DECODE_BTC_CASES[0]); i++) {
    const ur_decode_btc_case_t* c = &UR_DECODE_BTC_CASES[i];
    if (!c->accept) {
      continue;
    }
    struct btc_sign_request out;
    memset(&out, 0, sizeof(out));
    if (cbor_decode_btc_sign_request(c->cbor, c->cbor_len, &out, NULL) != ZCBOR_SUCCESS) {
      TEST_FAIL_MESSAGE(c->name);
    }

    struct crypto_keypath* kp = &out.btc_sign_request_btc_derivation_paths_crypto_keypath_m;
    if (!kp->crypto_keypath_components_path_component_m_count) {
      continue;
    }

    char m[200];
    snprintf(m, sizeof(m), "%s", c->name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, core_set_derivation_path(kp), m);
    expect_bytes(want, expect_path(c->path_index, c->path_hardened, c->path_count, want), m);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_m_44h_60h_0h_0_0_is_stored_as_ten_big_endian_words_with_the_hardened_bit_set);
  RUN_TEST(test_the_full_depth_the_struct_holds_is_stored);
  RUN_TEST(test_an_index_at_2_31_is_refused_because_it_is_the_hardened_bit_itself);
  RUN_TEST(test_the_highest_index_the_schema_allows_is_stored);
  RUN_TEST(test_a_component_without_a_child_index_is_refused_rather_than_reusing_the_last_scan);
  RUN_TEST(test_a_source_fingerprint_of_zero_is_refused_because_zero_means_none);
  RUN_TEST(test_a_refusal_leaves_no_path_behind);
  RUN_TEST(test_every_keypath_a_wallet_can_send_is_stored_whole_or_refused);
  return UNITY_END();
}
