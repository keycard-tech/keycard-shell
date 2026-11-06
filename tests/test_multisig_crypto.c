#include <string.h>

#include "bitcoin/multisig_crypto.h"
#include "crypto/aes.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "unity.h"

#include "vectors/vectors_multisig_crypto.h"

/*
 * Two derived values and one cipher. enc_key is what keeps a stored descriptor private; blob is the
 * four-byte index the store searches on, so it has to be the same for every session with the same card and
 * different for every card, without being a function of anything an attacker can read off the device. The
 * bytes below come from RFC 5869 and FIPS 198-1 computed outside this tree, so neither the HKDF labels nor
 * the little-endian fingerprint are being checked against themselves.
 */

static multisig_crypto_t session;

void setUp(void) {
  hal_host_aes_reset();
  hal_host_rng_seed(0x517a15);
  memset(&session, 0, sizeof(session));
}

void tearDown(void) {
  multisig_crypto_wipe(&session);
}

static void test_the_session_keys_are_the_derivation_the_header_describes(void) {
  for (size_t i = 0; i < MULTISIG_CRYPTO_KAT_COUNT; i++) {
    const multisig_crypto_kat_t* v = &MULTISIG_CRYPTO_KAT[i];
    uint8_t root[MULTISIG_ROOT_LEN];

    TEST_ASSERT_EQUAL_UINT(MULTISIG_ROOT_LEN, test_unhex(v->root, root, sizeof(root)));

    memset(&session, 0, sizeof(session));
    multisig_crypto_init(&session, root, v->master_fingerprint);

    TEST_ASSERT_HEX_MESSAGE(session.enc_key, sizeof(session.enc_key), v->enc_key, "enc_key");
    TEST_ASSERT_HEX_MESSAGE(session.blob, sizeof(session.blob), v->blob, "blob");
  }
}

static void test_the_blob_is_an_index_and_not_a_third_key(void) {
  uint8_t root_a[MULTISIG_ROOT_LEN], root_b[MULTISIG_ROOT_LEN];
  multisig_crypto_t other;

  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, root_a, sizeof(root_a));
  TEST_GIVEN(MULTISIG_CRYPTO_KAT[1].root, root_b, sizeof(root_b));

  multisig_crypto_init(&session, root_a, 0xDEADBEEF);
  multisig_crypto_init(&other, root_a, 0xDEADBEEF);
  TEST_ASSERT_EQUAL_MEMORY(session.blob, other.blob, sizeof(session.blob));

  /* Same card, same session, same index -- which is the whole point: the store matches on it. */
  multisig_crypto_init(&session, root_a, 0xDEADBEEF);
  TEST_ASSERT_EQUAL_MEMORY(session.blob, other.blob, sizeof(session.blob));

  /* A different card is a different index, and so is the same root under another master fingerprint. */
  multisig_crypto_init(&other, root_b, 0xDEADBEEF);
  TEST_ASSERT_TRUE(memcmp(session.blob, other.blob, sizeof(session.blob)) != 0);

  multisig_crypto_init(&other, root_a, 0x12345678);
  TEST_ASSERT_TRUE(memcmp(session.blob, other.blob, sizeof(session.blob)) != 0);

  /* Four bytes is a search key: the encryption key does not move with it. */
  TEST_ASSERT_TRUE(memcmp(session.enc_key, session.blob, sizeof(session.blob)) != 0);
  multisig_crypto_wipe(&other);
}

static void test_the_identity_path_is_the_one_eip_1581_reserves(void) {
  /* m/43'/60'/1581'/0'/0 -- the EIP-1581 identity key, used as the card-bound secret. A changed path here
   * silently changes every derived key, so it is pinned to the values rather than to the comment above it. */
  const uint32_t expected[MULTISIG_EIP1581_PATH_LEN] = {0x8000002b, 0x8000003c, 0x8000062d, 0x80000000, 0x00000000};

  TEST_ASSERT_EQUAL_UINT(5, MULTISIG_EIP1581_PATH_LEN);
  TEST_ASSERT_EQUAL_MEMORY(expected, MULTISIG_EIP1581_PATH, sizeof(expected));
}

static void test_a_descriptor_round_trips_and_refuses_to_decrypt_anything_else(void) {
  static const char body[] = "wpkh([deadbeef/48h/0h/0h/2h]xpub6/0/*)";
  const size_t len = sizeof(body) - 1;
  uint8_t nonce[CCM_NONCE_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d};
  uint8_t sealed[sizeof(body) + CCM_TAG_SIZE], opened[sizeof(body)];

  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, session.root, sizeof(session.root));
  multisig_crypto_init(&session, session.root, 0xDEADBEEF);

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_crypto_encrypt(&session, nonce, (const uint8_t*)body, len, sealed));
  TEST_ASSERT_TRUE(memcmp(sealed, body, len) != 0);

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_crypto_decrypt(&session, nonce, sealed, len + CCM_TAG_SIZE, opened));
  TEST_ASSERT_EQUAL_UINT(len, strlen((char*)opened));
  TEST_ASSERT_EQUAL_MEMORY(body, opened, len);

  sealed[0] ^= 0x01;
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, multisig_crypto_decrypt(&session, nonce, sealed, len + CCM_TAG_SIZE, opened));

  sealed[0] ^= 0x01;
  nonce[0] ^= 0x80;
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, multisig_crypto_decrypt(&session, nonce, sealed, len + CCM_TAG_SIZE, opened));
}

static void test_another_card_cannot_open_it(void) {
  static const char body[] = "descriptor";
  uint8_t root[MULTISIG_ROOT_LEN], nonce[CCM_NONCE_SIZE], sealed[32], opened[32];

  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, root, sizeof(root));
  memset(nonce, 0x2a, sizeof(nonce));

  multisig_crypto_init(&session, root, 0xDEADBEEF);
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_crypto_encrypt(&session, nonce, (const uint8_t*)body, sizeof(body) - 1, sealed));

  multisig_crypto_t other;
  memset(&other, 0, sizeof(other));
  TEST_GIVEN(MULTISIG_CRYPTO_KAT[1].root, root, sizeof(root));
  multisig_crypto_init(&other, root, 0xDEADBEEF);

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, multisig_crypto_decrypt(&other, nonce, sealed, sizeof(body) - 1 + CCM_TAG_SIZE, opened));
  multisig_crypto_wipe(&other);
}

static void test_wipe_leaves_nothing_behind(void) {
  uint8_t root[MULTISIG_ROOT_LEN];
  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, root, sizeof(root));

  multisig_crypto_init(&session, root, 0xDEADBEEF);

  const uint8_t any[sizeof(session)] = {0};
  TEST_ASSERT_TRUE(memcmp(session.root, any, sizeof(session.root)) != 0);

  multisig_crypto_wipe(&session);

  TEST_ASSERT_EQUAL_MEMORY(any, &session, sizeof(session));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_the_session_keys_are_the_derivation_the_header_describes);
  RUN_TEST(test_the_blob_is_an_index_and_not_a_third_key);
  RUN_TEST(test_the_identity_path_is_the_one_eip_1581_reserves);
  RUN_TEST(test_a_descriptor_round_trips_and_refuses_to_decrypt_anything_else);
  RUN_TEST(test_another_card_cannot_open_it);
  RUN_TEST(test_wipe_leaves_nothing_behind);

  return UNITY_END();
}
