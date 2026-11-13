#include "unity.h"

#include <string.h>

#include "core/core.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/keycard.h"
#include "keycard/keycard_cmdset.h"
#include "mem.h"
#include "sc_card.h"
#include "sc_host.h"
#include "session_v2.h"
#include "ui_host.h"
#include "ur/ur_types.h"
#include "vectors/vectors_core_eth.h"

/*
 * An ERC-4527 signing session, from the CBOR a wallet shows the camera to the CBOR the shell shows
 * back. The rows are in vectors_core_eth.h and carry the digest each request implies, computed by an
 * independent RLP and Keccak implementation that checks itself against the values the EIPs print.
 *
 * The digest is what makes the middle of the session assertable. The shell hashes what it parsed, the
 * card signs the hash it was sent and returns the signature with the public key it used, and the shell
 * then recovers that key from the signature over the hash it remembers -- so a parser that read the
 * transaction differently would fail to verify and report a card error rather than show a signature
 * over the wrong thing. The test pins the hash on its way in, by predicting the seal of the SIGN
 * command which covers it, and the signature on its way out.
 */

#define INS_EXPORT_KEY 0xc2
#define INS_SIGN 0xc0
#define EXPORT_PUBKEY 1       /* P2: the key alone */
#define EXPORT_PUBKEY_CHAIN 2 /* P2: the key and its chain code */

static v2_card_t card;
static unsigned seq;

void setUp(void) {
  memset(g_mem_heap, 0, sizeof(g_mem_heap));
  memset(&g_core, 0, sizeof(g_core));

  host_ui_reset();
  host_key_reset();
  hal_host_sc_reset();
  hal_host_aes_reset();

  seq = host_session_open(&card, &g_core.keycard);
}

void tearDown(void) {}

/* The seal of an export: the master key alone first, which is where the fingerprint the request is
 * checked against comes from, and then the signing key -- asked for with its chain code, so that is
 * what the answer has to carry. */
static size_t expect_export(uint8_t export_type, const uint8_t* path, size_t path_len,
                            uint8_t* seal) {
  size_t len = 0;
  v2_card_expect_command(&card, INS_EXPORT_KEY, 1, export_type, path, path_len, seal, &len);
  return len;
}

static void card_answers_export(const uint8_t priv[static 32], bool with_chain) {
  uint8_t pub[ECC256_POINT_SIZE + 1];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, priv, pub));

  uint8_t plain[128];
  size_t n = 0;

  plain[n++] = 0xa1;
  plain[n++] = (uint8_t)(with_chain ? 67 + 34 : 67);
  plain[n++] = 0x80;
  plain[n++] = 65;
  memcpy(&plain[n], pub, 65);
  n += 65;

  if (with_chain) {
    /* Any chain code at all: which key a request was made for is not what these rows are about. */
    plain[n++] = 0x82;
    plain[n++] = 32;
    memset(&plain[n], 0x51, 32);
    n += 32;
  }

  plain[n++] = 0x90;
  plain[n++] = 0x00;

  uint8_t sealed[256];
  const size_t len = v2_card_reply(&card, plain, n, sealed);
  sc_card_answer(sealed, len, (uint8_t)seq++);
}

/* The seal of the SIGN command, which covers the digest and the path: the one assertion that says
 * what the shell hashed. */
static size_t expect_sign(const uint8_t* digest, uint8_t* seal) {
  uint8_t data[32 + sizeof(CORE_ETH_PATH)];
  memcpy(data, digest, 32);
  memcpy(&data[32], CORE_ETH_PATH, sizeof(CORE_ETH_PATH));

  size_t len = 0;
  v2_card_expect_command(&card, INS_SIGN, 1, KEYCARD_SIGN_ECDSA_SECP256K1, data, sizeof(data), seal,
                         &len);
  return len;
}

/* The card's answer, in the template the applet answers with: a 0xa0 with the public key that made
 * the signature, then the DER of the signature itself. */
static void card_answers_sign(const uint8_t* reply, size_t len) {
  uint8_t plain[256];
  memcpy(plain, reply, len);
  plain[len] = 0x90;
  plain[len + 1] = 0x00;

  uint8_t sealed[256];
  const size_t sealed_len = v2_card_reply(&card, plain, len + 2, sealed);
  sc_card_answer(sealed, sealed_len, (uint8_t)seq++);
}

/* The fingerprint the request must name, computed the way a wallet computes it. */
static uint32_t master_fingerprint(void) {
  uint8_t pub[ECC256_POINT_SIZE + 1];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key33(&secp256k1, CORE_ETH_SIGN_PRIV, pub));

  uint8_t h[RIPEMD160_DIGEST_LENGTH];
  hash160(pub, PUBKEY_COMPRESSED_LEN, h);

  return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
}

static void given_request(struct eth_sign_request* request, const core_eth_case_t* c) {
  memset(request, 0, sizeof(*request));

  /* qrscan.c decodes the request into the pool that also holds the sign data, and the shell points at
   * those bytes rather than copying them -- so the pool holds them here too. */
  memcpy(g_mem_heap, c->sign_data, c->sign_data_len);
  request->eth_sign_request_sign_data.value = g_mem_heap;
  request->eth_sign_request_sign_data.len = c->sign_data_len;

  request->eth_sign_request_data_type.sign_data_type_choice = c->data_type;

  request->eth_sign_request_request_id_present = c->has_request_id != 0;
  request->eth_sign_request_request_id.eth_sign_request_request_id.value = CORE_ETH_REQUEST_ID;
  request->eth_sign_request_request_id.eth_sign_request_request_id.len =
      sizeof(CORE_ETH_REQUEST_ID);

  request->eth_sign_request_chain_id_present = c->has_chain_id != 0;
  request->eth_sign_request_chain_id.eth_sign_request_chain_id = (int32_t)c->chain_id;

  for (size_t i = 0; i < sizeof(CORE_ETH_PATH) / 4; i++) {
    const uint32_t raw = ((uint32_t)CORE_ETH_PATH[i * 4] << 24) |
                         ((uint32_t)CORE_ETH_PATH[i * 4 + 1] << 16) |
                         ((uint32_t)CORE_ETH_PATH[i * 4 + 2] << 8) | CORE_ETH_PATH[i * 4 + 3];
    struct path_component* component =
        &request->eth_sign_request_derivation_path.crypto_keypath_components_path_component_m[i];
    component->path_component_child_index_m_present = true;
    component->path_component_child_index_m = raw & 0x7fffffff;
    component->path_component_is_hardened_m = (raw & 0x80000000) != 0;
  }

  request->eth_sign_request_derivation_path.crypto_keypath_components_path_component_m_count =
      sizeof(CORE_ETH_PATH) / 4;
  request->eth_sign_request_derivation_path.crypto_keypath_depth_present = true;
  request->eth_sign_request_derivation_path.crypto_keypath_depth.crypto_keypath_depth =
      sizeof(CORE_ETH_PATH) / 4;
  request->eth_sign_request_derivation_path.crypto_keypath_source_fingerprint_present = true;
  request->eth_sign_request_derivation_path.crypto_keypath_source_fingerprint
      .crypto_keypath_source_fingerprint = master_fingerprint();
}

static const char* confirmation_screen(uint8_t data_type) {
  switch (data_type) {
  case sign_data_type_eth_raw_bytes_m_c:
    return "ui_display_msg";
  case sign_data_type_eth_typed_data_m_c:
    return "ui_display_eip712";
  default:
    return "ui_display_eth_tx";
  }
}

static void run_row(const core_eth_case_t* c) {
  struct eth_sign_request request;
  given_request(&request, c);

  uint8_t seal[256];
  expect_export(EXPORT_PUBKEY, NULL, 0, seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, false);
  expect_export(EXPORT_PUBKEY_CHAIN, CORE_ETH_PATH, sizeof(CORE_ETH_PATH), seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, true);

  host_ui_answer_call(confirmation_screen(c->data_type), CORE_EVT_UI_OK);
  host_ui_answer_call("ui_display_ur_qr", CORE_EVT_UI_OK);

  uint8_t sign_seal[256];
  size_t sign_seal_len = 0;
  if (c->digest != NULL) {
    sign_seal_len = expect_sign(c->digest, sign_seal);
    card_answers_sign(c->card_reply, c->card_reply_len);
  }

  core_eth_eip4527_run(&request);

  if (c->digest == NULL) {
    /* Refused before anything was signed: no QR where the signature belongs, an error in its place,
     * and the card never asked to sign. */
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, host_ui_call_count("ui_display_ur_qr"), c->name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, host_ui_info_calls(), c->name);
    sc_card_assert_no_apdu(3);
    return;
  }

  /* The user was asked, once, about the thing being signed. */
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, host_ui_call_count(confirmation_screen(c->data_type)), c->name);

  /* The hash on its way in. */
  uint8_t block[256];
  TEST_ASSERT_EQUAL_size_t_MESSAGE(sign_seal_len + 6, sc_card_apdu(3, block, sizeof(block)),
                                   c->name);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x18, block[1], c->name);
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(sign_seal, &block[5], sign_seal_len, c->name);
  sc_card_assert_no_apdu(4);

  /* And the signature on its way out. */
  uint32_t len = 0;
  ur_type_t type = 0;
  const uint8_t* qr = host_ui_ur_qr(&len, &type);
  TEST_ASSERT_NOT_NULL_MESSAGE(qr, c->name);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(c->expect_cbor_len, len, c->name);
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(c->expect_cbor, qr, len, c->name);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(ETH_SIGNATURE, type, c->name);
}

void test_sign_requests(void) {
  for (size_t i = 0; i < sizeof(CORE_ETH_CASES) / sizeof(CORE_ETH_CASES[0]); i++) {
    setUp();
    run_row(&CORE_ETH_CASES[i]);
  }
}

void test_a_refusal_to_confirm_shows_no_signature(void) {
  const core_eth_case_t* c = &CORE_ETH_CASES[0];

  struct eth_sign_request request;
  given_request(&request, c);

  uint8_t seal[256];
  expect_export(EXPORT_PUBKEY, NULL, 0, seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, false);
  expect_export(EXPORT_PUBKEY_CHAIN, CORE_ETH_PATH, sizeof(CORE_ETH_PATH), seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, true);

  /* The user looks at the transaction and puts the device down. */
  host_ui_answer_call("ui_display_eth_tx", CORE_EVT_UI_CANCELLED);

  core_eth_eip4527_run(&request);

  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_display_ur_qr"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_info_calls());
  sc_card_assert_no_apdu(3);
}

/* A request naming someone else's wallet is refused before the transaction is looked at: the
 * fingerprint of the card in hand is checked against the one the request was made for. */
void test_a_request_for_another_wallet_is_refused(void) {
  const core_eth_case_t* c = &CORE_ETH_CASES[0];

  struct eth_sign_request request;
  given_request(&request, c);
  request.eth_sign_request_derivation_path.crypto_keypath_source_fingerprint
      .crypto_keypath_source_fingerprint ^= 1;

  uint8_t seal[256];
  expect_export(EXPORT_PUBKEY, NULL, 0, seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, false);
  expect_export(EXPORT_PUBKEY_CHAIN, CORE_ETH_PATH, sizeof(CORE_ETH_PATH), seal);
  card_answers_export(CORE_ETH_SIGN_PRIV, true);

  core_eth_eip4527_run(&request);

  TEST_ASSERT_EQUAL_UINT(1, host_ui_info_calls());
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_display_eth_tx"));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_display_ur_qr"));
  sc_card_assert_no_apdu(3);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_sign_requests);
  RUN_TEST(test_a_refusal_to_confirm_shows_no_signature);
  RUN_TEST(test_a_request_for_another_wallet_is_refused);

  return UNITY_END();
}
