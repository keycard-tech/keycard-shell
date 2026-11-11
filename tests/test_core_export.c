#include "unity.h"

#include <string.h>

#include "core/core.h"
#include "crypto/bip32.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/command.h"
#include "keycard/keycard.h"
#include "keycard/secure_channel.h"
#include "keys_host.h"
#include "sc_card.h"
#include "sc_host.h"
#include "sc_v2_card.h"
#include "ui_host.h"

/*
 * A key leaving the shell.
 *
 * INS_GET_PUBLIC is the one command whose whole purpose is to hand something to the host, and the only
 * one the user has to agree to. What comes back is a layout a wallet parses -- the master fingerprint,
 * the derived public key, and for an extended request the chain code -- and every byte of it is
 * computed here twice: once by the shell, and once by a card model that holds keys of its own and does
 * not know what the shell is going to answer.
 *
 * The shell asks for two things to serve one request. It exports the master key first, to have its
 * fingerprint, and then the path the host named -- both sealed, so the only way to see inside them is
 * to predict the seal, which requires producing the same plaintext the shell did. That is what makes
 * the prediction an assertion rather than a formality: the derivation path in the clear is the one the
 * host sent, and the key that comes back is the one the card's own private key says it must be.
 *
 * The channel is opened with securechannel_open() rather than by activating a card, because what is
 * under test is a command and not how the shell came to hold a session. The card is a v2 one whose
 * certificate a CA vouches for, that CA installed with host_key_set() the way the release tool installs
 * the real one.
 */

#define RNG_SEED 0x5eedULL

#define INS_EXPORT_KEY 0xc2
#define EXPORT_PUBKEY 1        /* P2: the key alone */
#define EXPORT_PUBKEY_CHAIN 2  /* P2: the key and its chain code */

static command_t* cmd;
static v2_card_t card;
static unsigned seq;

/* TEST-ONLY KEY: invented for these tests, used nowhere else, guarding nothing real. */
static const uint8_t CARD_ID_PRIV[32] = {0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
                                         0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02,
                                         0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
                                         0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03};

/* TEST-ONLY KEY: invented for these tests, used nowhere else, guarding nothing real. */
static const uint8_t CARD_EPHEM_PRIV[32] = {0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91,
                                            0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12,
                                            0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92,
                                            0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13};

/* TEST-ONLY KEY: invented for these tests, used nowhere else, guarding nothing real. The master key
 * is what the shell exports to get a fingerprint; the derived one is what the host asked for. */
static const uint8_t MASTER_PRIV[32] = {0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1,
                                        0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12, 0x22,
                                        0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2,
                                        0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13, 0x23};

/* TEST-ONLY KEY: invented for these tests, used nowhere else, guarding nothing real. */
static const uint8_t DERIVED_PRIV[32] = {0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1,
                                         0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12, 0x22, 0x32,
                                         0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2,
                                         0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13, 0x23, 0x33};

static const uint8_t CHAIN_CODE[32] = {0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1, 0xc1,
                                       0xd1, 0xe1, 0xf1, 0x02, 0x12, 0x22, 0x32, 0x42,
                                       0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2,
                                       0xd2, 0xe2, 0xf2, 0x03, 0x13, 0x23, 0x33, 0x43};

void setUp(void) {
  host_ui_reset();
  host_key_reset();
  hal_host_sc_reset();
  hal_host_flash_reset();
  hal_host_aes_reset();
  memset(&g_core, 0, sizeof(g_core));

  cmd = &g_core.usb_command;
  seq = 0;
}

void tearDown(void) {}

/* A card switched on and a v2 channel open on it, the model left holding the same session keys. */
static void channel_open(void) {
  keycard_t* kc = &g_core.keycard;
  keycard_init(kc);
  sc_card_activate(&kc->sc);

  v2_card_init(&card, CARD_ID_PRIV, CARD_EPHEM_PRIV);
  v2_card_cert_sign(&card, SC_V2_CA_PRIV);

  uint8_t ca[33];
  v2_card_ca_public(ca);
  host_key_set(KEYCARD_CA_KEY, ca);

  hal_host_rng_seed(RNG_SEED);
  v2_card_draws(&card);

  v2_card_queue_open(&card, (uint8_t)seq++);

  /* The generator starts over for the module, so the salt and ephemeral key it draws are the ones the
   * model just drew from the same place. */
  hal_host_rng_seed(RNG_SEED);

  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc->ch, &kc->sc, &kc->apdu, SC_V2, card.cert));
  TEST_ASSERT_EQUAL_UINT8(1, kc->ch.open);
}

/* A GET_PUBLIC carrying the given path, as the framing delivers one. */
static void given_path(uint8_t p2, const uint8_t* path, size_t path_len) {
  const size_t components = path_len / 4;
  const size_t len = 6 + components * 4;

  uint8_t buf[6 + BIP44_MAX_PATH_LEN];

  buf[0] = 0xe0;
  buf[1] = INS_GET_PUBLIC;
  buf[2] = 0x00;
  buf[3] = p2;
  buf[4] = (uint8_t)(1 + components * 4);
  buf[5] = (uint8_t)components;
  memcpy(&buf[6], path, components * 4);

  memset(cmd, 0, sizeof(*cmd));

  TEST_ASSERT_EQUAL_INT(ERR_OK, command_init_recv(cmd, len));
  command_receive(cmd, buf, len);
  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, cmd->status);

  cmd->status = COMMAND_PROCESSING;
}

/* The seal of the EXPORT KEY the shell will send for this request. The seal is a function of the
 * plaintext, so computing it is the only way to know what the shell put inside -- and agreeing with
 * the shell later means the two derived the same command from the host's request. */
static size_t expect_export(uint8_t export_type, const uint8_t* path, size_t path_len, uint8_t* out) {
  size_t len = 0;
  v2_card_expect_command(&card, INS_EXPORT_KEY, 1, export_type, path, path_len, out, &len);
  return len;
}

/* The card's answer: a template with the public key, the chain code when asked for, and the status
 * word inside the seal as every v2 reply carries it. */
static void card_answers_export(const uint8_t priv[32], bool with_chain) {
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
    plain[n++] = 0x82;
    plain[n++] = 32;
    memcpy(&plain[n], CHAIN_CODE, 32);
    n += 32;
  }

  plain[n++] = 0x90;
  plain[n++] = 0x00;

  uint8_t sealed[256];
  const size_t len = v2_card_reply(&card, plain, n, sealed);
  sc_card_answer(sealed, len, (uint8_t)seq++);
}

/* What the shell exports at m is what a wallet would compute from it: the first four bytes of the
 * hash160 of the compressed master key, in the order the hash gives them. */
static void expect_master_fingerprint(uint8_t out[4]) {
  uint8_t pub[ECC256_POINT_SIZE + 1];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key33(&secp256k1, MASTER_PRIV, pub));

  uint8_t h[RIPEMD160_DIGEST_LENGTH];
  hash160(pub, PUBKEY_COMPRESSED_LEN, h);

  memcpy(out, h, 4);
}

/* One report's worth, which is the widest thing command_send will hand over at a time -- its length is
 * a byte, and 253 plus a status word is all of what a command may answer. */
static size_t answer(uint8_t* out) {
  return command_send(cmd, out, 255);
}

static void test_an_approved_export_carries_the_card_key_and_the_masters_fingerprint(void) {
  channel_open();

  static const uint8_t path[4] = {0x80, 0x00, 0x00, 0x2c}; /* m/44' */

  uint8_t seal_master[256];
  uint8_t seal_derived[256];
  const size_t master_len = expect_export(EXPORT_PUBKEY, NULL, 0, seal_master);
  card_answers_export(MASTER_PRIV, false);

  const size_t derived_len = expect_export(EXPORT_PUBKEY, path, sizeof(path), seal_derived);
  card_answers_export(DERIVED_PRIV, false);

  host_ui_answer_call("ui_confirm_export_key", CORE_EVT_UI_OK);

  uint8_t want_fingerprint[4];
  expect_master_fingerprint(want_fingerprint);

  given_path(0, path, sizeof(path));
  core_usb_run();

  uint8_t out[256] = { 0 };
  TEST_ASSERT_EQUAL_size_t(74, answer(out));

  /* The layout a wallet reads: a fingerprint of four, the key of sixty-five, no chain code, then the
   * status word the shell appends itself. */
  TEST_ASSERT_EQUAL_UINT8(4, out[0]);
  TEST_ASSERT_EQUAL_MEMORY(want_fingerprint, &out[1], 4);
  TEST_ASSERT_EQUAL_UINT8(65, out[5]);

  uint8_t want_pub[ECC256_POINT_SIZE + 1];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, DERIVED_PRIV, want_pub));
  TEST_ASSERT_EQUAL_MEMORY(want_pub, &out[6], 65);

  TEST_ASSERT_EQUAL_UINT8(0, out[71]); /* no chain code follows */
  TEST_ASSERT_EQUAL_HEX16(0x9000, (uint16_t)((out[72] << 8) | out[73]));

  /* Three blocks and no fourth: the handshake, then the two exports. */
  sc_card_assert_no_apdu(3);

  /* The exports are sealed, so this is the assertion that says what went into them: the master export
   * carries no path, and the second carries the one the host sent, under the type that asks for a key
   * alone. */
  uint8_t block[256];
  TEST_ASSERT_EQUAL_size_t(master_len + 6u, sc_card_apdu(1, block, sizeof(block)));
  TEST_ASSERT_EQUAL_UINT8(0x18, block[1]);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)master_len, block[4]);
  TEST_ASSERT_EQUAL_MEMORY(seal_master, &block[5], master_len);

  TEST_ASSERT_EQUAL_size_t(derived_len + 6u, sc_card_apdu(2, block, sizeof(block)));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)derived_len, block[4]);
  TEST_ASSERT_EQUAL_MEMORY(seal_derived, &block[5], derived_len);

  /* Approval is not a stamp the shell remembers: the next request asks again. */
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_confirm_export_key"));
}

/* The extended request is the same exchange with the chain code along, and it is what a wallet needs
 * to derive the rest of a tree from what the shell handed it. The card is asked for it by a different
 * export type, which is the only thing distinguishing the two on the wire. */
static void test_an_extended_export_adds_the_chain_code_the_card_gave(void) {
  channel_open();

  static const uint8_t path[8] = {0x80, 0x00, 0x00, 0x2c, 0x80, 0x00, 0x00, 0x00}; /* m/44'/0' */

  uint8_t seal_master[256];
  uint8_t seal_derived[256];
  expect_export(EXPORT_PUBKEY, NULL, 0, seal_master);
  card_answers_export(MASTER_PRIV, false);

  const size_t derived_len = expect_export(EXPORT_PUBKEY_CHAIN, path, sizeof(path), seal_derived);
  card_answers_export(DERIVED_PRIV, true);

  host_ui_answer_call("ui_confirm_export_key", CORE_EVT_UI_OK);

  given_path(1, path, sizeof(path));
  core_usb_run();

  uint8_t out[256] = { 0 };
  TEST_ASSERT_EQUAL_size_t(106, answer(out));

  TEST_ASSERT_EQUAL_UINT8(4, out[0]);
  TEST_ASSERT_EQUAL_UINT8(65, out[5]);
  TEST_ASSERT_EQUAL_UINT8(32, out[71]); /* the chain code follows, and is thirty-two long */
  TEST_ASSERT_EQUAL_MEMORY(CHAIN_CODE, &out[72], 32);
  TEST_ASSERT_EQUAL_HEX16(0x9000, (uint16_t)((out[104] << 8) | out[105]));

  sc_card_assert_no_apdu(3);

  uint8_t block[256];
  TEST_ASSERT_EQUAL_size_t(derived_len + 6u, sc_card_apdu(2, block, sizeof(block)));
  TEST_ASSERT_EQUAL_MEMORY(seal_derived, &block[5], derived_len);
}

/* The fingerprint of the master key is asked for once and kept afterwards, which is the difference
 * between a command that costs the card two exports and one that costs it three. The second request
 * still gets its own export -- what is cached is the master, not the answer. */
static void test_the_master_key_is_exported_once_for_two_requests(void) {
  channel_open();

  static const uint8_t path[4] = {0x80, 0x00, 0x00, 0x2c};

  uint8_t seal[256];
  expect_export(EXPORT_PUBKEY, NULL, 0, seal);
  card_answers_export(MASTER_PRIV, false);

  expect_export(EXPORT_PUBKEY, path, sizeof(path), seal);
  card_answers_export(DERIVED_PRIV, false);

  expect_export(EXPORT_PUBKEY, path, sizeof(path), seal);
  card_answers_export(DERIVED_PRIV, false);

  host_ui_answer_call("ui_confirm_export_key", CORE_EVT_UI_OK);

  given_path(0, path, sizeof(path));
  core_usb_run();

  uint8_t out[256];
  TEST_ASSERT_EQUAL_size_t(74, answer(out));

  given_path(0, path, sizeof(path));
  core_usb_run();

  TEST_ASSERT_EQUAL_size_t(74, answer(out));

  /* Four blocks: the handshake and three exports -- master, then one per request. No fourth export,
   * because the shell already knows who the master key is. */
  sc_card_assert_no_apdu(4);

  TEST_ASSERT_EQUAL_UINT(2, host_ui_call_count("ui_confirm_export_key"));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_an_approved_export_carries_the_card_key_and_the_masters_fingerprint);
  RUN_TEST(test_an_extended_export_adds_the_chain_code_the_card_gave);
  RUN_TEST(test_the_master_key_is_exported_once_for_two_requests);

  return UNITY_END();
}
