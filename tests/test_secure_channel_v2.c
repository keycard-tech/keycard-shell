#include <stdint.h>
#include <string.h>

#include "crypto/aes.h"
#include "crypto/ecdsa.h"
#include "crypto/hkdf.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "iso7816/smartcard.h"
#include "keycard/keycard.h"
#include "keycard/secure_channel.h"
#include "keycard/secure_channel_v2.h"
#include "sc_host.h"
#include "unity.h"

/*
 * secure_channel_v2.c is the encrypted channel a modern Keycard is talked to: an ECDHE handshake
 * whose session keys come from HKDF over the shared secret, a card signature over the transcript
 * checked against the identity key from SELECT, and then every APDU sealed with AES-128-CCM under a
 * counter nonce. It is asserted against a second implementation of the same protocol, written here
 * from the transcript and key schedule, rather than against itself: what matters is that the bytes
 * the shell produces are what a card holds the same keys to, and that a card which cannot prove its
 * identity gets nothing further.
 *
 * The handshake is deterministic given the seeded RNG, because the shell's salt and ephemeral key
 * are drawn from it: they are drawn once here to build the card's answer, then drawn again by the
 * module from the same seed.
 */

#define ATR_T1 "3BFA1300FF910131FE000031C173C84000009000D2" /* specific mode, T=1, LRC */
#define IFS_ANSWER "00E101FE1E"                             /* the card's answer to S(IFS) */
#define LABEL "sc_v2_ccm"
#define LABEL_LEN 9

#define RNG_SEED 0x5eedULL

/* The card's identity and ephemeral keys, fixed so the transcript is reproducible. */
static const uint8_t CARD_ID_PRIV[32] = {0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71,
                                         0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1,
                                         0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72,
                                         0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2};

static const uint8_t CARD_EPHEMERAL_PRIV[32] = {0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77,
                                                0x87, 0x97, 0xa7, 0xb7, 0xc7, 0xd7, 0xe7, 0xf7,
                                                0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78,
                                                0x88, 0x98, 0xa8, 0xb8, 0xc8, 0xd8, 0xe8, 0xf8};

static keycard_t kc;
static uint8_t cert[SCV2_CERT_SIZE];

void setUp(void) {
  hal_host_sc_reset();
  memset(&kc, 0, sizeof(kc));
  smartcard_init(&kc.sc);
  kc.ch.open = 0;

  /* The identity public key is the first 65 bytes of the certificate the applet handed back. */
  memset(cert, 0, sizeof(cert));
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, CARD_ID_PRIV, cert));
}

void tearDown(void) {}

static void activate(void) {
  hal_host_sc_reply_hex(ATR_T1);
  hal_host_sc_reply_hex(IFS_ANSWER);
  smartcard_activate(&kc.sc);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(SC_READY, kc.sc.state, "activation");
  hal_host_sc_sent_clear();
}

/* A card's answer as a T=1 I-block: NAD, the PCB carrying N(S), length, payload and the LRC of
 * 11.4.4. N(S) is one bit and counts modulo 2 (11.6, and T1_I_SEQ_MSK is 0x40), so the third block
 * is back to 0 -- pass the count and let it wrap, because a 2 in that field is the top bit of an
 * R-block instead. */
static void card_answer(const uint8_t* info, size_t len, uint8_t seq) {
  const uint8_t hdr[3] = {0x00, (uint8_t)((seq & 1) << 6), (uint8_t)len};

  uint8_t lrc = hdr[0] ^ hdr[1] ^ hdr[2];
  for (size_t i = 0; i < len; i++) {
    lrc ^= info[i];
  }

  hal_host_sc_reply(hdr, sizeof(hdr));
  hal_host_sc_reply(info, len);
  hal_host_sc_reply(&lrc, 1);
}

static void assert_apdu_bytes(const uint8_t* want, size_t len) {
  uint8_t got[128];

  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)(len + 4), (unsigned)hal_host_sc_sent_len(), "one block");
  const size_t sent = hal_host_sc_apdu(got, sizeof(got));
  TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)len, (unsigned)sent, "apdu length");
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(want, got, (unsigned)((len < sent) ? len : sent), "apdu");
}

/* The transcript the card signs: SHA-256 over the label, the shell's salt and both ephemeral public
 * keys, in that order. */
static void transcript(const uint8_t salt[SCV2_SALT_SIZE], const uint8_t client_pub[SCV2_PUBKEY_SIZE],
                       const uint8_t card_pub[SCV2_PUBKEY_SIZE], uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256 = {0};
  sha256_Init(&sha256);
  sha256_Update(&sha256, (const uint8_t*)LABEL, LABEL_LEN);
  sha256_Update(&sha256, salt, SCV2_SALT_SIZE);
  sha256_Update(&sha256, client_pub, SCV2_PUBKEY_SIZE);
  sha256_Update(&sha256, card_pub, SCV2_PUBKEY_SIZE);
  sha256_Final(&sha256, out);
}

/* The session keys, from the card's side of the same ECDHE. */
static void session_keys(const uint8_t salt[SCV2_SALT_SIZE], const uint8_t client_pub[SCV2_PUBKEY_SIZE],
                         uint8_t h2c[AES_128_KEY_SIZE], uint8_t c2h[AES_128_KEY_SIZE]) {
  uint8_t shared[SCV2_PUBKEY_SIZE];
  uint8_t okm[SCV2_OKM_SIZE];

  TEST_ASSERT_EQUAL_INT(0,
      ecdh_multiply(&secp256k1, CARD_EPHEMERAL_PRIV, client_pub, shared));
  TEST_ASSERT_EQUAL_INT(0,
      hkdf_sha256(salt, SCV2_SALT_SIZE, &shared[1], SHA256_DIGEST_LENGTH, (const uint8_t*)LABEL,
                  LABEL_LEN, okm, sizeof(okm)));
  memcpy(h2c, okm, AES_128_KEY_SIZE);
  memcpy(c2h, &okm[AES_128_KEY_SIZE], AES_128_KEY_SIZE);
}

static void zero_nonce(uint8_t nonce[SCV2_NONCE_SIZE]) {
  memset(nonce, 0, SCV2_NONCE_SIZE);
}

static void nonce_inc(uint8_t nonce[SCV2_NONCE_SIZE]) {
  for (int i = SCV2_NONCE_SIZE - 1; i >= 0; i--) {
    if (++nonce[i] != 0) {
      return;
    }
  }
}

/* DER for what the module hands to ecdsa_sig_from_der: a sequence of two INTEGERs, minimally
 * encoded. */
static size_t der_sig(const uint8_t sig[64], uint8_t* out) {
  uint8_t body[70];
  size_t n = 0;

  for (int half = 0; half < 2; half++) {
    const uint8_t* v = &sig[half * 32];
    size_t len = 32;
    while ((len > 1) && (v[0] == 0) && (v[1] < 0x80)) {
      v++;
      len--;
    }

    body[n++] = 0x02;
    if (v[0] & 0x80) {
      body[n++] = (uint8_t)(len + 1);
      body[n++] = 0x00;
    } else {
      body[n++] = (uint8_t)len;
    }
    memcpy(&body[n], v, len);
    n += len;
  }

  out[0] = 0x30;
  out[1] = (uint8_t)n;
  memcpy(&out[2], body, n);
  return n + 2;
}

/* What a well-formed card answers OPEN_SECURE_CHANNEL with: its ephemeral public key and a
 * signature over the transcript by the given identity key. */
static size_t card_open_answer(const uint8_t salt[SCV2_SALT_SIZE],
                               const uint8_t client_pub[SCV2_PUBKEY_SIZE], const uint8_t id_priv[32],
                               uint8_t* out, size_t maxlen) {
  uint8_t card_pub[SCV2_PUBKEY_SIZE];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, CARD_EPHEMERAL_PRIV, card_pub));

  uint8_t hash[SHA256_DIGEST_LENGTH];
  transcript(salt, client_pub, card_pub, hash);

  uint8_t raw[64];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_sign(&secp256k1, id_priv, hash, raw));

  uint8_t der[SCV2_SIG_DER_MAX];
  const size_t der_len = der_sig(raw, der);

  const size_t len = SCV2_PUBKEY_SIZE + der_len + 2;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)maxlen, (unsigned)len, "answer");

  memcpy(out, card_pub, SCV2_PUBKEY_SIZE);
  memcpy(&out[SCV2_PUBKEY_SIZE], der, der_len);
  out[len - 2] = 0x90;
  out[len - 1] = 0x00;

  return len;
}

/* The shell's salt and ephemeral private key come from the seeded RNG; drawing them here is how the
 * card model knows what to sign. */
static void read_handshake_draws(uint8_t salt[SCV2_SALT_SIZE], uint8_t client_priv[32],
                                 uint8_t client_pub[SCV2_PUBKEY_SIZE]) {
  hal_host_rng_seed(RNG_SEED);
  random_buffer(salt, SCV2_SALT_SIZE);
  random_buffer(client_priv, 32);
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, client_priv, client_pub));
}

void test_open_sends_the_salt_and_the_ephemeral_key(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  activate();
  card_answer(answer, answer_len, 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  TEST_ASSERT_EQUAL_UINT8(1, kc.ch.open);

  /* OPEN_SECURE_CHANNEL: the salt, then the uncompressed ephemeral key, 97 bytes of data. */
  uint8_t want[5 + SCV2_SALT_SIZE + SCV2_PUBKEY_SIZE + 1];
  want[0] = 0x80;
  want[1] = 0x10;
  want[2] = 0;
  want[3] = 0;
  want[4] = SCV2_SALT_SIZE + SCV2_PUBKEY_SIZE;
  memcpy(&want[5], salt, SCV2_SALT_SIZE);
  memcpy(&want[5 + SCV2_SALT_SIZE], client_pub, SCV2_PUBKEY_SIZE);
  want[sizeof(want) - 1] = 0x00;

  assert_apdu_bytes(want, sizeof(want));
}

/* The point of the handshake: a command sent after it is readable by the card, and the reply the
 * card seals is readable by the shell. */
void test_a_command_reaches_the_card_in_plaintext_it_holds_keys_for(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  uint8_t h2c[AES_128_KEY_SIZE];
  uint8_t c2h[AES_128_KEY_SIZE];
  session_keys(salt, client_pub, h2c, c2h);

  /* The card's answer to the command: three bytes sealed under the card-to-client key. */
  uint8_t nonce[SCV2_NONCE_SIZE];
  zero_nonce(nonce);
  uint8_t plain[3] = {0x03, 0x90, 0x00};
  uint8_t reply[sizeof(plain) + CCM_TAG_SIZE + 2];
  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c2h, nonce, plain, sizeof(plain), reply));
  memcpy(&reply[sizeof(plain) + CCM_TAG_SIZE], (uint8_t[]){0x90, 0x00}, 2);

  activate();
  card_answer(answer, answer_len, 0);
  card_answer(reply, sizeof(reply), 1);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  hal_host_sc_sent_clear();

  uint8_t pin[6];
  memset(pin, '1', sizeof(pin));
  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_v2_send_apdu(&kc.sc, &kc.ch.v2, &kc.apdu, pin, sizeof(pin)));

  /* What left is SECURED_APDU around a CCM seal; opening the seal must show the VERIFY command the
   * card is meant to see, header and all. */
  uint8_t sealed[64];
  const size_t sealed_len = hal_host_sc_apdu(sealed, sizeof(sealed));
  TEST_ASSERT_EQUAL_UINT(4 + 1 + (5 + sizeof(pin) + CCM_TAG_SIZE) + 1, sealed_len);
  TEST_ASSERT_EQUAL_UINT8(0x18, sealed[1]);
  TEST_ASSERT_EQUAL_UINT8(5 + sizeof(pin) + CCM_TAG_SIZE, sealed[4]);

  uint8_t inner[64];
  TEST_ASSERT_TRUE(aes128_ccm_decrypt(h2c, nonce, &sealed[5], sizeof(pin) + 5 + CCM_TAG_SIZE, inner));
  const uint8_t want_inner[11] = {0x80, 0x20, 0x00, 0x00, 0x06, '1', '1', '1', '1', '1', '1'};
  TEST_ASSERT_EQUAL_MEMORY(want_inner, inner, sizeof(want_inner));

  /* And the reply came back as the card sealed it. The sealed plaintext carries its own status word
   * and lr counts it, which is what lets APDU_SW and APDU_RESP_LEN read a channel answer the same way
   * they read a bare T=1 one -- so a card model must put the status word inside the plaintext. */
  TEST_ASSERT_EQUAL_UINT(sizeof(plain), kc.apdu.lr);
  TEST_ASSERT_EQUAL_MEMORY(plain, APDU_RESP(&kc.apdu), sizeof(plain));
}

/* Two identical commands must not look alike: the counter nonce is the only thing separating them,
 * and a repeat of the first nonce must not open the second. */
void test_each_command_advances_the_nonce(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  uint8_t h2c[AES_128_KEY_SIZE];
  uint8_t c2h[AES_128_KEY_SIZE];
  session_keys(salt, client_pub, h2c, c2h);

  uint8_t nonce0[SCV2_NONCE_SIZE];
  uint8_t nonce1[SCV2_NONCE_SIZE];
  zero_nonce(nonce0);
  memcpy(nonce1, nonce0, sizeof(nonce1));
  nonce_inc(nonce1);

  /* The card answers each command sealed under the nonce the shell is expected to be on, so a shell
   * that reused one would not be able to read the second reply either. */
  const uint8_t plain[3] = {0x03, 0x90, 0x00};
  uint8_t reply[3 + CCM_TAG_SIZE + 2];
  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c2h, nonce0, plain, sizeof(plain), reply));
  memcpy(&reply[3 + CCM_TAG_SIZE], (uint8_t[]){0x90, 0x00}, 2);

  uint8_t reply2[3 + CCM_TAG_SIZE + 2];
  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c2h, nonce1, plain, sizeof(plain), reply2));
  memcpy(&reply2[3 + CCM_TAG_SIZE], (uint8_t[]){0x90, 0x00}, 2);

  activate();
  card_answer(answer, answer_len, 0);
  card_answer(reply, sizeof(reply), 1);
  card_answer(reply2, sizeof(reply2), 2);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  hal_host_sc_sent_clear();

  const size_t sealed_len = 4 + 1 + (5 + 6 + CCM_TAG_SIZE) + 1;
  uint8_t pin[6];
  memset(pin, '1', sizeof(pin));
  uint8_t first[64];
  uint8_t second[64];

  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_v2_send_apdu(&kc.sc, &kc.ch.v2, &kc.apdu, pin, sizeof(pin)));
  TEST_ASSERT_EQUAL_UINT(sealed_len, hal_host_sc_apdu(first, sizeof(first)));

  hal_host_sc_sent_clear();
  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_v2_send_apdu(&kc.sc, &kc.ch.v2, &kc.apdu, pin, sizeof(pin)));
  TEST_ASSERT_EQUAL_UINT(sealed_len, hal_host_sc_apdu(second, sizeof(second)));

  /* Same key, same command, same length, and nothing in common but the header. */
  TEST_ASSERT_TRUE_MESSAGE(memcmp(&first[5], &second[5], sealed_len - 5) != 0,
                           "two commands sealed identically");

  uint8_t inner[64];
  TEST_ASSERT_TRUE(aes128_ccm_decrypt(h2c, nonce0, &first[5], 5 + 6 + CCM_TAG_SIZE, inner));
  TEST_ASSERT_TRUE(aes128_ccm_decrypt(h2c, nonce1, &second[5], 5 + 6 + CCM_TAG_SIZE, inner));

  /* The old nonce no longer opens anything: replaying the first seal gets the tag. */
  TEST_ASSERT_FALSE(aes128_ccm_decrypt(h2c, nonce0, &second[5], 5 + 6 + CCM_TAG_SIZE, inner));
}

/* A signature that cannot be parsed is refused where it stands -- and note which error it is: a
 * malformed DER is ERR_DATA, while a well-formed one by the wrong key is ERR_CRYPTO, below. Either
 * way the shell sends one block and no more, so nothing goes out under keys an impostor shares. */
void test_an_unparseable_signature_is_a_data_error(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));
  answer[SCV2_PUBKEY_SIZE + 4] ^= 0xff; /* inside the DER, at r */

  activate();
  card_answer(answer, answer_len, 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(5u + SCV2_SALT_SIZE + SCV2_PUBKEY_SIZE + 1u + 4u,
                                 (unsigned)hal_host_sc_sent_len(), "one block, nothing after");
}

/* The signature is checked against the identity key from SELECT, which is the one thing standing
 * between a reader and a card that made up an ephemeral key on the spot. */
void test_a_substituted_identity_is_caught(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  /* A signature by someone else's identity key, over the same transcript. */
  static const uint8_t other[32] = {0x09, 0x19, 0x29, 0x39, 0x49, 0x59, 0x69, 0x79,
                                    0x89, 0x99, 0xa9, 0xb9, 0xc9, 0xd9, 0xe9, 0xf9,
                                    0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
                                    0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa};

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, other, answer, sizeof(answer));

  activate();
  card_answer(answer, answer_len, 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
}

/* The card's ephemeral point is used in ECDHE before its signature is looked at, so the point
 * itself has to be refused when it is not on the curve -- that is where a small-subgroup or
 * invalid-curve oracle would be answered. */
void test_a_card_public_key_off_the_curve_is_refused(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  uint8_t bogus[SCV2_PUBKEY_SIZE];
  memset(bogus, 0, sizeof(bogus));
  bogus[0] = 0x04;
  memset(&bogus[1], 0xff, 64); /* no point with this x on secp256k1 */

  uint8_t refused[256];
  memcpy(refused, answer, answer_len);
  memcpy(refused, bogus, sizeof(bogus));

  activate();
  card_answer(refused, answer_len, 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(5u + SCV2_SALT_SIZE + SCV2_PUBKEY_SIZE + 1u + 4u,
                                 (unsigned)hal_host_sc_sent_len(), "one block, nothing after");
}

/* Less than a public key and a signature is not an answer at all. */
void test_a_short_open_answer_is_a_data_error(void) {
  activate();

  /* Public key and signature truncated, status word intact -- the length is checked after it. */
  uint8_t short_answer[SCV2_PUBKEY_SIZE - 1 + 2];
  memset(short_answer, 0x04, sizeof(short_answer) - 2);
  short_answer[sizeof(short_answer) - 2] = 0x90;
  short_answer[sizeof(short_answer) - 1] = 0x00;
  card_answer(short_answer, sizeof(short_answer), 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_DATA, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));
  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
}

/* A reply whose CCM tag has been disturbed is not decrypted into an APDU. */
void test_a_tampered_reply_is_not_unlocked(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  uint8_t h2c[AES_128_KEY_SIZE];
  uint8_t c2h[AES_128_KEY_SIZE];
  session_keys(salt, client_pub, h2c, c2h);

  uint8_t nonce[SCV2_NONCE_SIZE];
  zero_nonce(nonce);
  const uint8_t plain[3] = {0x03, 0x90, 0x00};
  uint8_t reply[3 + CCM_TAG_SIZE + 2];
  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c2h, nonce, plain, sizeof(plain), reply));
  memcpy(&reply[3 + CCM_TAG_SIZE], (uint8_t[]){0x90, 0x00}, 2);
  reply[3] ^= 0x01; /* the tag */

  activate();
  card_answer(answer, answer_len, 0);
  card_answer(reply, sizeof(reply), 1);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));

  uint8_t pin[6];
  memset(pin, '1', sizeof(pin));
  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO,
                        securechannel_v2_send_apdu(&kc.sc, &kc.ch.v2, &kc.apdu, pin, sizeof(pin)));
}

/* 6982 is the applet saying the security condition is not satisfied; the channel is over, whatever
 * the caller wanted to believe. */
void test_the_card_refusing_the_security_condition_closes_the_exchange(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  activate();
  card_answer(answer, answer_len, 0);
  card_answer((const uint8_t[]){0x69, 0x82}, 2, 1);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));

  uint8_t pin[6];
  memset(pin, '1', sizeof(pin));
  APDU_RESET(&kc.apdu);
  APDU_CLA(&kc.apdu) = 0x80;
  APDU_INS(&kc.apdu) = 0x20;
  APDU_P1(&kc.apdu) = 0;
  APDU_P2(&kc.apdu) = 0;

  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO,
                        securechannel_v2_send_apdu(&kc.sc, &kc.ch.v2, &kc.apdu, pin, sizeof(pin)));
}

/* Closing takes the session material out of the struct, so a card pulled and re-seated cannot be
 * talked to with keys its own handshake never produced. */
void test_closing_zeroes_the_session(void) {
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  read_handshake_draws(salt, client_priv, client_pub);

  uint8_t answer[256];
  const size_t answer_len = card_open_answer(salt, client_pub, CARD_ID_PRIV, answer, sizeof(answer));

  activate();
  card_answer(answer, answer_len, 0);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc.ch, &kc.sc, &kc.apdu, SC_V2, cert));

  uint8_t some[SCV2_OKM_SIZE];
  session_keys(salt, client_pub, some, &some[AES_128_KEY_SIZE]);
  TEST_ASSERT_EQUAL_MEMORY(some, kc.ch.v2.key_h2c, SCV2_OKM_SIZE);

  securechannel_close(&kc.ch);

  TEST_ASSERT_EQUAL_UINT8(0, kc.ch.open);
  const uint8_t zero[sizeof(kc.ch.v2)] = {0};
  TEST_ASSERT_EQUAL_MEMORY(zero, &kc.ch.v2, sizeof(kc.ch.v2));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_open_sends_the_salt_and_the_ephemeral_key);
  RUN_TEST(test_a_command_reaches_the_card_in_plaintext_it_holds_keys_for);
  RUN_TEST(test_each_command_advances_the_nonce);
  RUN_TEST(test_an_unparseable_signature_is_a_data_error);
  RUN_TEST(test_a_substituted_identity_is_caught);
  RUN_TEST(test_a_card_public_key_off_the_curve_is_refused);
  RUN_TEST(test_a_short_open_answer_is_a_data_error);
  RUN_TEST(test_a_tampered_reply_is_not_unlocked);
  RUN_TEST(test_the_card_refusing_the_security_condition_closes_the_exchange);
  RUN_TEST(test_closing_zeroes_the_session);

  return UNITY_END();
}
