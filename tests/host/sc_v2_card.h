#ifndef SC_V2_CARD_H
#define SC_V2_CARD_H

#include <stdint.h>
#include <string.h>

#include "crypto/aes.h"
#include "crypto/ecdsa.h"
#include "crypto/hkdf.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "hal_host.h"
#include "keycard/secure_channel_v2.h"
#include "sc_card.h"
#include "unity.h"

/*
 * A second implementation of the v2 secure channel -- the ECDHE one a modern applet runs -- written
 * from the transcript and key schedule rather than from app/keycard/secure_channel_v2.c, so that what
 * a suite asserts is interoperability.
 *
 * The schedule: the shell sends a salt and an ephemeral public key, the card answers with its own
 * ephemeral key and a signature by the identity key the certificate vouches for, over SHA-256 of
 * (label, salt, client key, card key). HKDF-SHA-256 over the ECDH x-coordinate, salted by the shell's
 * salt and keyed by the same label, yields h2c then c2h. Every command is then an inner APDU sealed
 * with AES-128-CCM under h2c and carried in SECURED_APDU, and the reply is sealed under c2h -- with
 * one counter nonce per command, serving both directions and advanced once the reply has been read.
 *
 * As in v1, a reply carries its own status word inside the seal and lr counts it.
 *
 * The shell's salt and ephemeral key come from the seeded RNG, so a test seeds, draws whatever the
 * commands before the handshake took, calls v2_card_draws(), and seeds the same value again before
 * running the module. The model draws from the stream's current position, not from a seed of its own.
 */

#define SC_V2_CARD_LABEL "sc_v2_ccm"
#define SC_V2_CARD_LABEL_LEN 9

typedef struct {
  uint8_t id_priv[32];                /* the identity key the certificate vouches for */
  uint8_t eph_priv[32];
  uint8_t cert[SCV2_CERT_SIZE];       /* what the application info hands over: identity key first */
  uint8_t salt[SCV2_SALT_SIZE];
  uint8_t client_priv[32];
  uint8_t client_pub[SCV2_PUBKEY_SIZE];
  uint8_t h2c[AES_128_KEY_SIZE];
  uint8_t c2h[AES_128_KEY_SIZE];
  uint8_t nonce[SCV2_NONCE_SIZE];     /* where the counter stands */
} v2_card_t;

/* DER for what the module hands to ecdsa_sig_from_der: a sequence of two INTEGERs, minimally
 * encoded. */
static inline size_t v2_card_der_sig(const uint8_t sig[64], uint8_t* out) {
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

static inline void v2_card_init(v2_card_t* c, const uint8_t id_priv[32], const uint8_t eph_priv[32]) {
  memset(c, 0, sizeof(*c));
  memcpy(c->id_priv, id_priv, sizeof(c->id_priv));
  memcpy(c->eph_priv, eph_priv, sizeof(c->eph_priv));

  /* The identity public key is the first 65 bytes of what the applet calls its certificate. */
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, c->id_priv, c->cert));
}

/* The transcript the card signs, and the session keys from the card's side of the same ECDHE. */
static inline void v2_card_transcript(const v2_card_t* c, const uint8_t card_pub[SCV2_PUBKEY_SIZE],
                                      uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256 = {0};
  sha256_Init(&sha256);
  sha256_Update(&sha256, (const uint8_t*)SC_V2_CARD_LABEL, SC_V2_CARD_LABEL_LEN);
  sha256_Update(&sha256, c->salt, SCV2_SALT_SIZE);
  sha256_Update(&sha256, c->client_pub, SCV2_PUBKEY_SIZE);
  sha256_Update(&sha256, card_pub, SCV2_PUBKEY_SIZE);
  sha256_Final(&sha256, out);
}

static inline void v2_card_derive(v2_card_t* c) {
  uint8_t shared[SCV2_PUBKEY_SIZE];
  uint8_t okm[SCV2_OKM_SIZE];

  TEST_ASSERT_EQUAL_INT(0, ecdh_multiply(&secp256k1, c->eph_priv, c->client_pub, shared));
  TEST_ASSERT_EQUAL_INT(0,
      hkdf_sha256(c->salt, SCV2_SALT_SIZE, &shared[1], SHA256_DIGEST_LENGTH,
                  (const uint8_t*)SC_V2_CARD_LABEL, SC_V2_CARD_LABEL_LEN, okm, sizeof(okm)));
  memcpy(c->h2c, okm, AES_128_KEY_SIZE);
  memcpy(c->c2h, &okm[AES_128_KEY_SIZE], AES_128_KEY_SIZE);
}

/* The shell's salt and ephemeral key, drawn from wherever the generator stands. The chain starts
 * over with the handshake, so the nonce does too. */
static inline void v2_card_draws(v2_card_t* c) {
  random_buffer(c->salt, SCV2_SALT_SIZE);
  random_buffer(c->client_priv, sizeof(c->client_priv));
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, c->client_priv, c->client_pub));
  v2_card_derive(c);
}

/* What a well-formed card answers OPEN_SECURE_CHANNEL with: its ephemeral public key and a signature
 * over the transcript by the given identity key -- which is how a test says "an impostor answered",
 * by handing it someone else's key. */
static inline size_t v2_card_open_answer(const v2_card_t* c, const uint8_t id_priv[32], uint8_t* out,
                                         size_t maxlen) {
  uint8_t card_pub[SCV2_PUBKEY_SIZE];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, c->eph_priv, card_pub));

  uint8_t hash[SHA256_DIGEST_LENGTH];
  v2_card_transcript(c, card_pub, hash);

  uint8_t raw[64];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_sign(&secp256k1, id_priv, hash, raw));

  uint8_t der[SCV2_SIG_DER_MAX];
  const size_t der_len = v2_card_der_sig(raw, der);

  const size_t len = SCV2_PUBKEY_SIZE + der_len + 2;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)maxlen, (unsigned)len, "answer");

  memcpy(out, card_pub, SCV2_PUBKEY_SIZE);
  memcpy(&out[SCV2_PUBKEY_SIZE], der, der_len);
  out[len - 2] = 0x90;
  out[len - 1] = 0x00;

  return len;
}

static inline void v2_card_queue_open(v2_card_t* c, uint8_t seq) {
  uint8_t answer[256];
  const size_t len = v2_card_open_answer(c, c->id_priv, answer, sizeof(answer));
  sc_card_answer(answer, len, seq);
}

/* The data field of the SECURED_APDU the shell will put on the wire for a command of the given header
 * and data, as the model computes it: the inner APDU -- header, length, data -- sealed under h2c with
 * the counter at the value the command is sent with, and its length as Lc. The wrapper around it is
 * always 80 18 00 00 Lc, that field, then Le 00. That is the same nonce the reply comes back under, so
 * this does not advance it. */
static inline void v2_card_expect_command(const v2_card_t* c, uint8_t ins, uint8_t p1, uint8_t p2,
                                          const uint8_t* data, size_t data_len, uint8_t* out,
                                          size_t* out_len) {
  uint8_t inner[256];
  inner[0] = 0x80;
  inner[1] = ins;
  inner[2] = p1;
  inner[3] = p2;
  inner[4] = (uint8_t)data_len;
  if (data_len) {
    memcpy(&inner[5], data, data_len);
  }

  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c->h2c, c->nonce, inner, data_len + 5, out));

  *out_len = data_len + 5 + CCM_TAG_SIZE;
}

/* A reply sealed under c2h with the nonce of the command it answers, the status word inside the seal
 * and another outside, and the counter advanced -- both sides move once per command. */
static inline size_t v2_card_reply(v2_card_t* c, const uint8_t* plain, size_t plain_len,
                                   uint8_t* out) {
  TEST_ASSERT_TRUE(aes128_ccm_encrypt(c->c2h, c->nonce, plain, plain_len, out));

  const size_t len = plain_len + CCM_TAG_SIZE;
  out[len] = 0x90;
  out[len + 1] = 0x00;

  for (int i = SCV2_NONCE_SIZE - 1; i >= 0; i--) {
    if (++c->nonce[i] != 0) {
      break;
    }
  }

  return len + 2;
}

/* A reply that is nothing but a status word. */
static inline size_t v2_card_reply_ok(v2_card_t* c, uint8_t* out) {
  const uint8_t accepted[2] = {0x90, 0x00};
  return v2_card_reply(c, accepted, sizeof(accepted), out);
}

#endif
