#ifndef SC_V1_CARD_H
#define SC_V1_CARD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/aes.h"
#include "crypto/ecdsa.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "hal_host.h"
#include "sc_card.h"
#include "unity.h"

/*
 * A second implementation of the v1 secure channel -- the one keyed by a stored pairing -- written
 * from the schedule rather than from app/keycard/secure_channel_v1.c, so that what a suite asserts
 * is interoperability: the bytes the shell puts on the wire are the bytes a paired card computes,
 * and what comes back is what that card can decrypt and MAC.
 *
 * The schedule: ECDH between the shell's ephemeral key and the applet's secure-element key, SHA-512
 * over (x, the stored pairing key, the card's nonce) into the encryption key and the MAC key, then
 * every command sealed with AES-256-CBC under a chain both sides carry forward -- a request is
 * encrypted under the standing iv and MACed over its header, and the reply is encrypted under that
 * request's MAC and MACed over its length, with the reply's MAC becoming the next iv.
 *
 * The shell's ephemeral key and its mutual-authenticate challenge come from the seeded RNG, so a
 * test seeds the generator, draws what the commands before the handshake took, calls
 * v1_card_draws(), and then seeds the same value again before running the module. The model's draws
 * have to land where the module's land, which is why they are taken from the stream's current
 * position rather than from a seed of the model's own.
 */

typedef struct {
  uint8_t sc_pub[65];                     /* the applet's secure-element key, as the shell sees it */
  uint8_t pairing_key[SHA256_DIGEST_LENGTH];
  uint8_t client_priv[32];                /* the shell's ephemeral key, drawn from the seed */
  uint8_t client_pub[65];
  uint8_t challenge[32];                  /* what the shell seals in MUTUAL AUTHENTICATE */
  uint8_t card_nonce[SHA256_DIGEST_LENGTH];
  uint8_t card_iv[AES_IV_SIZE];
  uint8_t enc_key[AES_256_KEY_SIZE];
  uint8_t mac_key[AES_256_KEY_SIZE];
  uint8_t cmd_ct[48];                     /* the challenge padded and encrypted under card_iv */
  uint8_t cmd_mac[16];                    /* its MAC, which is the iv the reply must use */
  uint8_t iv[AES_IV_SIZE];                /* where the chain stands: the iv of the next request */
} v1_card_t;

/* ISO 9797-1 mechanism 1: 0x80 then zeros to the next block boundary. */
static inline size_t v1_pad1(const uint8_t* data, size_t len, uint8_t* out) {
  const size_t padded = ((len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
  if (len) {
    memcpy(out, data, len);
  }
  out[len] = 0x80;
  memset(&out[len + 1], 0, padded - len - 1);
  return padded;
}

/* SHA-256 over two buffers run together, which is what a pairing cryptogram is. */
static inline void v1_sha256_cat(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen,
                                 uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  sha256_Update(&ctx, a, alen);
  sha256_Update(&ctx, b, blen);
  sha256_Final(&ctx, out);
}

/* The session keys: SHA-512 over the ECDH x-coordinate, the stored pairing key and the card's
 * nonce, which fills the encryption key and the MAC key in that order. */
static inline void v1_session_keys(v1_card_t* c, const uint8_t client_priv[32]) {
  uint8_t shared[65];
  TEST_ASSERT_EQUAL_INT(0, ecdh_multiply(&secp256k1, client_priv, c->sc_pub, shared));

  uint8_t keys[AES_256_KEY_SIZE + AES_256_KEY_SIZE];
  SHA512_CTX sha512 = {0};
  sha512_Init(&sha512);
  sha512_Update(&sha512, &shared[1], SHA256_DIGEST_LENGTH);
  sha512_Update(&sha512, c->pairing_key, SHA256_DIGEST_LENGTH);
  sha512_Update(&sha512, c->card_nonce, SHA256_DIGEST_LENGTH);
  sha512_Final(&sha512, keys);

  memcpy(c->enc_key, keys, AES_256_KEY_SIZE);
  memcpy(c->mac_key, &keys[AES_256_KEY_SIZE], AES_256_KEY_SIZE);
}

/* The MAC the shell computes for a command, so a card answering it knows what iv to encrypt under. */
static inline void v1_command_mac(const v1_card_t* c, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                  const uint8_t* ciphertext, size_t ct_len, uint8_t mac[AES_BLOCK_SIZE]) {
  uint8_t buf[256];
  const size_t len = ct_len + AES_BLOCK_SIZE;
  TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE((unsigned)sizeof(buf), (unsigned)len, "mac input");

  memset(buf, 0, AES_BLOCK_SIZE);
  buf[0] = cla;
  buf[1] = ins;
  buf[2] = p1;
  buf[3] = p2;
  buf[4] = (uint8_t)len;
  memcpy(&buf[AES_BLOCK_SIZE], ciphertext, ct_len);

  TEST_ASSERT_TRUE(aes_cbc_mac(c->mac_key, buf, len, mac));
}

/* Everything a well-formed card has to have said by the end of the handshake, and what the shell
 * will send, so a test can predict the wire. */
static inline void v1_card_draws(v1_card_t* c, const uint8_t sc_pub[65],
                                 const uint8_t pairing_key[SHA256_DIGEST_LENGTH]) {
  memset(c, 0, sizeof(*c));
  memcpy(c->sc_pub, sc_pub, sizeof(c->sc_pub));
  memcpy(c->pairing_key, pairing_key, sizeof(c->pairing_key));
  memset(c->card_nonce, 0xc0, sizeof(c->card_nonce));
  memset(c->card_iv, 0x11, sizeof(c->card_iv));

  random_buffer(c->client_priv, sizeof(c->client_priv));
  random_buffer(c->challenge, sizeof(c->challenge));

  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, c->client_priv, c->client_pub));

  v1_session_keys(c, c->client_priv);

  uint8_t padded[48];
  v1_pad1(c->challenge, sizeof(c->challenge), padded);
  TEST_ASSERT_TRUE(aes_encrypt_cbc(c->enc_key, c->card_iv, padded, sizeof(padded), c->cmd_ct));
  v1_command_mac(c, 0x80, 0x11, 0, 0, c->cmd_ct, sizeof(c->cmd_ct), c->cmd_mac);
}

/* A card's reply under this schedule: the MAC over [length, zeros, ciphertext], then the
 * ciphertext, then a status word. The MAC the card sends is also what both sides chain to, so the
 * card's chain moves here as well. */
static inline size_t v1_card_reply(v1_card_t* c, const uint8_t iv[AES_BLOCK_SIZE],
                                   const uint8_t* plain, size_t plain_len, uint8_t* out) {
  uint8_t padded[256];
  const size_t ct_len = v1_pad1(plain, plain_len, padded);

  uint8_t ct[256];
  TEST_ASSERT_TRUE(aes_encrypt_cbc(c->enc_key, iv, padded, ct_len, ct));

  const size_t len = ct_len + AES_BLOCK_SIZE;
  uint8_t mac_buf[256];
  memset(mac_buf, 0, AES_BLOCK_SIZE);
  mac_buf[0] = (uint8_t)len;
  memcpy(&mac_buf[AES_BLOCK_SIZE], ct, ct_len);

  uint8_t mac[AES_BLOCK_SIZE];
  TEST_ASSERT_TRUE(aes_cbc_mac(c->mac_key, mac_buf, len, mac));

  memcpy(c->iv, mac, AES_BLOCK_SIZE);

  memcpy(out, mac, AES_BLOCK_SIZE);
  memcpy(&out[AES_BLOCK_SIZE], ct, ct_len);
  out[AES_BLOCK_SIZE + ct_len] = 0x90;
  out[AES_BLOCK_SIZE + ct_len + 1] = 0x00;

  return len + 2;
}

/* The APDU the shell will put on the wire for a command of the given header and plaintext, as the
 * model computes it: MAC of (header, length, zeros, ciphertext) followed by the ciphertext. The iv of
 * the card's answer is returned, because that is what a reply has to be encrypted under.
 *
 * The header is part of the MAC, so a prediction that gets P1 or P2 wrong is not caught by the MAC
 * check -- the card's reply then opens under an iv neither side holds, and the first block of it is
 * garbage while everything after it reads fine. */
static inline void v1_card_expect_command(const v1_card_t* c, uint8_t ins, uint8_t p1, uint8_t p2,
                                          const uint8_t* plain, size_t plain_len, uint8_t* out,
                                          size_t* out_len, uint8_t reply_iv[AES_BLOCK_SIZE]) {
  uint8_t padded[256];
  const size_t ct_len = v1_pad1(plain, plain_len, padded);

  uint8_t ct[256];
  TEST_ASSERT_TRUE(aes_encrypt_cbc(c->enc_key, c->iv, padded, ct_len, ct));

  const size_t lc = ct_len + AES_BLOCK_SIZE;
  v1_command_mac(c, 0x80, ins, p1, p2, ct, ct_len, out);
  memcpy(&out[AES_BLOCK_SIZE], ct, ct_len);

  memcpy(reply_iv, out, AES_BLOCK_SIZE);
  *out_len = lc;
}

/* The two blocks a good card answers the handshake with: its nonce and iv, then its own 34-byte
 * plaintext (a cryptogram plus a status word) under the chain. The seq is the first of the two,
 * because a card's send-sequence runs across a whole activation, not across one command. */
static inline void v1_card_queue_open(v1_card_t* c, uint8_t seq) {
  uint8_t first[SHA256_DIGEST_LENGTH + AES_IV_SIZE + 2];
  memcpy(first, c->card_nonce, sizeof(c->card_nonce));
  memcpy(&first[sizeof(c->card_nonce)], c->card_iv, sizeof(c->card_iv));
  first[sizeof(first) - 2] = 0x90;
  first[sizeof(first) - 1] = 0x00;
  sc_card_answer(first, sizeof(first), seq);

  uint8_t plain[34];
  memset(plain, 0x5a, sizeof(plain) - 2);
  plain[32] = 0x90;
  plain[33] = 0x00;

  uint8_t second[64 + 2];
  const size_t len = v1_card_reply(c, c->cmd_mac, plain, sizeof(plain), second);
  sc_card_answer(second, len, seq + 1);
}

#endif
