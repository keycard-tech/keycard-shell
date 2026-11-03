#ifndef KEYCARD_SIGNATURE_H
#define KEYCARD_SIGNATURE_H

#include "common.h"
#include "keycard/keycard_cmdset.h"
#include "util/tlv.h"

/* The public key the card signs with, uncompressed. */
#define KEYCARD_PUBKEY_LEN 65

/* The BIP-340 signature the card writes, without the header that introduces it. */
#define KEYCARD_SCHNORR_SIG_LEN 64

/* A signature that arrives with its recovery id appended instead of a public key to check against.
 * Same length as a public key, and no relation to one. */
#define KEYCARD_RECOVERED_SIG_LEN 65

typedef struct {
  const uint8_t* key;   /* NULL when the reply carried its recovery id */
  const uint8_t* sig;
  uint16_t sig_len;
} keycard_signature_t;

/**
 * Reads the reply to SIGN.  The template is the same whatever was signed -- 0xa0 holding the 0x80
 * public key, and then the signature -- but the two algorithms end it differently: ECDSA writes bare
 * DER, which fills what is left of the template, and BIP-340 a 0x88 primitive. `algo` is the one the
 * command was made with.
 *
 * An ECDSA reply is also accepted as a bare 0x80 holding r||s||recovery id, which is the shape that
 * needs no key: `key` is NULL and `sig` is those bytes, so `sig_len` is the same as a public key's by
 * coincidence and nothing else.
 */
bool keycard_read_signature_reply(const uint8_t* data, uint16_t len, keycard_sign_algo_t algo, keycard_signature_t* out);

#endif	/* KEYCARD_SIGNATURE_H */
