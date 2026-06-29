#ifndef __SECURE_CHANNEL_V2
#define __SECURE_CHANNEL_V2

#include <stdint.h>
#include <stddef.h>
#include "iso7816/smartcard.h"
#include "crypto/aes.h"
#include "error.h"

#define SCV2_CERT_SIZE 98
#define SCV2_PUBKEY_SIZE 65
#define SCV2_SALT_SIZE 32
#define SCV2_OKM_SIZE 32
#define SCV2_NONCE_SIZE CCM_NONCE_SIZE

/* Maximum DER-encoded signature size (72 bytes + header overhead) */
#define SCV2_SIG_DER_MAX 76

/* Inner APDU header: CLA || INS || P1 || P2 || LC || data */
#define SCV2_INNER_APDU_HEADER_LEN 5

typedef struct __attribute__((packed, aligned(4))) {
  uint8_t key_h2c[AES_128_KEY_SIZE];
  uint8_t key_c2h[AES_128_KEY_SIZE];
  uint8_t nonce_counter[SCV2_NONCE_SIZE];
} secure_channel_v2_t;

/**
 * Open a Secure Channel V2 session.
 *
 * Performs ECDHE handshake:
 *  1. Generate random salt and ephemeral key pair
 *  2. Send OPEN_SECURE_CHANNEL (INS=0x10, P1=0) with salt || client_eph_pub
 *  3. Parse card response: card_eph_pub(65) || signature(DER)
 *  4. Compute ECDHE shared secret
 *  5. Derive session keys via HKDF-SHA256
 *  6. Verify card signature over transcript
 *  7. Initialize nonce counter to zero
 *
 * @param sc     output secure channel V2 state
 * @param card   smartcard handle
 * @param apdu   APDU buffer (reused for tx/rx)
 * @param cert   98-byte certificate from SELECT (card identity pubkey inside)
 */
app_err_t securechannel_v2_open(secure_channel_v2_t* sc, smartcard_t* card, apdu_t* apdu, const uint8_t cert[SCV2_CERT_SIZE]);

/**
 * Init a card with SecureChannel V2
 */
app_err_t securechannel_v2_init(smartcard_t* card, secure_channel_v2_t* sc, apdu_t* apdu, uint8_t* data, uint32_t len);

/**
 * Encrypt and send an APDU over the V2 secure channel.
 *
 * Builds an inner APDU (CLA||INS||P1||P2||LC||data), encrypts with
 * AES-128-CCM using key_h2c, and sends as SECURED_APDU (INS=0x18).
 * Response is decrypted with AES-128-CCM using key_c2h.
 *
 * @param sc     open secure channel V2 state
 * @param card   smartcard handle
 * @param apdu   APDU with CLA/INS/P1/P2 fields set; data and len provided separately
 * @param data   plaintext command data
 * @param len    plaintext data length
 * @return ERR_OK on success, decrypted response in apdu
 */
app_err_t securechannel_v2_send_apdu(smartcard_t* card, secure_channel_v2_t* sc, apdu_t* apdu, uint8_t* data, uint32_t len);

/**
 * Close a V2 secure channel session, clearing keys.
 */
void securechannel_v2_close(secure_channel_v2_t* sc);

#endif
