#ifndef _SESSION_V2_H_
#define _SESSION_V2_H_

#include <stdint.h>

#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/keycard.h"
#include "keycard/secure_channel.h"
#include "keys_host.h"
#include "sc_card.h"
#include "sc_v2_card.h"

/*
 * A card switched on and a v2 secure channel opened on it, which is the state most of what the shell
 * does needs to be in before a test can say anything about it. The model keeps the same session keys
 * the shell derived, so from here a test can queue answers and check the commands underneath the
 * seals.
 *
 * The seed is fed to the RNG twice on purpose: once for the shell's ephemeral key and once for the
 * model's, which is how the two end up with the same shared secrets without either being told the
 * other's.
 */

/* TEST-ONLY KEY: the card's identification key, which is what the shell binds the channel to. The CA
 * that signs for it is SC_V2_CA_PRIV, next to the model that presents the certificate. */
static const uint8_t HOST_SESSION_CARD_ID_PRIV[32] = {
    0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02,
    0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03};

/* TEST-ONLY KEY: the card's ephemeral key for the handshake. */
static const uint8_t HOST_SESSION_CARD_EPHEM_PRIV[32] = {
    0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02, 0x12,
    0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03, 0x13};

#define HOST_SESSION_RNG_SEED 0x5eedULL

/* Opens the channel and leaves the model ready for the first answer, whose sequence number is
 * returned -- 1, because opening the channel consumed number 0. */
static inline unsigned host_session_open(v2_card_t* card, keycard_t* kc) {
  keycard_init(kc);
  sc_card_activate(&kc->sc);

  v2_card_init(card, HOST_SESSION_CARD_ID_PRIV, HOST_SESSION_CARD_EPHEM_PRIV);
  v2_card_cert_sign(card, SC_V2_CA_PRIV);

  uint8_t ca[33];
  v2_card_ca_public(ca);
  host_key_set(KEYCARD_CA_KEY, ca);

  hal_host_rng_seed(HOST_SESSION_RNG_SEED);
  v2_card_draws(card);

  v2_card_queue_open(card, 0);
  hal_host_rng_seed(HOST_SESSION_RNG_SEED);

  TEST_ASSERT_EQUAL_INT(ERR_OK, securechannel_open(&kc->ch, &kc->sc, &kc->apdu, SC_V2, card->cert));
  TEST_ASSERT_EQUAL_UINT8(1, kc->ch.open);

  return 1;
}

#endif /* _SESSION_V2_H_ */
