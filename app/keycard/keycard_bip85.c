#include <string.h>

#include "keycard_cmdset.h"
#include "crypto/memzero.h"
#include "keycard/secure_channel.h"

/* Export the frozen V3 Privacy Pools BIP-85 root.
 * The caller must validate the decrypted response and erase kc->apdu.data.
 */
app_err_t keycard_cmd_export_bip85_root(keycard_t* kc) {
  if (kc == NULL || kc->app_version < 0x0400 ||
      kc->ch.version != SC_V2 || !kc->ch.open) {
    return ERR_CRYPTO;
  }

  /* m/83696968'/128169'/32'/0', hardened, big-endian. */
  static const uint8_t BIP85_PATH[16] = {
    0x84, 0xfd, 0x1d, 0x48,
    0x80, 0x01, 0xf4, 0xa9,
    0x80, 0x00, 0x00, 0x20,
    0x80, 0x00, 0x00, 0x00
  };

  /* The secure-channel transport clears its input buffer. */
  SC_BUF(path, sizeof(BIP85_PATH));
  memcpy(path, BIP85_PATH, sizeof(BIP85_PATH));

  APDU_RESET(&kc->apdu);
  APDU_CLA(&kc->apdu) = 0x80;
  APDU_INS(&kc->apdu) = 0xc4;
  APDU_P1(&kc->apdu) = 32;
  APDU_P2(&kc->apdu) = 0;

  app_err_t err = securechannel_send_apdu(
      &kc->sc, &kc->ch, &kc->apdu,
      path, sizeof(BIP85_PATH));

  memzero(path, sizeof(path));
  return err;
}
