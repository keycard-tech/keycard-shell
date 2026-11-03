#include "core/core_btc_sig.h"

#include <string.h>

#include "crypto/bip32.h"
#include "crypto/ecdsa.h"
#include "keycard/signature.h"

app_err_t core_btc_read_signature(uint8_t* data, uint16_t len, uint8_t sighash, uint8_t* sig_val, psbt_record_t* rec) {
  keycard_signature_t reply;
  if (!keycard_read_signature_reply(data, len, KEYCARD_SIGN_ECDSA_SECP256K1, &reply)) {
    return ERR_DATA;
  }

  if (reply.key == NULL) {
    /* A partial signature is filed under the key it was made with, and this reply named none. */
    return ERR_DATA;
  }

  /* der[1] counts what the sequence holds, so the signature is two bytes longer: r and s at their
   * widest, padding octet included, make 70 there and 72 all told. */
  const uint8_t* der = reply.sig;
  if ((reply.sig_len < 2) || (der[0] != 0x30) || (der[1] > DER_ECDSA_MAX_SIGNATURE_LEN - 2) ||
      (der[1] + 2 > reply.sig_len)) {
    return ERR_DATA;
  }

  uint16_t der_len = der[1] + 2;
  memcpy(sig_val, der, der_len);
  sig_val[der_len] = sighash;

  rec->scope = PSBT_SCOPE_INPUTS;
  rec->type = PSBT_IN_PARTIAL_SIG;

  rec->key = (uint8_t*)reply.key;
  rec->key_size = PUBKEY_COMPRESSED_LEN;
  rec->key[0] = 0x02 | (reply.key[64] & 1);

  rec->val = sig_val;
  rec->val_size = der_len + 1;

  return ERR_OK;
}

app_err_t core_btc_read_schnorr_signature(uint8_t* data, uint16_t len, psbt_record_t* rec) {
  keycard_signature_t reply;
  if (!keycard_read_signature_reply(data, len, KEYCARD_SIGN_BIP340_SCHNORR, &reply)) {
    return ERR_DATA;
  }

  rec->scope = PSBT_SCOPE_INPUTS;
  rec->type = PSBT_IN_TAP_KEY_SIG;
  rec->key = NULL;
  rec->key_size = 0;
  rec->val = (uint8_t*)reply.sig;
  rec->val_size = reply.sig_len;

  return ERR_OK;
}
