#include "keycard/signature.h"

#define TLV_SIGNATURE_TEMPLATE 0xa0
#define TLV_PUB_KEY 0x80
#define TLV_SCHNORR_SIGNATURE 0x88

bool keycard_read_signature_reply(const uint8_t* data, uint16_t len, keycard_sign_algo_t algo, keycard_signature_t* out) {
  if ((algo != KEYCARD_SIGN_ECDSA_SECP256K1) && (algo != KEYCARD_SIGN_BIP340_SCHNORR)) {
    return false;
  }

  tlv_t tlv;
  tlv_open(&tlv, data, len);

  if ((algo == KEYCARD_SIGN_ECDSA_SECP256K1) &&
      tlv_read_value(&tlv, TLV_PUB_KEY, &out->sig, &out->sig_len)) {
    out->key = NULL;
    return out->sig_len == KEYCARD_RECOVERED_SIG_LEN;
  }

  tlv_t signed_data;
  if (!tlv_enter(&tlv, TLV_SIGNATURE_TEMPLATE, &signed_data)) {
    return false;
  }

  const uint8_t* key;
  uint16_t key_len;
  if (!tlv_read_value(&signed_data, TLV_PUB_KEY, &key, &key_len) || (key_len != KEYCARD_PUBKEY_LEN)) {
    return false;
  }

  out->key = key;

  if (algo == KEYCARD_SIGN_BIP340_SCHNORR) {
    if (!tlv_read_value(&signed_data, TLV_SCHNORR_SIGNATURE, &out->sig, &out->sig_len) ||
        (out->sig_len != KEYCARD_SCHNORR_SIG_LEN)) {
      return false;
    }
    return true;
  }

  out->sig = signed_data.p;
  out->sig_len = signed_data.end - signed_data.p;

  return out->sig_len > 0;
}
