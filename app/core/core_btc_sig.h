#ifndef CORE_BTC_SIG_H
#define CORE_BTC_SIG_H

#include "bitcoin/psbt.h"
#include "common.h"
#include "error.h"

/**
 * Adds the signature the card answered a SIGN command with to a PSBT input record: the compressed
 * public key as the key, the DER and the sighash byte as the value.
 *
 * `sig_val` is where the value is assembled and has to hold DER_ECDSA_MAX_SIGNATURE_LEN + 1 bytes.
 * The reply has no room for the sighash byte -- its template ends with the DER -- so the value is
 * built here rather than borrowed, and outlives this call only as long as the caller's buffer.
 */
app_err_t core_btc_read_signature(uint8_t* data, uint16_t len, uint8_t sighash, uint8_t* sig_val, psbt_record_t* rec);

/** The BIP-340 form: no key, and the 64 byte signature as the value, which the reply does have room for. */
app_err_t core_btc_read_schnorr_signature(uint8_t* data, uint16_t len, psbt_record_t* rec);

#endif	/* CORE_BTC_SIG_H */
