#include "card.h"
#include "core.h"
#include "crypto/memzero.h"
#include "crypto/hmac.h"
#include "crypto/bip39.h"
#include "crypto/slip39.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "error.h"
#include "keycard/keycard_cmdset.h"
#include "pwr.h"
#include "settings.h"
#include "ui/i18n.h"
#include "ui/input.h"
#include "ui/ui.h"

void card_change_name() {
  char name[KEYCARD_NAME_MAX_LEN + 1];
  uint8_t len = KEYCARD_NAME_MAX_LEN;

  if (ui_read_string(LSTR(MENU_CARD_NAME), LSTR(PROMPT_CARD_NAME), name, &len, UI_READ_STRING_ALLOW_EMPTY) != CORE_EVT_UI_OK) {
    return;
  }

  if (keycard_set_name(&g_core.keycard, name) == ERR_OK) {
    ui_info(ICON_INFO_SUCCESS, LSTR(CARD_NAME_CHANGE_SUCCESS), name, 0);
  } else {
    ui_card_transport_error();
  }
}

void card_change_pin() {
  SC_BUF(pin, KEYCARD_PIN_LEN);

  if (ui_read_pin(pin, SECRET_NEW_CODE, 1) != CORE_EVT_UI_OK) {
    return;
  }

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PIN, pin, KEYCARD_PIN_LEN);
  memzero(pin, KEYCARD_PIN_LEN);

  if (err == ERR_OK) {
    ui_info(ICON_INFO_SUCCESS, LSTR(PIN_CHANGE_SUCCESS), NULL, 0);
  } else {
    ui_card_transport_error();
  }
}

void card_change_puk() {
  if (!g_settings.skip_help && (ui_prompt(LSTR(MENU_CHANGE_PUK), LSTR(PUK_CHANGE_PROMPT), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK)) {
    return;
  }

  SC_BUF(puk, KEYCARD_PUK_LEN);

  if (ui_read_puk(puk, SECRET_NEW_CODE, 1) != CORE_EVT_UI_OK) {
    return;
  }

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PUK, puk, KEYCARD_PUK_LEN);
  memzero(puk, KEYCARD_PUK_LEN);

  if (err == ERR_OK) {
    ui_info(ICON_INFO_SUCCESS, LSTR(PUK_CHANGE_SUCCESS), LSTR(INFO_WRITE_KEEP_SAFE), 0);
  } else {
    ui_card_transport_error();
  }
}

void card_change_pairing() {
  if (!g_settings.skip_help && (ui_prompt(LSTR(MENU_CHANGE_PAIRING), LSTR(PAIRING_CHANGE_PROMPT), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK)) {
    return;
  }

  SC_BUF(password, KEYCARD_PAIRING_PASS_MAX_LEN);
  uint8_t len = KEYCARD_PAIRING_PASS_MAX_LEN;

  if (ui_read_string(LSTR(PAIRING_CREATE_TITLE), LSTR(PROMPT_NEW_PAIRING), (char *) password, &len, 0) != CORE_EVT_UI_OK) {
    return;
  }

  uint8_t pairing[32];

  keycard_pairing_password_hash(password, len, pairing);
  memzero(password, len);

  app_err_t err = keycard_cmd_change_credential(&g_core.keycard, KEYCARD_PAIRING, pairing, 32);

  if (err == ERR_OK) {
    ui_info(ICON_INFO_SUCCESS, LSTR(PAIRING_CHANGE_SUCCESS), LSTR(INFO_WRITE_KEEP_SAFE), 0);
  } else {
    ui_card_transport_error();
  }
}

void card_reset() {
  if (keycard_factoryreset(&g_core.keycard) == ERR_OK) {
    ui_info(ICON_INFO_SUCCESS, LSTR(FACTORY_RESET_SUCCESS), LSTR(FACTORY_RESET_SUCCESS_SUB), 0);
    pwr_reboot();
  }
}

static void derive_fingerprint_from_seed(const uint8_t* seed, size_t seed_len, uint32_t* fingerprint) {
  uint8_t I[64];
  hmac_sha512((uint8_t*)"Bitcoin seed", 12, seed, seed_len, I);
  
  uint8_t master_priv_key[32];
  memcpy(master_priv_key, I, 32);
  
  uint8_t pub_key_uncompressed[65];
  
  ecdsa_get_public_key65(&secp256k1, master_priv_key, pub_key_uncompressed);
  
  uint8_t pub_key_compressed[33];
  pub_key_compressed[0] = 0x02 | (pub_key_uncompressed[64] & 1);
  memcpy(&pub_key_compressed[1], &pub_key_uncompressed[1], 32);
  
  uint8_t hash160_result[20];  // RIPEMD160 output is 20 bytes
  hash160(pub_key_compressed, 33, hash160_result);
  
  *fingerprint = (hash160_result[0] << 24) |
  (hash160_result[1] << 16) |
  (hash160_result[2] << 8) |
  hash160_result[3];
  
  memzero(I, sizeof(I));
  memzero(master_priv_key, sizeof(master_priv_key));
  memzero(pub_key_uncompressed, sizeof(pub_key_uncompressed));
  memzero(pub_key_compressed, sizeof(pub_key_compressed));
  memzero(hash160_result, sizeof(hash160_result));
}

static void verify_fingerprint_result(const uint8_t* seed, size_t seed_len) {
  uint32_t derived_fp, card_fp;
  
  derive_fingerprint_from_seed(seed, seed_len, &derived_fp);
  
  if (core_get_fingerprint(NULL, 0, &card_fp) != ERR_OK) {
    ui_card_transport_error();
    return;
  }
  
  if (derived_fp == card_fp) {
    ui_info(ICON_INFO_SUCCESS, LSTR(INFO_VERIFY_MNEMO_MATCH_MSG), LSTR(INFO_VERIFY_MNEMO_MATCH_SUB), 0);
  } else {
    ui_info(ICON_INFO_ERROR, LSTR(INFO_VERIFY_MNEMO_MISMATCH_MSG), LSTR(INFO_VERIFY_MNEMO_MISMATCH_SUB), 0);
  }
}

void card_verify_mnemonic() {
  slip39_shard_t shards[SLIP39_MAX_MEMBERS];
  uint8_t slip39_ems[SLIP39_SEED_STRENGTH];
  uint16_t indexes[BIP39_MAX_MNEMONIC_LEN];
  uint32_t len;

  uint8_t pass_len = KEYCARD_BIP39_PASS_MAX_LEN;
  char passphrase[KEYCARD_BIP39_PASS_MAX_LEN];
  uint8_t seed[64];
  
  memset(passphrase, 0x00, KEYCARD_BIP39_PASS_MAX_LEN);
  memset(indexes, 0xff, sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN);
  
  core_evt_t err;

  while ((err = ui_read_mnemonic_verify(&len)) == CORE_EVT_UI_OK) {
    if (len == SLIP39_MNEMO_LEN) {
      err = ui_read_slip39(shards, indexes, slip39_ems);
    } else if (len == 0) {
      err = ui_scan_mnemonic(indexes, &len);
    } else {
      err = ui_read_bip39(indexes, len);
    }

    if (err == CORE_EVT_UI_OK && (ui_read_string(LSTR(MNEMO_PASSPHRASE_TITLE), LSTR(MNEMO_VERIFY_PASS_PROMPT), passphrase, &pass_len, UI_READ_STRING_ALLOW_EMPTY) == CORE_EVT_UI_OK)) {
      break;
    }
  }

  if (err != CORE_EVT_UI_OK) {
    return;
  }

  size_t seed_len;

  if (len == SLIP39_MNEMO_LEN) {
    slip39_decrypt(slip39_ems, 16, passphrase, shards[0].extendable, shards[0].iteration_exponent, shards[0].identifier, seed);
    seed_len = 16;    
  } else {
    mnemonic_indexes_to_seed(indexes, len, passphrase, seed); 
    seed_len = 64;
  }

  verify_fingerprint_result(seed, seed_len);
  
  memzero(seed, sizeof(seed));
  memset(indexes, 0xff, sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN);
  memzero(passphrase, KEYCARD_BIP39_PASS_MAX_LEN);  
}
