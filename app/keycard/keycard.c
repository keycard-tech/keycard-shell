#include <string.h>

#include "keycard.h"
#include "keycard_cmdset.h"
#include "application_info.h"
#include "pairing.h"
#include "error.h"
#include "ui/ui.h"
#include "util/tlv.h"
#include "common.h"
#include "crypto/rand.h"
#include "crypto/sha2.h"
#include "crypto/pbkdf2.h"
#include "crypto/bip39.h"
#include "crypto/secp256k1.h"
#include "storage/keys.h"

#define KEYCARD_AID_LEN 9
#define KEYCARD_MIN_VERSION 0x0301

#define KEYCARD_DEF_PIN_RETRIES 3
#define KEYCARD_DEF_PUK_RETRIES 5

const uint8_t KEYCARD_AID[] = {0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01};
const uint8_t KEYCARD_DEFAULT_PSK[] = {0x67, 0x5d, 0xea, 0xbb, 0x0d, 0x7c, 0x72, 0x4b, 0x4a, 0x36, 0xca, 0xad, 0x0e, 0x28, 0x08, 0x26, 0x15, 0x9e, 0x89, 0x88, 0x6f, 0x70, 0x82, 0x53, 0x5d, 0x43, 0x1e, 0x92, 0x48, 0x48, 0xbc, 0xf1};

static void keycard_random_puk(uint8_t puk[KEYCARD_PUK_LEN]) {
  for (int i = 0; i < KEYCARD_PUK_LEN; i++) {
    puk[i] = '0' + random_uniform(10);
  }
}

static void keycard_random_duress(uint8_t pin[KEYCARD_PIN_LEN], uint8_t duress[KEYCARD_PIN_LEN]) {
  do {
    for (int i = 0; i < KEYCARD_PIN_LEN; i++) {
      duress[i] = '0' + random_uniform(10);
    }
  } while(memcmp(pin, duress, KEYCARD_PIN_LEN) == 0);
}

static app_err_t keycard_init_card(keycard_t* kc, uint8_t* sc_key, uint8_t* pin) {
  uint8_t puk[KEYCARD_PUK_LEN];
  if (ui_read_pin(pin, SECRET_NEW_CODE, 0) != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  keycard_random_puk(puk);

  uint8_t duress_pin[KEYCARD_PIN_LEN];
  bool has_duress = true;

  while (true) {
    if (ui_read_duress_pin(duress_pin) != CORE_EVT_UI_OK) {
      keycard_random_duress(pin, duress_pin);
      has_duress = false;
    } else if (memcmp(duress_pin, pin, KEYCARD_PIN_LEN) == 0) {
      ui_info(ICON_INFO_ERROR, LSTR(DURESS_EQ_PIN_MSG), LSTR(DURESS_EQ_PIN_SUB), 0);
      continue;
    }

    break;
  }

  if (keycard_cmd_init(kc, sc_key, pin, puk, (uint8_t*)KEYCARD_DEFAULT_PSK, KEYCARD_DEF_PIN_RETRIES, KEYCARD_DEF_PUK_RETRIES, duress_pin) != ERR_OK) {
    memset(puk, 0, KEYCARD_PUK_LEN);
    ui_keycard_init_failed();
    return ERR_CRYPTO;
  }

  memset(puk, 0, KEYCARD_PUK_LEN);
  ui_keycard_init_ok(has_duress);
  return ERR_OK;
}

static app_err_t keycard_check_genuine(keycard_t* kc) {
  uint8_t tmp[SHA256_DIGEST_LENGTH];
  random_buffer(tmp, SHA256_DIGEST_LENGTH);

  if (keycard_cmd_identify(kc, tmp) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(&kc->apdu);
  uint8_t* data = APDU_RESP(&kc->apdu);

  uint16_t len;
  uint16_t tag;
  uint16_t off = tlv_read_tag(data, &tag);
  if (tag != 0xa0) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);

  off += tlv_read_tag(&data[off], &tag);
  if (tag != 0x8a) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);
  if (len != 98) {
    return ERR_DATA;
  }

  uint8_t* cert = &data[off];
  uint8_t ca_pub[65];

  if (ecdsa_sig_from_der(&cert[98], 72, ca_pub)) {
    return ERR_DATA;
  }

  if (ecdsa_verify(&secp256k1, cert, ca_pub, tmp)) {
    return ERR_CRYPTO;
  }

  sha256_Raw(cert, 33, tmp);

  if (ecdsa_recover_pub_from_sig(&secp256k1, ca_pub, &cert[33], tmp, cert[97])) {
    return ERR_CRYPTO;
  }

  ca_pub[0] = 0x02 | (ca_pub[64] & 1);
  const uint8_t* expected_ca_pub;
  key_read_public(KEYCARD_CA_KEY, &expected_ca_pub);

  if (memcmp(ca_pub, expected_ca_pub, 33)) {
    return ERR_CRYPTO;
  }

  return ERR_OK;
}

app_err_t keycard_factoryreset(keycard_t* kc) {
  if (ui_confirm_factory_reset() != CORE_EVT_UI_OK) {
    return ERR_CANCEL;
  }

  return keycard_cmd_factory_reset(kc);
}

static app_err_t keycard_factoryreset_on_init(keycard_t* kc) {
  app_err_t err = keycard_factoryreset(kc);

  if ((err == ERR_OK) || (err == ERR_CANCEL)) {
    return ERR_RETRY;
  } else {
    return err;
  }
}

static app_err_t keycard_pair(keycard_t* kc, pairing_t* pairing, uint8_t* instance_uid) {
  memcpy(pairing->instance_uid, instance_uid, APP_INFO_INSTANCE_UID_LEN);
  
  if (pairing_read(pairing) == ERR_OK) {
    ui_keycard_already_paired();
    return ERR_OK;
  }

  if (keycard_check_genuine(kc) != ERR_OK) {
    if (ui_keycard_not_genuine() != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }
  }

  uint8_t* psk = (uint8_t*) KEYCARD_DEFAULT_PSK;
  bool default_pass = true;
  
  while(1) {
    app_err_t err = keycard_cmd_autopair(kc, psk, pairing);
    if (err == ERR_OK) {
      if (pairing_write(pairing) != ERR_OK) {
        ui_keycard_flash_failed();
        return ERR_DATA;
      }

      ui_keycard_paired(default_pass);
      return ERR_OK;
    } else if (err == ERR_FULL) {
      return ERR_FULL;
    }

    uint8_t password[KEYCARD_PAIRING_PASS_MAX_LEN + 1];
    uint8_t pairing[32];
    uint8_t len = KEYCARD_PAIRING_PASS_MAX_LEN;
    psk = pairing;

    if (ui_keycard_pairing_failed(kc->name, default_pass) == CORE_EVT_UI_CANCELLED) {
      return keycard_factoryreset_on_init(kc);
    }

    if (ui_read_pairing(password, &len) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }

    default_pass = false;
    keycard_pairing_password_hash(password, len, pairing);
  }
}

static app_err_t keycard_unblock(keycard_t* kc, uint8_t pukRetries) {
  uint8_t pin[KEYCARD_PIN_LEN];

  if (pukRetries) {
    if (ui_prompt_try_puk() != CORE_EVT_UI_OK) {
      pukRetries = 0;
    } else if (ui_read_pin(pin, SECRET_NEW_CODE, 0) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }
  }

  while(pukRetries) {
    uint8_t puk[KEYCARD_PUK_LEN];
    if (ui_read_puk(puk, pukRetries, 0) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }

    if (keycard_cmd_unblock_pin(kc, pin, puk) != ERR_OK) {
      return ERR_TXRX;
    }

    uint16_t sw = APDU_SW(&kc->apdu);

    if (sw == SW_OK) {
      ui_keycard_puk_ok();
      return ERR_OK;
    } else if ((sw & 0x63c0) == 0x63c0) {
      pukRetries = (sw & 0xf);
      ui_keycard_wrong_puk(pukRetries);
    } else {
      return sw;
    }    
  }

  return keycard_factoryreset_on_init(kc);
}

static app_err_t keycard_authenticate(keycard_t* kc, uint8_t* pin, uint8_t* cached_pin) {
  if (keycard_cmd_get_status(kc) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(&kc->apdu);
  app_status_t pinStatus;
  application_status_parse(APDU_RESP(&kc->apdu), &pinStatus);

  while(pinStatus.pin_retries) {
    if (!(*cached_pin) && (ui_read_pin(pin, pinStatus.pin_retries, 0) != CORE_EVT_UI_OK)) {
      return ERR_CANCEL;
    }

    *cached_pin = 0;

    if (keycard_cmd_verify_pin(kc, pin) != ERR_OK) {
      return ERR_TXRX;
    }

    uint16_t sw = APDU_SW(&kc->apdu);

    if (sw == SW_OK) {
      ui_keycard_pin_ok();
      return ERR_OK;
    } else if ((sw & 0x63c0) == 0x63c0) {
      pinStatus.pin_retries = (sw & 0xf);
      ui_keycard_wrong_pin(pinStatus.pin_retries);
    } else {
      return sw;
    }
  } 

  return keycard_unblock(kc, pinStatus.puk_retries);
}

static void keycard_generate_seed(const uint16_t* indexes, uint32_t len, const char* passphrase, uint8_t* seed) {
  char mnemonic[BIP39_MAX_MNEMONIC_LEN * 10];
  mnemonic_from_indexes(mnemonic, indexes, len);
  mnemonic_to_seed(mnemonic, passphrase, seed);
  memset(mnemonic, 0, sizeof(mnemonic));
}

static app_err_t keycard_read_mnemonic(keycard_t* kc, uint16_t indexes[BIP39_MAX_MNEMONIC_LEN], uint32_t* len, char* passphrase) {
  bool has_pass;
  i18n_str_id_t mode_selected = ui_read_mnemonic_len(len, &has_pass);
  core_evt_t err;

  if (mode_selected == MENU_MNEMO_GENERATE) {
    if (keycard_cmd_generate_mnemonic(kc, *len) != ERR_OK) {
      return ERR_TXRX;
    }

    APDU_ASSERT_OK(&kc->apdu);
    uint8_t* data = APDU_RESP(&kc->apdu);

    for (int i = 0; i < ((*len) << 1); i += 2) {
      indexes[(i >> 1)] = ((data[i] << 8) | data[i+1]);
    }

    memset(data, 0, ((*len) << 1));

    err = ui_backup_mnemonic(indexes, *len);
  } else if (mode_selected == MENU_MNEMO_IMPORT) {
read_mnemonic:
    err = ui_read_mnemonic(indexes, *len);

    if ((err == CORE_EVT_UI_OK) && !mnemonic_check(indexes, *len)) {
      ui_bad_seed();
      goto read_mnemonic;
    }
  } else {
    err = ui_scan_mnemonic(indexes, len);
  }

  if (err == CORE_EVT_UI_OK) {
    if (has_pass) {
      uint8_t len = KEYCARD_BIP39_PASS_MAX_LEN;;
      ui_read_string(LSTR(MNEMO_PASSPHRASE_TITLE), "", passphrase, &len, UI_READ_STRING_UNDISMISSABLE);
    }

    return ERR_OK;
  } else {
    return ERR_CANCEL;
  }
}

static app_err_t keycard_init_keys(keycard_t* kc) {
  uint16_t indexes[BIP39_MAX_MNEMONIC_LEN];
  uint32_t len;
  char passphrase[KEYCARD_BIP39_PASS_MAX_LEN];
  app_err_t err;

  do {
    memset(passphrase, 0x00, KEYCARD_BIP39_PASS_MAX_LEN);
    memset(indexes, 0xff, (sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN));
    err = keycard_read_mnemonic(kc, indexes, &len, passphrase);

    if (err == ERR_TXRX) {
      return ERR_TXRX;
    }
  } while(err != ERR_OK);

  SC_BUF(seed, 64);
  keycard_generate_seed(indexes, len, passphrase, seed);
  memset(indexes, 0xff, (sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN));

  if(keycard_cmd_load_seed(kc, seed) != ERR_OK) {
    return ERR_TXRX;
  }

  APDU_ASSERT_OK(&kc->apdu);

  ui_seed_loaded();
  return ERR_OK;
}

static app_err_t keycard_read_name(keycard_t* kc) {
  if (keycard_cmd_get_data(kc) != ERR_OK) {
    return ERR_TXRX;
  }

  if ((APDU_SW(&kc->apdu) != SW_OK) || (kc->apdu.lr == 0)) {
    return ERR_OK;
  }

  uint8_t* data = APDU_RESP(&kc->apdu);
  if ((data[0] >> 5) != 1) {
    return ERR_OK;
  }

  size_t name_len = data[0] & 0x1f;

  char *title = (char *) &data[1];
  data[1 + name_len] = '\0';

  strncpy(kc->name, title, KEYCARD_NAME_MAX_LEN);

  return ERR_OK;
}

static app_err_t keycard_setup(keycard_t* kc, uint8_t* pin, uint8_t* cached_pin) {
  if (keycard_cmd_select(kc, KEYCARD_AID, KEYCARD_AID_LEN) != ERR_OK) {
    return ERR_TXRX;
  }

  kc->ch.open = 0;

  if (APDU_SW(&kc->apdu) != SW_OK) {
    ui_keycard_wrong_card();
    return APDU_SW(&kc->apdu);
  }

  app_info_t info;
  if (application_info_parse(APDU_RESP(&kc->apdu), &info) != ERR_OK) {
    ui_keycard_wrong_card();
    return ERR_DATA;
  }

  uint8_t init_keys;
  app_err_t err;

  switch (info.status) {
    case NOT_INITIALIZED:
      ui_keycard_not_initialized();
      err = keycard_init_card(kc, info.sc_key, pin);
      if (err != ERR_OK) {
        return err;
      }

      *cached_pin = 1;
      return ERR_RETRY;
    case INIT_NO_KEYS:
      init_keys = 1;
      ui_keycard_no_keys();
      break;
    case INIT_WITH_KEYS:
      init_keys = 0;
      ui_keycard_ready();
      break;
    default:
      return ERR_DATA;
  }

  if (info.version < KEYCARD_MIN_VERSION) {
    ui_keycard_old_card();
    return ERR_DATA;
  }

  if (keycard_read_name(kc) != ERR_OK) {
    return ERR_TXRX;
  }

  APP_ALIGNED(pairing_t pairing, 4);
  err = keycard_pair(kc, &pairing, info.instance_uid);
  if (err == ERR_FULL) {
    if (ui_keycard_no_pairing_slots() == CORE_EVT_UI_OK) {
      return keycard_factoryreset_on_init(kc);
    }

    return ERR_FULL;
  } else if (err != ERR_OK) {
    return err;
  }

  err = securechannel_open(&kc->ch, &kc->sc, &kc->apdu, &pairing, info.sc_key);
  if (err != ERR_OK) {
    if (err != ERR_TXRX) {
      pairing_erase(&pairing);
      ui_keycard_secure_channel_failed();
      return ERR_RETRY;
    } else {
      return ERR_TXRX;
    }
  }

  ui_keycard_secure_channel_ok();

  err = keycard_authenticate(kc, pin, cached_pin);
  if (err != ERR_OK) {
    return err;
  }

  if (init_keys) {
    return keycard_init_keys(kc);
  } else {
    return ERR_OK;
  }
}

void keycard_init(keycard_t* kc) {
  smartcard_init(&kc->sc);
  kc->ch.open = 0;
}

void keycard_activate(keycard_t* kc) {
  smartcard_activate(&kc->sc);
  
  ui_card_accepted();

  if (kc->sc.state != SC_READY) {
    ui_card_activation_error();
    return;
  }

  app_err_t res;
  SC_BUF(pin, KEYCARD_PIN_LEN);
  uint8_t cached_pin = 0;

  do {
    res = keycard_setup(kc, pin, &cached_pin);
  } while(res == ERR_RETRY);

  memset(pin, 0, sizeof(pin));

  if (res != ERR_OK) {
    ui_card_transport_error();
    smartcard_deactivate(&kc->sc);
  }
}

app_err_t keycard_read_signature(uint8_t* data, uint8_t* digest, uint8_t* out_sig) {
  if (tlv_read_fixed_primitive(0x80, 65, data, out_sig) != TLV_INVALID) {
    return ERR_OK;
  }

  uint16_t len;
  uint16_t tag;
  uint16_t off = tlv_read_tag(data, &tag);

  if (tag != 0xa0) {
    return ERR_DATA;
  }

  off += tlv_read_length(&data[off], &len);

  off += tlv_read_tag(&data[off], &tag);
  if (tag != 0x80) {
    return ERR_DATA;
  }
  off += tlv_read_length(&data[off], &len);

  uint8_t* pub = &data[off];

  if (ecdsa_sig_from_der(&pub[len], 72, out_sig)) {
    return ERR_DATA;
  }

  uint8_t* pub_tmp = &pub[len];

  for (int i = 0; i < 4; i++) {
    if (!ecdsa_recover_pub_from_sig(&secp256k1, pub_tmp, out_sig, digest, i)) {
      if (!memcmp(pub_tmp, pub, 65)) {
        out_sig[64] = i;
        return ERR_OK;
      }
    }
  }

  return ERR_DATA;
}

app_err_t keycard_set_name(keycard_t* kc, const char* name) {
  SC_BUF(metadata, 127);
  uint8_t metadata_len = 1;

  for (int i = 0; i < KEYCARD_NAME_MAX_LEN; i++) {
    if (name[i] == '\0') {
      break;
    }

    metadata[metadata_len++] = name[i];
  }

  metadata[0] = ((1 << 5) | (metadata_len - 1));

  if (keycard_cmd_get_data(kc) != ERR_OK) {
    return ERR_TXRX;
  }

  if ((APDU_SW(&kc->apdu) != SW_OK)) {
    return ERR_DATA;
  }

  if (kc->apdu.lr != 0) {
    uint8_t* data = APDU_RESP(&kc->apdu);

    if ((data[0] >> 5) == 1) {
      uint8_t copy_off =  1 + (data[0] & 0x1f);
      uint8_t copy_len = kc->apdu.lr - copy_off;
      memcpy(&metadata[metadata_len], &data[copy_off], copy_len);
      metadata_len += copy_len;
    }
  }

  if (keycard_cmd_set_data(kc, metadata, metadata_len) != ERR_OK) {
    return ERR_TXRX;
  }

  if ((APDU_SW(&kc->apdu) != SW_OK)) {
    return ERR_DATA;
  }

  strncpy(kc->name, name, KEYCARD_NAME_MAX_LEN);
  return ERR_OK;
}

void keycard_pairing_password_hash(uint8_t* pass, uint8_t len, uint8_t pairing[32]) {
  pbkdf2_hmac_sha256(pass, len, (uint8_t*)"Keycard Pairing Password Salt", 29, 50000, pairing, 32);
}

void keycard_in(keycard_t* kc) {
  ui_card_inserted();
  smartcard_in(&kc->sc);
}

void keycard_out(keycard_t* kc) {
  ui_card_removed();
  smartcard_out(&kc->sc);
  kc->ch.open = 0;
}
