#include <string.h>

#include "keycard.h"
#include "keycard_cmdset.h"
#include "application_info.h"
#include "pairing.h"
#include "error.h"
#include "ui/ui.h"
#include "util/tlv.h"
#include "common.h"
#include "core/settings.h"
#include "crypto/rand.h"
#include "crypto/sha2.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "crypto/bip39.h"
#include "crypto/slip39.h"
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

static void keycard_generate_bip39_seed(const uint16_t* indexes, uint32_t len, const char* passphrase, uint8_t* seed) {
  char mnemonic[BIP39_MAX_MNEMONIC_LEN * 10];
  mnemonic_from_indexes(mnemonic, indexes, len);
  mnemonic_to_seed(mnemonic, passphrase, seed);
  memset(mnemonic, 0, sizeof(mnemonic));
}

static app_err_t keycard_generate_slip39(const uint8_t* seed, const size_t seed_len, slip39_shard_t shards[SLIP39_MAX_MEMBERS], uint16_t indexes[SLIP39_MNEMO_LEN], uint8_t ems[SLIP39_SEED_STRENGTH]) {
  if (!g_settings.skip_help && (ui_prompt(LSTR(MENU_MNEMO_SLIP39), LSTR(MNEMO_BACKUP_SLIP39_PROMPT), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK)) {
    return ERR_CANCEL;
  }

  uint8_t slip39_tmp[SHA256_DIGEST_LENGTH];
  sha256_Raw(seed, seed_len, slip39_tmp);
  uint32_t shard_count = 1;
  uint32_t threshold = 2;

  core_evt_t err;

  do {
    if (ui_read_number(LSTR(MNEMO_SLIP39_COUNT_TITLE), 1, 16, &shard_count, false) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }

    if (shard_count == 1) {
      err = CORE_EVT_UI_OK;
      threshold = 1;
    } else {
      err = ui_read_number(LSTR(MNEMO_SLIP39_THRESHOLD_TITLE), 2, shard_count, &threshold, true);
    }
  } while(err != CORE_EVT_UI_OK);

  slip39_generate(threshold, slip39_tmp, SLIP39_SEED_STRENGTH, ems, shards, shard_count);

  for (int i = 0; i < shard_count; i++) {
    slip39_encode_mnemonic(&shards[i], indexes, SLIP39_MNEMO_LEN);
    if (ui_backup_mnemonic(indexes, SLIP39_MNEMO_LEN, SLIP39_WORDLIST, SLIP39_WORDS_COUNT, false) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }
  }

  memset(slip39_tmp, 0, SHA256_DIGEST_LENGTH);
  return ERR_OK;
}

static app_err_t keycard_generate_bip39(const uint8_t* raw_mnemo, uint16_t indexes[BIP39_MAX_MNEMONIC_LEN], size_t mnemo_len) {
  if (!g_settings.skip_help && (ui_prompt(LSTR(MENU_MNEMO_GENERATE), LSTR(MNEMO_BACKUP_PROMPT), UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK)) {
    return ERR_CANCEL;
  }

  for (int i = 0; i < (mnemo_len * 2); i += 2) {
    indexes[i / 2] = ((raw_mnemo[i] << 8) | raw_mnemo[i+1]);
  }

  return ui_backup_mnemonic(indexes, mnemo_len, BIP39_WORDLIST_ENGLISH, BIP39_WORD_COUNT, !g_settings.skip_help) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
}

static app_err_t keycard_read_bip39(uint16_t indexes[BIP39_MAX_MNEMONIC_LEN], size_t mnemo_len) {
  while (1) {
    if (ui_read_mnemonic(indexes, mnemo_len, BIP39_WORDLIST_ENGLISH, BIP39_WORD_COUNT) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }

    if (!mnemonic_check(indexes, mnemo_len)) {
      ui_bad_seed();
    } else {
      return ERR_OK;
    }
  }
}

static app_err_t keycard_read_slip39(slip39_shard_t shards[SLIP39_MAX_MEMBERS], uint16_t indexes[SLIP39_MNEMO_LEN], uint8_t ems[SLIP39_SEED_STRENGTH]) {
  uint8_t shard_idx = 0;
  uint8_t shard_count = 1;
  const char* part_success = LSTR(INFO_SLIP39_PART_OK_SUB);
  size_t part_success_len = strlen(part_success);
  char part_counter_msg[part_success_len + 3];
  memcpy(&part_counter_msg[2], part_success, part_success_len + 1);

  while(shard_idx < shard_count) {
    if (ui_read_mnemonic(indexes, SLIP39_MNEMO_LEN, SLIP39_WORDLIST, SLIP39_WORDS_COUNT) != CORE_EVT_UI_OK) {
      return ERR_CANCEL;
    }

    if (slip39_decode_mnemonic(indexes, SLIP39_MNEMO_LEN, &shards[shard_idx]) < 0) {
      ui_bad_seed();
    } else if ((shards[0].identifier != shards[shard_idx].identifier) || (shards[0].group_index != shards[shard_idx].group_index)) {
      ui_info(ICON_INFO_ERROR, LSTR(INFO_SLIP39_MISMATCH_MSG), LSTR(INFO_SLIP39_MISMATCH_SUB), 0);
    } else if (shards[0].group_threshold != 1) {
      ui_info(ICON_INFO_ERROR, LSTR(INFO_SLIP39_UNSUPPORTED_MSG), LSTR(INFO_SLIP39_UNSUPPORTED_SUB), 0);
    } else {
      memset(&indexes[3], 0xff, sizeof(uint16_t) * (SLIP39_MNEMO_LEN - 3));

      shard_count = shards[0].member_threshold;
      shard_idx++;

      uint8_t parts_left = shard_count - shard_idx;

      if (parts_left) {
        int off = 1;
        part_counter_msg[off--] = '0' + (parts_left % 9);
        if (parts_left > 9) {
          part_counter_msg[off--] = '1';
        }

        ui_info(ICON_INFO_SUCCESS, LSTR(INFO_SLIP39_PART_OK_MSG), &part_counter_msg[off + 1], 0);
      }
    }
  }

  slip39_combine(shards, shard_count, ems, SLIP39_SEED_STRENGTH);

  return ERR_OK;
}

static app_err_t keycard_get_seed(keycard_t* kc, uint8_t seed[64], uint32_t* seed_len) {
  uint8_t* slip39_ems = &seed[16];
  slip39_shard_t shards[16];

  uint16_t indexes[BIP39_MAX_MNEMONIC_LEN];
  uint32_t len;
  char passphrase[KEYCARD_BIP39_PASS_MAX_LEN];

  memset(passphrase, 0x00, KEYCARD_BIP39_PASS_MAX_LEN);
  memset(indexes, 0xff, sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN);

  bool has_pass;
  i18n_str_id_t mode_selected = ui_read_mnemonic_len(&len, &has_pass);
  bool slip39 = len == SLIP39_MNEMO_LEN;

  app_err_t err;

  if (mode_selected == MENU_MNEMO_GENERATE) {
    uint8_t* data = APDU_RESP(&kc->apdu);

    if ((keycard_cmd_generate_mnemonic(kc, len) != ERR_OK) || (APDU_SW(&kc->apdu) != 0x9000)) {
      err = ERR_TXRX;
    } else {
      if (slip39) {
        // in practice the card will generate 36 bytes and not 40, but that is still well within the APDU buffer size and the extra bytes make no difference
        err = keycard_generate_slip39(data, len * 2, shards, indexes, slip39_ems);
      } else {
        err = keycard_generate_bip39(data, indexes, len);
      }
    }

    memset(data, 0, len * 2);
  } else if (mode_selected == MENU_MNEMO_IMPORT) {
    if (slip39) {
      err = keycard_read_slip39(shards, indexes, slip39_ems);
    } else {
      err = keycard_read_bip39(indexes, len);
    }
  } else {
    err = ui_scan_mnemonic(indexes, &len) == CORE_EVT_UI_OK ? ERR_OK : ERR_CANCEL;
  }

  if (err == ERR_OK) {
    if (has_pass) {
      uint8_t pass_len = KEYCARD_BIP39_PASS_MAX_LEN;;
      ui_read_string(LSTR(MNEMO_PASSPHRASE_TITLE), "", passphrase, &pass_len, UI_READ_STRING_UNDISMISSABLE);
    }

    if (slip39) {
      slip39_decrypt(slip39_ems, 16, passphrase, shards[0].extendable, shards[0].iteration_exponent, shards[0].identifier, seed);
      *seed_len = 16;
    } else {
      keycard_generate_bip39_seed(indexes, len, passphrase, seed);
      *seed_len = 64;
    }

    err = ERR_OK;
  } else {
    err = ERR_CANCEL;
  }

  memset(indexes, 0xff, sizeof(uint16_t) * BIP39_MAX_MNEMONIC_LEN);
  memset(shards, 0, sizeof(slip39_shard_t) * 16);
  memset(passphrase, 0, KEYCARD_BIP39_PASS_MAX_LEN);
  return err;
}

static uint32_t keycard_generate_key_template(uint8_t* seed, uint32_t seed_len, uint8_t* out) {
  uint8_t tmp[64];
  hmac_sha512((uint8_t*) "Bitcoin seed", 12, seed, seed_len, tmp);
  out[0] = 0xa1;
  out[1] = 0x44;
  out[2] = 0x81;
  out[3] = 0x20;
  memcpy(&out[4], tmp, 32);
  out[36] = 0x82;
  out[37] = 0x20;
  memcpy(&out[38], &tmp[32], 32);
  memset(tmp, 0, 64);
  return 70;
}

static app_err_t keycard_init_keys(keycard_t* kc) {
  app_err_t err;
  uint32_t seed_len = 0;

  SC_BUF(seed, 70);

  do {
    err = keycard_get_seed(kc, seed, &seed_len);

    if (err == ERR_TXRX) {
      return ERR_TXRX;
    }
  } while(err != ERR_OK);

  if (seed_len == 64) {
    if (keycard_cmd_load_seed(kc, seed) != ERR_OK) {
      return ERR_TXRX;
    }
  } else {
    seed_len = keycard_generate_key_template(seed, seed_len, seed);

    if (keycard_cmd_load_key(kc, seed, seed_len) != ERR_OK) {
      return ERR_TXRX;
    }
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
