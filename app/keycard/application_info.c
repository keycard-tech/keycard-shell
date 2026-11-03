#include "application_info.h"
#include "util/tlv.h"

#define TLV_APPLICATION_INFO_TEMPLATE 0xa4
#define TLV_APPLICATION_STATUS_TEMPLATE 0xa3
#define TLV_PUB_KEY 0x80
#define TLV_UID 0x8f
#define TLV_KEY_UID 0x8e
#define TLV_BOOL 0x01
#define TLV_INT 0x02
#define TLV_STATUS 0x8c
#define TLV_CAPABILITIES 0x8d
#define TLV_CERT 0x8a

static app_err_t app_info_parse_v3(tlv_t* tlv, app_info_t* info) {
  uint16_t key_uid_len;

  if (!tlv_read_fixed(tlv, TLV_UID, APP_INFO_INSTANCE_UID_LEN, info->v3.instance_uid)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(tlv, TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, info->v3.sc_key)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(tlv, TLV_INT, sizeof(uint16_t), (uint8_t*)&info->version)) {
    return ERR_DATA;
  }
  info->version = (info->version >> 8) | (info->version << 8);

  if (!tlv_read_fixed(tlv, TLV_INT, sizeof(uint8_t), &info->v3.free_pairing)) {
    return ERR_DATA;
  }
  if (!tlv_read_primitive(tlv, TLV_KEY_UID, APP_INFO_KEY_UID_LEN, info->key_uid, &key_uid_len)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(tlv, TLV_CAPABILITIES, sizeof(uint8_t), &info->capabilities)) {
    return ERR_DATA;
  }

  info->status = (key_uid_len == APP_INFO_KEY_UID_LEN) ? INIT_WITH_KEYS : INIT_NO_KEYS;

  return ERR_OK;
}

static app_err_t app_info_parse_v4(tlv_t* tlv, app_info_t* info) {
  uint16_t key_uid_len;

  if (!tlv_read_fixed(tlv, TLV_INT, sizeof(uint16_t), (uint8_t*)&info->version)) {
    return ERR_DATA;
  }
  info->version = (info->version >> 8) | (info->version << 8);

  if (!tlv_read_fixed(tlv, TLV_STATUS, sizeof(uint8_t), &info->v4.app_status)) {
    return ERR_DATA;
  }
  if (!tlv_read_primitive(tlv, TLV_KEY_UID, APP_INFO_KEY_UID_LEN, info->key_uid, &key_uid_len)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(tlv, TLV_CAPABILITIES, sizeof(uint8_t), &info->capabilities)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(tlv, TLV_CERT, APP_INFO_CERT_SIZE, info->v4.cert_data)) {
    return ERR_DATA;
  }

  if ((info->v4.app_status & APP_STATUS_INITIALIZED) == APP_STATUS_INITIALIZED) {
    info->status = (key_uid_len == APP_INFO_KEY_UID_LEN) ? INIT_WITH_KEYS : INIT_NO_KEYS;
  } else {
    info->status = NOT_INITIALIZED;
  }

  return ERR_OK;
}

app_err_t application_info_parse(uint8_t* buf, uint16_t len, app_info_t* info) {
  tlv_t tlv;
  tlv_open(&tlv, buf, len);

  tlv_t probe = tlv;
  uint16_t tag;
  if (!tlv_read_tag(&probe, &tag)) {
    return ERR_DATA;
  }

  if (tag == TLV_PUB_KEY) {
    /* Uninitialized card: bare TLV_PUB_KEY (V3-style) */
    if (!tlv_read_fixed(&tlv, TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, info->v3.sc_key)) {
      return ERR_DATA;
    }
    info->status = NOT_INITIALIZED;
    info->version = 0;
    return ERR_OK;
  }

  /* Initialized card: constructed TLV_APPLICATION_INFO_TEMPLATE */
  tlv_t inner;
  if (!tlv_enter(&tlv, TLV_APPLICATION_INFO_TEMPLATE, &inner)) {
    return ERR_DATA;
  }

  /* Detect version by first inner tag:
   * V3 starts with 0x8F (instanceUID), V4 starts with 0x02 (appVersion INTEGER) */
  probe = inner;
  if (!tlv_read_tag(&probe, &tag)) {
    return ERR_DATA;
  }
  if (tag == TLV_UID) {
    return app_info_parse_v3(&inner, info);
  }
  if (tag == TLV_INT) {
    return app_info_parse_v4(&inner, info);
  }

  return ERR_DATA;
}

app_err_t application_status_parse(uint8_t* buf, uint16_t len, app_status_t* status) {
  tlv_t tlv;
  tlv_open(&tlv, buf, len);

  tlv_t inner;
  if (!tlv_enter(&tlv, TLV_APPLICATION_STATUS_TEMPLATE, &inner)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(&inner, TLV_INT, sizeof(uint8_t), &status->pin_retries)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(&inner, TLV_INT, sizeof(uint8_t), &status->puk_retries)) {
    return ERR_DATA;
  }
  if (!tlv_read_fixed(&inner, TLV_BOOL, sizeof(uint8_t), &status->has_key)) {
    return ERR_DATA;
  }

  return ERR_OK;
}
