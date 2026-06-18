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

static app_err_t app_info_parse_v3(uint8_t* buf, uint16_t off, app_info_t* info) {
  uint16_t len;

  /* instanceUID (0x8F) — 16 bytes */
  if ((len = tlv_read_fixed_primitive(TLV_UID, APP_INFO_INSTANCE_UID_LEN, &buf[off], info->v3.instance_uid)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* secureChannelPubKey (0x80) — 65 bytes */
  if ((len = tlv_read_fixed_primitive(TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, &buf[off], info->v3.sc_key)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* appVersion (INTEGER 0x02) — 2 bytes, big-endian */
  if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint16_t), &buf[off], (uint8_t*)(&info->version))) == TLV_INVALID) {
    return ERR_DATA;
  }
  info->version = (info->version >> 8) | (info->version << 8);
  off += len;

  /* freePairingSlots (INTEGER 0x02) — 1 byte */
  if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint8_t), &buf[off], &info->v3.free_pairing)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* keyUID (0x8E) — 0 or 32 bytes */
  uint16_t key_uid_len;
  if ((len = tlv_read_primitive(TLV_KEY_UID, APP_INFO_KEY_UID_LEN, &buf[off], info->key_uid, &key_uid_len)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* capabilities (0x8D) — 1 byte */
  if ((len = tlv_read_fixed_primitive(TLV_CAPABILITIES, sizeof(uint8_t), &buf[off], &info->capabilities)) == TLV_INVALID) {
    return ERR_DATA;
  }

  info->status = (key_uid_len == APP_INFO_KEY_UID_LEN) ? INIT_WITH_KEYS : INIT_NO_KEYS;

  return ERR_OK;
}

static app_err_t app_info_parse_v4(uint8_t* buf, uint16_t off, app_info_t* info) {
  uint16_t len;

  /* appVersion (INTEGER 0x02) — 2 bytes, big-endian */
  if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint16_t), &buf[off], (uint8_t*)(&info->version))) == TLV_INVALID) {
    return ERR_DATA;
  }
  info->version = (info->version >> 8) | (info->version << 8);
  off += len;

  /* appStatus (0x8C) — 1 byte */
  if ((len = tlv_read_fixed_primitive(TLV_STATUS, sizeof(uint8_t), &buf[off], &info->v4.app_status)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* keyUID (0x8E) — 0 or 32 bytes */
  uint16_t key_uid_len;
  if ((len = tlv_read_primitive(TLV_KEY_UID, APP_INFO_KEY_UID_LEN, &buf[off], info->key_uid, &key_uid_len)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* capabilities (0x8D) — 1 byte */
  if ((len = tlv_read_fixed_primitive(TLV_CAPABILITIES, sizeof(uint8_t), &buf[off], &info->capabilities)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  /* certData (0x8A) — 98 bytes */
  if ((len = tlv_read_fixed_primitive(TLV_CERT, APP_INFO_CERT_SIZE, &buf[off], info->v4.cert_data)) == TLV_INVALID) {
    return ERR_DATA;
  }

  if ((info->v4.app_status & APP_STATUS_INITIALIZED) == APP_STATUS_INITIALIZED) {
    info->status = (key_uid_len == APP_INFO_KEY_UID_LEN) ? INIT_WITH_KEYS : INIT_NO_KEYS;
  } else {
    info->status = NOT_INITIALIZED;
  }

  return ERR_OK;
}

app_err_t application_info_parse(uint8_t* buf, app_info_t* info) {
  uint16_t tag;
  uint16_t off = tlv_read_tag(buf, &tag);

  if (tag == TLV_PUB_KEY) {
    /* Uninitialized card: bare TLV_PUB_KEY (V3-style) */
    if (tlv_read_fixed_primitive(TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, buf, info->v3.sc_key) == TLV_INVALID) {
      return ERR_DATA;
    }
    info->status = NOT_INITIALIZED;
    info->version = 0;
    return ERR_OK;
  }

  if (tag != TLV_APPLICATION_INFO_TEMPLATE) {
    return ERR_DATA;
  }

  /* Initialized card: constructed TLV_APPLICATION_INFO_TEMPLATE */
  uint16_t len;
  off += tlv_read_length(&buf[off], &len);

  /* Detect version by first inner tag:
   * V3 starts with 0x8F (instanceUID), V4 starts with 0x02 (appVersion INTEGER) */
  if (buf[off] == TLV_UID) {
    return app_info_parse_v3(buf, off, info);
  } else if (buf[off] == TLV_INT) {
    return app_info_parse_v4(buf, off, info);
  }

  return ERR_DATA;
}

app_err_t application_status_parse(uint8_t* buf, app_status_t* status) {
  uint16_t tag;
  uint16_t off = tlv_read_tag(buf, &tag);

  if (tag != TLV_APPLICATION_STATUS_TEMPLATE) {
    return ERR_DATA;
  }

  uint16_t len;
  off += tlv_read_length(&buf[off], &len);

  if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint8_t), &buf[off], &status->pin_retries)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint8_t), &buf[off], &status->puk_retries)) == TLV_INVALID) {
    return ERR_DATA;
  }
  off += len;

  if ((len = tlv_read_fixed_primitive(TLV_BOOL, sizeof(uint8_t), &buf[off], &status->has_key)) == TLV_INVALID) {
    return ERR_DATA;
  }

  return ERR_OK;
}
