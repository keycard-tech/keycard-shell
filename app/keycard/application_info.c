#include "application_info.h"
#include "util/tlv.h"

#define TLV_APPLICATION_INFO_TEMPLATE 0xa4
#define TLV_APPLICATION_STATUS_TEMPLATE 0xa3
#define TLV_PUB_KEY 0x80
#define TLV_UID 0x8f
#define TLV_KEY_UID 0x8e
#define TLV_BOOL 0x01
#define TLV_INT 0x02

app_err_t application_info_parse(uint8_t* buf, app_info_t* info) {
  uint16_t tag;
  uint16_t off = tlv_read_tag(buf, &tag);

  if (tag == TLV_APPLICATION_INFO_TEMPLATE) {
    uint16_t len;
    off += tlv_read_length(&buf[off], &len);

    if ((len = tlv_read_fixed_primitive(TLV_UID, APP_INFO_INSTANCE_UID_LEN, &buf[off], info->instance_uid)) == TLV_INVALID) {
      return ERR_DATA;
    }
    off += len;   

    if ((len = tlv_read_fixed_primitive(TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, &buf[off], info->sc_key)) == TLV_INVALID) {
      return ERR_DATA;
    }
    off += len;

    if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint16_t), &buf[off], (uint8_t*)(&info->version))) == TLV_INVALID) {
      return ERR_DATA;
    }
    
    info->version = (info->version >> 8) | (info->version << 8);
    off += len;

    if ((len = tlv_read_fixed_primitive(TLV_INT, sizeof(uint8_t), &buf[off], &info->free_pairing)) == TLV_INVALID) {
      return ERR_DATA;
    }
    off += len;

    if (tlv_read_primitive(TLV_KEY_UID, APP_INFO_KEY_UID_LEN, &buf[off], info->key_uid, &len) == TLV_INVALID) {
      return ERR_DATA;
    }

    if (len == 0) {
      info->status = INIT_NO_KEYS;
    } else if (len == APP_INFO_KEY_UID_LEN) {
      info->status = INIT_WITH_KEYS;
    } else {
      return ERR_DATA;
    }
  } else if (tag == TLV_PUB_KEY) {
    if (tlv_read_fixed_primitive(TLV_PUB_KEY, APP_INFO_PUBKEY_LEN, buf, info->sc_key) == TLV_INVALID) {
      return ERR_DATA;
    }
    info->status = NOT_INITIALIZED;
  } else {
    return ERR_DATA;
  }

  return ERR_OK;
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
  off += len;  

  return ERR_OK;
}
