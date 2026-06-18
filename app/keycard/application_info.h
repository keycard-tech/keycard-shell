#ifndef __APPLICATION_INFO_H
#define __APPLICATION_INFO_H

#include <stdint.h>
#include "error.h"

#define APP_INFO_INSTANCE_UID_LEN 16
#define APP_INFO_KEY_UID_LEN 32
#define APP_INFO_PUBKEY_LEN 65
#define APP_INFO_CERT_SIZE 98

#define APP_STATUS_INITIALIZED 0x10
#define APP_STATUS_LEE_MODE 0x20

typedef enum {
  NOT_INITIALIZED,
  INIT_NO_KEYS,
  INIT_WITH_KEYS
} app_info_status_t;

/* V3-specific fields (firmware < 0x0400) */
typedef struct {
  uint8_t instance_uid[APP_INFO_INSTANCE_UID_LEN];
  uint8_t sc_key[APP_INFO_PUBKEY_LEN];
  uint8_t free_pairing;
} app_info_v3_t;

/* V4-specific fields (firmware >= 0x0400) */
typedef struct {
  uint8_t cert_data[APP_INFO_CERT_SIZE];
  uint8_t app_status;
} app_info_v4_t;

typedef struct {
  app_info_status_t status;
  uint16_t version;
  uint8_t key_uid[APP_INFO_KEY_UID_LEN];
  uint8_t capabilities;
  union {
    app_info_v3_t v3;
    app_info_v4_t v4;
  };
} app_info_t;

typedef struct {
  uint8_t pin_retries;
  uint8_t puk_retries;
  uint8_t has_key;
} app_status_t;

app_err_t application_info_parse(uint8_t* buf, app_info_t* info);
app_err_t application_status_parse(uint8_t* buf, app_status_t* status);
#endif
