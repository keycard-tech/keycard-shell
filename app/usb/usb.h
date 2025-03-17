#ifndef __USB__
#define __USB__

#include "common.h"
#include "hal.h"
#include "pwr.h"

#define USB_EP_HALT 0

#define USB_MANUFACTURER_IDX 1
#define USB_PRODUCT_IDX 2
#define USB_SN_IDX 3

#define USB_MANUFACTURER_STR "Status Research & Development"
#define USB_PRODUCT_STR "Keycard Shell"

#define USB_NOTIFICATION_IDX 0

#define USB_POLL_INTERVAL_MS 2

typedef struct __attribute__((packed)) {
  uint8_t len;
  uint8_t type;
  uint16_t usb_version;
  uint8_t dev_class;
  uint8_t dev_subclass;
  uint8_t dev_protocol;
  uint8_t max_packet_size;
  uint16_t vendor_id;
  uint16_t product_id;
  uint16_t dev_version;
  uint8_t manufacturer_str_idx;
  uint8_t product_str_idx;
  uint8_t serial_number_str_idx;
  uint8_t config_count;
} usb_dev_desc_t;

typedef struct __attribute__((packed)) {
  uint8_t len;
  uint8_t type;
  uint16_t total_len;
  uint8_t if_count;
  uint8_t config_id;
  uint8_t config_str_idx;
  uint8_t attr;
  uint8_t max_power;
} usb_conf_desc_t;

typedef struct __attribute__((packed)) {
  uint8_t len;
  uint8_t type;
  uint8_t if_id;
  uint8_t alt_id;
  uint8_t ep_count;
  uint8_t class;
  uint8_t subclass;
  uint8_t protocol;
  uint8_t if_str_idx;
} usb_if_desc_t;

typedef struct __attribute__((packed)) {
  uint8_t len;
  uint8_t type;
  uint8_t addr;
  uint8_t attr;
  uint16_t max_packet_size;
  uint8_t poll_interval;
} usb_ep_desc_t;

typedef struct __attribute__((packed)) {
  uint8_t len;
  uint8_t type;
  uint16_t hid_version;
  uint8_t country_code;
  uint8_t desc_count;
  uint8_t desc_type;
  uint16_t desc_len;
} usb_hid_desc_t;

typedef struct __attribute__((packed)) {
  usb_conf_desc_t confd;
  usb_if_desc_t ifd;
  usb_hid_desc_t hidd;
  usb_ep_desc_t epind;
  usb_ep_desc_t epoutd;
} usb_hid_inout_desc_t;

typedef struct __attribute__((packed)) {
  uint8_t req_type;
  uint8_t req;
  union {
    uint16_t val;
    struct {
        uint8_t desc_idx;
        uint8_t desc_type;
    };
  };
  uint16_t idx;
  uint16_t len;
} usb_setup_packet_t;

typedef enum {
  USB_REQUEST_DEV = 0,
  USB_REQUEST_IF = 1,
  USB_REQUEST_EP = 2,
} usb_request_recipient_t;

typedef enum {
  USB_REQUEST_STD = 0,
  USB_REQUEST_CLASS = 32,
  USB_REQUEST_VEND = 64,
} usb_request_type_t;

typedef enum {
  USB_REQ_GET_STATUS = 0x00,
  USB_REQ_CLEAR_FEATURE = 0x01,
  USB_REQ_SET_FEATURE = 0x03,
  USB_REQ_SET_ADDRESS = 0x05,
  USB_REQ_GET_DESCRIPTOR = 0x06,
  USB_REQ_SET_DESCRIPTOR = 0x07,
  USB_REQ_GET_CONFIGURATION = 0x08,
  USB_REQ_SET_CONFIGURATION = 0x09,
  USB_REQ_GET_INTERFACE = 0x0a,
  USB_REQ_SET_INTERFACE = 0x11,
  USB_REQ_SYNCH_FRAME = 0x12,
} usb_std_request_t;

typedef enum {
  USB_DESC_DEV = 0x01,
  USB_DESC_CONFIG = 0x02,
  USB_DESC_STRING = 0x03,
  USB_DESC_HID = 0x21,
  USB_DESC_HID_REPORT = 0x22,
} usb_desc_id_t;

typedef enum {
  USB_HID_GET_REPORT = 0x01,
  USB_HID_GET_IDLE = 0x02,
  USB_HID_GET_PROTOCOL = 0x03,
  USB_HID_SET_REPORT = 0x09,
  USB_HID_SET_IDLE = 0x0a,
  USB_HID_SET_PROTOCOL = 0x0b,
} usb_hid_request_type_t;

typedef enum {
  USB_CMD_PING = 2,
  USB_CMD_APDU = 5,
} usb_cmd_t;

void usb_hid_send_rapdu();
bool usb_send_busy();

static inline bool usb_connected() {
  return hal_gpio_get(GPIO_VUSB_OK) == GPIO_RESET;
}

static inline void usb_start_if_connected() {
  if (usb_connected()) {
    pwr_usb_plugged(false);
  }
}

#endif
