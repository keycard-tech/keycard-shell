#include "usb.h"
#include "hal.h"
#include "core/core.h"
#include "crypto/util.h"
#include "keycard/command.h"

static uint8_t _usb_packet[HAL_USB_MPS];
static uint8_t _apdu_channel[2];
static uint8_t _usb_send_busy = false;

APP_ALIGNED(const static uint8_t kpro_hid_report_desc[27], 4) = {
  0x06, 0x00, 0xff,  // Usage Page (Vendor Defined 0xff00)
  0x09, 0x01,        // Usage (0x01)
  0xa1, 0x01,        // Collection (Application)
  0x15, 0x00,        //   Logical Minimum (0)
  0x26, 0xff, 0x00,  //   Logical Maximum (255)
  0x75, 0x08,        //   Report Size (8)
  0x95, 0x40,        //   Report Count (64)
  0x09, 0x01,        //   Usage (0x01)
  0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
  0x95, 0x40,        //   Report Count (64)
  0x09, 0x01,        //   Usage (0x01)
  0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
  0xc0,              // End Collection
};

APP_ALIGNED(const static usb_dev_desc_t kpro_dev_desc, 4) = {
    .len = 18,
    .type = 0x01, // Device descriptor
    .usb_version = 0x0200, // USB 2.0
    .dev_class = 0, // Class in IF descriptor
    .dev_subclass = 0,
    .dev_protocol = 0,
    .max_packet_size = HAL_USB_MPS, // EP0 packet size
    .vendor_id = 0x1209, // pid.codes
    .product_id = 0x21f7, // Keycard Shell PID
    .dev_version = 0x0100, // Version 1.0
    .manufacturer_str_idx = USB_MANUFACTURER_IDX,
    .product_str_idx = USB_PRODUCT_IDX,
    .serial_number_str_idx = USB_SN_IDX,
    .config_count = 1
};

APP_ALIGNED(const static usb_hid_inout_desc_t kpro_conf_desc, 4) = {
    .confd = {
        .len = 9,
        .type = 0x02, // Config descriptor
        .total_len = sizeof(usb_hid_inout_desc_t),
        .if_count = 1,
        .config_id = 1,
        .config_str_idx = 0,
        .attr = 0x80, // bus powered
        .max_power = 250, // 500mA
    },
    .ifd = {
        .len = 9,
        .type = 0x04, // Interface descriptor
        .if_id = 0,
        .alt_id = 0,
        .ep_count = 2,
        .class = 3, // HID
        .subclass = 0,
        .protocol = 0,
        .if_str_idx = 0,
    },
    .hidd = {
        .len = 9,
        .type = 0x21, // HID
        .hid_version = 0x0111, //Version 1.11
        .country_code = 0,
        .desc_count = 1,
        .desc_type = 0x22, // HID Report
        .desc_len = sizeof(kpro_hid_report_desc),
    },
    .epind = {
        .len = 7,
        .type = 0x05, // Endpoint descriptor
        .addr = 0x81, // EP1 IN
        .attr = 0x3, // Interrupt transfer type
        .max_packet_size = HAL_USB_MPS,
        .poll_interval = USB_POLL_INTERVAL_MS, // in ms
    },
    .epoutd = {
        .len = 7,
        .type = 0x05, // Endpoint descriptor
        .addr = 0x01, // EP1 OUT
        .attr = 0x3, // Interrupt transfer type
        .max_packet_size = HAL_USB_MPS,
        .poll_interval = USB_POLL_INTERVAL_MS, // in ms
    }
};

static void usb_get_status(uint16_t status) {
  hal_usb_send(0x80, (uint8_t*)&status, 2);
}

static void usb_stall_ep0() {
  hal_usb_set_stall(0x00, 1);
  hal_usb_set_stall(0x80, 1);
}

static void usb_ep0_ack() {
  hal_usb_send(0x80, NULL, 0);
}

static void usb_hid_next_recv() {
  hal_usb_next_recv(0x01, _usb_packet, HAL_USB_MPS);
}

static void usb_get_string(uint8_t idx, uint16_t maxlen) {
  uint8_t report[HAL_USB_MPS];
  uint8_t len = 0;
  const char* to_copy = NULL;

  if (idx == 0) {
    len = 4;
    report[2] = 0x09;
    report[3] = 0x04;
  } else if (idx == USB_SN_IDX) {
    uint8_t uid[HAL_DEVICE_UID_LEN];
    hal_device_uid(uid);

    len = 2;
    // we cannot include the last byte to keep in the 64 bytes limit
    for (int i = 0; i < (HAL_DEVICE_UID_LEN - 1); i++) {
      report[len++] = HEX_DIGITS[(uid[i] >> 4) & 0xf];
      report[len++] = 0;
      report[len++] = HEX_DIGITS[uid[i] & 0xf];
      report[len++] = 0;
    }
  } else if (idx == USB_MANUFACTURER_IDX) {
    to_copy = USB_MANUFACTURER_STR;
  } else if (idx == USB_PRODUCT_IDX) {
    to_copy = USB_PRODUCT_STR;
  } else {
    len = 2;
  }

  if (to_copy) {
    len = 2;
    while(*to_copy != '\0') {
      report[len++] = *(to_copy++);
      report[len++] = 0;
    }
  }

  report[0] = len;
  report[1] = 3; // String descriptor

  hal_usb_send(0x80, report, APP_MIN(len, maxlen));
}

static void usb_get_descriptor(usb_desc_id_t desc_id, uint8_t idx, uint16_t len) {
  switch(desc_id) {
  case USB_DESC_DEV:
    usb_hid_next_recv();
    hal_usb_send(0x80, (uint8_t*) &kpro_dev_desc, APP_MIN(sizeof(kpro_dev_desc), len));
    break;
  case USB_DESC_CONFIG:
    hal_usb_send(0x80, (uint8_t*) &kpro_conf_desc, APP_MIN(sizeof(kpro_conf_desc), len));
    break;
  case USB_DESC_STRING:
    usb_get_string(idx, len);
    break;
  case USB_DESC_HID:
    hal_usb_send(0x80, (uint8_t*) &kpro_conf_desc.hidd, APP_MIN(sizeof(usb_hid_desc_t), len));
    break;
  case USB_DESC_HID_REPORT:
    hal_usb_send(0x80, kpro_hid_report_desc, APP_MIN(sizeof(kpro_hid_report_desc), len));
    break;
  default:
    usb_stall_ep0();
  }
}

static void usb_dev_std_req(usb_setup_packet_t* packet) {
  uint8_t config = 1;

  switch(packet->req) {
  case USB_REQ_GET_STATUS:
    usb_get_status(0);
    break;
  case USB_REQ_CLEAR_FEATURE:
    usb_ep0_ack();
    break;
  case USB_REQ_SET_FEATURE:
    usb_ep0_ack();
    break;
  case USB_REQ_SET_ADDRESS:
    hal_usb_set_address(packet->val);
    usb_ep0_ack();
    break;
  case USB_REQ_GET_DESCRIPTOR:
    usb_get_descriptor(packet->desc_type, packet->desc_idx, packet->len);
    break;
  case USB_REQ_SET_DESCRIPTOR:
    usb_stall_ep0();
    break;
  case USB_REQ_GET_CONFIGURATION:
    hal_usb_send(0x80, &config, 1);
    break;
  case USB_REQ_SET_CONFIGURATION:
    usb_ep0_ack();
    break;
  default:
    break;
  }
}

static void usb_if_std_req(usb_setup_packet_t* packet) {
  uint8_t if_id = 0;

  switch(packet->req) {
  case USB_REQ_GET_STATUS:
    usb_get_status(0);
    break;
  case USB_REQ_CLEAR_FEATURE:
    usb_stall_ep0();
    break;
  case USB_REQ_SET_FEATURE:
    usb_stall_ep0();
    break;
  case USB_REQ_GET_DESCRIPTOR:
    usb_get_descriptor(packet->desc_type, packet->desc_idx, packet->len);
    break;
  case USB_REQ_GET_INTERFACE:
    hal_usb_send(0x80, &if_id, 1);
    break;
  case USB_REQ_SET_INTERFACE:
    usb_stall_ep0();
    break;
  default:
    break;
  }
}

static void usb_if_class_req(usb_setup_packet_t* packet) {
  uint8_t idle = 0;

  switch(packet->req) {
  case USB_HID_GET_REPORT:
    usb_ep0_ack();
    break;
  case USB_HID_GET_IDLE:
    hal_usb_send(0x80, &idle, 1);
    break;
  case USB_HID_GET_PROTOCOL:
    hal_usb_send(0x80, &idle, 1);
    break;
  case USB_HID_SET_REPORT:
    usb_ep0_ack();
    break;
  case USB_HID_SET_IDLE:
    usb_ep0_ack();
    break;
  case USB_HID_SET_PROTOCOL:
    usb_ep0_ack();
    break;
  default:
    usb_stall_ep0();
  }
}

static void usb_ep_std_req(usb_setup_packet_t* packet) {
  switch(packet->req) {
  case USB_REQ_GET_STATUS:
    usb_get_status(hal_usb_get_stall(packet->idx));
    break;
  case USB_REQ_CLEAR_FEATURE:
    if (packet->val == USB_EP_HALT) {
      hal_usb_set_stall(packet->idx, 0);
    }
    break;
  case USB_REQ_SET_FEATURE:
    hal_usb_set_stall(packet->idx, 1);
    break;
  case USB_REQ_SYNCH_FRAME:
    hal_usb_set_stall(packet->idx, 1);
    break;
  default:
    break;
  }
}

static void usb_dev_req(usb_setup_packet_t* packet) {
  switch(packet->req_type & 0x60) {
  case USB_REQUEST_STD:
    usb_dev_std_req(packet);
    break;
  case USB_REQUEST_CLASS:
  case USB_REQUEST_VEND:
  default:
    break;
  }
}

static void usb_if_req(usb_setup_packet_t* packet) {
  switch(packet->req_type & 0x60) {
  case USB_REQUEST_STD:
    usb_if_std_req(packet);
    break;
  case USB_REQUEST_CLASS:
    usb_if_class_req(packet);
    break;
  case USB_REQUEST_VEND:
  default:
    break;
  }
}

static void usb_ep_req(usb_setup_packet_t* packet) {
  switch(packet->req_type & 0x60) {
  case USB_REQUEST_STD:
    usb_ep_std_req(packet);
    break;
  case USB_REQUEST_CLASS:
  case USB_REQUEST_VEND:
  default:
    break;
  }
}

void usb_hid_send_rapdu() {
  uint8_t packet[HAL_USB_MPS];

  packet[0] = _apdu_channel[0];
  packet[1] = _apdu_channel[1];
  packet[2] = USB_CMD_APDU;
  packet[3] = (g_core.usb_command.segment_count >> 8);
  packet[4] = (g_core.usb_command.segment_count & 0xff);

  uint16_t send_off = 5;
  if (!g_core.usb_command.segment_count) {
    packet[5] = 0;
    packet[6] = g_core.usb_command.apdu.lr;
    send_off += 2;
  }

  uint8_t len = command_send(&g_core.usb_command, &packet[send_off], (HAL_USB_MPS - send_off));

  if (hal_usb_send(0x81, packet, HAL_USB_MPS) == HAL_SUCCESS) {
    _usb_send_busy = true;
    command_send_ack(&g_core.usb_command, len);
  }
}

bool usb_send_busy() {
  return _usb_send_busy;
}

void hal_usb_setup_cb(uint8_t* data) {
  usb_setup_packet_t* packet = (usb_setup_packet_t*) data;

  switch(packet->req_type & 0x1f) {
  case USB_REQUEST_DEV:
    usb_dev_req(packet);
    break;
  case USB_REQUEST_IF:
    usb_if_req(packet);
    break;
  case USB_REQUEST_EP:
    usb_ep_req(packet);
    break;
  default:
    usb_stall_ep0();
    break;
  }
}

void hal_usb_data_in_cb(uint8_t epaddr) {
  _usb_send_busy = false;

  if (epaddr == 0) {
    hal_usb_next_recv(0, NULL, 0);
  } else {
    usb_hid_next_recv();
  }
}

static void hal_usb_hid_capdu() {
  _apdu_channel[0] = _usb_packet[0];
  _apdu_channel[1] = _usb_packet[1];

  if (_usb_packet[2] == USB_CMD_PING) {
    hal_usb_send(0x81, _usb_packet, HAL_USB_MPS);
  }

  if ((_usb_packet[2] != USB_CMD_APDU) || (g_core.usb_command.status != COMMAND_INBOUND)) {
    return;
  }

  uint16_t recv_off = 5;

  if (_usb_packet[3] == 0 && _usb_packet[4] == 0) {
    if (command_init_recv(&g_core.usb_command, ((_usb_packet[5] << 8) | _usb_packet[6])) != ERR_OK) {
      return;
    }

    recv_off += 2;
  }

  command_receive(&g_core.usb_command, &_usb_packet[recv_off], (HAL_USB_MPS - recv_off));

}

void hal_usb_data_out_cb(uint8_t epaddr) {
  if (epaddr == 0) {
    usb_ep0_ack(); // we don't implement anything with relevant DATA OUT phase on EP0
  } else {
    hal_usb_hid_capdu();
    usb_hid_next_recv();
  }
}
