#include <string.h>

#include "hal.h"
#include "hal_host.h"

/*
 * The USB HID function, scripted as a wire rather than as a device.
 *
 * usb.c is callback driven: every report the host sends arrives through hal_usb_data_out_cb, which
 * pulls it with hal_usb_next_recv, and every report the shell produces leaves through hal_usb_send and
 * is followed by a request for the next one. So a test holds the host side -- it queues reports for
 * hal_usb_next_recv to hand out and reads back what hal_usb_send was called with -- and calls the
 * callbacks itself, because on the device those are the peripheral interrupting. Enumeration is not
 * modelled.
 *
 * The stall and the device address are kept because usb.c asks the peripheral for them rather than
 * tracking them locally: usb_send_busy() is a question about hardware state.
 */

#define USB_QUEUED_MAX 64
#define USB_SENT_MAX 256

static struct {
  uint8_t epaddr;
  uint8_t data[HAL_USB_MPS];
  size_t len;
} out_q[USB_QUEUED_MAX];
static unsigned out_head, out_count;

static struct {
  uint8_t epaddr;
  uint8_t data[HAL_USB_MPS];
  size_t len;
} sent[USB_SENT_MAX];
static unsigned sent_count;

static uint8_t stall[16]; /* indexed by endpoint number: 0x81 and 0x01 are the same endpoint */
static uint8_t device_address;

void hal_host_usb_reset(void) {
  memset(out_q, 0, sizeof(out_q));
  memset(sent, 0, sizeof(sent));
  memset(stall, 0, sizeof(stall));
  out_head = out_count = 0;
  sent_count = 0;
  device_address = 0;
}

/* A report the host sends. Longer is truncated to the endpoint's width, which is what the peripheral
 * would do to a host that overreached; a shell that asks for more shows up as a wrong length. */
void hal_host_usb_out(uint8_t epaddr, const uint8_t* data, size_t len) {
  if (len > HAL_USB_MPS) {
    len = HAL_USB_MPS;
  }

  if (out_count >= USB_QUEUED_MAX) {
    return;
  }

  out_q[out_count].epaddr = epaddr;
  memcpy(out_q[out_count].data, data, len);
  out_q[out_count].len = len;
  out_count++;
}

unsigned hal_host_usb_send_calls(void) {
  return sent_count;
}

/* The nth report the shell sent, oldest first, or 0 bytes when there are fewer than n+1 of them. */
size_t hal_host_usb_sent_at(unsigned n, uint8_t* buf, size_t maxlen) {
  if (n >= sent_count) {
    return 0;
  }

  const size_t copied = sent[n].len < maxlen ? sent[n].len : maxlen;
  memcpy(buf, sent[n].data, copied);
  return sent[n].len;
}

uint8_t hal_host_usb_sent_epaddr(unsigned n) {
  return (n < sent_count) ? sent[n].epaddr : 0;
}

/* What has left is forgotten; what the host has queued is not, because a test may be mid-exchange. */
void hal_host_usb_sent_clear(void) {
  memset(sent, 0, sizeof(sent));
  sent_count = 0;
}

uint8_t hal_host_usb_stall(uint8_t epaddr) {
  return stall[epaddr & 0x0f];
}

uint8_t hal_host_usb_device_address(void) {
  return device_address;
}

hal_err_t hal_usb_send(uint8_t epaddr, const uint8_t* data, size_t len) {
  if (sent_count >= USB_SENT_MAX) {
    return HAL_FAIL;
  }

  if (len > HAL_USB_MPS) {
    len = HAL_USB_MPS;
  }

  sent[sent_count].epaddr = epaddr;
  sent[sent_count].len = len;
  if (len && data) {
    memcpy(sent[sent_count].data, data, len);
  }

  sent_count++;
  return HAL_SUCCESS;
}

hal_err_t hal_usb_next_recv(uint8_t epaddr, uint8_t* data, size_t len) {
  if ((out_head >= out_count) || (out_q[out_head].epaddr != epaddr)) {
    /* usb.c ignores this result and works on the buffer it passed, so a test that has run dry
     * re-delivers its last report. The way to stop is not to call in. */
    return HAL_FAIL;
  }

  const size_t copied = out_q[out_head].len < len ? out_q[out_head].len : len;
  memcpy(data, out_q[out_head].data, copied);
  if (copied < len) {
    memset(data + copied, 0, len - copied);
  }

  out_head++;
  return HAL_SUCCESS;
}

hal_err_t hal_usb_set_stall(uint8_t epaddr, uint8_t s) {
  stall[epaddr & 0x0f] = s;
  return HAL_SUCCESS;
}

uint8_t hal_usb_get_stall(uint8_t epaddr) {
  return stall[epaddr & 0x0f];
}

hal_err_t hal_usb_set_address(uint8_t addr) {
  device_address = addr;
  return HAL_SUCCESS;
}
