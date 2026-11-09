#include <string.h>

#include "hal.h"
#include "sc_host.h"
#include "freertos/task.h"

#define WIRE_MAX 4096
#define TIMEOUTS_MAX 64
#define SCRIPT_OFF UINT32_MAX

static uint8_t sent[WIRE_MAX];
static size_t sent_len;
static unsigned send_calls;
static unsigned send_refuse_left;

static uint8_t reply[WIRE_MAX];
static size_t reply_len;
static size_t reply_pos;
static uint32_t received;
static unsigned read_calls;
static unsigned fail_read_after = SCRIPT_OFF;

static unsigned wait_calls;
static unsigned fail_notify_after = SCRIPT_OFF;
static uint32_t notify_value = HAL_SUCCESS;

static uint32_t timeouts[TIMEOUTS_MAX];
static unsigned timeout_count;
static uint32_t blocklen;
static uint64_t delayed_us;
static unsigned start_calls;
static unsigned stop_calls;
static unsigned abort_calls;

static bool pps_called;
static int pps_protocol;
static uint32_t pps_baud;
static uint32_t pps_freq;
static uint8_t pps_guard;
static uint32_t pps_timeout;
static bool pps_refuse;

void hal_host_sc_reset(void) {
  memset(sent, 0, sizeof(sent));
  sent_len = 0;
  send_calls = 0;
  send_refuse_left = 0;

  memset(reply, 0, sizeof(reply));
  reply_len = 0;
  reply_pos = 0;
  received = 0;
  read_calls = 0;
  fail_read_after = SCRIPT_OFF;

  wait_calls = 0;
  fail_notify_after = SCRIPT_OFF;
  notify_value = HAL_SUCCESS;

  memset(timeouts, 0, sizeof(timeouts));
  timeout_count = 0;
  blocklen = 0;
  delayed_us = 0;
  start_calls = 0;
  stop_calls = 0;
  abort_calls = 0;

  pps_called = false;
  pps_protocol = -1;
  pps_baud = 0;
  pps_freq = 0;
  pps_guard = 0;
  pps_timeout = 0;
  pps_refuse = false;
}

void hal_host_sc_reply(const uint8_t* bytes, size_t len) {
  if (reply_len + len > sizeof(reply)) {
    return;
  }
  memcpy(reply + reply_len, bytes, len);
  reply_len += len;
}

static size_t unhex_char(char c) {
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  }
  if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  }
  return c - 'A' + 10;
}

void hal_host_sc_reply_hex(const char* hex) {
  while ((*hex != '\0') && (hex[1] != '\0')) {
    while ((*hex == ' ') || (hex[1] == ' ')) {
      hex++;
    }
    if (hex[1] == '\0') {
      return;
    }
    const uint8_t byte = (uint8_t)((unhex_char(*hex) << 4) | unhex_char(hex[1]));
    hal_host_sc_reply(&byte, 1);
    hex += 2;
  }
}

size_t hal_host_sc_unread(void) {
  return reply_len - reply_pos;
}

void hal_host_sc_fail_read_after(unsigned n) {
  fail_read_after = n;
}

void hal_host_sc_fail_notify_after(unsigned n) {
  fail_notify_after = n;
}

void hal_host_sc_notify_value(uint32_t value) {
  notify_value = value;
}

void hal_host_sc_refuse_send(unsigned n) {
  send_refuse_left = n;
}

void hal_host_sc_pps_refuse(bool refuse) {
  pps_refuse = refuse;
}

const uint8_t* hal_host_sc_sent(void) {
  return sent;
}

size_t hal_host_sc_sent_len(void) {
  return sent_len;
}

void hal_host_sc_sent_clear(void) {
  sent_len = 0;
  send_calls = 0;
}

unsigned hal_host_sc_send_calls(void) {
  return send_calls;
}

unsigned hal_host_sc_timeout_count(void) {
  return timeout_count;
}

uint32_t hal_host_sc_timeout(unsigned i) {
  return i < timeout_count ? timeouts[i] : 0;
}

uint32_t hal_host_sc_last_timeout(void) {
  return timeout_count ? timeouts[timeout_count - 1] : 0;
}

uint32_t hal_host_sc_blocklen(void) {
  return blocklen;
}

uint32_t hal_host_sc_delayed_us(void) {
  return (uint32_t)delayed_us;
}

unsigned hal_host_sc_starts(void) {
  return start_calls;
}

unsigned hal_host_sc_stops(void) {
  return stop_calls;
}

unsigned hal_host_sc_aborts(void) {
  return abort_calls;
}

bool hal_host_sc_pps_called(void) {
  return pps_called;
}

int hal_host_sc_pps_protocol(void) {
  return pps_protocol;
}

uint32_t hal_host_sc_pps_baud(void) {
  return pps_baud;
}

uint32_t hal_host_sc_pps_freq(void) {
  return pps_freq;
}

uint8_t hal_host_sc_pps_guard(void) {
  return pps_guard;
}

uint32_t hal_host_sc_pps_timeout(void) {
  return pps_timeout;
}

hal_err_t hal_smartcard_start() {
  start_calls++;
  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_stop() {
  stop_calls++;
  return HAL_SUCCESS;
}

void hal_smartcard_abort() {
  abort_calls++;
}

hal_err_t hal_smartcard_set_timeout(uint32_t timeout) {
  if (timeout_count < TIMEOUTS_MAX) {
    timeouts[timeout_count] = timeout;
  }
  timeout_count++;
  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_set_blocklen(uint32_t len) {
  blocklen = len;
  return HAL_SUCCESS;
}

hal_err_t hal_smartcard_send(const uint8_t* data, size_t len) {
  send_calls++;

  if (send_refuse_left > 0) {
    send_refuse_left--;
    return HAL_FAIL;
  }

  if (sent_len + len > sizeof(sent)) {
    return HAL_FAIL;
  }

  memcpy(sent + sent_len, data, len);
  sent_len += len;

  return HAL_SUCCESS;
}

hal_err_t hal_smarcard_recv(uint8_t* data, size_t len) {
  read_calls++;

  if (read_calls > fail_read_after) {
    return HAL_FAIL;
  }

  const size_t available = reply_len - reply_pos;
  const size_t taken = available < len ? available : len;
  memcpy(data, reply + reply_pos, taken);
  reply_pos += taken;
  received = taken;

  return taken == len ? HAL_SUCCESS : HAL_FAIL;
}

uint32_t hal_smartcard_received(void) {
  return received;
}

hal_err_t hal_smartcard_pps(smartcard_protocol_t protocol, uint32_t baud, uint32_t freq, uint8_t guard,
                            uint32_t timeout) {
  pps_called = true;
  pps_protocol = protocol;
  pps_baud = baud;
  pps_freq = freq;
  pps_guard = guard;
  pps_timeout = timeout;

  return pps_refuse ? HAL_FAIL : HAL_SUCCESS;
}

hal_err_t hal_delay_us(uint32_t usec) {
  delayed_us += usec;
  return HAL_SUCCESS;
}

void vTaskDelay(TickType_t ticks) {
  delayed_us += (uint64_t)ticks * 1000;
}

BaseType_t xTaskNotifyWaitIndexed(uint32_t index_to_wait_on, uint32_t bits_to_clear_on_entry,
                                  uint32_t bits_to_clear_on_exit, uint32_t* notification_value,
                                  TickType_t ticks_to_wait) {
  wait_calls++;

  if (wait_calls > fail_notify_after) {
    return pdFAIL;
  }

  if (notification_value != NULL) {
    *notification_value = notify_value;
  }

  return pdPASS;
}
