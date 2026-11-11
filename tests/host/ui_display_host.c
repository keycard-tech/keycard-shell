#include <string.h>

#include "ui/ui.h"
#include "ui_host.h"

/*
 * The screens and prompts a USB command shows: the QR pair that moves data in and out over the light
 * and the camera, the transaction and message renderings, the confirmations, and the progress bar.
 *
 * Recorded by name and answered from a script. What these take is a rendered thing -- a transaction
 * context, an EIP-712 type, an address -- so pinning the arguments would pin the current layout rather
 * than a protocol; what a test asserts is that the confirmation happened and what the user did about
 * it.
 *
 * Every default is a refusal. A confirmation granted by default lets a test pass by never saying who
 * pressed the button. The scalar out-parameters are zeroed so a caller that reads one after a refusal
 * reads nothing rather than the stack; no scan delivers data, because the decoder lives in the camera
 * path and a test that needs bytes to arrive has to script them, which nothing asks for yet.
 */

#define DISPLAY_CALLS 64

static struct {
  const char* fn;
  uint8_t progress;
} calls[DISPLAY_CALLS];
static unsigned count;

static void record(const char* fn) {
  if (count >= DISPLAY_CALLS) {
    return;
  }

  calls[count].fn = fn;
  count++;
}

void host_ui_display_reset(void) {
  memset(calls, 0, sizeof(calls));
  count = 0;
}

unsigned host_ui_display_calls(void) {
  return count;
}

const char* host_ui_display_call(unsigned i) {
  return (i < count) ? calls[i].fn : "";
}

/* The progress bar's readings, oldest first: the fractions an upgrade reported, in order. */
uint8_t host_ui_display_progress_at(unsigned i) {
  return (i < count) ? calls[i].progress : 0;
}

core_evt_t ui_qrscan(ur_type_t type, void* out) {
  (void)type;
  (void)out;
  record("ui_qrscan");
  return host_ui_answer_for("ui_qrscan");
}

core_evt_t ui_qrscan_tx(ur_type_t* type, void* out) {
  (void)out;
  if (type) {
    *type = 0;
  }
  record("ui_qrscan_tx");
  return host_ui_answer_for("ui_qrscan_tx");
}

core_evt_t ui_display_eth_tx(const uint8_t* address, const txContent_t* tx) {
  (void)address;
  (void)tx;
  record("ui_display_eth_tx");
  return host_ui_answer_for("ui_display_eth_tx");
}

core_evt_t ui_display_btc_tx(const btc_tx_ctx_t* tx) {
  (void)tx;
  record("ui_display_btc_tx");
  return host_ui_answer_for("ui_display_btc_tx");
}

core_evt_t ui_display_eip712(const uint8_t* address, const eip712_ctx_t* eip712) {
  (void)address;
  (void)eip712;
  record("ui_display_eip712");
  return host_ui_answer_for("ui_display_eip712");
}

core_evt_t ui_display_msg(addr_type_t addr_type, const uint8_t* address, const uint8_t* msg,
                          uint32_t len) {
  (void)addr_type;
  (void)address;
  (void)msg;
  (void)len;
  record("ui_display_msg");
  return host_ui_answer_for("ui_display_msg");
}

core_evt_t ui_display_ur_qr(const char* title, const uint8_t* data, uint32_t len, ur_type_t type) {
  (void)title;
  (void)data;
  (void)len;
  (void)type;
  record("ui_display_ur_qr");
  return host_ui_answer_for("ui_display_ur_qr");
}

core_evt_t ui_display_address_qr(const char* title, const char* address, uint32_t* index) {
  (void)title;
  (void)address;
  if (index) {
    *index = 0;
  }
  record("ui_display_address_qr");
  return host_ui_answer_for("ui_display_address_qr");
}

core_evt_t ui_display_msg_qr(const char* title, const char* msg, const char* label) {
  (void)title;
  (void)msg;
  (void)label;
  record("ui_display_msg_qr");
  return host_ui_answer_for("ui_display_msg_qr");
}

core_evt_t ui_verify_address(ui_verify_match_fn_t match, void* ctx, uint32_t first_index,
                             uint32_t last_index, bool* found) {
  (void)match;
  (void)ctx;
  (void)first_index;
  (void)last_index;
  if (found) {
    *found = false;
  }
  record("ui_verify_address");
  return host_ui_answer_for("ui_verify_address");
}

core_evt_t ui_confirm_export_key(void) {
  record("ui_confirm_export_key");
  return host_ui_answer_for("ui_confirm_export_key");
}

core_evt_t ui_device_auth(uint32_t first_auth, uint32_t auth_time, uint32_t auth_count) {
  (void)first_auth;
  (void)auth_time;
  (void)auth_count;
  record("ui_device_auth");
  return host_ui_answer_for("ui_device_auth");
}

core_evt_t ui_devinfo(const char* fw_ver, const char* app_ver, const char* db_ver, const char* sn) {
  (void)fw_ver;
  (void)app_ver;
  (void)db_ver;
  (void)sn;
  record("ui_devinfo");
  return host_ui_answer_for("ui_devinfo");
}

core_evt_t ui_read_mnemonic_verify(uint32_t* len) {
  if (len) {
    *len = 0;
  }
  record("ui_read_mnemonic_verify");
  return host_ui_answer_for("ui_read_mnemonic_verify");
}

core_evt_t ui_read_number_direct(const char* title, uint32_t* num) {
  (void)title;
  if (num) {
    *num = 0;
  }
  record("ui_read_number_direct");
  return host_ui_answer_for("ui_read_number_direct");
}

void ui_update_progress(const char* title, uint8_t progress) {
  (void)title;
  if (count < DISPLAY_CALLS) {
    record("ui_update_progress");
    calls[count - 1].progress = progress;
  }
}
