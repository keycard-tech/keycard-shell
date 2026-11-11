#include "unity.h"

#include <string.h>

#include "app_tasks.h"
#include "core/core.h"
#include "crypto/ecdsa.h"
#include "crypto/memzero.h"
#include "crypto/secp256k1.h"
#include "crypto/util.h"
#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/command.h"
#include "sc_host.h"
#include "storage/keys.h"
#include "usb/usb.h"
#include "ui_host.h"

/*
 * What the shell answers a host with, before any of the work the answer stands for.
 *
 * A command arrives as an APDU header, goes through the table core_usb_run() drives, and leaves as
 * segments through command.c. Three things are decided there independent of what any handler does: a
 * header of another class never reaches the table at all, an instruction the table does not have is
 * refused with its own reason, and a refusal is still a reply -- the host is waiting on the wire, so a
 * status word goes out rather than the shell going quiet.
 *
 * The tests hand over a command the way the framing does -- init_recv, receive, then the state
 * usb_task.c sets before it notifies the core -- and run it through core_usb_run(), the public entry,
 * so nothing in app/ has to be opened up for them.
 *
 * INS_GET_APP_CONF is here because it is a whole command the dispatcher answers itself, with no card
 * and no prompt: the firmware version, the token database's version, the device's serial and the public
 * half of its authentication key. It is the one row of the table whose bytes can be pinned, which makes
 * it the check that the routing did not merely reach a handler but handed it the command and read the
 * answer back.
 */

#define APP_CONF_LEN (11 + HAL_DEVICE_UID_LEN + 33)

static command_t* cmd;

/* A command as the wire delivers one: the announced length, then the header, then the state
 * usb_task.c puts it in when it posts the command to the core. */
static void given(uint8_t cla, uint8_t ins) {
  uint8_t header[5] = { cla, ins, 0x00, 0x00, 0x00 };

  cmd = &g_core.usb_command;
  memset(cmd, 0, sizeof(*cmd));

  TEST_ASSERT_EQUAL_INT(ERR_OK, command_init_recv(cmd, sizeof(header)));
  command_receive(cmd, header, sizeof(header));
  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, cmd->status);

  cmd->status = COMMAND_PROCESSING;
}

/* A command carrying data, which is how a derivation path arrives: a count of components, then that
 * many 4-byte numbers. */
static void given_path(uint8_t ins, uint8_t p2, const uint8_t* path, size_t path_len) {
  const size_t components = path_len / 4;
  const size_t len = 6 + components * 4;

  uint8_t buf[6 + BIP44_MAX_PATH_LEN + 4];

  buf[0] = 0xe0;
  buf[1] = ins;
  buf[2] = 0x00;
  buf[3] = p2;
  buf[4] = (uint8_t)(1 + components * 4);
  buf[5] = (uint8_t)components;
  memcpy(&buf[6], path, components * 4);

  cmd = &g_core.usb_command;
  memset(cmd, 0, sizeof(*cmd));

  TEST_ASSERT_EQUAL_INT(ERR_OK, command_init_recv(cmd, len));
  command_receive(cmd, buf, len);
  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, cmd->status);

  cmd->status = COMMAND_PROCESSING;
}

/* The reply the dispatcher left behind, as it would go out on the wire. */
static size_t reply(uint8_t* out, size_t max) {
  const uint8_t len = command_send(cmd, out, max);
  return len;
}

void setUp(void) {
  hal_host_flash_reset();
  hal_host_usb_reset();
  host_ui_reset();
  memset(&g_core, 0, sizeof(g_core));
}

void tearDown(void) {
}

static void test_a_command_of_another_class_is_refused_and_answered(void) {
  given(0x80, INS_GET_PUBLIC);

  core_usb_run();

  TEST_ASSERT_EQUAL_HEX16(0x6e00, APDU_SW(&cmd->apdu));

  /* Refused is not the same as dropped: the command is queued for the host either way. */
  TEST_ASSERT_EQUAL_INT(COMMAND_OUTBOUND, cmd->status);

  uint8_t out[16] = { 0 };
  TEST_ASSERT_EQUAL_UINT8(2, reply(out, sizeof(out)));
  TEST_ASSERT_EQUAL_HEX16(0x6e00, (out[0] << 8) | out[1]);
}

static void test_an_instruction_the_table_does_not_have_is_refused(void) {
  given(0xe0, 0x01);

  core_usb_run();

  /* The unknown instruction is refused with its own reason, not the class's. */
  TEST_ASSERT_EQUAL_HEX16(0x6d00, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_INT(COMMAND_OUTBOUND, cmd->status);
}

static void test_a_get_response_with_nothing_pending_is_refused(void) {
  given(0xe0, INS_GET_RESPONSE);

  /* Nothing answered a command before this one, so there is no second page of anything. */
  cmd->extra_data = NULL;
  cmd->extra_len = 0;

  core_usb_run();

  TEST_ASSERT_EQUAL_HEX16(0x6985, APDU_SW(&cmd->apdu));
  /* A run that ends leaves nothing queued behind it, whatever the command answered. */
  TEST_ASSERT_NULL(cmd->extra_data);
  TEST_ASSERT_EQUAL_UINT16(0, cmd->extra_len);
}

static void test_the_app_config_carries_the_version_the_serial_and_the_device_key(void) {
  given(0xe0, INS_GET_APP_CONF);

  core_usb_run();

  TEST_ASSERT_EQUAL_UINT16(APP_CONF_LEN, cmd->apdu.lr);

  uint8_t out[APP_CONF_LEN] = { 0 };
  TEST_ASSERT_EQUAL_UINT8(APP_CONF_LEN, reply(out, sizeof(out)));

  TEST_ASSERT_EQUAL_MEMORY(FW_VERSION, out, 3);
  TEST_ASSERT_EQUAL_UINT8(FW_VARIANT_OF(FW_VERSION[3]), out[7 + HAL_DEVICE_UID_LEN + 33]);
  TEST_ASSERT_EQUAL_UINT8(FW_BETA_OF(FW_VERSION[3]), out[8 + HAL_DEVICE_UID_LEN + 33]);

  uint8_t uid[HAL_DEVICE_UID_LEN];
  hal_device_uid(uid);
  TEST_ASSERT_EQUAL_MEMORY(uid, &out[7], HAL_DEVICE_UID_LEN);

  uint8_t key[32];
  /* The compressed key is written by the uncompressed routine, which fills 65 bytes and then
   * rewrites the first: a 33 byte buffer here would be overflowed by the call, not by the assert. */
  uint8_t pub[65];
  key_read_private(DEV_AUTH_PRIV_KEY, key);
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key33(&secp256k1, key, pub));
  memzero(key, sizeof(key));
  TEST_ASSERT_EQUAL_MEMORY(pub, &out[7 + HAL_DEVICE_UID_LEN], 33);
  memzero(pub, sizeof(pub));

  TEST_ASSERT_EQUAL_HEX16(0x9000, (out[APP_CONF_LEN - 2] << 8) | out[APP_CONF_LEN - 1]);
}

/* Three tasks block on one kernel primitive, at three indices: the core, the card and the ui. A
 * command that walks a card and then waits for the host needs the two answers told apart, which is
 * what the index is for. */
static void test_the_core_wakes_for_a_notification_on_its_own_index(void) {
  hal_host_notify_answer(CORE_EVENT_IDX, CORE_USB_EVT);

  TEST_ASSERT_EQUAL_INT(CORE_EVT_USB_CMD, core_wait_event(1, 1));

  /* One answer is one wait's worth. With nothing left pending, the next one times out. */
  hal_host_notify_timeouts(CORE_EVENT_IDX, true);
  TEST_ASSERT_EQUAL_INT(CORE_EVT_NONE, core_wait_event(1, 1));
}

static void test_a_notification_for_another_task_does_not_wake_the_core(void) {
  hal_host_notify_timeouts(CORE_EVENT_IDX, true);
  hal_host_notify_answer(SMARTCARD_TASK_NOTIFICATION_IDX, HAL_SUCCESS);

  TEST_ASSERT_EQUAL_INT(CORE_EVT_NONE, core_wait_event(1, 1));
}

/* The other half of a notification: a wake-up that arrives while the core is not accepting host
 * commands is a command to drop whatever the host was waiting for -- with a reason, not in silence. */
static void test_a_command_the_host_abandoned_is_answered_a_reason(void) {
  given(0xe0, INS_GET_PUBLIC);

  hal_host_notify_answer(CORE_EVENT_IDX, CORE_USB_EVT);
  hal_host_notify_timeouts(CORE_EVENT_IDX, true);

  TEST_ASSERT_EQUAL_INT(CORE_EVT_NONE, core_wait_event(1, 0));

  TEST_ASSERT_EQUAL_HEX16(0x6982, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_INT(COMMAND_OUTBOUND, cmd->status);
}

/* A report in, a report out -- the framing usb.c adds over command.c, with the shell's own callbacks
 * driven the way the peripheral drives them: the armed read completing, then the OUT data arriving. */
static void given_report(const uint8_t* apdu, size_t len) {
  uint8_t report[HAL_USB_MPS] = { 0 };

  report[0] = 0x01;
  report[1] = 0x02;
  report[2] = USB_CMD_APDU;
  report[3] = 0;
  report[4] = 0;
  report[5] = (uint8_t)(len >> 8);
  report[6] = (uint8_t)len;
  memcpy(&report[7], apdu, len);

  hal_host_usb_out(0x01, report, sizeof(report));
  hal_usb_data_in_cb(1);
  hal_usb_data_out_cb(1);
}

static void test_a_hid_report_becomes_a_command(void) {
  const uint8_t apdu[] = { 0xe0, INS_GET_APP_CONF, 0x00, 0x00 };

  given_report(apdu, sizeof(apdu));

  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, g_core.usb_command.status);
  TEST_ASSERT_EQUAL_UINT16(sizeof(apdu), g_core.usb_command.apdu.lr);

  /* usb_task.c posts the command to the core in this state, and sends the reply itself afterwards. */
  g_core.usb_command.status = COMMAND_PROCESSING;
  core_usb_run();

  /* Nothing has left: the reply is the task's to send, and it is not sent by the dispatcher. */
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());

  usb_hid_send_rapdu();

  uint8_t out[HAL_USB_MPS] = { 0 };
  TEST_ASSERT_EQUAL_size_t(HAL_USB_MPS, hal_host_usb_sent_at(0, out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT8(0x81, hal_host_usb_sent_epaddr(0));

  TEST_ASSERT_EQUAL_UINT8(0x01, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0x02, out[1]);
  TEST_ASSERT_EQUAL_UINT8(USB_CMD_APDU, out[2]);

  /* The first report carries the total in its own header, which later ones do not. */
  TEST_ASSERT_EQUAL_UINT8(0, out[3]);
  TEST_ASSERT_EQUAL_UINT8(0, out[4]);
  TEST_ASSERT_EQUAL_UINT8(0, out[5]);
  TEST_ASSERT_EQUAL_UINT8(APP_CONF_LEN, out[6]);
  TEST_ASSERT_EQUAL_MEMORY(FW_VERSION, &out[7], 3);

  /* The peripheral is busy until it reports the transfer done, which is what usb_task.c polls. */
  TEST_ASSERT_TRUE(usb_send_busy());
}

/* A report on a long command is segmented, and the continuation carries no length header -- so the
 * two halves have to be told apart by the segment count, which is what the host counts on. */
static void test_a_second_report_carries_no_length_header(void) {
  const uint8_t apdu[] = { 0xe0, INS_GET_APP_CONF, 0x00, 0x00 };

  given_report(apdu, sizeof(apdu));
  g_core.usb_command.status = COMMAND_PROCESSING;
  core_usb_run();
  usb_hid_send_rapdu();

  /* The transfer completing is what clears the busy flag; nothing else does. */
  hal_usb_data_in_cb(1);
  TEST_ASSERT_FALSE(usb_send_busy());

  usb_hid_send_rapdu();

  uint8_t out[HAL_USB_MPS] = { 0 };
  TEST_ASSERT_EQUAL_size_t(HAL_USB_MPS, hal_host_usb_sent_at(1, out, sizeof(out)));

  TEST_ASSERT_EQUAL_UINT8(0, out[3]);
  TEST_ASSERT_EQUAL_UINT8(1, out[4]); /* segment_count 1, in the two bytes a continuation has */

  /* A continuation carries data where a first report carries a length -- and where it resumed is the
   * byte after the version tail, ending on the status word. */
  TEST_ASSERT_EQUAL_UINT8(FW_BETA_OF(FW_VERSION[3]), out[5]);
  TEST_ASSERT_EQUAL_UINT8(0x90, out[6]);
  TEST_ASSERT_EQUAL_UINT8(0x00, out[7]);
}

/* The one command answered without reaching the core at all. */
static void test_a_ping_is_echoed_as_it_arrived(void) {
  uint8_t report[HAL_USB_MPS] = { 0 };
  report[0] = 0x07;
  report[1] = 0x08;
  report[2] = USB_CMD_PING;
  report[3] = 0x5a;

  hal_host_usb_out(0x01, report, sizeof(report));
  hal_usb_data_in_cb(1);
  hal_usb_data_out_cb(1);

  uint8_t out[HAL_USB_MPS] = { 0 };
  TEST_ASSERT_EQUAL_size_t(HAL_USB_MPS, hal_host_usb_sent_at(0, out, sizeof(out)));
  TEST_ASSERT_EQUAL_MEMORY(report, out, HAL_USB_MPS);

  /* A ping is not a command, so the core was never woken and nothing is queued for it. */
  TEST_ASSERT_EQUAL_INT(COMMAND_INBOUND, g_core.usb_command.status);
}

/* A host that asks for the rest of a reply the shell never started giving it. There is no pending
 * segment to hand over -- but the host is waiting on the wire, so it gets a reason rather than silence. */
static void test_a_response_that_was_never_started_is_refused_a_reason(void) {
  given(0xe0, INS_GET_RESPONSE);

  core_usb_run();

  TEST_ASSERT_EQUAL_HEX16(0x6985, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_INT(COMMAND_OUTBOUND, cmd->status);
}

/* A first report announces how many bytes the command will be. One that announces more than the
 * buffer holds cannot be received at all, and the refusal happens before any of it is copied -- the
 * shell is not left holding a command that cannot complete, which the second half of this case is
 * really about. */
static void test_a_command_larger_than_the_buffer_is_refused_before_any_of_it_is_taken_in(void) {
  uint8_t report[HAL_USB_MPS] = { 0 };
  report[0] = 0x01;
  report[1] = 0x02;
  report[2] = USB_CMD_APDU;
  report[5] = (uint8_t)(APDU_BUF_LEN >> 8);
  report[6] = (uint8_t)APDU_BUF_LEN; /* the first length that does not fit, by one byte */

  hal_host_usb_out(0x01, report, sizeof(report));
  hal_usb_data_in_cb(1);
  hal_usb_data_out_cb(1);

  cmd = &g_core.usb_command;

  TEST_ASSERT_EQUAL_INT(COMMAND_INBOUND, cmd->status);
  TEST_ASSERT_EQUAL_UINT16(0, cmd->apdu.lr);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());

  /* A command that was never begun leaves nothing in the way of the next one. */
  const uint8_t apdu[] = { 0xe0, INS_GET_APP_CONF, 0x00, 0x00 };
  given_report(apdu, sizeof(apdu));

  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, cmd->status);
  TEST_ASSERT_EQUAL_UINT16(sizeof(apdu), cmd->apdu.lr);
}

/* One command at a time: a report that arrives while the shell still holds an answer for the host is
 * not a new command, and taking it in would overwrite the reply nobody has read yet. */
static void test_a_second_command_while_one_is_outstanding_is_not_taken_in(void) {
  const uint8_t first[] = { 0xe0, INS_GET_APP_CONF, 0x00, 0x00 };
  const uint8_t second[] = { 0xe0, INS_GET_RESPONSE, 0x00, 0x00 };

  given_report(first, sizeof(first));
  given_report(second, sizeof(second));

  cmd = &g_core.usb_command;

  TEST_ASSERT_EQUAL_INT(COMMAND_COMPLETE, cmd->status);
  TEST_ASSERT_EQUAL_UINT16(sizeof(first), cmd->apdu.lr);
  TEST_ASSERT_EQUAL_UINT8(INS_GET_APP_CONF, APDU_INS(&cmd->apdu));
}

/* What a host asks for when it wants a key out of the shell: a derivation path, and the user's
 * agreement to hand one over. Both refusals come before the card is involved, which is the point of
 * the pair -- a request the shell cannot serve, and a request the user will not allow, are both settled
 * with the host and not with the card. */
static void test_a_derivation_path_too_long_to_hold_is_refused_without_a_prompt(void) {
  /* One component past what the shell holds. The components themselves are never read, which is what
   * the case is about -- but the request has to carry them to be a request for them. */
  uint8_t path[BIP44_MAX_PATH_LEN + 4];
  memset(path, 0x2c, sizeof(path));

  given_path(INS_GET_PUBLIC, 0, path, sizeof(path));

  core_usb_run();

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, host_ui_call_count("ui_confirm_export_key"));
}

static void test_a_key_export_the_user_declines_is_answered_a_reason_and_reaches_no_card(void) {
  static const uint8_t path[4] = {0x80, 0x00, 0x00, 0x2c}; /* m/44' */

  given_path(INS_GET_PUBLIC, 0, path, sizeof(path));

  host_ui_answer_call("ui_confirm_export_key", CORE_EVT_UI_CANCELLED);

  core_usb_run();

  TEST_ASSERT_EQUAL_HEX16(0x6982, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(1, host_ui_call_count("ui_confirm_export_key"));

  /* The prompt comes first, so no command ever left for the card: a key nobody approved was never
   * asked for. */
  TEST_ASSERT_EQUAL_UINT(0, hal_host_sc_send_calls());
}

/* Enumeration, which is everything a host does before it is entitled to a single report. A SETUP
 * packet is eight bytes the peripheral hands over as they came on the wire; a descriptor request
 * carries its index in the low half of the value and its type above it. */
static void given_setup(uint8_t req_type, uint8_t req, uint8_t desc_idx, uint8_t desc_type, uint16_t idx,
                        uint16_t len) {
  uint8_t data[8] = {req_type, req, desc_idx, desc_type, (uint8_t)idx, (uint8_t)(idx >> 8), (uint8_t)len,
                     (uint8_t)(len >> 8)};

  hal_usb_setup_cb(data);
}

/* What the shell answered on the control endpoint. */
static size_t sent(uint8_t* out, size_t max) {
  const size_t len = hal_host_usb_sent_at(0, out, max);
  TEST_ASSERT_EQUAL_UINT8(0x80, hal_host_usb_sent_epaddr(0));
  return len;
}

/* What an accepted request with no data stage looks like: one send, and nothing in it. The length
 * alone cannot say so -- no reply and an empty reply are the same number -- so the call count is what
 * carries the assertion. */
static void assert_ep0_ack(void) {
  uint8_t nothing[8] = { 0xa5 };

  TEST_ASSERT_EQUAL_UINT(1, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_size_t(0, sent(nothing, sizeof(nothing)));
}

/* A stalled control endpoint is unstalled by the host's CLEAR_FEATURE; a test asks the same way to get
 * back to a quiet endpoint between requests. */
static void given_ep0_cleared(void) {
  hal_usb_set_stall(0x00, 0);
  hal_usb_set_stall(0x80, 0);
  hal_host_usb_sent_clear();
}

static void expect_utf16(uint8_t idx, const char* text) {
  uint8_t out[HAL_USB_MPS] = { 0 };
  const size_t want = 2 + 2 * strlen(text);

  given_setup(0x80, USB_REQ_GET_DESCRIPTOR, idx, USB_DESC_STRING, 0, sizeof(out));

  TEST_ASSERT_EQUAL_size_t(want, sent(out, sizeof(out)));

  /* The length byte counts itself and the type, and every character is followed by the high byte a
   * UTF-16 unit has and a C string does not. */
  TEST_ASSERT_EQUAL_UINT8(want, out[0]);
  TEST_ASSERT_EQUAL_UINT8(USB_DESC_STRING, out[1]);

  for (size_t i = 0; i < strlen(text); i++) {
    TEST_ASSERT_EQUAL_UINT8((uint8_t)text[i], out[2 + 2 * i]);
    TEST_ASSERT_EQUAL_UINT8(0, out[3 + 2 * i]);
  }
}

/* What a host matches on before it loads a driver, and what it then asks for by number. */
static void test_the_device_descriptor_says_who_the_shell_is(void) {
  given_setup(0x80, USB_REQ_GET_DESCRIPTOR, 0, USB_DESC_DEV, 0, sizeof(usb_dev_desc_t));

  uint8_t out[HAL_USB_MPS] = { 0 };
  TEST_ASSERT_EQUAL_size_t(sizeof(usb_dev_desc_t), sent(out, sizeof(out)));

  usb_dev_desc_t desc;
  memcpy(&desc, out, sizeof(desc));

  TEST_ASSERT_EQUAL_UINT8(18, desc.len);
  TEST_ASSERT_EQUAL_UINT8(0x01, desc.type);
  TEST_ASSERT_EQUAL_UINT16(0x0200, desc.usb_version);
  TEST_ASSERT_EQUAL_UINT16(0x1209, desc.vendor_id); /* pid.codes */
  TEST_ASSERT_EQUAL_UINT16(0x21f7, desc.product_id);
  TEST_ASSERT_EQUAL_UINT8(HAL_USB_MPS, desc.max_packet_size); /* the same width as every report */
  TEST_ASSERT_EQUAL_UINT8(1, desc.config_count);

  /* The three strings a host reads are the ones the string descriptor answers below. */
  TEST_ASSERT_EQUAL_UINT8(USB_MANUFACTURER_IDX, desc.manufacturer_str_idx);
  TEST_ASSERT_EQUAL_UINT8(USB_PRODUCT_IDX, desc.product_str_idx);
  TEST_ASSERT_EQUAL_UINT8(USB_SN_IDX, desc.serial_number_str_idx);
}

/* The configuration descriptor is one block: header, interface, HID, and the two endpoints. A host
 * reads the length out of the descriptor itself, so the two have to agree -- one number is stated in
 * the descriptor and the other is what the shell was willing to put on the wire. */
static void test_the_configuration_descriptor_describes_its_own_length(void) {
  given_setup(0x80, USB_REQ_GET_DESCRIPTOR, 0, USB_DESC_CONFIG, 0, sizeof(usb_hid_inout_desc_t));

  uint8_t out[HAL_USB_MPS] = { 0 };
  const size_t len = sent(out, sizeof(out));

  TEST_ASSERT_EQUAL_size_t(sizeof(usb_hid_inout_desc_t), len);
  TEST_ASSERT_EQUAL_UINT8(9, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0x02, out[1]);

  usb_conf_desc_t confd;
  memcpy(&confd, out, sizeof(confd));
  TEST_ASSERT_EQUAL_UINT16(len, confd.total_len);
}

static void test_the_manufacturer_and_product_strings_are_utf_16(void) {
  expect_utf16(USB_MANUFACTURER_IDX, USB_MANUFACTURER_STR);

  hal_host_usb_sent_clear();

  expect_utf16(USB_PRODUCT_IDX, USB_PRODUCT_STR);
}

/* The serial number is the device's UID written out in hex, and it does not all fit: sixteen bytes
 * become sixty-four characters of UTF-16, two past what one report holds, so the last byte of the UID
 * is not in the serial a host reads. What the shell answers is pinned here because it is not something
 * a host can discover -- it can only observe it, if it knows the UID. */
static void test_the_serial_string_is_the_uid_minus_its_last_byte(void) {
  uint8_t uid[HAL_DEVICE_UID_LEN];
  hal_device_uid(uid);

  given_setup(0x80, USB_REQ_GET_DESCRIPTOR, USB_SN_IDX, USB_DESC_STRING, 0, HAL_USB_MPS);

  uint8_t out[HAL_USB_MPS] = { 0 };
  const size_t want = 2 + 4 * (HAL_DEVICE_UID_LEN - 1);

  TEST_ASSERT_EQUAL_size_t(want, sent(out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT8(want, out[0]);
  TEST_ASSERT_EQUAL_UINT8(USB_DESC_STRING, out[1]);

  for (size_t i = 0; i < HAL_DEVICE_UID_LEN - 1; i++) {
    TEST_ASSERT_EQUAL_HEX8(HEX_DIGITS[(uid[i] >> 4) & 0xf], out[2 + 4 * i]);
    TEST_ASSERT_EQUAL_UINT8(0, out[3 + 4 * i]);
    TEST_ASSERT_EQUAL_HEX8(HEX_DIGITS[uid[i] & 0xf], out[4 + 4 * i]);
    TEST_ASSERT_EQUAL_UINT8(0, out[5 + 4 * i]);
  }
}

/* A request for a descriptor the shell does not have is refused the way USB refuses: the control
 * endpoint stalls, and nothing is sent to be misread as an answer. */
static void test_a_descriptor_the_shell_has_not_stalls_the_control_endpoint(void) {
  given_setup(0x80, USB_REQ_GET_DESCRIPTOR, 0, 0x0f, 0, HAL_USB_MPS);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x80));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
}

static void test_an_address_is_taken_and_an_unknown_recipient_is_refused(void) {
  given_setup(0x80, USB_REQ_SET_ADDRESS, 7, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(7, hal_host_usb_device_address());

  /* The acknowledgement is a zero-length transfer, not a silence. */
  TEST_ASSERT_EQUAL_UINT(1, hal_host_usb_send_calls());
  uint8_t out[8];
  TEST_ASSERT_EQUAL_size_t(0, hal_host_usb_sent_at(0, out, sizeof(out)));

  /* A recipient that is neither device, interface nor endpoint -- the shell reads those five bits and
   * stalls on anything else, rather than guessing which interface was meant. */
  hal_host_usb_sent_clear();

  given_setup(0x80 | 0x07, USB_REQ_GET_STATUS, 0, 0, 0, 2); /* recipient 7 is reserved */

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x80));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
}

/* The HID class requests carry no payload either way: an idle rate of zero is what the shell was
 * configured with, and a request the HID class does not define is stalled rather than answered with
 * something the host would accept as a number. */
static void test_a_hid_request_is_answered_and_an_unknown_class_request_is_not(void) {
  given_setup(0x81 | USB_REQUEST_CLASS, USB_HID_GET_IDLE, 0, 0, 0, 1);

  uint8_t out[8] = { 0xff };
  TEST_ASSERT_EQUAL_size_t(1, sent(out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT8(0, out[0]);

  hal_host_usb_sent_clear();

  given_setup(0x81 | USB_REQUEST_CLASS, 0x99, 0, 0, 0, 1);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x80));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
}

/* Endpoints halt, report that they halted, and are cleared again -- and the status word is the halt,
 * read back through the same endpoint number the host named in wIndex. */
static void test_an_endpoint_halt_is_set_reported_and_cleared(void) {
  given_setup(0x02 /* host-to-device, standard, endpoint */, USB_REQ_SET_FEATURE, USB_EP_HALT, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x81));

  /* Nothing is sent: halting an endpoint is not a transfer. */
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());

  given_setup(0x82, USB_REQ_GET_STATUS, 0, 0, 0x81, 2);

  uint8_t out[8] = { 0 };
  TEST_ASSERT_EQUAL_size_t(2, sent(out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT16(1, (uint16_t)(out[0] | (out[1] << 8)));

  given_setup(0x02, USB_REQ_CLEAR_FEATURE, USB_EP_HALT, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(0, hal_host_usb_stall(0x81));

  hal_host_usb_sent_clear();

  given_setup(0x82, USB_REQ_GET_STATUS, 0, 0, 0x81, 2);

  TEST_ASSERT_EQUAL_size_t(2, sent(out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT16(0, (uint16_t)(out[0] | (out[1] << 8)));
}

/* A host may clear a feature the shell does not implement; that is not a licence to drop the halt. The
 * request is answered by the same code as the real one, so the guard is the number in wValue. */
static void test_an_unknown_endpoint_feature_is_refused_and_leaves_the_halt_in_place(void) {
  /* ENDPOINT_HALT is the only feature an endpoint has, so a selector beside it is a request the shell
   * cannot do: refused on the control pipe, and nothing the host did not ask about changing state. */
  given_setup(0x02 /* host-to-device, standard, endpoint */, USB_REQ_SET_FEATURE, USB_EP_HALT + 1, 0,
              0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(0, hal_host_usb_stall(0x81));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());

  given_ep0_cleared();

  given_setup(0x02, USB_REQ_SET_FEATURE, USB_EP_HALT, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x81));

  /* Clearing a feature the shell does not have is refused the same way, and the halt that is really
   * there stays where it is: the request was not about it. */
  given_setup(0x02, USB_REQ_CLEAR_FEATURE, USB_EP_HALT + 1, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x81));
}

/* One interface, always. It is reported, and an interface-level feature is refused rather than
 * remembered: there is nothing at that level for the shell to have configured, and a shell that
 * accepted the request would be promising a state it does not keep. */
static void test_the_interface_is_reported_and_its_features_are_refused(void) {
  given_setup(0x81 /* device-to-host, standard, interface */, USB_REQ_GET_INTERFACE, 0, 0, 0, 1);

  uint8_t out[8] = { 0xff };
  TEST_ASSERT_EQUAL_size_t(1, sent(out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT8(0, out[0]);

  /* An interface is neither halted nor enabled by a host: the shell stalls to say so. */
  given_setup(0x01, USB_REQ_SET_FEATURE, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
}

/* One interface, always, and one alternate setting on it. The default is reported and confirmed;
 * anything a host names beside it is not in the descriptors, and 9.4.10 and 9.4.9 make that a Request
 * Error rather than a polite yes. wValue carries the alternate setting, wIndex the interface. */
static void test_the_default_interface_setting_is_accepted_and_any_other_is_refused(void) {
  given_setup(0x01 /* host-to-device, standard, interface */, USB_REQ_SET_INTERFACE, 0, 0, 0, 0);

  assert_ep0_ack();
  TEST_ASSERT_EQUAL_UINT8(0, hal_host_usb_stall(0x00));

  given_ep0_cleared();

  given_setup(0x01, USB_REQ_SET_INTERFACE, 1 /* a second alternate setting */, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));

  given_ep0_cleared();

  given_setup(0x81, USB_REQ_GET_INTERFACE, 0, 0, 1 /* an interface no configuration declares */, 1);

  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
}

/* SYNCH_FRAME is an endpoint request asking for the frame number of an isochronous endpoint. This
 * device has interrupt endpoints only, so the answer is a refusal on the control pipe. It used to be
 * an order to halt the endpoint named in wIndex, which is the report channel the host is polling: a
 * refusal that stopped the thing the host was talking about. */
static void test_a_synchronisation_request_is_refused_without_stopping_the_report_channel(void) {
  given_setup(0x82 /* device-to-host, standard, endpoint */, USB_REQ_SYNCH_FRAME, 0, 0, 0x81, 2);

  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(0, hal_host_usb_stall(0x81));
}

/* A number with no case is refused, which is the least the shell can do: 9.4 asks a device to answer
 * standard requests, and an answer of nothing at all leaves the host waiting for a status stage no one
 * arms -- the shell's own way of accepting is a zero-length IN, and nothing under hal_usb_setup_cb
 * does it instead. That silence is also how two wrong constants in usb.h survived: Table 9-4 gives the
 * standard request codes in decimal, GET_INTERFACE, SET_INTERFACE and SYNCH_FRAME being 10, 11 and 12,
 * and the enum had 0x11 and 0x12, which are seventeen and eighteen. What is left to refuse here are the
 * two numbers Table 9-4 itself reserves, and they stay in this test so that the next request the shell
 * does not know ends as a stall a host can read instead of a timeout nobody can. */
static void test_a_request_number_the_shell_does_not_have_is_refused(void) {
  given_setup(0x01 /* standard, interface */, 0x02 /* reserved for future use */, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x80));

  given_ep0_cleared();

  given_setup(0x02 /* standard, endpoint */, 0x04 /* reserved for future use */, 0, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT(0, hal_host_usb_send_calls());
  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
}

/* A HID request belongs to the interface. Aimed somewhere else it is not a request the shell has,
 * whatever the number says, and a class request to the device or a vendor request to an endpoint is
 * refused rather than mistaken for the interface's. */
static void test_a_class_or_vendor_request_at_the_wrong_recipient_is_refused(void) {
  given_setup(0x20 /* host-to-device, class, device */, USB_HID_SET_IDLE, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));

  given_ep0_cleared();

  given_setup(0x42 /* host-to-device, vendor, endpoint */, 0x00, 0, 0, 0x81, 0);

  TEST_ASSERT_EQUAL_UINT8(1, hal_host_usb_stall(0x00));
  TEST_ASSERT_EQUAL_UINT8(0, hal_host_usb_stall(0x81));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_command_of_another_class_is_refused_and_answered);
  RUN_TEST(test_an_instruction_the_table_does_not_have_is_refused);
  RUN_TEST(test_a_get_response_with_nothing_pending_is_refused);
  RUN_TEST(test_the_app_config_carries_the_version_the_serial_and_the_device_key);
  RUN_TEST(test_the_core_wakes_for_a_notification_on_its_own_index);
  RUN_TEST(test_a_notification_for_another_task_does_not_wake_the_core);
  RUN_TEST(test_a_command_the_host_abandoned_is_answered_a_reason);
  RUN_TEST(test_an_endpoint_halt_is_set_reported_and_cleared);
  RUN_TEST(test_an_unknown_endpoint_feature_is_refused_and_leaves_the_halt_in_place);
  RUN_TEST(test_the_interface_is_reported_and_its_features_are_refused);
  RUN_TEST(test_the_default_interface_setting_is_accepted_and_any_other_is_refused);
  RUN_TEST(test_a_request_number_the_shell_does_not_have_is_refused);
  RUN_TEST(test_a_synchronisation_request_is_refused_without_stopping_the_report_channel);
  RUN_TEST(test_a_class_or_vendor_request_at_the_wrong_recipient_is_refused);
  RUN_TEST(test_the_device_descriptor_says_who_the_shell_is);
  RUN_TEST(test_the_configuration_descriptor_describes_its_own_length);
  RUN_TEST(test_the_manufacturer_and_product_strings_are_utf_16);
  RUN_TEST(test_the_serial_string_is_the_uid_minus_its_last_byte);
  RUN_TEST(test_a_descriptor_the_shell_has_not_stalls_the_control_endpoint);
  RUN_TEST(test_an_address_is_taken_and_an_unknown_recipient_is_refused);
  RUN_TEST(test_a_hid_request_is_answered_and_an_unknown_class_request_is_not);
  RUN_TEST(test_a_derivation_path_too_long_to_hold_is_refused_without_a_prompt);
  RUN_TEST(test_a_key_export_the_user_declines_is_answered_a_reason_and_reaches_no_card);
  RUN_TEST(test_a_response_that_was_never_started_is_refused_a_reason);
  RUN_TEST(test_a_command_larger_than_the_buffer_is_refused_before_any_of_it_is_taken_in);
  RUN_TEST(test_a_second_command_while_one_is_outstanding_is_not_taken_in);
  RUN_TEST(test_a_hid_report_becomes_a_command);
  RUN_TEST(test_a_second_report_carries_no_length_header);
  RUN_TEST(test_a_ping_is_echoed_as_it_arrived);

  return UNITY_END();
}
