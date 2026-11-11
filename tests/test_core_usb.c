#include "unity.h"

#include <string.h>

#include "app_tasks.h"
#include "core/core.h"
#include "crypto/ecdsa.h"
#include "crypto/memzero.h"
#include "crypto/secp256k1.h"
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

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_command_of_another_class_is_refused_and_answered);
  RUN_TEST(test_an_instruction_the_table_does_not_have_is_refused);
  RUN_TEST(test_a_get_response_with_nothing_pending_is_refused);
  RUN_TEST(test_the_app_config_carries_the_version_the_serial_and_the_device_key);
  RUN_TEST(test_the_core_wakes_for_a_notification_on_its_own_index);
  RUN_TEST(test_a_notification_for_another_task_does_not_wake_the_core);
  RUN_TEST(test_a_command_the_host_abandoned_is_answered_a_reason);
  RUN_TEST(test_a_hid_report_becomes_a_command);
  RUN_TEST(test_a_second_report_carries_no_length_header);
  RUN_TEST(test_a_ping_is_echoed_as_it_arrived);

  return UNITY_END();
}
