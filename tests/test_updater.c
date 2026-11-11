#include "unity.h"

#include <string.h>

#include "app_tasks.h"
#include "core/core.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/sha2.h"
#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/command.h"
#include "keys_host.h"
#include "mem.h"
#include "sc_host.h"
#include "ethereum/eth_db.h"
#include "ui_host.h"

#include "vectors/vectors_eth_db.h"

/*
 * Two upgrades, arrived at over the wire and finished in flash.
 *
 * Both are segmented: the first command announces a total in its first four bytes, and what follows is
 * the image until the count is up. Every segment answers 9000 and asks for more, so the interesting
 * part is what the shell does at the boundary -- what it verifies, what it asks the user, and what it
 * leaves in flash when the answer is no. A rejected image must not survive in the upgrade area, because
 * that area is what the bootloader boots if a switch is ever requested.
 *
 * The keys are real. A firmware upgrade is checked against the .header of the *bootloader*, at
 * HAL_FLASH_ADDR + HAL_FW_HEADER_OFFSET, which is a block the app cannot rewrite and which
 * tools/bootloader-perso.py provisions -- so the test provisions it too, into the flash model, and the
 * signature over the image is the firmware's own ecdsa path. A token database is checked against
 * .db_auth_key, a section the release tool substitutes, and host_key_set() substitutes it here the same
 * way. Nothing in either check is stubbed: an image signed with some other key is refused by the code
 * under test, not by a test that declined to run it.
 *
 * The segments are driven one core_usb_run() at a time, with the core's wait told to time out. Left
 * scripted to succeed with no event set, core_wait_event() recurses looking for one it recognises, so a
 * segmented command would re-dispatch the same segment forever.
 */

#define SEG_LEN 240
#define IMG_LEN 656 /* through the version bytes and one more flash word */
#define AREA_LEN (HAL_FLASH_FW_BLOCK_COUNT * HAL_FLASH_BLOCK_SIZE)
/* The image's own header, in the order the linker script lays it out: the signature over everything
 * else, then the version the upgrade is accepted or refused on. */
#define SIG_LEN 64
#define VERSION_OFFSET (HAL_FW_HEADER_OFFSET + SIG_LEN)

#define RNG_SEED 0x5f3759dfUL

#define APP_CONF_LEN (11 + HAL_DEVICE_UID_LEN + 33)

static const uint8_t SIGNING_PRIV[32] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/* Some other key, so a refusal can be told from an accident. */
static const uint8_t OTHER_PRIV[32] = {
  0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
  0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
  0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
  0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
};

static uint8_t image[IMG_LEN];
static uint8_t* db;
static command_t* cmd;

/* The firmware's own digest of an image: the area minus the 64 signature bytes, and past the image as
 * far as the area goes -- which after the erase that opens an upgrade is all 0xff. */
static void image_digest(const uint8_t* img, size_t len, uint8_t digest[32]) {
  SHA256_CTX sha;
  sha256_Init(&sha);
  sha256_Update(&sha, img, HAL_FW_HEADER_OFFSET);
  sha256_Update(&sha, &img[VERSION_OFFSET], len - VERSION_OFFSET);

  static uint8_t erased[HAL_FLASH_BLOCK_SIZE];
  memset(erased, 0xff, sizeof(erased));
  size_t rest = AREA_LEN - len;
  while (rest > 0) {
    const size_t n = rest > sizeof(erased) ? sizeof(erased) : rest;
    sha256_Update(&sha, erased, n);
    rest -= n;
  }

  sha256_Final(&sha, digest);
}

static void sign_image(const uint8_t priv[32]) {
  uint8_t digest[32];
  image_digest(image, IMG_LEN, digest);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(0, ecdsa_sign(&secp256k1, priv, digest, &image[HAL_FW_HEADER_OFFSET]));
}

static void given_image(uint8_t major, uint8_t minor, uint8_t patch, const uint8_t priv[32]) {
  memset(image, 0xa5, sizeof(image));
  image[VERSION_OFFSET] = major;
  image[VERSION_OFFSET + 1] = minor;
  image[VERSION_OFFSET + 2] = patch;
  image[VERSION_OFFSET + 3] = 0;

  sign_image(priv);
}

/* The .header of the bootloader, where the key an upgrade is verified against lives: 64 bytes of point
 * -- x then y, no prefix byte, which is the PKA's own encoding and why the section is 68 bytes wide --
 * and four bytes after it. */
static void given_firmware_key(const uint8_t priv[32]) {
  uint8_t pub[65];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key65(&secp256k1, priv, pub));

  uint8_t* block = hal_host_flash_block(0);
  memcpy(&block[HAL_FW_HEADER_OFFSET], &pub[1], 64);
}

static void send(uint8_t ins, uint8_t p1, const uint8_t* payload, size_t len) {
  uint8_t buf[5 + 4 + SEG_LEN];

  buf[0] = 0xe0;
  buf[1] = ins;
  buf[2] = p1;
  buf[3] = 0x00;
  buf[4] = (uint8_t)len;
  if (len > 0) {
    memcpy(&buf[5], payload, len);
  }

  cmd = &g_core.usb_command;
  memset(cmd, 0, sizeof(*cmd));

  TEST_ASSERT_EQUAL_INT(ERR_OK, command_init_recv(cmd, 5 + len));
  command_receive(cmd, buf, 5 + len);

  cmd->status = COMMAND_PROCESSING;

  core_usb_run();
}

/* An image, delivered the way the host delivers it: the announced length first, then SEG_LEN at a
 * time. The status word of the last command is what the caller asserts. */
static void upload(uint8_t ins, const uint8_t* bytes, size_t total) {
  size_t off = 0;

  while (off < total) {
    uint8_t payload[4 + SEG_LEN];
    size_t n = total - off;
    if (n > SEG_LEN) {
      n = SEG_LEN;
    }

    size_t plen = 0;
    if (off == 0) {
      payload[plen++] = (uint8_t)(total >> 24);
      payload[plen++] = (uint8_t)(total >> 16);
      payload[plen++] = (uint8_t)(total >> 8);
      payload[plen++] = (uint8_t)total;
    }

    memcpy(&payload[plen], &bytes[off], n);
    plen += n;

    send(ins, (off == 0) ? 0 : 1, payload, plen);
    off += n;
  }
}

static bool area_is_erased(void) {
  const uint8_t* block = hal_host_flash_block(HAL_FLASH_ADDR_TO_BLOCK(HAL_FLASH_FW_UPGRADE_AREA));

  for (size_t i = 0; i < HAL_FLASH_BLOCK_SIZE; i++) {
    if (block[i] != 0xff) {
      return false;
    }
  }

  return true;
}

void setUp(void) {
  if (db == NULL) {
    db = hal_host_low_mem(ETH_DB_BODY + 64);
  }

  hal_host_flash_reset();
  hal_host_usb_reset();
  host_ui_reset();
  host_key_reset();

  memset(&g_core, 0, sizeof(g_core));

  /* The two halves of a switch that already happened: what the next test asks is whether *this*
   * command asks for one. */
  g_bootcmd = 0;
  hal_host_reboots_clear();

  /* A core wait that times out, so one segment is dispatched per send(). Left to succeed with no
   * event set, core_wait_event() recurses looking for one it recognises. */
  hal_host_notify_timeouts(CORE_EVENT_IDX, true);
}

void tearDown(void) {
  host_key_reset();
}

/* A whole upgrade: signed by a key the device was given, newer than the one it runs. */
static void test_a_signed_firmware_upgrade_switches_the_bank_and_reboots(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, SIGNING_PRIV);

  host_ui_answer_prompt(CORE_EVT_UI_OK);

  upload(INS_FW_UPGRADE, image, IMG_LEN);

  TEST_ASSERT_EQUAL_HEX16(0x9000, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(BOOTCMD_SWITCH_FW, g_bootcmd);
  TEST_ASSERT_EQUAL_UINT(1, hal_host_reboots());
  TEST_ASSERT_EQUAL_UINT(0, hal_host_flash_violations());

  /* One progress reading per segment, and the last of them says it is done. */
  TEST_ASSERT_EQUAL_UINT(100, host_ui_display_progress_at(host_ui_display_calls() - 1));
}

/* The erase that opens an upgrade, and the programming that follows, are both the device's own. */
static void test_the_first_segment_clears_the_upgrade_area_before_writing_it(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, SIGNING_PRIV);

  /* Announce the whole image and deliver one segment, so this stops before the verification. */
  uint8_t payload[4 + SEG_LEN];
  payload[0] = 0;
  payload[1] = 0;
  payload[2] = (uint8_t)(IMG_LEN >> 8);
  payload[3] = (uint8_t)IMG_LEN;
  memcpy(&payload[4], image, SEG_LEN);
  send(INS_FW_UPGRADE, 0, payload, sizeof(payload));

  const size_t erases = HAL_FLASH_FW_BLOCK_COUNT;
  TEST_ASSERT_EQUAL_UINT(erases, hal_host_flash_erases());
  TEST_ASSERT_TRUE(hal_host_flash_programs() > 0);

  const uint8_t* area = hal_host_flash_block(HAL_FLASH_ADDR_TO_BLOCK(HAL_FLASH_FW_UPGRADE_AREA));
  TEST_ASSERT_EQUAL_UINT8(0xa5, area[0]);
  TEST_ASSERT_EQUAL_UINT8(0xff, area[SEG_LEN]);
}

/* A downgrade is refused, and refused without leaving the older image where the bootloader would find
 * it. */
static void test_an_older_firmware_is_refused_and_the_area_cleared(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] - 1, SIGNING_PRIV);

  const unsigned infos_before = host_ui_info_calls();
  upload(INS_FW_UPGRADE, image, IMG_LEN);

  TEST_ASSERT_EQUAL_HEX16(0x6982, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, g_bootcmd);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_reboots());
  TEST_ASSERT_TRUE(area_is_erased());

  /* The user is told why, once, and is not asked to confirm what was already rejected. */
  TEST_ASSERT_EQUAL_UINT(infos_before + 1, host_ui_info_calls());
}

/* The other half of the same no: an image signed by somebody else. */
static void test_firmware_signed_by_another_key_is_refused(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, OTHER_PRIV);

  upload(INS_FW_UPGRADE, image, IMG_LEN);

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, g_bootcmd);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_reboots());
  TEST_ASSERT_TRUE(area_is_erased());
}

/* A user who declines is the same no as a bad signature, except that nothing was wrong with the
 * image. */
static void test_a_declined_firmware_upgrade_is_not_switched(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, SIGNING_PRIV);

  /* The confirmation is the last thing before the switch; the refusal is its default, but say it. */
  host_ui_answer_prompt(CORE_EVT_UI_CANCELLED);

  upload(INS_FW_UPGRADE, image, IMG_LEN);

  TEST_ASSERT_EQUAL_HEX16(0x6982, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, g_bootcmd);
  TEST_ASSERT_EQUAL_UINT(0, hal_host_reboots());
  TEST_ASSERT_TRUE(area_is_erased());
}

/* Three ways a segment is not a segment, all refused before anything is written. */
static void test_a_segment_that_is_not_a_whole_flash_word_is_refused(void) {
  given_firmware_key(SIGNING_PRIV);

  uint8_t payload[4 + 15];
  payload[0] = 0;
  payload[1] = 0;
  payload[2] = 0;
  payload[3] = 128;
  memset(&payload[4], 0xa5, 15);

  send(INS_FW_UPGRADE, 0, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
}

static void test_a_first_segment_without_a_length_is_refused(void) {
  uint8_t payload[3] = { 0xa5, 0xa5, 0xa5 };

  send(INS_FW_UPGRADE, 0, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_flash_erases());
}

static void test_more_than_was_announced_is_refused(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, SIGNING_PRIV);

  /* Announce half an image, then send the whole of it. */
  uint8_t payload[4 + SEG_LEN];
  payload[0] = 0;
  payload[1] = 0;
  payload[2] = 0;
  payload[3] = SEG_LEN;
  memcpy(&payload[4], image, SEG_LEN);
  send(INS_FW_UPGRADE, 0, payload, sizeof(payload));

  send(INS_FW_UPGRADE, 1, image, SEG_LEN);

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, hal_host_reboots());
}

static void test_the_progress_bar_follows_the_bytes_received(void) {
  given_firmware_key(SIGNING_PRIV);
  given_image(FW_VERSION[0], FW_VERSION[1], FW_VERSION[2] + 1, SIGNING_PRIV);

  upload(INS_FW_UPGRADE, image, IMG_LEN);

  const unsigned first = host_ui_display_progress_at(0);
  const unsigned mid = host_ui_display_progress_at(1);

  /* 240 of 656, then 480 of 656 -- integers, and rising. */
  TEST_ASSERT_EQUAL_UINT((SEG_LEN * 100) / IMG_LEN, first);
  TEST_ASSERT_EQUAL_UINT(((2 * SEG_LEN) * 100) / IMG_LEN, mid);
  TEST_ASSERT_TRUE(mid > first);
}

/* ------------------------------------------------------------------ the token database */

static void given_db(const uint8_t priv[32]) {
  memcpy(db, ETH_DB, ETH_DB_BODY);

  uint8_t digest[32];
  sha256_Raw(db, ETH_DB_BODY, digest);

  hal_host_rng_seed(RNG_SEED);
  TEST_ASSERT_EQUAL_INT(0, ecdsa_sign(&secp256k1, priv, digest, &db[ETH_DB_BODY]));
}

static void given_db_key(const uint8_t priv[32]) {
  uint8_t pub[65];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_get_public_key33(&secp256k1, priv, pub));
  host_key_set(DB_VERIFICATION_KEY, pub);
}

static uint32_t installed_db_version(void) {
  uint32_t version = 0;
  eth_db_lookup_version(&version);
  return version;
}

static void test_a_signed_database_update_is_installed(void) {
  given_db_key(SIGNING_PRIV);
  given_db(SIGNING_PRIV);

  host_ui_answer_prompt(CORE_EVT_UI_OK);

  upload(INS_ERC20_UPGRADE, db, ETH_DB_BODY + 64);

  TEST_ASSERT_EQUAL_HEX16(0x9000, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(ETH_DB_VERSION, installed_db_version());
  TEST_ASSERT_EQUAL_UINT(0, hal_host_flash_violations());
}

/* What the host is told about the token database is the version that was just installed, which is the
 * only way the two halves of this file meet: the upgrade arrives through one instruction and leaves
 * through another. */
static void test_an_installed_database_shows_up_in_the_app_config(void) {
  given_db_key(SIGNING_PRIV);
  given_db(SIGNING_PRIV);

  host_ui_answer_prompt(CORE_EVT_UI_OK);
  upload(INS_ERC20_UPGRADE, db, ETH_DB_BODY + 64);

  send(INS_GET_APP_CONF, 0, NULL, 0);

  uint8_t out[APP_CONF_LEN] = {0};
  TEST_ASSERT_EQUAL_UINT8(APP_CONF_LEN, command_send(cmd, out, sizeof(out)));

  const uint32_t reported = ((uint32_t)out[3] << 24) | ((uint32_t)out[4] << 16) |
                            ((uint32_t)out[5] << 8) | out[6];
  TEST_ASSERT_EQUAL_UINT(ETH_DB_VERSION, reported);
}

/* The anchor the firmware was built with refuses a database signed with some other key. This is the
 * shipped .db_auth_key refusing a blob, with nothing substituted at all. */
static void test_a_database_signed_by_another_key_is_refused(void) {
  given_db(SIGNING_PRIV);

  host_ui_answer_prompt(CORE_EVT_UI_OK);

  upload(INS_ERC20_UPGRADE, db, ETH_DB_BODY + 64);

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, installed_db_version());
}

static void test_a_declined_database_update_is_not_installed(void) {
  given_db_key(SIGNING_PRIV);
  given_db(SIGNING_PRIV);

  /* The default, said out loud: nobody pressed anything. */
  host_ui_answer_prompt(CORE_EVT_UI_CANCELLED);

  upload(INS_ERC20_UPGRADE, db, ETH_DB_BODY + 64);

  TEST_ASSERT_EQUAL_HEX16(0x6982, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, installed_db_version());
}

/* MIN_DB_LEN is the signature and a version descriptor, and there is no notice for the difference
 * between that and a corrupt database -- both are "try again". */
static void test_a_database_shorter_than_its_own_header_is_refused(void) {
  given_db_key(SIGNING_PRIV);

  uint8_t payload[4 + 28];
  memset(payload, 0x5a, sizeof(payload));

  payload[0] = 0;
  payload[1] = 0;
  payload[2] = 0;
  payload[3] = 28; /* what is left after the four bytes that announced it */

  send(INS_ERC20_UPGRADE, 0, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_HEX16(0x6a80, APDU_SW(&cmd->apdu));
  TEST_ASSERT_EQUAL_UINT(0, installed_db_version());
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_signed_firmware_upgrade_switches_the_bank_and_reboots);
  RUN_TEST(test_the_first_segment_clears_the_upgrade_area_before_writing_it);
  RUN_TEST(test_an_older_firmware_is_refused_and_the_area_cleared);
  RUN_TEST(test_firmware_signed_by_another_key_is_refused);
  RUN_TEST(test_a_declined_firmware_upgrade_is_not_switched);
  RUN_TEST(test_a_segment_that_is_not_a_whole_flash_word_is_refused);
  RUN_TEST(test_a_first_segment_without_a_length_is_refused);
  RUN_TEST(test_more_than_was_announced_is_refused);
  RUN_TEST(test_the_progress_bar_follows_the_bytes_received);

  RUN_TEST(test_a_signed_database_update_is_installed);
  RUN_TEST(test_an_installed_database_shows_up_in_the_app_config);
  RUN_TEST(test_a_database_signed_by_another_key_is_refused);
  RUN_TEST(test_a_declined_database_update_is_not_installed);
  RUN_TEST(test_a_database_shorter_than_its_own_header_is_refused);

  return UNITY_END();
}
