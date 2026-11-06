#include <string.h>

#include "crypto/aes.h"
#include "crypto/sha2.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/pairing.h"
#include "storage/fs.h"
#include "storage/keys.h"
#include "unity.h"

/*
 * Pairing is three functions over the store, and the interesting part is what leaves the device: the key is
 * written under a secret that is fused into the chip, with the card's instance uid as the IV, so a record
 * read back on another machine decrypts to something else without any error being raised -- the record is
 * encrypted, not authenticated. And this is the module where the store's erase polarity was once inverted:
 * under fs_erase_all(), FS_REJECT means delete, so a predicate that answers it to a foreign magic deletes
 * settings, the token database and every other pairing it walks past.
 */

#define MAGIC_OTHER 0x1234
#define MAGIC_PAIRING 0x5041 /* pairing.c's own, so a census can count what pairing_write() left behind */

#define FILLER_LEN 4096
#define FILLER_DATA (FILLER_LEN - sizeof(fs_entry_t))

#define ASSERT_CLEAN_FLASH() \
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation())

static uint8_t* scratch;
static pairing_t card_a;
static pairing_t card_b;
static pairing_t unpaired;

void setUp(void) {
  if (scratch == NULL) {
    scratch = hal_host_low_mem(FILLER_LEN);
  }

  hal_host_flash_reset();
  hal_host_aes_reset();
  hal_host_derive_reset();

  memset(&card_a, 0, sizeof(card_a));
  memset(&card_b, 0, sizeof(card_b));
  memset(&unpaired, 0, sizeof(unpaired));

  memset(card_a.instance_uid, 0xa1, sizeof(card_a.instance_uid));
  memset(card_a.key, 0xa2, sizeof(card_a.key));
  card_a.idx = 3;

  memset(card_b.instance_uid, 0xb1, sizeof(card_b.instance_uid));
  memset(card_b.key, 0xb2, sizeof(card_b.key));
  card_b.idx = 7;

  memset(unpaired.instance_uid, 0xc1, sizeof(unpaired.instance_uid));
}

void tearDown(void) {}

static void write_foreign(size_t payload) {
  fs_entry_t* entry = (fs_entry_t*) scratch;

  entry->magic = MAGIC_OTHER;
  entry->len = payload;
  memset(scratch + sizeof(fs_entry_t), 0x5b, payload);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(entry, sizeof(fs_entry_t) + payload));
}

struct uid_ctx {
  const uint8_t* uid;
};

static fs_action_t match_uid(void* ctx, fs_entry_t* entry) {
  struct uid_ctx* uid_ctx = ctx;

  if (entry->magic != MAGIC_PAIRING) {
    return FS_REJECT;
  }

  return memcmp(((const pairing_t*)entry)->instance_uid, uid_ctx->uid, APP_INFO_INSTANCE_UID_LEN) ? FS_REJECT : FS_ACCEPT;
}

struct census {
  uint16_t magic;
  uint32_t seen;
};

static fs_action_t keep_count(void* ctx, fs_entry_t* entry) {
  struct census* census = ctx;

  if (entry->magic == census->magic) {
    census->seen++;
  }

  /* FS_ACCEPT here means keep: a census has to leave the store as it found it. */
  return FS_ACCEPT;
}

static uint32_t count(uint16_t magic) {
  struct census census = {.magic = magic, .seen = 0};

  fs_iterate(keep_count, &census);

  return census.seen;
}

static void test_a_paired_card_comes_back_with_its_key_and_index(void) {
  pairing_t read = card_a;

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  memset(&read, 0, sizeof(read));
  memcpy(read.instance_uid, card_a.instance_uid, sizeof(read.instance_uid));

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_a.key, read.key, sizeof(read.key));
  TEST_ASSERT_EQUAL_UINT(card_a.idx, read.idx);
  ASSERT_CLEAN_FLASH();
}

static void test_the_record_on_flash_does_not_hold_the_key(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));

  /* The stored bytes are the CBC chain of the pairing key under the device's derived key, with the card's
   * uid as IV -- which is what makes the uid part of the identity of a record rather than just a label
   * next to it. */
  uint8_t enc_key[AES_256_KEY_SIZE], expected[AES_256_KEY_SIZE];
  TEST_ASSERT_EQUAL_INT(ERR_OK, key_read_private(PAIRING_ENC_PRIV_KEY, enc_key));
  TEST_ASSERT_EQUAL_INT(1, aes_encrypt_cbc(enc_key, card_a.instance_uid, card_a.key, sizeof(card_a.key), expected));

  /* Nothing in flash spells the key. */
  for (uint32_t block = 0; block < HAL_FLASH_DATA_BLOCK_COUNT; block++) {
    const uint8_t* bytes = hal_host_flash_block(block);

    for (size_t off = 0; off + sizeof(card_a.key) <= HAL_FLASH_BLOCK_SIZE; off++) {
      if (memcmp(&bytes[off], card_a.key, sizeof(card_a.key)) == 0) {
        TEST_FAIL_MESSAGE("the pairing key is stored in the clear");
      }
    }
  }

  struct uid_ctx uid_ctx = {.uid = card_a.instance_uid};
  pairing_t* record = (pairing_t*)fs_find(match_uid, &uid_ctx);
  TEST_ASSERT_NOT_NULL(record);
  TEST_ASSERT_EQUAL_MEMORY(expected, record->key, sizeof(expected));
}

static void test_a_card_that_was_never_paired_is_not_found(void) {
  pairing_t read = unpaired;

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, pairing_read(&read));
}

static void test_each_card_keeps_its_own_key(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_b));
  TEST_ASSERT_EQUAL_UINT(2, count(MAGIC_PAIRING));

  pairing_t read = card_b;
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_b.key, read.key, sizeof(read.key));
  TEST_ASSERT_EQUAL_UINT(card_b.idx, read.idx);

  read = card_a;
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_a.key, read.key, sizeof(read.key));
  TEST_ASSERT_EQUAL_UINT(card_a.idx, read.idx);
}

static void test_a_refused_encryption_is_not_written(void) {
  /* Two: the model spends one on the pairing key derivation, which is also a CBC job. */
  hal_host_aes_refuse_next(2);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, pairing_write(&card_a));

  TEST_ASSERT_EQUAL_UINT(0, count(MAGIC_PAIRING));
}

static void test_a_refused_decryption_is_not_a_pairing(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));

  /* Distinguishing this from the case above matters: a record that decrypts to the wrong key is a record
   * from another device, and the secure channel rejects it later. A read that never ran has to say so, or
   * the caller hands out whatever was in out->key. */
  pairing_t read = card_a;
  memset(read.key, 0xa5, sizeof(read.key));

  hal_host_aes_refuse_next(2);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, pairing_read(&read));
}

static void test_a_record_from_another_device_decrypts_to_something_else(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));

  const uint8_t another_device[AES_256_KEY_SIZE] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
  };
  hal_host_device_secret_set(another_device);

  pairing_t read = card_a;
  memset(read.key, 0, sizeof(read.key));

  /* No MAC on the record, so nothing is detected: the answer is simply not the key, and the secure channel
   * that uses it fails closed. The point of the test is that the device secret is what protects a dumped
   * store, not the uid. */
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_TRUE(memcmp(read.key, card_a.key, sizeof(card_a.key)) != 0);
}

static void test_erasing_an_unknown_card_leaves_everything_else_alone(void) {
  for (size_t i = 0; i < 8; i++) {
    write_foreign(FILLER_DATA);
  }

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  TEST_ASSERT_EQUAL_UINT(8, count(MAGIC_OTHER));
  TEST_ASSERT_EQUAL_UINT(1, count(MAGIC_PAIRING));

  /* An erase that finds its card answers FS_STOP for the match and FS_ACCEPT -- keep -- for everything
   * else, and a foreign magic has to land in that same keep. Answering FS_REJECT instead deleted all eight
   * entries above, across twenty blocks, while reporting ERR_DATA. */
  pairing_t gone = unpaired;
  pairing_erase(&gone);

  TEST_ASSERT_EQUAL_UINT_MESSAGE(8, count(MAGIC_OTHER), "another module's entries were erased");
  TEST_ASSERT_EQUAL_UINT(1, count(MAGIC_PAIRING));

  pairing_t read = card_a;
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_a.key, read.key, sizeof(read.key));
  ASSERT_CLEAN_FLASH();
}

static void test_erasing_a_paired_card_removes_it_and_only_it(void) {
  for (size_t i = 0; i < 4; i++) {
    write_foreign(FILLER_DATA);
  }

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_b));

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_erase(&card_a));

  TEST_ASSERT_EQUAL_UINT(4, count(MAGIC_OTHER));

  pairing_t read = card_b;
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_b.key, read.key, sizeof(read.key));

  read = card_a;
  TEST_ASSERT_EQUAL_INT(ERR_DATA, pairing_read(&read));
  ASSERT_CLEAN_FLASH();
}

static void test_pairing_the_same_card_twice_appends_and_the_first_record_wins(void) {
  pairing_t second = card_a;
  memset(second.key, 0x33, sizeof(second.key));
  second.idx = 42;

  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_write(&second));

  /* fs_write() fills free space; it does not replace. keycard_pair() reads before it writes and returns
   * "already paired", which is the only reason this never bites -- a caller that wrote an updated record
   * would find the original on the next boot. */
  TEST_ASSERT_EQUAL_UINT(2, count(MAGIC_PAIRING));

  pairing_t read = card_a;
  TEST_ASSERT_EQUAL_INT(ERR_OK, pairing_read(&read));
  TEST_ASSERT_EQUAL_MEMORY(card_a.key, read.key, sizeof(read.key));
  TEST_ASSERT_EQUAL_UINT(card_a.idx, read.idx);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_paired_card_comes_back_with_its_key_and_index);
  RUN_TEST(test_the_record_on_flash_does_not_hold_the_key);
  RUN_TEST(test_a_card_that_was_never_paired_is_not_found);
  RUN_TEST(test_each_card_keeps_its_own_key);
  RUN_TEST(test_a_refused_encryption_is_not_written);
  RUN_TEST(test_a_refused_decryption_is_not_a_pairing);
  RUN_TEST(test_a_record_from_another_device_decrypts_to_something_else);
  RUN_TEST(test_erasing_an_unknown_card_leaves_everything_else_alone);
  RUN_TEST(test_erasing_a_paired_card_removes_it_and_only_it);
  RUN_TEST(test_pairing_the_same_card_twice_appends_and_the_first_record_wins);

  return UNITY_END();
}
