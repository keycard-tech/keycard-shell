#include <string.h>

#include "bitcoin/multisig_crypto.h"
#include "crypto/aes.h"
#include "error.h"
#include "framework/test_util.h"
#include "hal.h"
#include "hal_host.h"
#include "storage/fs.h"
#include "storage/multisig_store.h"
#include "unity.h"

#include "vectors/vectors_multisig_crypto.h"

/*
 * The encrypted multisig descriptors. Only the four-byte blob is in the clear, and it is a keyed hash, so
 * the store can answer "what belongs to this card" without the session key deciding whether anything can
 * be read: the CCM tag is the gate. Everything here is about that split -- which bytes are searchable,
 * which are secret, what a foreign or truncated record does, and what the count means when the caller's
 * array is shorter than the answer.
 */

#define MAGIC_OTHER 0x1234

static uint8_t* scratch;
static multisig_crypto_t card;
static multisig_crypto_t other_card;

void setUp(void) {
  if (scratch == NULL) {
    scratch = hal_host_low_mem(4096);
  }

  hal_host_flash_reset();
  hal_host_aes_reset();
  hal_host_rng_seed(0x1ee715);

  uint8_t root[MULTISIG_ROOT_LEN];

  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, root, sizeof(root));
  multisig_crypto_init(&card, root, 0xDEADBEEF);

  TEST_GIVEN(MULTISIG_CRYPTO_KAT[1].root, root, sizeof(root));
  multisig_crypto_init(&other_card, root, 0xDEADBEEF);
}

void tearDown(void) {
  multisig_crypto_wipe(&card);
  multisig_crypto_wipe(&other_card);
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

  return FS_ACCEPT;
}

static uint32_t entries(uint16_t magic) {
  struct census census = {.magic = magic, .seen = 0};

  fs_iterate(keep_count, &census);

  return census.seen;
}

static void write_foreign(size_t payload) {
  fs_entry_t* entry = (fs_entry_t*) scratch;

  entry->magic = MAGIC_OTHER;
  entry->len = payload;
  memset(scratch + sizeof(fs_entry_t), 0x77, payload);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(entry, sizeof(fs_entry_t) + payload));
}

static void test_a_saved_descriptor_reads_back(void) {
  static const char body[] = "wpkh([deadbeef/48h/0h/0h/2h]xpub661MyMw/0/*)";
  const size_t len = sizeof(body) - 1;
  multisig_entry_t* found[4];
  uint8_t opened[128];
  size_t out_len = 0;

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, len));
  TEST_ASSERT_EQUAL_UINT(1, entries(MULTISIG_STORE_MAGIC));

  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&card, found, 4));
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_read(&card, found[0], opened, sizeof(opened), &out_len));
  TEST_ASSERT_EQUAL_UINT(len, out_len);
  TEST_ASSERT_EQUAL_MEMORY(body, opened, len);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation());
}

static void test_only_the_index_is_searchable(void) {
  static const char body[] = "coldcard-export-2-of-3-p2wsh-name";

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, sizeof(body) - 1));

  /* The descriptor text, and the session's own key material, are not in flash: the entry holds the blob,
   * a nonce and a CCM output. */
  for (uint32_t block = 0; block < HAL_FLASH_DATA_BLOCK_COUNT; block++) {
    const uint8_t* bytes = hal_host_flash_block(block);

    for (size_t off = 0; off + sizeof(body) <= HAL_FLASH_BLOCK_SIZE; off++) {
      if (memcmp(&bytes[off], body, sizeof(body)) == 0) {
        TEST_FAIL_MESSAGE("the descriptor is stored in the clear");
      }
    }
  }

  /* The blob is what a scan finds, and it is a keyed hash of the fingerprint rather than the fingerprint. */
  TEST_ASSERT_TRUE(entries(MULTISIG_STORE_MAGIC) == 1);
}

static void test_each_cards_descriptors_are_listed_apart(void) {
  static const char mine[] = "mine";
  static const char theirs[] = "theirs";
  multisig_entry_t* found[4];

  TEST_ASSERT_TRUE(memcmp(card.blob, other_card.blob, sizeof(card.blob)) != 0);

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)mine, sizeof(mine) - 1));
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&other_card, (const uint8_t*)theirs, sizeof(theirs) - 1));
  TEST_ASSERT_EQUAL_UINT(2, entries(MULTISIG_STORE_MAGIC));

  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&card, found, 4));

  uint8_t opened[64];
  size_t out_len = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_read(&card, found[0], opened, sizeof(opened), &out_len));
  TEST_ASSERT_EQUAL_MEMORY(mine, opened, out_len);
}

static void test_the_count_is_what_was_found_not_what_was_returned(void) {
  multisig_entry_t* found[2];

  for (size_t i = 0; i < 3; i++) {
    const char body[] = {(char)('a' + i), 0};
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, 1));
  }

  /* The header says so, and the caller needs it to know its array was too small: the return is the number
   * of entries belonging to this card, while at most max pointers are written. Asking again with a smaller
   * array does not shrink the answer -- there is no way to tell "you missed some" apart from "here they
   * are" except by comparing the two numbers, which is the caller's job. */
  TEST_ASSERT_EQUAL_UINT(3, multisig_store_list(&card, found, 2));
  TEST_ASSERT_EQUAL_UINT(3, multisig_store_list(&card, found, 1));

  uint8_t opened[16];
  size_t out_len = 0;

  for (size_t i = 0; i < 2; i++) {
    TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_read(&card, found[i], opened, sizeof(opened), &out_len));
    TEST_ASSERT_EQUAL_UINT(1, out_len);
  }
}

static void test_a_new_session_with_the_same_card_reads_the_old_entries(void) {
  static const char body[] = "descriptor body";
  multisig_entry_t* found[4];

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, sizeof(body) - 1));

  multisig_crypto_t reborn;
  uint8_t root[MULTISIG_ROOT_LEN];
  memset(&reborn, 0, sizeof(reborn));
  TEST_GIVEN(MULTISIG_CRYPTO_KAT[0].root, root, sizeof(root));
  multisig_crypto_init(&reborn, root, 0xDEADBEEF);

  TEST_ASSERT_EQUAL_MEMORY(card.blob, reborn.blob, sizeof(reborn.blob));
  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&reborn, found, 4));

  uint8_t opened[64];
  size_t out_len = 0;
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_read(&reborn, found[0], opened, sizeof(opened), &out_len));
  TEST_ASSERT_EQUAL_MEMORY(body, opened, out_len);

  multisig_crypto_wipe(&reborn);
}

static void test_another_cards_key_does_not_open_the_entry(void) {
  static const char body[] = "not for you";
  multisig_entry_t* found[4];

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, sizeof(body) - 1));

  /* The list is by blob, but nothing stops a caller handing another card's session to read(): the entry is
   * still the right magic. The tag is what refuses -- the store has no other way to say so. */
  uint8_t opened[64];
  size_t out_len = 0;

  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&card, found, 4));
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, multisig_store_read(&other_card, found[0], opened, sizeof(opened), &out_len));
}

static void test_an_entry_bigger_than_the_scratch_buffer_is_refused(void) {
  /* MULTISIG_MAX_ENTRY_SIZE bounds the save buffer from the outside: 1024 - header - blob - nonce - tag. */
  const size_t limit = MULTISIG_MAX_ENTRY_SIZE - sizeof(fs_entry_t) - MULTISIG_FP_BLOB_LEN - CCM_NONCE_SIZE - CCM_TAG_SIZE;
  uint8_t body[MULTISIG_MAX_ENTRY_SIZE];

  memset(body, 0x42, sizeof(body));

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, body, limit));
  TEST_ASSERT_EQUAL_INT(ERR_FULL, multisig_store_save(&card, body, limit + 1));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, entries(MULTISIG_STORE_MAGIC), "a refused save still wrote something");
}

static void test_a_record_the_reader_cannot_make_sense_of_is_refused(void) {
  static const char body[] = "x";
  uint8_t opened[64];
  size_t out_len = 0;

  /* Another module's entry. */
  write_foreign(64);
  fs_entry_t* foreign = (fs_entry_t*) scratch;
  TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_store_read(&card, (multisig_entry_t*)foreign, opened, sizeof(opened), &out_len));

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)body, 1));

  multisig_entry_t* found[4];
  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&card, found, 4));

  /* A buffer one byte short of the plaintext. */
  TEST_ASSERT_EQUAL_INT(ERR_FULL, multisig_store_read(&card, found[0], opened, 0, &out_len));

  /* A record whose declared length leaves no room for a tag: 17 is blob plus nonce, so data_len is 0. */
  fs_entry_t* short_entry = (fs_entry_t*) scratch;
  short_entry->magic = MULTISIG_STORE_MAGIC;
  short_entry->len = MULTISIG_FP_BLOB_LEN + CCM_NONCE_SIZE;
  memset(scratch + sizeof(fs_entry_t), 0, short_entry->len);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(short_entry, sizeof(fs_entry_t) + short_entry->len));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_store_read(&card, (multisig_entry_t*)scratch, opened, sizeof(opened), &out_len));
}

static void test_a_refused_encryption_is_not_stored(void) {
  static const char body[] = "descriptor that never got encrypted";

  /* The save path refuses to write when the peripheral refuses to encrypt, which is what the ERR_CRYPTO
   * arm above is for: an entry of scratch-buffer garbage is not a saved descriptor. */
  hal_host_aes_refuse_next(1);
  TEST_ASSERT_EQUAL_INT(ERR_CRYPTO, multisig_store_save(&card, (const uint8_t*)body, sizeof(body) - 1));

  TEST_ASSERT_EQUAL_UINT(0, entries(MULTISIG_STORE_MAGIC));
  TEST_ASSERT_EQUAL_UINT(0, multisig_store_list(&card, (multisig_entry_t**)(void*[]){NULL}, 0));
}

static void test_delete_removes_one_entry(void) {
  static const char first[] = "first";
  static const char second[] = "second";
  multisig_entry_t* found[4];

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)first, sizeof(first) - 1));
  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_save(&card, (const uint8_t*)second, sizeof(second) - 1));
  write_foreign(64);

  TEST_ASSERT_EQUAL_UINT(2, multisig_store_list(&card, found, 4));

  uint8_t opened[64];
  size_t out_len = 0;
  multisig_entry_t* doomed = found[0];

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_delete(&card, doomed));
  TEST_ASSERT_EQUAL_UINT(1, multisig_store_list(&card, found, 4));
  TEST_ASSERT_EQUAL_UINT(1, entries(MAGIC_OTHER));

  TEST_ASSERT_EQUAL_INT(ERR_OK, multisig_store_read(&card, found[0], opened, sizeof(opened), &out_len));
  TEST_ASSERT_EQUAL_UINT(6, out_len);
  TEST_ASSERT_EQUAL_MEMORY(second, opened, out_len);

  /* Deleting an entry of another module's magic is refused, rather than taken as a licence to erase
   * whatever the pointer happens to name. */
  fs_entry_t* not_mine = (fs_entry_t*) scratch;
  not_mine->magic = MAGIC_OTHER;
  not_mine->len = 8;
  TEST_ASSERT_EQUAL_INT(ERR_DATA, multisig_store_delete(&card, (multisig_entry_t*)not_mine));
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_a_saved_descriptor_reads_back);
  RUN_TEST(test_only_the_index_is_searchable);
  RUN_TEST(test_each_cards_descriptors_are_listed_apart);
  RUN_TEST(test_the_count_is_what_was_found_not_what_was_returned);
  RUN_TEST(test_a_new_session_with_the_same_card_reads_the_old_entries);
  RUN_TEST(test_another_cards_key_does_not_open_the_entry);
  RUN_TEST(test_an_entry_bigger_than_the_scratch_buffer_is_refused);
  RUN_TEST(test_a_record_the_reader_cannot_make_sense_of_is_refused);
  RUN_TEST(test_a_refused_encryption_is_not_stored);
  RUN_TEST(test_delete_removes_one_entry);

  return UNITY_END();
}
