#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "keycard/scv2_whitelist.h"
#include "storage/fs.h"

/*
 * The whitelist is three functions over the store, and it is where the store's predicate polarity gets
 * paid for: in fs_erase_all(), FS_REJECT does not mean "not mine", it means "delete this". A predicate
 * that answers FS_REJECT to an entry of another kind therefore deletes every entry of another kind --
 * settings, pairings, multisig descriptors, the token database -- and since a removal that finds
 * nothing never stops the scan, it does that across the whole store while answering ERR_DATA.
 *
 * The rest is the whitelist's own shape: one entry per card, add() refusing to write a second copy,
 * remove() stopping at the first match, and the errors its callers branch on.
 */

#define MAGIC_OTHER 0x1234
#define MAGIC_WHITELIST 0x5343 /* spelled here to build a state add() will not create, and to count */

#define FILLER_LEN 4096
#define FILLER_DATA (FILLER_LEN - sizeof(fs_entry_t))

#define ASSERT_CLEAN_FLASH() \
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation())

static uint8_t card_a[SCV2_WHITELIST_PUBKEY_LEN];
static uint8_t card_b[SCV2_WHITELIST_PUBKEY_LEN];
static uint8_t card_c[SCV2_WHITELIST_PUBKEY_LEN];
static uint8_t stranger[SCV2_WHITELIST_PUBKEY_LEN];

/* Entries handed to fs_write() have to be below 4 GB, which fs.c walks them with uint32_t arithmetic. */
static uint8_t* scratch;

void setUp(void) {
  if (scratch == NULL) {
    scratch = hal_host_low_mem(FILLER_LEN);
  }

  hal_host_flash_reset();

  memset(card_a, 0xa1, sizeof(card_a));
  memset(card_b, 0xb2, sizeof(card_b));
  memset(card_c, 0xc3, sizeof(card_c));
  memset(stranger, 0xd4, sizeof(stranger));
}

void tearDown(void) {
}

static void write_other(size_t payload) {
  fs_entry_t* entry = (fs_entry_t*) scratch;

  entry->magic = MAGIC_OTHER;
  entry->len = payload;
  memset(scratch + sizeof(fs_entry_t), 0x5b, payload);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(entry, sizeof(fs_entry_t) + payload));
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

static uint32_t count_magic(uint16_t magic) {
  struct census census = { .magic = magic, .seen = 0 };

  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase_all(keep_count, &census));
  return census.seen;
}

static fs_action_t find_other(void* ctx, fs_entry_t* entry) {
  (void) ctx;
  return entry->magic == MAGIC_OTHER ? FS_ACCEPT : FS_REJECT;
}

static void test_an_empty_whitelist_holds_no_card(void) {
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_check(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_remove(card_a));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
}

static void test_a_card_added_is_whitelisted(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_check(card_b));
  TEST_ASSERT_EQUAL_UINT(1, count_magic(MAGIC_WHITELIST));
  ASSERT_CLEAN_FLASH();
}

static void test_adding_a_card_twice_writes_nothing(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));

  const size_t programs = hal_host_flash_programs();
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));

  TEST_ASSERT_EQUAL_size_t(programs, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_UINT(1, count_magic(MAGIC_WHITELIST));
}

static void test_removing_a_card_keeps_the_other_cards(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_b));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_c));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_remove(card_b));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_check(card_b));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_c));
  TEST_ASSERT_EQUAL_UINT(2, count_magic(MAGIC_WHITELIST));
  ASSERT_CLEAN_FLASH();
}

static void test_removing_a_card_leaves_entries_of_other_kinds(void) {
  write_other(16);
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));
  write_other(16);

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_remove(card_a));

  TEST_ASSERT_EQUAL_UINT(2, count_magic(MAGIC_OTHER));
  TEST_ASSERT_EQUAL_UINT(0, count_magic(MAGIC_WHITELIST));
  ASSERT_CLEAN_FLASH();
}

static void test_removing_a_card_that_is_not_whitelisted_leaves_the_store(void) {
  /* One entry per block, and a removal that never matches scans every block there is: each one it
   * rewrote was a block where an unrelated entry had to be copied over to survive. */
  for (int i = 0; i < 8; i++) {
    write_other(FILLER_DATA);
  }

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));
  TEST_ASSERT_EQUAL_UINT(8, count_magic(MAGIC_OTHER));

  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_remove(stranger));

  TEST_ASSERT_EQUAL_UINT(8, count_magic(MAGIC_OTHER));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_a));
  ASSERT_CLEAN_FLASH();
}

static void test_a_duplicate_card_needs_two_removals(void) {
  /* add() checks first, so a second copy comes only from a store assembled another way -- a restore,
   * or a rewrite that kept it. remove() stops at the first match, which is also what a lookup returns,
   * so the copy underneath stays invisible until the one above it is gone. */
  fs_entry_t* entry = (fs_entry_t*) scratch;

  entry->magic = MAGIC_WHITELIST;
  entry->len = SCV2_WHITELIST_PUBKEY_LEN;
  memcpy(scratch + sizeof(fs_entry_t), card_a, SCV2_WHITELIST_PUBKEY_LEN);

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write(entry, sizeof(fs_entry_t) + SCV2_WHITELIST_PUBKEY_LEN));
  TEST_ASSERT_EQUAL_UINT(2, count_magic(MAGIC_WHITELIST));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_remove(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_a));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_remove(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_check(card_a));
  ASSERT_CLEAN_FLASH();
}

/* Packs the store with entries of one payload until the store refuses, which leaves the tail of the
 * last block as the only room left -- small entries then fill that too. */
static void fill_until_full(size_t payload) {
  int written = 0;

  while (written < 40000) {
    fs_entry_t* entry = (fs_entry_t*) scratch;
    entry->magic = MAGIC_OTHER;
    entry->len = payload;

    if (fs_write(entry, sizeof(fs_entry_t) + payload) != ERR_OK) {
      break;
    }

    written++;
  }

  TEST_ASSERT_TRUE(written > 0);
}

static void test_a_full_store_answers_err_full(void) {
  fill_until_full(FILLER_DATA);
  fill_until_full(240);
  fill_until_full(16);

  /* The header promises ERR_DATA when the slots are gone; the store says ERR_FULL, and keycard.c
   * ignores whatever comes back -- so a card approved here is not remembered next time. */
  TEST_ASSERT_EQUAL_INT(ERR_FULL, scv2_whitelist_add(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, scv2_whitelist_check(card_a));
  ASSERT_CLEAN_FLASH();

  fs_entry_t* hole = fs_find(find_other, NULL);
  TEST_ASSERT_NOT_NULL(hole);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_erase(hole));

  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_add(card_a));
  TEST_ASSERT_EQUAL_INT(ERR_OK, scv2_whitelist_check(card_a));
  ASSERT_CLEAN_FLASH();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_an_empty_whitelist_holds_no_card);
  RUN_TEST(test_a_card_added_is_whitelisted);
  RUN_TEST(test_adding_a_card_twice_writes_nothing);
  RUN_TEST(test_removing_a_card_keeps_the_other_cards);
  RUN_TEST(test_removing_a_card_leaves_entries_of_other_kinds);
  RUN_TEST(test_removing_a_card_that_is_not_whitelisted_leaves_the_store);
  RUN_TEST(test_a_duplicate_card_needs_two_removals);
  RUN_TEST(test_a_full_store_answers_err_full);

  return UNITY_END();
}
