#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "error.h"
#include "hal.h"
#include "hal_host.h"
#include "ethereum/eth_db.h"
#include "storage/fs.h"

#include "vectors/vectors_eth_db.h"

/*
 * eth_db.c is the store's heaviest consumer: the token database arrives as one blob of mixed entries
 * and is installed by a single fs_write(), spanning many flash blocks in one call. Its four lookups
 * and one updater are everything the device does with what it kept, and the corpus is the release the
 * Shell actually ships, with each row confirmed against the upstream chain and token lists the release
 * was generated from -- see vectors/vectors_eth_db.h.
 *
 * Two shapes here are easy to get wrong and are pinned on purpose. eth_full_db_rewrite() erases every
 * database entry before writing the new one, and reads the erase's answer as ERR_DATA because its
 * predicate never stops the scan; and an install that fails halfway through a block has to leave a
 * prefix of the log, which is what makes the store readable again rather than garbage.
 */

#define ASSERT_CLEAN_FLASH() \
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation())

static uint8_t blob_store[ETH_DB_BODY];
static uint8_t* blob = blob_store;

void setUp(void) {

  hal_host_flash_reset();
}

void tearDown(void) {
}

static app_err_t install(void) {
  memcpy(blob, ETH_DB, ETH_DB_BODY);
  return eth_db_update(blob, ETH_DB_BODY);
}

/* A census walks the log keeping everything, which fs_erase_all does without touching flash: a
 * predicate that never accepts leaves nothing to rewrite. */
static fs_action_t census_keep(void* ctx, fs_entry_t* entry) {
  (void) entry;
  (*(uint32_t*) ctx)++;
  return FS_ACCEPT;
}

static uint32_t count_entries(void) {
  uint32_t entries = 0;

  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase_all(census_keep, &entries));
  return entries;
}

static void assert_chain(const eth_db_chain_t* row) {
  chain_desc_t chain = { .chain_id = row->chain_id };

  TEST_ASSERT_EQUAL_MESSAGE(ERR_OK, eth_db_lookup_chain(&chain), row->name);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(row->ticker, chain.ticker, row->name);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(row->name, chain.name, row->name);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(row->short_name, chain.short_name, row->name);
}

static void assert_token(const eth_db_token_t* row) {
  erc20_desc_t token = { .chain = row->chain_id, .addr = row->addr };

  TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_OK, eth_db_lookup_erc20(&token), row->ticker);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(row->decimals, token.decimals, row->ticker);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(row->ticker, token.ticker, row->ticker);
}

static void test_an_empty_store_holds_no_database(void) {
  chain_desc_t chain = { .chain_id = 1 };
  uint8_t addr[20] = { 0 };
  erc20_desc_t token = { .chain = 1, .addr = addr };
  uint32_t version;

  TEST_ASSERT_EQUAL_INT(ERR_DATA, eth_db_lookup_chain(&chain));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, eth_db_lookup_erc20(&token));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, eth_db_lookup_version(&version));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
}

static void test_the_release_installs_in_one_write(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  TEST_ASSERT_EQUAL_UINT(ETH_DB_ENTRIES, count_entries());
  ASSERT_CLEAN_FLASH();

  /* A store that is already erased is filled without erasing anything, and the whole release goes
   * in as one write per entry. */
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  TEST_ASSERT_TRUE(hal_host_flash_programs() >= ETH_DB_ENTRIES);
}

static void test_every_chain_of_the_release_reads_back(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  for (size_t i = 0; i < sizeof(ETH_DB_CHAINS) / sizeof(ETH_DB_CHAINS[0]); i++) {
    assert_chain(&ETH_DB_CHAINS[i]);
  }
}

static void test_every_sampled_token_reads_back(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  for (size_t i = 0; i < sizeof(ETH_DB_TOKENS) / sizeof(ETH_DB_TOKENS[0]); i++) {
    assert_token(&ETH_DB_TOKENS[i]);
  }

  /* One entry lists every (chain, address) pair the token is good on, so a net other than the
   * first has to answer as well. */
  for (size_t i = 0; i < sizeof(ETH_DB_OTHER_NETS) / sizeof(ETH_DB_OTHER_NETS[0]); i++) {
    assert_token(&ETH_DB_OTHER_NETS[i]);
  }
}

static void test_what_the_release_does_not_carry_is_not_found(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  for (size_t i = 0; i < sizeof(ETH_DB_MISSING_CHAINS) / sizeof(ETH_DB_MISSING_CHAINS[0]); i++) {
    chain_desc_t chain = { .chain_id = ETH_DB_MISSING_CHAINS[i] };
    TEST_ASSERT_EQUAL_INT(ERR_DATA, eth_db_lookup_chain(&chain));
  }

  for (size_t i = 0; i < sizeof(ETH_DB_MISSING_TOKENS) / sizeof(ETH_DB_MISSING_TOKENS[0]); i++) {
    const eth_db_token_t* row = &ETH_DB_MISSING_TOKENS[i];
    erc20_desc_t token = { .chain = row->chain_id, .addr = row->addr };
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_DATA, eth_db_lookup_erc20(&token), row->ticker);
  }
}

static void test_the_version_of_the_store_is_the_release(void) {
  uint32_t version;

  TEST_ASSERT_EQUAL_INT(ERR_OK, install());
  TEST_ASSERT_EQUAL_INT(ERR_OK, eth_db_lookup_version(&version));
  TEST_ASSERT_EQUAL_UINT(ETH_DB_VERSION, version);

  /* The updater reads the version out of the blob before deciding anything, and the release blob
   * is a full database, not a delta. */
  TEST_ASSERT_EQUAL_INT(ERR_OK, eth_db_extract_version(blob, &version));
  TEST_ASSERT_EQUAL_UINT(ETH_DB_VERSION, version);
}

static void test_installing_again_leaves_one_copy_of_the_database(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());
  TEST_ASSERT_EQUAL_UINT(ETH_DB_ENTRIES, count_entries());

  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  /* Replacing the release costs one erase per block the old one spanned, and no more entries than
   * the release carries. */
  TEST_ASSERT_EQUAL_size_t(ETH_DB_BODY / HAL_FLASH_BLOCK_SIZE + 1, hal_host_flash_erases());
  TEST_ASSERT_EQUAL_UINT(ETH_DB_ENTRIES, count_entries());
  ASSERT_CLEAN_FLASH();

  assert_chain(&ETH_DB_CHAINS[0]);
  assert_token(&ETH_DB_TOKENS[0]);
}

static void test_a_blob_that_is_not_a_database_is_refused(void) {
  memcpy(blob, ETH_DB, ETH_DB_BODY);
  blob[0] = 0xff;
  blob[1] = 0xff;

  uint32_t version;

  TEST_ASSERT_EQUAL_INT(ERR_UNSUPPORTED, eth_db_update(blob, ETH_DB_BODY));
  TEST_ASSERT_EQUAL_INT(ERR_UNSUPPORTED, eth_db_extract_version(blob, &version));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_UINT(0, count_entries());
}

static void test_an_install_that_fails_halfway_leaves_a_readable_store(void) {
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());

  hal_host_flash_interrupt_after(ETH_DB_ENTRIES / 2, -1);
  TEST_ASSERT_EQUAL_INT(ERR_HW, install());
  hal_host_flash_interrupt_after(-1, -1);

  /* The log is a prefix of the second install, so the reader stops with it instead of running off
   * into half-written entries: no cell was written over an unerased one, and what was placed is
   * still readable. */
  ASSERT_CLEAN_FLASH();

  uint32_t kept = count_entries();
  TEST_ASSERT_TRUE(kept > 0);
  TEST_ASSERT_TRUE(kept < ETH_DB_ENTRIES);

  chain_desc_t chain = { .chain_id = ETH_DB_CHAINS[0].chain_id };
  TEST_ASSERT_EQUAL_INT(ERR_OK, eth_db_lookup_chain(&chain));
  TEST_ASSERT_EQUAL_STRING(ETH_DB_CHAINS[0].name, chain.name);

  /* The next attempt, from the same store, restores the whole database. */
  TEST_ASSERT_EQUAL_INT(ERR_OK, install());
  TEST_ASSERT_EQUAL_UINT(ETH_DB_ENTRIES, count_entries());
  assert_token(&ETH_DB_TOKENS[0]);
  ASSERT_CLEAN_FLASH();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_an_empty_store_holds_no_database);
  RUN_TEST(test_the_release_installs_in_one_write);
  RUN_TEST(test_every_chain_of_the_release_reads_back);
  RUN_TEST(test_every_sampled_token_reads_back);
  RUN_TEST(test_what_the_release_does_not_carry_is_not_found);
  RUN_TEST(test_the_version_of_the_store_is_the_release);
  RUN_TEST(test_installing_again_leaves_one_copy_of_the_database);
  RUN_TEST(test_a_blob_that_is_not_a_database_is_refused);
  RUN_TEST(test_an_install_that_fails_halfway_leaves_a_readable_store);

  return UNITY_END();
}
