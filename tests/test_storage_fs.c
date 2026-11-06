#include "unity.h"

#include <stdio.h>

#include "hal.h"
#include "hal_host.h"
#include "storage/fs.h"

#include <string.h>

/*
 * The store is a log: an entry is appended to the first erased space found, and a delete rewrites the
 * block without it. fs.c is the only thing in the device that touches flash for everything the user
 * keeps -- settings, pairings, whitelisted cards, multisig descriptors, the token database -- and its
 * six entry points are the whole API. They are pinned here against a flash model that refuses, as the
 * silicon does, to write over a cell that is not erased.
 *
 * One convention runs through the predicates and is easy to get backwards, because fs.c reads the enum
 * from the point of view of a rewrite rather than a lookup: FS_ACCEPT means the entry survives, and
 * FS_STOP means drop this entry, end the scan, and report success. A predicate that never returns
 * FS_STOP leaves fs_erase_all answering ERR_DATA after doing the work. The device's own consumers
 * carry that shape: pairing_erase() and scv2_whitelist_remove() pass FS_STOP for a match and FS_ACCEPT
 * for everything else.
 */

#define MAGIC_A 0x4141
#define MAGIC_B 0x4242

#define PAGE HAL_FLASH_BLOCK_SIZE

/* fs.c keeps its on-flash markers to itself. What a reader has to agree with is that the word where an
 * entry ended carries the pad mark and, in its low six bits, how many bytes to skip. */
#define PAD_MASK 0x00c0
#define PAD_MARK 0x0080
#define PAD_LEN(field) ((field) & 0x3f)

#define ASSERT_CLEAN_FLASH() \
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, hal_host_flash_violations(), hal_host_flash_last_violation())
#define ASSERT_BLOCK_ERASED(b) \
  TEST_ASSERT_EACH_EQUAL_UINT_MESSAGE(0xff, hal_host_flash_block(b), PAGE, \
                                      hal_host_flash_last_violation())

/* Below 4 GB, because fs.c walks the buffer it is writing with (uint32_t) arithmetic. */
static uint8_t* blob;

void setUp(void) {
  if (blob == NULL) {
    blob = hal_host_low_mem(3 * PAGE);
  }

  hal_host_flash_reset();
}

void tearDown(void) {
}

/* The first block the store may use, read from the map the store itself reads. */
static uint32_t first_data_block(void) {
  return HAL_FLASH_ADDR_TO_BLOCK(hal_flash_get_data_segments()->addr);
}

/* HAL_FLASH_BLOCK_ADDR multiplies its argument with no parentheses around it, so an argument that is
 * an expression has to be parenthesized by the caller. */
static uint32_t page_addr(uint32_t block) {
  return HAL_FLASH_BLOCK_ADDR((block));
}

static size_t blob_append(uint8_t* at, uint16_t magic, uint8_t seed, size_t payload_len) {
  fs_entry_t* entry = (fs_entry_t*)at;
  entry->magic = magic;
  entry->len = (uint16_t)payload_len;

  for (size_t i = 0; i < payload_len; i++) {
    at[sizeof(fs_entry_t) + i] = (uint8_t)(seed + i);
  }

  return sizeof(fs_entry_t) + payload_len;
}

static fs_action_t by_magic(void* ctx, fs_entry_t* entry) {
  return entry->magic == (uint16_t)(uintptr_t)ctx ? FS_ACCEPT : FS_REJECT;
}

/* The shape a delete takes, as in pairing_erase(): stop at the entry to drop, keep everything else. */
static fs_action_t drop_by_magic(void* ctx, fs_entry_t* entry) {
  return entry->magic == (uint16_t)(uintptr_t)ctx ? FS_STOP : FS_ACCEPT;
}

struct collect {
  uint16_t magic;
  size_t count;
  uint32_t addr[8];
  size_t len[8];
  uint8_t head[8];
};

static fs_action_t collect(void* ctx, fs_entry_t* entry) {
  struct collect* c = (struct collect*)ctx;

  if (c->magic != 0 && entry->magic != c->magic) {
    return FS_REJECT;
  }

  if (c->count < sizeof(c->addr) / sizeof(*c->addr)) {
    c->addr[c->count] = (uint32_t)(uintptr_t)entry;
    c->len[c->count] = entry->len;
    c->head[c->count] = ((uint8_t*)entry)[sizeof(fs_entry_t)];
  }

  c->count++;

  /* Both of these continue the scan; only FS_STOP ends it. */
  return FS_REJECT;
}

static void test_an_unwritten_store_holds_nothing(void) {
  struct collect seen = {.magic = 0};

  TEST_ASSERT_NULL(fs_find(by_magic, (void*)(uintptr_t)MAGIC_A));

  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(0, seen.count);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_format());
  TEST_ASSERT_EQUAL_UINT(HAL_FLASH_DATA_BLOCK_COUNT, hal_host_flash_erases());
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  ASSERT_CLEAN_FLASH();
}

static void test_a_written_entry_is_found_where_it_was_written(void) {
  size_t written = blob_append(blob, MAGIC_A, 0xa1, 100);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, written));

  fs_entry_t* entry = fs_find(by_magic, (void*)(uintptr_t)MAGIC_A);
  TEST_ASSERT_NOT_NULL(entry);
  TEST_ASSERT_EQUAL_PTR(hal_host_flash_block(first_data_block()), entry);
  TEST_ASSERT_EQUAL_UINT16(MAGIC_A, entry->magic);
  TEST_ASSERT_EQUAL_UINT16(100, entry->len);

  uint8_t payload[100];
  for (size_t i = 0; i < sizeof(payload); i++) {
    payload[i] = (uint8_t)(0xa1 + i);
  }
  TEST_ASSERT_EQUAL_MEMORY(payload, (uint8_t*)entry + sizeof(fs_entry_t), sizeof(payload));

  /* What follows an entry is a pad marker, not free space: it is how a reader tells the end of the log
   * from a block that was never written. */
  uint8_t* page = hal_host_flash_block(first_data_block());
  uint16_t pad;
  memcpy(&pad, page + written, sizeof(pad));
  TEST_ASSERT_EQUAL_UINT16(PAD_MARK, pad & PAD_MASK);
  TEST_ASSERT_EQUAL_UINT16(HAL_FLASH_WORD_SIZE - (written & (HAL_FLASH_WORD_SIZE - 1)),
                           PAD_LEN(pad));
  TEST_ASSERT_EQUAL_UINT8(0xff, page[written + PAD_LEN(pad)]);

  /* A fresh store is erased already, so appending must not erase anything. */
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

/* fs_find returns the first match in scan order, which is why settings_commit erases the entry it
 * found before writing the new value: without the erase the stale value would be the one read back. */
static void test_the_first_entry_in_the_log_is_the_one_found(void) {
  size_t written = blob_append(blob, MAGIC_A, 0x11, 32);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, written));

  written = blob_append(blob, MAGIC_A, 0x22, 32);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, written));

  fs_entry_t* entry = fs_find(by_magic, (void*)(uintptr_t)MAGIC_A);
  TEST_ASSERT_NOT_NULL(entry);
  TEST_ASSERT_EQUAL_UINT8(0x11, ((uint8_t*)entry)[sizeof(fs_entry_t)]);

  struct collect seen = {.magic = MAGIC_A};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(2, seen.count);
  ASSERT_CLEAN_FLASH();
}

/* An entry is never split across blocks; the writer pads the rest of the block and carries on in the
 * next one, so a scan of a block sees either entries or a pad, never half an entry. */
static void test_entries_that_do_not_fit_move_to_the_next_page(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 4000);
  total += blob_append(blob + total, MAGIC_A, 0x02, 4000);
  total += blob_append(blob + total, MAGIC_A, 0x03, 4000);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = MAGIC_A};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(3, seen.count);

  const uint32_t first = page_addr(first_data_block());
  TEST_ASSERT_EQUAL_UINT32(first, seen.addr[0]);
  TEST_ASSERT_EQUAL_UINT32(first + 4004, seen.addr[1]);
  TEST_ASSERT_EQUAL_UINT32(page_addr(first_data_block() + 1), seen.addr[2]);
  TEST_ASSERT_EQUAL_UINT8(0x03, seen.head[2]);

  /* Nothing was thrown away and nothing was rewritten, so no erase at all. */
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

/* A block used up exactly is the case the padding has to be careful about: the marker cannot go past
 * the end of the block, because the next block belongs to whatever comes next and is not erased. */
static void test_a_block_filled_exactly_leaves_the_next_one_erased(void) {
  size_t total = blob_append(blob, MAGIC_A, 0x01, PAGE - sizeof(fs_entry_t));
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_violations());

  uint8_t* next = hal_host_flash_block(first_data_block() + 1);
  for (size_t i = 0; i < HAL_FLASH_WORD_SIZE; i++) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0xff, next[i],
                                   "the pad of a full block was written into the next block");
  }

  /* Two entries that together fill the block say the same thing about the other path through the
   * writer, the one that ends a write rather than fitting one in. */
  hal_host_flash_reset();

  total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 2046);
  total += blob_append(blob + total, MAGIC_A, 0x02, PAGE - 4 - 2050);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_violations());

  next = hal_host_flash_block(first_data_block() + 1);
  TEST_ASSERT_EQUAL_UINT8(0xff, next[0]);

  /* Not writing the marker is only right if the log is still readable and appendable: the next entry
   * goes to the block after, and all three are found. */
  total = blob_append(blob, MAGIC_B, 0x09, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(3, seen.count);
  TEST_ASSERT_EQUAL_UINT32(page_addr(first_data_block() + 1), seen.addr[2]);

  ASSERT_CLEAN_FLASH();
}

/* A delete is a rewrite: the block is copied out with the entry left behind, erased, and written back.
 * Everything else in the block has to come through byte for byte. */
static void test_erasing_one_entry_keeps_the_others(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0xaa, 100);
  total += blob_append(blob + total, MAGIC_B, 0xbb, 100);
  total += blob_append(blob + total, MAGIC_A, 0xcc, 100);

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  fs_entry_t* middle = fs_find(by_magic, (void*)(uintptr_t)MAGIC_B);
  TEST_ASSERT_NOT_NULL(middle);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_erase(middle));

  TEST_ASSERT_NULL(fs_find(by_magic, (void*)(uintptr_t)MAGIC_B));

  struct collect seen = {.magic = MAGIC_A};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(2, seen.count);
  TEST_ASSERT_EQUAL_UINT8(0xaa, seen.head[0]);
  TEST_ASSERT_EQUAL_UINT8(0xcc, seen.head[1]);

  /* One block held it, so one block was rewritten. */
  TEST_ASSERT_EQUAL_UINT(1, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

static void test_erasing_an_address_that_holds_no_entry_reports_err_data(void) {
  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase((fs_entry_t*)(HAL_FLASH_BLOCK_ADDR(first_data_block()) +
                                                          4096)));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  ASSERT_CLEAN_FLASH();
}

/* The shape the device's own deletes take: FS_STOP for the entry to drop, FS_ACCEPT for the ones to
 * keep. Stopping ends the scan, so a second copy of the same key further down the log survives a
 * remove, which every caller inherits: pairing_erase() and scv2_whitelist_remove() can leave a
 * whitelisted card in place if the same card was written twice. */
static void test_erase_all_drops_the_match_and_keeps_the_rest(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_B, 0x02, 64);
  total += blob_append(blob + total, MAGIC_A, 0x03, 64);
  total += blob_append(blob + total, MAGIC_B, 0x04, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_erase_all(drop_by_magic, (void*)(uintptr_t)MAGIC_B));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);

  /* The first B is gone and the second survives, in the order they were written. */
  TEST_ASSERT_EQUAL_size_t(3, seen.count);
  TEST_ASSERT_EQUAL_UINT8(0x01, seen.head[0]);
  TEST_ASSERT_EQUAL_UINT8(0x03, seen.head[1]);
  TEST_ASSERT_EQUAL_UINT8(0x04, seen.head[2]);
  ASSERT_CLEAN_FLASH();

  /* Nothing matched, so nothing was rewritten and the answer says so. */
  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase_all(drop_by_magic, (void*)(uintptr_t)0x9999));
  ASSERT_CLEAN_FLASH();
}

/* A block used up exactly, seen from the rewrite path rather than the writer: it is copied out whole
 * and comes back byte for byte. Only the writer needed a rule about padding at a block boundary --
 * _fs_commit_block() pads a copy that is shorter than its block, and it is always shorter, because a
 * block is rewritten only when something in it was dropped and what was dropped took space that the
 * copy does not fill. */
static fs_action_t keep_a(void* ctx, fs_entry_t* entry) {
  (void) ctx;
  return entry->magic == MAGIC_A ? FS_ACCEPT : FS_STOP;
}

static void test_a_full_block_survives_being_rewritten(void) {
  size_t total = blob_append(blob, MAGIC_A, 0x5c, PAGE - sizeof(fs_entry_t));
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  total = blob_append(blob, MAGIC_B, 0x0b, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_erase_all(keep_a, NULL));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);

  fs_entry_t* entry = (fs_entry_t*)(uintptr_t)seen.addr[0];
  TEST_ASSERT_EQUAL_UINT16(MAGIC_A, entry->magic);
  TEST_ASSERT_EQUAL_UINT16(PAGE - sizeof(fs_entry_t), entry->len);

  uint8_t page[PAGE - sizeof(fs_entry_t)];
  for (size_t i = 0; i < sizeof(page); i++) {
    page[i] = (uint8_t)(0x5c + i);
  }
  TEST_ASSERT_EQUAL_MEMORY(page, (uint8_t*)entry + sizeof(fs_entry_t), sizeof(page));

  ASSERT_CLEAN_FLASH();
}

/* The trap in that convention: fs_erase_all reports ERR_OK only because a predicate returned FS_STOP,
 * which is also what tells it to stop scanning. A predicate written in the lookup shape -- ACCEPT for
 * what matches, REJECT for the rest -- rewrites the block and then answers ERR_DATA as if it had
 * failed, which is how an erase looks successful to the store and unsuccessful to its caller. */
static void test_erase_all_without_a_stop_reports_err_data_after_rewriting(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_B, 0x02, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  TEST_ASSERT_EQUAL_INT(ERR_DATA, fs_erase_all(by_magic, (void*)(uintptr_t)MAGIC_B));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);
  TEST_ASSERT_EQUAL_UINT16(MAGIC_B, ((fs_entry_t*)(uintptr_t)seen.addr[0])->magic);
  ASSERT_CLEAN_FLASH();
}

/* An entry wider than a block cannot be written anywhere, and the attempt must not have written
 * anything on the way to saying so. */
static void test_an_entry_larger_than_a_block_is_refused(void) {
  size_t total = blob_append(blob, MAGIC_A, 0x01, PAGE);

  TEST_ASSERT_EQUAL_INT(ERR_FULL, fs_write((fs_entry_t*)blob, total));
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

/* The data area is two segments, and which is scanned first is the bank-swap option byte. The same
 * bytes are the store either way; what changes is where a new entry goes and which one a lookup finds
 * first -- so a device that swapped banks after a firmware update reads its own log back in the other
 * order. */
static void test_the_other_bank_orientation_reads_the_same_store(void) {
  const uint32_t front_before = HAL_FLASH_BLOCK_ADDR(first_data_block());

  size_t total = blob_append(blob, MAGIC_A, 0x01, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);
  TEST_ASSERT_EQUAL_UINT32(front_before, seen.addr[0]);

  hal_host_flash_bank_swapped(true);

  const uint32_t front_after = HAL_FLASH_BLOCK_ADDR(first_data_block());
  TEST_ASSERT_TRUE(front_after != front_before);

  /* The same bytes are the store either way; the two segments are simply scanned in the other order,
   * so the entry that was at the front is now at the back. */
  seen = (struct collect){.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);
  TEST_ASSERT_EQUAL_UINT32(front_before, seen.addr[0]);

  total = blob_append(blob, MAGIC_B, 0x02, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  seen = (struct collect){.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(2, seen.count);
  TEST_ASSERT_EQUAL_UINT32(front_after, seen.addr[0]);
  TEST_ASSERT_EQUAL_UINT8(0x02, seen.head[0]);

  fs_entry_t* entry = fs_find(by_magic, (void*)(uintptr_t)MAGIC_A);
  TEST_ASSERT_NOT_NULL(entry);
  TEST_ASSERT_EQUAL_UINT32(front_before, (uint32_t)(uintptr_t)entry);
  TEST_ASSERT_EQUAL_UINT8(0x01, ((uint8_t*)entry)[sizeof(fs_entry_t)]);

  ASSERT_CLEAN_FLASH();
}

/* The store writes entries end to end, so from the second entry of a write onward both the address and
 * the length are off the device's 16 byte program width. Recorded rather than judged: on the target
 * these are the calls stm32_flash.c splits into head and tail, and whether the H5 accepts a doubleword
 * assembled across separate calls is silicon, not something a host test can say. If fs.c ever pads its
 * entries to the program width this fails, and the question can be closed. */
static void test_writes_inside_a_block_are_off_the_program_width(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_A, 0x02, 64);
  total += blob_append(blob + total, MAGIC_A, 0x03, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  /* Three entries and the marker that closes the write. */
  TEST_ASSERT_EQUAL_size_t(4, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_size_t(4, hal_host_flash_unaligned_programs());
  ASSERT_CLEAN_FLASH();
}

/* What an interrupted write leaves behind is a clean prefix. The writer stops at the failure, so the
 * entries before it are the log, everything after it stays erased, and the next save appends to what is
 * readable instead of landing on bytes no read can see. The writer used to continue: the entry written
 * past the hole then came back as a record nobody had written, or was written over. */
static void test_a_write_that_fails_midway_leaves_a_clean_prefix(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_A, 0x02, 64);
  total += blob_append(blob + total, MAGIC_A, 0x03, 64);

  hal_host_flash_interrupt_after(1, -1);

  /* The hardware failure is the answer, rather than the "log is full" that a stopped walk reported
   * whenever the failure was not on the last entry. */
  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = MAGIC_A};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);

  uint8_t* page = hal_host_flash_block(first_data_block());
  for (size_t i = 68; i < 5 * 68; i++) {
    TEST_ASSERT_EQUAL_UINT8(0xff, page[i]);
  }

  /* The next save takes the space the failure left, which is erased: the log grows from what was
   * readable, and no cell is programmed twice. */
  total = blob_append(blob, MAGIC_B, 0x09, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  seen = (struct collect){.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(2, seen.count);
  TEST_ASSERT_EQUAL_UINT8(0x01, seen.head[0]);
  TEST_ASSERT_EQUAL_UINT8(0x09, seen.head[1]);
  ASSERT_CLEAN_FLASH();
}

/* An erase is the destructive one: the block is copied, erased and written back, so a failure is worth
 * reading carefully. The store reports ERR_HW and the entry it meant to delete is still there -- which
 * is what this model does rather than what silicon does, because a block erased halfway on hardware has
 * lost whatever the erase had already reached. */
static void test_an_erase_that_fails_leaves_the_entry(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_B, 0x02, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  fs_entry_t* doomed = fs_find(by_magic, (void*)(uintptr_t)MAGIC_B);
  TEST_ASSERT_NOT_NULL(doomed);

  hal_host_flash_interrupt_after(-1, 0);

  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_erase(doomed));

  TEST_ASSERT_NOT_NULL(fs_find(by_magic, (void*)(uintptr_t)MAGIC_B));
  TEST_ASSERT_NOT_NULL(fs_find(by_magic, (void*)(uintptr_t)MAGIC_A));
  ASSERT_CLEAN_FLASH();
}

/* The marker that closes a write can fail on its own. The entry is in, the marker is not, and the
 * answer says the hardware failed -- which is the honest answer, since a later write to that block
 * starts from the entry's unaligned end. */
static void test_a_pad_that_fails_is_reported(void) {
  size_t total = blob_append(blob, MAGIC_A, 0x01, 100);

  hal_host_flash_interrupt_after(1, -1);

  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = MAGIC_A};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(1, seen.count);

  uint8_t* page = hal_host_flash_block(first_data_block());
  TEST_ASSERT_EQUAL_UINT8(0xff, page[104]);
  ASSERT_CLEAN_FLASH();
}

/* An erase is destructive before it is selective: the block is erased and then written back from the
 * staging buffer, so if the write-back fails the entries that were meant to survive are gone with the
 * one that was meant to leave. This is where a store that keeps several things in one block earns its
 * design review. */
static void test_an_erase_whose_copy_back_fails_takes_the_neighbours(void) {
  size_t total = 0;
  total += blob_append(blob + total, MAGIC_A, 0x01, 64);
  total += blob_append(blob + total, MAGIC_B, 0x02, 64);
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  fs_entry_t* doomed = fs_find(by_magic, (void*)(uintptr_t)MAGIC_B);
  TEST_ASSERT_NOT_NULL(doomed);

  hal_host_flash_interrupt_after(0, -1);

  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_erase(doomed));

  struct collect seen = {.magic = 0};
  fs_iterate(collect, &seen);
  TEST_ASSERT_EQUAL_size_t(0, seen.count);
  ASSERT_CLEAN_FLASH();
}

/* Formatting the store erases every block it owns, so one block refusing is reported and the rest are
 * still erased. */
static void test_a_format_that_cannot_erase_reports_err_hw(void) {
  hal_host_flash_interrupt_after(-1, 0);

  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_format());
  TEST_ASSERT_EQUAL_UINT(HAL_FLASH_DATA_BLOCK_COUNT - 1, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

/* Every entry point checks that flash unlocked before it starts, and none of them has any other way to
 * find out that it did not. */
static void test_a_store_that_cannot_unlock_reports_err_hw(void) {
  size_t total = blob_append(blob, MAGIC_A, 0x01, 64);

  hal_host_flash_refuse_unlock(true);

  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_write((fs_entry_t*)blob, total));
  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_erase((fs_entry_t*)(uintptr_t)page_addr(first_data_block())));
  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_erase_all(by_magic, (void*)(uintptr_t)MAGIC_A));
  TEST_ASSERT_EQUAL_INT(ERR_HW, fs_format());

  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_programs());
  TEST_ASSERT_EQUAL_size_t(0, hal_host_flash_erases());
  ASSERT_CLEAN_FLASH();
}

/* The third action a predicate can return, from fs_iterate(): stop here, having seen what you came for.
 * No caller in app/ uses it -- multisig_store_list() counts to the size of its array and keeps going --
 * so this is the shape of the API rather than a device behaviour. */
static fs_action_t stop_after_two(void* ctx, fs_entry_t* entry) {
  (void) entry;
  struct collect* seen = (struct collect*) ctx;
  seen->count++;
  return seen->count >= 2 ? FS_STOP : FS_REJECT;
}

static void test_iterate_ends_when_the_predicate_says_stop(void) {
  size_t total = 0;
  for (uint8_t i = 0; i < 4; i++) {
    total += blob_append(blob + total, MAGIC_A, 0x10 * (i + 1), 64);
  }
  TEST_ASSERT_EQUAL_INT(ERR_OK, fs_write((fs_entry_t*)blob, total));

  struct collect seen = {.magic = 0};
  fs_iterate(stop_after_two, &seen);
  TEST_ASSERT_EQUAL_size_t(2, seen.count);
  ASSERT_CLEAN_FLASH();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_an_unwritten_store_holds_nothing);
  RUN_TEST(test_a_written_entry_is_found_where_it_was_written);
  RUN_TEST(test_the_first_entry_in_the_log_is_the_one_found);
  RUN_TEST(test_entries_that_do_not_fit_move_to_the_next_page);
  RUN_TEST(test_a_block_filled_exactly_leaves_the_next_one_erased);
  RUN_TEST(test_erasing_one_entry_keeps_the_others);
  RUN_TEST(test_erasing_an_address_that_holds_no_entry_reports_err_data);
  RUN_TEST(test_erase_all_drops_the_match_and_keeps_the_rest);
  RUN_TEST(test_a_full_block_survives_being_rewritten);
  RUN_TEST(test_erase_all_without_a_stop_reports_err_data_after_rewriting);
  RUN_TEST(test_an_entry_larger_than_a_block_is_refused);
  RUN_TEST(test_writes_inside_a_block_are_off_the_program_width);
  RUN_TEST(test_the_other_bank_orientation_reads_the_same_store);
  RUN_TEST(test_a_write_that_fails_midway_leaves_a_clean_prefix);
  RUN_TEST(test_an_erase_that_fails_leaves_the_entry);
  RUN_TEST(test_a_pad_that_fails_is_reported);
  RUN_TEST(test_an_erase_whose_copy_back_fails_takes_the_neighbours);
  RUN_TEST(test_a_format_that_cannot_erase_reports_err_hw);
  RUN_TEST(test_a_store_that_cannot_unlock_reports_err_hw);
  RUN_TEST(test_iterate_ends_when_the_predicate_says_stop);

  return UNITY_END();
}
