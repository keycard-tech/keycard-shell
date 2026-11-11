#include "keys_host.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "storage/keys.h"

#define MAX_PATCHED 4

static struct {
  uint8_t* at;
  uint8_t original[33];
} patched[MAX_PATCHED];
static unsigned patched_count;

static size_t page_size(void) {
  static size_t size;

  if (size == 0) {
    size = (size_t)sysconf(_SC_PAGESIZE);
  }

  return size;
}

/* The section the linker put a key in is read-only, which is the point of it. The write is the release
 * tool's: the same bytes, replaced in place. Read-only again when the write is done, so a stray store
 * elsewhere in .rodata still faults. */
static void write_protected(uint8_t* at, const uint8_t* bytes, size_t len) {
  const size_t page = page_size();
  uintptr_t start = (uintptr_t)at & ~(page - 1);
  uint8_t* base = (uint8_t*)start;
  const size_t span = ((uintptr_t)at + len) - start;

  if (mprotect(base, span, PROT_READ | PROT_WRITE) != 0) {
    fprintf(stderr, "host_key_set: cannot make the page of a key writable\n");
    abort();
  }

  memcpy(at, bytes, len);

  if (mprotect(base, span, PROT_READ) != 0) {
    fprintf(stderr, "host_key_set: cannot restore a key to read-only\n");
    abort();
  }
}

void host_key_set(key_type_t type, const uint8_t public_key[33]) {
  if (type == FW_VERIFICATION_KEY) {
    /* Not a section: the firmware reads that one from the running image's header in flash. Write it
     * with hal_host_flash_block(), so the store's semantics still apply to it. */
    fprintf(stderr, "host_key_set: FW_VERIFICATION_KEY lives in flash, not in a section\n");
    abort();
  }

  const uint8_t* at = NULL;
  if (key_read_public(type, &at) != ERR_OK) {
    fprintf(stderr, "host_key_set: the firmware holds no key of that type\n");
    abort();
  }

  for (unsigned i = 0; i < patched_count; i++) {
    if (patched[i].at == (uint8_t*)at) {
      write_protected((uint8_t*)at, public_key, 33);
      return;
    }
  }

  if (patched_count >= MAX_PATCHED) {
    fprintf(stderr, "host_key_set: more keys patched than the seam holds\n");
    abort();
  }

  memcpy(patched[patched_count].original, at, 33);
  patched[patched_count].at = (uint8_t*)at;
  patched_count++;

  write_protected((uint8_t*)at, public_key, 33);
}

void host_key_reset(void) {
  while (patched_count > 0) {
    patched_count--;
    write_protected(patched[patched_count].at, patched[patched_count].original, 33);
  }
}
