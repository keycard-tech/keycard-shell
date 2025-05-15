#ifndef __FS_H
#define __FS_H

#include <stdint.h>
#include "hal.h"

#define FS_ENTRY_DATA(__TYPE__, __ENTRY__) (__TYPE__)(((uint32_t) __ENTRY__) + sizeof(fs_entry_t))

typedef struct __attribute__((packed)) {
  uint16_t magic;
  uint16_t len;
} fs_entry_t;

typedef enum {
  FS_REJECT,
  FS_ACCEPT,
  FS_STOP
} fs_action_t;

typedef fs_action_t (*fs_predicate_t)(void* ctx, fs_entry_t* entry);

fs_entry_t* fs_find(fs_predicate_t predicate, void* ctx);
app_err_t fs_write(fs_entry_t* first_entry, size_t total_length);
app_err_t fs_erase(fs_entry_t* entry);
app_err_t fs_erase_all(fs_predicate_t predicate, void* ctx);

#endif
