#include "fs.h"
#include "mem.h"

#include <string.h>

struct fs_find_ctx {
  fs_predicate_t predicate;
  void* ctx;
  fs_entry_t* found;
};

struct fs_write_ctx {
  size_t total_length;
  uint8_t* last_write;
  fs_entry_t* next_entry;
  app_err_t err;
};

struct fs_erase_ctx {
  uint32_t block;
  size_t off;
  uint8_t* data;
  uint8_t pending_erase;
  uint8_t stop;
  fs_predicate_t predicate;
  void* ctx;
  app_err_t err;
};

enum fs_iterator_action {
  FS_ITER_END,
  FS_ITER_NEXT,
  FS_ITER_SKIP_BYTES,
  FS_ITER_SKIP_PAGE
};

#define FS_MAGIC_FREE 0xffff
#define FS_MAGIC_PAD_MASK 0x00c0
#define FS_MAGIC_PAD 0x0080

typedef enum fs_iterator_action (*fs_iterator_cb_t)(void* ctx, fs_entry_t* entry, size_t* to_skip);

static fs_action_t _fs_erase_one(void* ctx, fs_entry_t* entry) {
  return ((uint32_t) ctx) == ((uint32_t) entry) ? FS_STOP : FS_ACCEPT;
}

static uint8_t* _fs_get_page(uint32_t idx) {
  if (idx >= HAL_FLASH_DATA_BLOCK_COUNT) {
    return NULL;
  }

  const hal_flash_data_segment_t *map = hal_flash_get_data_segments();

  int off = 0;

  while(idx >= map[off].count) {
    idx -= map[off++].count;
  }

  return (uint8_t*) (map[off].addr + (HAL_FLASH_BLOCK_SIZE * idx));
}

static enum fs_iterator_action _fs_get_entry(void* ctx, fs_entry_t* entry, size_t* to_skip) {
  struct fs_find_ctx* find_ctx = (struct fs_find_ctx *) ctx;

  if (entry->magic == FS_MAGIC_FREE) {
    return FS_ITER_SKIP_PAGE;
  }

  switch(find_ctx->predicate(find_ctx->ctx, entry)) {
  case FS_REJECT:
    return FS_ITER_NEXT;
  case FS_ACCEPT:
    find_ctx->found = entry;
  case FS_STOP:
    return FS_ITER_END;
  }

  return FS_ITER_NEXT;
}

struct fs_iterate_ctx {
  fs_predicate_t predicate;
  void* ctx;
};

static enum fs_iterator_action _fs_iterate_all(void* ctx, fs_entry_t* entry, size_t* to_skip) {
  (void) to_skip;
  struct fs_iterate_ctx* iter_ctx = (struct fs_iterate_ctx *) ctx;

  if (entry->magic == FS_MAGIC_FREE) {
    return FS_ITER_SKIP_PAGE;
  }

  switch(iter_ctx->predicate(iter_ctx->ctx, entry)) {
  case FS_REJECT:
  case FS_ACCEPT:
    return FS_ITER_NEXT;
  case FS_STOP:
    return FS_ITER_END;
  }

  return FS_ITER_NEXT;
}

static hal_err_t _fs_pad(uint8_t* addr) {
  if (addr == NULL) {
    return HAL_SUCCESS;
  }

  size_t padlen = HAL_FLASH_WORD_SIZE - (((uint32_t) addr) & (HAL_FLASH_WORD_SIZE - 1));
  uint8_t padding[padlen];

  for (int i = 0; i < padlen; i++) {
    padding[i] = FS_MAGIC_PAD | (padlen - i);
  }

  return hal_flash_program(padding, addr, padlen);
}

static enum fs_iterator_action _fs_write_entries(void* ctx, fs_entry_t* entry, size_t* to_skip) {
  struct fs_write_ctx* write_ctx = (struct fs_write_ctx *) ctx;

  if (entry->magic == FS_MAGIC_FREE) {
    size_t total_entry_len = (write_ctx->next_entry->len + 4);
    size_t off = ((uint32_t) entry) & (HAL_FLASH_BLOCK_SIZE - 1);
    if ((HAL_FLASH_BLOCK_SIZE - off) < total_entry_len) {
      _fs_pad(write_ctx->last_write);
      write_ctx->last_write = NULL;
      return FS_ITER_SKIP_PAGE;
    }

    if (hal_flash_program((uint8_t*) write_ctx->next_entry, (uint8_t*) entry, total_entry_len) != HAL_SUCCESS) {
      write_ctx->err = ERR_HW;
    }

    write_ctx->last_write = ((uint8_t*) entry) + total_entry_len;
    write_ctx->total_length -= total_entry_len;

    if (write_ctx->total_length == 0) {
      if (_fs_pad(write_ctx->last_write) != HAL_SUCCESS) {
        write_ctx->err = ERR_HW;
      }

      return FS_ITER_END;
    } else {
      write_ctx->next_entry = (fs_entry_t*) (((uint32_t) write_ctx->next_entry) + total_entry_len);
      *to_skip = total_entry_len;
      return FS_ITER_SKIP_BYTES;
    }
  }

  return FS_ITER_NEXT;
}

static void _fs_commit_block(struct fs_erase_ctx* erase_ctx) {
  if (!erase_ctx->pending_erase) {
    erase_ctx->off = 0;
    return;
  }

  erase_ctx->pending_erase = 0;

  if (hal_flash_erase(erase_ctx->block) != HAL_SUCCESS) {
    erase_ctx->err = ERR_HW;
    return;
  }

  if (erase_ctx->off == 0) {
    return;
  }

  size_t padlen = HAL_FLASH_WORD_SIZE - (erase_ctx->off & (HAL_FLASH_WORD_SIZE - 1));

  while (padlen) {
    erase_ctx->data[erase_ctx->off++] = FS_MAGIC_PAD | padlen--;
  }

  if (hal_flash_program(erase_ctx->data, (uint8_t*) HAL_FLASH_BLOCK_ADDR(erase_ctx->block), erase_ctx->off) != HAL_SUCCESS) {
    erase_ctx->err = ERR_HW;
  }

  erase_ctx->off = 0;
}

static enum fs_iterator_action _fs_erase_entries(void* ctx, fs_entry_t* entry, size_t* to_skip) {
  struct fs_erase_ctx* erase_ctx = (struct fs_erase_ctx *) ctx;
  int block = HAL_FLASH_ADDR_TO_BLOCK((uint32_t)entry);

  if (erase_ctx->block != block) {
    _fs_commit_block(erase_ctx);

    if (erase_ctx->stop) {
      return FS_ITER_END;
    }
  }

  erase_ctx->block = block;

  if (entry->magic == FS_MAGIC_FREE) {
    return FS_ITER_SKIP_PAGE;
  }

  fs_action_t action = erase_ctx->stop ? FS_ACCEPT : erase_ctx->predicate(erase_ctx->ctx, entry);
  int copy_len;

  switch(action) {
  case FS_REJECT:
    erase_ctx->pending_erase = 1;
    break;
  case FS_ACCEPT:
    copy_len = entry->len + 4;
    memcpy(&erase_ctx->data[erase_ctx->off], (uint8_t*) entry, copy_len);
    erase_ctx->off += copy_len;
    break;
  case FS_STOP:
    erase_ctx->pending_erase = 1;
    erase_ctx->err = ERR_OK;
    erase_ctx->stop = 1;
    break;
  }

  return FS_ITER_NEXT;
}

static enum fs_iterator_action _fs_iterate_page(uint8_t* p, fs_iterator_cb_t cb, void *ctx) {
  size_t off = 0;

  while (off < HAL_FLASH_BLOCK_SIZE) {
    fs_entry_t* entry = (fs_entry_t*)&p[off];
    if ((entry->magic & FS_MAGIC_PAD_MASK) == FS_MAGIC_PAD) {
      off += (entry->magic & (~FS_MAGIC_PAD_MASK & 0xff));
      continue;
    }

    size_t to_skip = 0;

    switch(cb(ctx, entry, &to_skip)) {
    case FS_ITER_END:
      return FS_ITER_END;
    case FS_ITER_NEXT:
      off += entry->len + 4;
      break;
    case FS_ITER_SKIP_BYTES:
      off += to_skip;
      break;
    case FS_ITER_SKIP_PAGE:
      return FS_ITER_NEXT;
    }
  }

  return FS_ITER_NEXT;
}

static void _fs_iterate(fs_iterator_cb_t cb, void *ctx) {
  for(int i = 0; i < HAL_FLASH_DATA_BLOCK_COUNT; i++) {
    if (_fs_iterate_page(_fs_get_page(i), cb, ctx) == FS_ITER_END) {
      return;
    }
  }
}

fs_entry_t* fs_find(fs_predicate_t predicate, void* ctx) {
  struct fs_find_ctx finder_ctx = { .predicate = predicate, .ctx = ctx, .found = NULL };
  _fs_iterate(_fs_get_entry, &finder_ctx);
  return finder_ctx.found;
}

void fs_iterate(fs_predicate_t predicate, void* ctx) {
  struct fs_iterate_ctx iter_ctx = { .predicate = predicate, .ctx = ctx };
  _fs_iterate(_fs_iterate_all, &iter_ctx);
}

app_err_t fs_write(fs_entry_t* first_entry, size_t total_length) {
  if (hal_flash_begin_program() != HAL_SUCCESS) {
    return ERR_HW;
  }

  struct fs_write_ctx write_ctx = { .total_length = total_length, .last_write = NULL, .next_entry = first_entry, .err = ERR_OK };
  _fs_iterate(_fs_write_entries, &write_ctx);

  hal_flash_end_program();

  return write_ctx.total_length ? ERR_FULL : write_ctx.err;
}

app_err_t fs_erase(fs_entry_t* entry) {
  if (hal_flash_begin_program() != HAL_SUCCESS) {
    return ERR_HW;
  }

  struct fs_erase_ctx erase_ctx = { .block = 0, .data = g_flash_swap, .predicate = _fs_erase_one, .ctx = entry, .err = ERR_DATA, .stop = 0, .pending_erase = 0 };
  _fs_iterate_page((uint8_t*) HAL_FLASH_BLOCK_ADDR(HAL_FLASH_ADDR_TO_BLOCK((uint32_t)entry)), _fs_erase_entries, &erase_ctx);
  _fs_commit_block(&erase_ctx);

  hal_flash_end_program();

  return erase_ctx.err;
}

app_err_t fs_erase_all(fs_predicate_t predicate, void* ctx) {
  if (hal_flash_begin_program() != HAL_SUCCESS) {
    return ERR_HW;
  }

  struct fs_erase_ctx erase_ctx = { .block = 0, .data = g_flash_swap, .predicate = predicate, .ctx = ctx, .err = ERR_DATA, .stop = 0, .pending_erase = 0 };
  _fs_iterate(_fs_erase_entries, &erase_ctx);
  _fs_commit_block(&erase_ctx);

  hal_flash_end_program();

  return erase_ctx.err;
}
