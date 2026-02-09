#include <ctype.h>
#include <string.h>
#include <inttypes.h>
#include "compactsize.h"
#include "psbt_tx.h"

const uint8_t PSBT_MAGIC[4] = {0x70, 0x73, 0x62, 0x74};

#define ASSERT_SPACE(s) \
  if (tx->write_pos+(s) > tx->data + tx->data_capacity) { \
    return PSBT_OOB_WRITE; \
  }

size_t psbt_size(psbt_t *tx) {
  return tx->write_pos - tx->data;
}

static psbt_result_t psbt_write_header(psbt_t *tx) {
  ASSERT_SPACE(sizeof(PSBT_MAGIC));
  memcpy(tx->write_pos, PSBT_MAGIC, sizeof(PSBT_MAGIC));
  tx->write_pos += sizeof(PSBT_MAGIC);

  ASSERT_SPACE(1);
  *tx->write_pos = 0xff;
  tx->write_pos++;

  tx->state = PSBT_ST_GLOBAL;

  return PSBT_OK;
}

psbt_result_t psbt_init(psbt_t *tx, uint8_t *dest, size_t dest_size) {
  tx->write_pos = dest;
  tx->data = dest;
  tx->data_capacity = dest_size;
  tx->state = PSBT_ST_INIT;
  return PSBT_OK;
}

psbt_result_t psbt_close_records(psbt_t *tx) {
  ASSERT_SPACE(1);
  *tx->write_pos = '\0';
  tx->write_pos++;
  return PSBT_OK;
}

psbt_result_t psbt_finalize(psbt_t *tx) {
  psbt_result_t res;

  if (tx->state != PSBT_ST_OUTPUTS_NEW && tx->state != PSBT_ST_OUTPUTS) {
    return PSBT_INVALID_STATE;
  }

  res = psbt_close_records(tx);
  if (res != PSBT_OK)
    return res;

  tx->state = PSBT_ST_FINALIZED;

  return PSBT_OK;
}

static psbt_result_t psbt_write_record(psbt_t *tx, psbt_record_t *rec) {
  uint32_t size;
  uint32_t key_size_with_type = rec->key_size + 1;

  // write key length
  size = compactsize_length(key_size_with_type);
  ASSERT_SPACE(size);
  compactsize_write((uint8_t*)tx->write_pos, key_size_with_type);
  tx->write_pos += size;

  // write type
  ASSERT_SPACE(1);
  *tx->write_pos++ = rec->type;

  // write key
  ASSERT_SPACE(rec->key_size);
  memcpy(tx->write_pos, rec->key, rec->key_size);
  tx->write_pos += rec->key_size;

  // write value length
  size = compactsize_length(rec->val_size);
  ASSERT_SPACE(size);
  compactsize_write((uint8_t*)tx->write_pos, rec->val_size);
  tx->write_pos += size;

  // write value
  ASSERT_SPACE(rec->val_size);
  memcpy(tx->write_pos, rec->val, rec->val_size);
  tx->write_pos += rec->val_size;

  return PSBT_OK;
}

static psbt_result_t psbt_read_header(psbt_t *tx) {
  ASSERT_SPACE(5);

  if (memcmp(tx->write_pos, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0) {
    return PSBT_READ_ERROR;
  }

  tx->write_pos += 4;

  if (*tx->write_pos++ != 0xff) {
    return PSBT_READ_ERROR;
  }

  tx->state = PSBT_ST_GLOBAL;

  return PSBT_OK;
}

static psbt_result_t psbt_read_record(psbt_t *tx, size_t src_size, psbt_record_t *rec) {
  psbt_result_t res = PSBT_OK;
  uint64_t size;
  uint32_t size_len;

  size_len = compactsize_peek_length(*tx->write_pos);
  ASSERT_SPACE(size_len);
  size = compactsize_read(tx->write_pos, &res);
  if (size == 0) {
    return PSBT_READ_ERROR;
  }

  tx->write_pos += size_len;

  if (res != PSBT_OK) {
    return res;
  }

  if (tx->write_pos + size > tx->data + src_size) {
    return PSBT_READ_ERROR;
  }

  ASSERT_SPACE(size);

  rec->key_size = size - 1; // don't include type in key size
  rec->type = *tx->write_pos;
  rec->key = tx->write_pos + 1;

  tx->write_pos += size;

  switch (tx->state) {
  case PSBT_ST_GLOBAL:
    rec->scope = PSBT_SCOPE_GLOBAL;
    break;
  case PSBT_ST_INPUTS:
    rec->scope = PSBT_SCOPE_INPUTS;
    break;
  case PSBT_ST_OUTPUTS:
    rec->scope = PSBT_SCOPE_OUTPUTS;
    break;
  default:
    return PSBT_INVALID_STATE;
  }

  size_len = compactsize_peek_length(*tx->write_pos);

  ASSERT_SPACE(size_len);
  size = compactsize_read(tx->write_pos, &res);

  if (res != PSBT_OK) {
    return res;
  }

  tx->write_pos += size_len;

  if (tx->write_pos + size > tx->data + src_size) {
    return PSBT_READ_ERROR;
  }

  rec->val_size = size;
  rec->val = tx->write_pos;

  ASSERT_SPACE(size);
  tx->write_pos += size;

  return PSBT_OK;
}

static void tx_counter(psbt_txelem_t *elem) {
  psbt_elem_t psbt_elem;
  psbt_tx_counter_t *counter = (psbt_tx_counter_t *)elem->user_data;

  psbt_elem.user_data = counter->user_data;
  psbt_elem.type = PSBT_ELEM_TXELEM;
  psbt_elem.elem.txelem = elem;

  // forward txelem events to user
  if (counter->handler) {
    counter->handler(&psbt_elem);
  }

  switch (elem->elem_type) {
  case PSBT_TXELEM_TXIN:
    counter->inputs++;
    return;
  case PSBT_TXELEM_TXOUT:
    counter->outputs++;
    return;
  default:
    return;
  }
}

psbt_result_t psbt_read(const uint8_t *src, size_t src_size, psbt_t *tx, psbt_elem_handler_t *elem_handler, void* user_data) {
  psbt_record_t rec;
  psbt_result_t res;

  psbt_elem_t elem;
  elem.type = PSBT_ELEM_RECORD;
  elem.user_data = user_data;

  int kvs = 0;
  uint8_t *end;

  psbt_tx_counter_t counter = {
    .inputs = 0,
    .outputs = 0,
    .user_data = user_data,
    .handler = elem_handler,
  };

  if (tx->state != PSBT_ST_INIT) {
    return PSBT_INVALID_STATE;
  }

  if (src_size > tx->data_capacity) {
    return PSBT_OOB_WRITE;
  }

  if (src != tx->data) {
    memcpy(tx->data, src, src_size);
  }

  // parsing should try to get this to the finalized state,
  // otherwise it's an invalid psbt
  tx->state = PSBT_ST_INIT;
  tx->write_pos = tx->data;

  // XXX: needed so that the asserts work properly. this is probably fine...
  tx->data_capacity = src_size;

  end = tx->data + src_size;

  while (tx->state != PSBT_ST_FINALIZED && tx->write_pos <= end) {
    switch(tx->state) {
    case PSBT_ST_INIT:
      res = psbt_read_header(tx);
      if (res != PSBT_OK) {
        return res;
      }
      break;
    case PSBT_ST_GLOBAL:
    case PSBT_ST_INPUTS:
    case PSBT_ST_OUTPUTS:
      if (*tx->write_pos == 0) {
        switch (tx->state) {
        case PSBT_ST_GLOBAL:
          tx->state = PSBT_ST_INPUTS_NEW;
          break;
        case PSBT_ST_INPUTS:
          if (++kvs >= counter.inputs) {
            tx->state = PSBT_ST_OUTPUTS_NEW;
            kvs = 0;
          } else {
            tx->state = PSBT_ST_INPUTS_NEW;
          }
          break;
        case PSBT_ST_OUTPUTS:
          if (++kvs >= counter.outputs) {
            tx->state = PSBT_ST_FINALIZED;
          } else {
            tx->state = PSBT_ST_OUTPUTS_NEW;
          }
          break;
        default:
          return PSBT_READ_ERROR;
        }
      } else {
        res = psbt_read_record(tx, src_size, &rec);

        if (res != PSBT_OK) {
          return res;
        }

        if (tx->state == PSBT_ST_GLOBAL && rec.type == PSBT_GLOBAL_UNSIGNED_TX) {
          // parse transaction for number of inputs/outputs
          res = psbt_btc_tx_parse(rec.val, rec.val_size, (void*) &counter, tx_counter);

          if (res != PSBT_OK) {
            return res;
          }
        }

        // record callback
        if (elem_handler) {
          elem.type = PSBT_ELEM_RECORD;
          elem.index = kvs;
          elem.elem.rec = &rec;
          elem_handler(&elem);
        }
      }
      break;
    case PSBT_ST_OUTPUTS_NEW:
      if (*tx->write_pos != 0) {
        return PSBT_READ_ERROR;
      }
      tx->write_pos++;
      tx->state = PSBT_ST_OUTPUTS;
      break;
    case PSBT_ST_INPUTS_NEW:
      if (*tx->write_pos != 0) {
        return PSBT_READ_ERROR;
      }
      tx->write_pos++;
      tx->state = PSBT_ST_INPUTS;
      break;
    case PSBT_ST_FINALIZED:
      return PSBT_READ_ERROR;
    }
  }

  if (tx->state != PSBT_ST_FINALIZED) {
    return PSBT_INVALID_STATE;
  } else if (*tx->write_pos != 0) {
    return PSBT_READ_ERROR;
  }

  tx->write_pos++;

  return PSBT_OK;
}

psbt_result_t psbt_write_global_record(psbt_t *tx, psbt_record_t *rec) {
  if (tx->state == PSBT_ST_INIT) {
    // write header if we haven't yet
    psbt_write_header(tx);
    tx->state = PSBT_ST_GLOBAL;
  } else if (tx->state != PSBT_ST_GLOBAL) {
    return PSBT_INVALID_STATE;
  }

  return psbt_write_record(tx, rec);
}

psbt_result_t psbt_new_input_record_set(psbt_t *tx) {
  psbt_result_t res;
  if (tx->state == PSBT_ST_GLOBAL || tx->state == PSBT_ST_INPUTS_NEW || tx->state == PSBT_ST_INPUTS) {
    res = psbt_close_records(tx);
    if (res != PSBT_OK) {
      return res;
    }

    tx->state = PSBT_ST_INPUTS_NEW;
    return PSBT_OK;
  } else if (tx->state != PSBT_ST_INPUTS) {
    return PSBT_INVALID_STATE;
  }

  return psbt_close_records(tx);
}

psbt_result_t psbt_new_output_record_set(psbt_t *tx) {
  psbt_result_t res;
  if ((tx->state == PSBT_ST_INPUTS) || (tx->state == PSBT_ST_INPUTS_NEW) || (tx->state == PSBT_ST_OUTPUTS_NEW) || (tx->state == PSBT_ST_OUTPUTS)) {
    res = psbt_close_records(tx);
    if (res != PSBT_OK) {
      return res;
    }

    tx->state = PSBT_ST_OUTPUTS_NEW;
    return PSBT_OK;
  } else if (tx->state != PSBT_ST_OUTPUTS) {
    return PSBT_INVALID_STATE;
  }

  return psbt_close_records(tx);
}

psbt_result_t psbt_write_input_record(psbt_t *tx, psbt_record_t *rec) {
  psbt_result_t res;
  if (tx->state == PSBT_ST_GLOBAL) {
    // close global records
    if ((res = psbt_close_records(tx)) != PSBT_OK) {
      return res;
    }
    tx->state = PSBT_ST_INPUTS;
  } else if (tx->state != PSBT_ST_INPUTS && tx->state != PSBT_ST_INPUTS_NEW) {
    return PSBT_INVALID_STATE;
  }

  return psbt_write_record(tx, rec);
}

psbt_result_t psbt_write_output_record(psbt_t *tx, psbt_record_t *rec) {
  psbt_result_t res;
  if (tx->state == PSBT_ST_INPUTS) {
    // close global records
    if ((res = psbt_close_records(tx)) != PSBT_OK) {
      return res;
    }
    tx->state = PSBT_ST_OUTPUTS;
  } else if (tx->state != PSBT_ST_OUTPUTS && tx->state != PSBT_ST_OUTPUTS_NEW) {
    return PSBT_INVALID_STATE;
  }

  return psbt_write_record(tx, rec);
}
