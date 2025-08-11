#include "psbt_tx.h"
#include "compactsize.h"
#include <string.h>

#define SEGREGATED_WITNESS_FLAG 0x1

#define ASSERT_SPACE(s)							\
  if (p+(s) > data + data_size) {		\
    return PSBT_READ_ERROR; \
  }

static psbt_result_t parse_txin(uint8_t **cursor, uint8_t *data, uint32_t data_size, psbt_txin_t *txin) {
  uint64_t script_len;
  size_t size_len;
  psbt_result_t res = PSBT_OK;

  uint8_t *p = *cursor;

  ASSERT_SPACE(32);
  txin->txid = p;
  p += 32;

  ASSERT_SPACE(4);
  memcpy(&txin->index, p, sizeof(uint32_t));
  p += 4;

  ASSERT_SPACE(1);
  size_len = compactsize_peek_length(*p);

  ASSERT_SPACE(size_len);
  script_len = compactsize_read(p, &res);
  if (res != PSBT_OK)
    return res;

  p += size_len;

  txin->script_len = script_len;
  txin->script = script_len ? p : NULL;

  p += script_len;

  ASSERT_SPACE(4);
  memcpy(&txin->sequence_number, p, sizeof(uint32_t));
  p += 4;

  *cursor = p;

  return PSBT_OK;
}

static psbt_result_t parse_txout(uint8_t **cursor, uint8_t *data, uint32_t data_size, psbt_txout_t *txout) {
  size_t size_len;
  uint64_t script_len;
  psbt_result_t res = PSBT_OK;

  uint8_t *p = *cursor;

  ASSERT_SPACE(8);
  txout->amount = p;
  p += 8;

  ASSERT_SPACE(1);
  size_len = compactsize_peek_length(*p);

  ASSERT_SPACE(size_len);
  script_len = compactsize_read(p, &res);
  if (res != PSBT_OK) {
    return res;
  }

  p += size_len;

  txout->script = p;
  txout->script_len = script_len;

  ASSERT_SPACE(script_len);
  p += script_len;

  *cursor = p;

  return PSBT_OK;
}

static psbt_result_t parse_witness_item(uint8_t **cursor, uint8_t *data, uint32_t data_size, psbt_witness_item_t *witness_item) {
  uint32_t size_len, item_len;
  psbt_result_t res = PSBT_OK;

  uint8_t *p = *cursor;

  ASSERT_SPACE(1);
  size_len = compactsize_peek_length(*p);

  ASSERT_SPACE(size_len);
  item_len = compactsize_read(p, &res);
  if (res != PSBT_OK) {
    return res;
  }

  p += size_len;

  witness_item->item = p;
  witness_item->item_len = item_len;

  p += item_len;

  *cursor = p;

  return PSBT_OK;
}

psbt_result_t psbt_btc_tx_parse(uint8_t *data, uint32_t data_size, void *user_data, psbt_txelem_handler_t *handler) {
  psbt_tx_t tx;
  psbt_result_t res = PSBT_OK;
  psbt_txin_t txin;
  psbt_txout_t txout;
  psbt_txelem_t txelem;
  psbt_witness_item_t wi;

  uint64_t count = 0;
  uint8_t flag = 0;
  uint32_t size_len = 0;
  size_t inputs = 0;
  size_t i = 0, j = 0;

  uint8_t *p = data;
  txelem.user_data = user_data;

  ASSERT_SPACE(4);

  memcpy(&tx.version, p, sizeof(uint32_t));
  p += 4;

  ASSERT_SPACE(1);

  if (*p == 0) {
    p++;
    ASSERT_SPACE(1);
    flag = *p;
    p++;
    ASSERT_SPACE(1);
  }

  size_len = compactsize_peek_length(*p);

  ASSERT_SPACE(size_len);
  count = compactsize_read(p, &res);
  if (res != PSBT_OK) {
    return res;
  }

  p += size_len;

  inputs = count;

  // parse inputs
  for (i = 0; i < count; i++) {
    res = parse_txin(&p, data, data_size, &txin);
    if (res != PSBT_OK) {
      return res;
    }
    txelem.elem_type = PSBT_TXELEM_TXIN;
    txelem.elem.txin = &txin;
    handler(&txelem);
  }

  ASSERT_SPACE(1);
  size_len = compactsize_peek_length(*p);

  ASSERT_SPACE(size_len);
  count = compactsize_read(p, &res);
  if (res != PSBT_OK)
    return res;

  p += size_len;

  // parse outputs
  for (i = 0; i < count; i++) {
    res = parse_txout(&p, data, data_size, &txout);
    if (res != PSBT_OK) {
      return res;
    }
    txelem.elem_type = PSBT_TXELEM_TXOUT;
    txelem.elem.txout = &txout;
    handler(&txelem);
  }

  if (flag & SEGREGATED_WITNESS_FLAG) {
    for (i = 0; i < inputs; i++) {
      ASSERT_SPACE(1);
      size_len = compactsize_peek_length(*p);

      ASSERT_SPACE(size_len);
      count = compactsize_read(p, &res);
      if (res != PSBT_OK) {
        return res;
      }

      p += size_len;

      for (j = 0; j < count; j++) {
        res = parse_witness_item(&p, data, data_size, &wi);
        if (res != PSBT_OK) {
          return res;
        }
        wi.input_index = i;
        wi.item_index = j;
        txelem.elem_type = PSBT_TXELEM_WITNESS_ITEM;
        txelem.elem.witness_item = &wi;
        handler(&txelem);
      }

    }
  }

  ASSERT_SPACE(4);
  memcpy(&tx.lock_time, p, sizeof(uint32_t));

  p += 4;

  if (p != data + data_size) {
    return PSBT_READ_ERROR;
  }

  txelem.elem_type = PSBT_TXELEM_TX;
  txelem.elem.tx = &tx;
  handler(&txelem);

  return PSBT_OK;
}
