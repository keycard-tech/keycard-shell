#include "common.h"
#include "error.h"
#include "mem.h"
#include "qrcode.h"
#include "camera/camera.h"
#include "crypto/crc32.h"
#include "screen/screen.h"
#include "ui/theme.h"
#include "ui/ui_internal.h"
#include "ui/dialog.h"
#include "ur/ur.h"
#include "ur/ur_decode.h"

#define QR_SCORE_RED 1
#define QR_SCORE_YELLOW 3
#define QR_SCORE_GREEN 5

#define QR_TICK_COUNT 20
#define QR_TICK_PERCENT 5

typedef struct {
  uint16_t prev_color;
  uint8_t prev_percent_done;
  uint8_t score;
} qrscan_indicator_t;

app_err_t qrscan_decode(struct quirc *qrctx, ur_t* ur) {
  struct quirc_code qrcode;
  struct quirc_data *qrdata = (struct quirc_data *)qrctx;

  if (quirc_count(qrctx) != 1) {
    return ERR_SCAN;
  }

  quirc_extract(qrctx, 0, &qrcode);
  quirc_decode_error_t err = quirc_decode(&qrcode, qrdata);

  return !err ? ur_process_part(ur, qrdata->payload, qrdata->payload_len) : ERR_DECODE;
}

app_err_t qrscan_deserialize(ur_t* ur) {
  if (g_ui_cmd.params.qrscan.type == UR_ANY_TX) {
    if (ur->type == ETH_SIGN_REQUEST || ur->type == CRYPTO_PSBT || ur->type == BTC_SIGN_REQUEST) {
      g_ui_cmd.params.qrscan.type = ur->type;
    } else {
      return ERR_DATA;
    }
  } else if (ur->type != g_ui_cmd.params.qrscan.type) {
    return ERR_DATA;
  }

  if ((ur->crc != 0) && (crc32(ur->data, ur->data_len) != ur->crc)) {
    return ERR_DATA;
  }

  app_err_t err;
  data_t* data;

  switch(ur->type) {
  case ETH_SIGN_REQUEST:
    err = cbor_decode_eth_sign_request(ur->data, ur->data_len, g_ui_cmd.params.qrscan.out, NULL) == ZCBOR_SUCCESS ? ERR_OK : ERR_DATA;
    break;
  case CRYPTO_PSBT:
    err = cbor_decode_psbt(ur->data, ur->data_len, g_ui_cmd.params.qrscan.out, NULL) == ZCBOR_SUCCESS ? ERR_OK : ERR_DATA;
    break;
  case BTC_SIGN_REQUEST:
    err = cbor_decode_btc_sign_request(ur->data, ur->data_len, g_ui_cmd.params.qrscan.out, NULL) == ZCBOR_SUCCESS ? ERR_OK : ERR_DATA;
    break;
  case FS_DATA:
    data = g_ui_cmd.params.qrscan.out;
    data->data = ur->data;
    data->len = ur->data_len;
    err = ERR_OK;
    break;
  case DEV_AUTH:
    err = cbor_decode_dev_auth(ur->data, ur->data_len, g_ui_cmd.params.qrscan.out, NULL) == ZCBOR_SUCCESS ? ERR_OK : ERR_DATA;
    break;
  default:
    err = ERR_DATA;
    break;
  }

  return err;
}

static inline void qrscan_reset_and_draw_indicator(qrscan_indicator_t* indicator) {
  indicator->score = QR_SCORE_RED;
  indicator->prev_color = 0;
  indicator->prev_percent_done = 0;

  screen_area_t tick = { .x = TH_QRSCAN_INDICATOR_MARGIN, .y = TH_QRSCAN_TICK_BOTTOM, .width = TH_QRSCAN_TICK_WIDTH, .height = TH_QRSCAN_TICK_HEIGHT };

  for (int i = 0; i < QR_TICK_COUNT; i++) {
    screen_fill_area(&tick, TH_COLOR_QR_EMPTY_TICK);
    tick.y -= (TH_QRSCAN_TICK_HEIGHT + TH_QRSCAN_TICK_SPACING);
  }
}

static inline void qrscan_draw_indicator(qrscan_indicator_t* indicator, uint8_t percent_done) {
  uint16_t indicator_color;

  if (indicator->score > QR_SCORE_YELLOW) {
    indicator_color = TH_COLOR_QR_OK;
  } else if (indicator->score > QR_SCORE_RED) {
    indicator_color = TH_COLOR_QR_NOT_DECODED;
  } else {
    indicator_color = TH_COLOR_QR_NOT_FOUND;
    indicator->score = QR_SCORE_RED;
  }

  uint8_t start_tick;

  if (indicator->prev_color != indicator_color) {
    indicator->prev_color = indicator_color;
    start_tick = 0;
  } else {
    start_tick = indicator->prev_percent_done / QR_TICK_PERCENT;
  }

  uint8_t end_tick = percent_done / QR_TICK_PERCENT;
  indicator->prev_percent_done = percent_done;

  screen_area_t tick = {
      .x = TH_QRSCAN_INDICATOR_MARGIN,
      .y = TH_QRSCAN_TICK_BOTTOM - (start_tick * (TH_QRSCAN_TICK_HEIGHT + TH_QRSCAN_TICK_SPACING)),
      .width = TH_QRSCAN_TICK_WIDTH,
      .height = TH_QRSCAN_TICK_HEIGHT
  };

  for (int i = start_tick; i < end_tick; i++) {
    screen_fill_area(&tick, indicator_color);
    tick.y -= (TH_QRSCAN_TICK_HEIGHT + TH_QRSCAN_TICK_SPACING);
  }
}

app_err_t qrscan_scan() {
  struct quirc qrctx;
  app_err_t res = ERR_OK;
  ur_t ur = { .data_max_len = MEM_HEAP_SIZE, .data = g_mem_heap, .percent_done = 0, .crc = 0};

  screen_fill_area(&screen_fullarea, TH_COLOR_QR_BG);
  dialog_nav_hints(ICON_NAV_CANCEL, ICON_NAV_NONE);

  if (camera_start() != HAL_SUCCESS) {
    res = ERR_HW;
    goto end;
  }

  uint8_t* fb;

  qrscan_indicator_t indicator;
  qrscan_reset_and_draw_indicator(&indicator);

  while (1) {
    if (camera_next_frame(&fb) != HAL_SUCCESS) {
      continue;
    }

    quirc_set_image(&qrctx, fb);
    quirc_begin(&qrctx, NULL, NULL);

    uint32_t total_luma = quirc_threshold(&qrctx);
    camera_autoexposure(total_luma);
    screen_camera_passthrough(fb);

    quirc_end(&qrctx);

    app_err_t qrerr = qrscan_decode(&qrctx, &ur);
    indicator.score--;

    if (qrerr == ERR_OK) {
      indicator.score = QR_SCORE_GREEN;
      hal_inactivity_timer_reset();
      if (qrscan_deserialize(&ur) == ERR_OK) {
        screen_wait();
        goto end;
      } else {
        ur.crc = 0;
        ur.percent_done = 0;
        screen_wait();
        qrscan_reset_and_draw_indicator(&indicator);
        goto next_scan;
      }
    } else if (qrerr == ERR_DECODE && indicator.score < QR_SCORE_YELLOW) {
      indicator.score = QR_SCORE_YELLOW;
    } else if (qrerr != ERR_SCAN) {
      indicator.score = QR_SCORE_GREEN;
    }

    screen_wait();

next_scan:
    if (camera_submit(fb) != HAL_SUCCESS) {
      res = ERR_HW;
      goto end;
    }

    qrscan_draw_indicator(&indicator, ur.percent_done);

    keypad_key_t k = ui_wait_keypress(0);

    if (k != KEYPAD_KEY_INVALID) {
      switch(k) {
      case KEYPAD_KEY_CANCEL:
      case KEYPAD_KEY_BACK:
        res = ERR_CANCEL;
        goto end;
        break;
      default:
        break;
      }
    }
  }

end:
  camera_stop();
  return res;
}
