#include "qrcodegen.h"
#include "qrout.h"
#include "crypto/util.h"
#include "screen/screen.h"
#include "ur/ur.h"
#include "ui/dialog.h"
#include "ui/theme.h"
#include "ui/ui_internal.h"

#define QR_DISPLAY_TIMEOUT 60000
#define QR_FRAME_DURATION 200
#define QR_MAX_VERSION 21
#define QR_BUF_LEN qrcodegen_BUFFER_LEN_FOR_VERSION(QR_MAX_VERSION)
#define QR_MAX_SEGMENT_LENGTH 200

app_err_t qrout_display(const char* str, uint16_t max_y) {
  uint8_t tmpBuf[QR_BUF_LEN];
  uint8_t qrcode[QR_BUF_LEN];

  if (!qrcodegen_encodeText(str, tmpBuf, qrcode, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN, QR_MAX_VERSION, qrcodegen_Mask_AUTO, 1)) {
    return ERR_DATA;
  }

  screen_area_t qrarea;
  qrarea.height = max_y - (TH_TITLE_HEIGHT + TH_QRCODE_VERTICAL_MARGIN);

  int qrsize = qrcodegen_getSize(qrcode);
  int scale = qrarea.height / qrsize;
  qrarea.height = scale * qrsize;

  qrarea.width = qrarea.height;
  qrarea.x = (SCREEN_WIDTH - qrarea.width) / 2;
  qrarea.y = TH_TITLE_HEIGHT + (((max_y - TH_TITLE_HEIGHT) - qrarea.height) / 2);

  screen_draw_qrcode(&qrarea, qrcode, qrsize, scale);

  return ERR_OK;
}

static void qrout_prepare_canvas(const char* title) {
  dialog_title_colors(title, SCREEN_COLOR_WHITE, SCREEN_COLOR_BLACK, SCREEN_COLOR_BLACK);
  dialog_footer_colors(TH_TITLE_HEIGHT, SCREEN_COLOR_WHITE);
  dialog_nav_hints_colors(ICON_NONE, ICON_NAV_CONFIRM, SCREEN_COLOR_WHITE, SCREEN_COLOR_BLACK);
}

static app_err_t qrout_display_single_ur(ur_out_t* ur) {
  char urstr[QR_BUF_LEN/2];

  if (ur_encode(ur, urstr, sizeof(urstr)) != ERR_OK) {
    return ERR_DATA;
  }

  if (qrout_display(urstr, (SCREEN_HEIGHT - TH_SCREEN_MARGIN)) != ERR_OK) {
    return ERR_DATA;
  }

  while(1) {
    switch(ui_wait_keypress(pdMS_TO_TICKS(QR_DISPLAY_TIMEOUT))) {
    case KEYPAD_KEY_INVALID:
    case KEYPAD_KEY_CONFIRM:
      return ERR_OK;
    default:
      break;
    }
  }
}

static app_err_t qrout_display_animated_ur(ur_out_t* ur) {
  char urstr[QR_BUF_LEN/2];

  while(1) {
    if (ur_encode_next(ur, urstr, sizeof(urstr)) != ERR_OK) {
      return ERR_DATA;
    }

    if (qrout_display(urstr, (SCREEN_HEIGHT - TH_SCREEN_MARGIN)) != ERR_OK) {
      return ERR_DATA;
    }

    switch(ui_wait_keypress(QR_FRAME_DURATION)) {
    case KEYPAD_KEY_CONFIRM:
      return ERR_OK;
    default:
      break;
    }
  }
}

app_err_t qrout_display_ur() {
  qrout_prepare_canvas(g_ui_cmd.params.qrout.title);

  ur_out_t ur;
  ur_out_init(&ur, g_ui_cmd.params.qrout.type, g_ui_cmd.params.qrout.data, g_ui_cmd.params.qrout.len, QR_MAX_SEGMENT_LENGTH);

  if (ur.part.ur_part_seqLen > 1) {
    return qrout_display_animated_ur(&ur);
  } else {
    return qrout_display_single_ur(&ur);
  }
}

app_err_t qrout_display_address() {
  qrout_prepare_canvas(g_ui_cmd.params.address.title);

  uint16_t qr_height = SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT - ((TH_FONT_DATA)->yAdvance * 2);

  screen_text_ctx_t ctx = {
      .bg = SCREEN_COLOR_WHITE,
      .fg = SCREEN_COLOR_BLACK,
      .font = TH_FONT_DATA,
      .x = TH_QRCODE_ADDR_MARGIN,
      .y = qr_height + TH_QRCODE_VERTICAL_MARGIN
  };

  if (qrout_display(g_ui_cmd.params.address.address, qr_height) != ERR_OK) {
    return ERR_DATA;
  }

  screen_draw_text(&ctx, (SCREEN_WIDTH - TH_QRCODE_ADDR_MARGIN), SCREEN_HEIGHT - TH_NAV_HINT_HEIGHT, (uint8_t*) g_ui_cmd.params.address.address, strlen(g_ui_cmd.params.address.address), false, true);

  dialog_pager_colors(*g_ui_cmd.params.address.index, UINT32_MAX, 0, SCREEN_COLOR_WHITE, SCREEN_COLOR_BLACK);

  while(1) {
    switch(ui_wait_keypress(portMAX_DELAY)) {
    case KEYPAD_KEY_CANCEL:
    case KEYPAD_KEY_BACK:
    case KEYPAD_KEY_INVALID:
    case KEYPAD_KEY_CONFIRM:
      *g_ui_cmd.params.address.index = UINT32_MAX;
      return ERR_OK;
    case KEYPAD_KEY_LEFT:
      if (*g_ui_cmd.params.address.index) {
        (*g_ui_cmd.params.address.index)--;
        return ERR_OK;
      }

      break;
    case KEYPAD_KEY_RIGHT:
      if (*g_ui_cmd.params.address.index < INT32_MAX) {
        (*g_ui_cmd.params.address.index)++;
        return ERR_OK;
      }
      break;
    default:
      break;
    }
  }
}
