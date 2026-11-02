#include <stdlib.h>
#include <string.h>

#include "qrcode/qrcode.h"
#include "qrcode/qrcodegen.h"
#include "unity.h"
#include "vectors/vectors_qrcode.h"

#define QR_SCRATCH_SIZE qrcodegen_BUFFER_LEN_FOR_VERSION(qrcodegen_VERSION_MAX)
#define QR_FRAME_SIZE (QUIRC_WIDTH * QUIRC_HEIGHT)

/* quirc numbers the ECC levels by decoding order, qrcodegen by protection strength. */
static const enum qrcodegen_Ecc ECC_QUIRC_TO_QRCODEGEN[] = {
    [QUIRC_ECC_LEVEL_M] = qrcodegen_Ecc_MEDIUM,
    [QUIRC_ECC_LEVEL_L] = qrcodegen_Ecc_LOW,
    [QUIRC_ECC_LEVEL_H] = qrcodegen_Ecc_HIGH,
    [QUIRC_ECC_LEVEL_Q] = qrcodegen_Ecc_QUARTILE,
};

static struct quirc qr;
static quirc_pixel_t frame[QR_FRAME_SIZE];

void setUp(void) {
  memset(&qr, 0, sizeof(qr));
  memset(frame, 0xff, sizeof(frame));
}

void tearDown(void) {}

static int dark_module(const qr_vector_t* vector, int x, int y) {
  const int i = (y * vector->size) + x;

  return (vector->matrix[i >> 3] >> (i & 7)) & 1;
}

static void test_decode_vectors(void) {
  for (size_t i = 0; i < sizeof(QR_VECTORS) / sizeof(QR_VECTORS[0]); i++) {
    const qr_vector_t* vector = &QR_VECTORS[i];
    struct quirc_code code;
    struct quirc_data data;

    memset(&code, 0, sizeof(code));
    code.size = vector->size;
    memcpy(code.cell_bitmap, vector->matrix, (((size_t)vector->size * vector->size) + 7) / 8);

    TEST_ASSERT_EQUAL_INT_MESSAGE(QUIRC_SUCCESS, quirc_decode(&code, &data), vector->payload);

    TEST_ASSERT_EQUAL_INT(vector->version, data.version);
    TEST_ASSERT_EQUAL_INT(vector->ecc, data.ecc_level);
    TEST_ASSERT_EQUAL_INT(vector->mask, data.mask);
    TEST_ASSERT_EQUAL_INT(vector->data_type, data.data_type);
    TEST_ASSERT_EQUAL_INT(vector->payload_len, data.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(vector->payload, data.payload, vector->payload_len);
  }
}

static void test_encoder_reproduces_reference_matrix(void) {
  static uint8_t tmp[QR_SCRATCH_SIZE];
  static uint8_t qrcode[QR_SCRATCH_SIZE];
  static uint8_t segment_buf[qrcodegen_BUFFER_LEN_MAX];

  for (size_t i = 0; i < sizeof(QR_VECTORS) / sizeof(QR_VECTORS[0]); i++) {
    const qr_vector_t* vector = &QR_VECTORS[i];
    struct qrcodegen_Segment segment;
    int mismatch = -1;

    /* Where the reference picked the segmentation itself, a competing encoder may split the
     * payload differently, so the symbols are not comparable module for module. */
    if (!vector->single_segment) {
      continue;
    }

    switch (vector->data_type) {
      case QUIRC_DATA_TYPE_NUMERIC:
        TEST_ASSERT_TRUE(qrcodegen_calcSegmentBufferSize(qrcodegen_Mode_NUMERIC, vector->payload_len) <= sizeof(segment_buf));
        segment = qrcodegen_makeNumeric(vector->payload, segment_buf);
        break;

      case QUIRC_DATA_TYPE_ALPHA:
        TEST_ASSERT_TRUE(qrcodegen_calcSegmentBufferSize(qrcodegen_Mode_ALPHANUMERIC, vector->payload_len) <= sizeof(segment_buf));
        segment = qrcodegen_makeAlphanumeric(vector->payload, segment_buf);
        break;

      case QUIRC_DATA_TYPE_BYTE:
        TEST_ASSERT_TRUE(qrcodegen_calcSegmentBufferSize(qrcodegen_Mode_BYTE, vector->payload_len) <= sizeof(segment_buf));
        segment = qrcodegen_makeBytes((const uint8_t*)vector->payload, vector->payload_len, segment_buf);
        break;

      default:
        TEST_FAIL_MESSAGE("no encoder mode for the vector's data type");
        return;
    }

    TEST_ASSERT_TRUE(qrcodegen_encodeSegmentsAdvanced(
        &segment, 1, ECC_QUIRC_TO_QRCODEGEN[vector->ecc], vector->version, vector->version,
        (enum qrcodegen_Mask)vector->mask, false, tmp, qrcode
    ));

    TEST_ASSERT_EQUAL_INT(vector->size, qrcodegen_getSize(qrcode));

    for (int y = 0; (y < vector->size) && (mismatch < 0); y++) {
      for (int x = 0; x < vector->size; x++) {
        if (qrcodegen_getModule(qrcode, x, y) != dark_module(vector, x, y)) {
          mismatch = (y * vector->size) + x;
          break;
        }
      }
    }

    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, mismatch, vector->payload);
  }
}

/* qrcodegen writes a module grid; the scanner reads a frame. Drawing one into the other is what
 * puts the detector, and not just the decoder, under test. */
static void draw(const uint8_t* qrcode, int size, int scale, int x0, int y0, int shear) {
  const int center = y0 + ((size * scale) / 2);

  for (int y = 0; y < size; y++) {
    for (int x = 0; x < size; x++) {
      if (!qrcodegen_getModule(qrcode, x, y)) {
        continue;
      }

      for (int dy = 0; dy < scale; dy++) {
        /* A horizontal shift growing away from the middle row, which leaves the modules
         * parallelograms rather than squares and exercises the perspective correction. */
        const int shift = ((y0 + (y * scale)) - center) * shear / 100;

        for (int dx = 0; dx < scale; dx++) {
          const int px = x0 + (x * scale) + dx + shift;
          const int py = y0 + (y * scale) + dy;

          if ((px >= 0) && (px < QUIRC_WIDTH) && (py >= 0) && (py < QUIRC_HEIGHT)) {
            frame[(py * QUIRC_WIDTH) + px] = QUIRC_PIXEL_BLACK;
          }
        }
      }
    }
  }
}

static void scan_once(struct quirc* q, struct quirc_data* data) {
  struct quirc_code code;

  quirc_set_image(q, frame);
  quirc_begin(q, NULL, NULL);
  quirc_threshold(q);
  quirc_end(q);

  TEST_ASSERT_EQUAL_INT(1, quirc_count(q));

  quirc_extract(q, 0, &code);
  TEST_ASSERT_EQUAL_INT_MESSAGE(QUIRC_SUCCESS, quirc_decode(&code, data), (const char*)data->payload);
}

static void encode_to(const char* text, uint8_t* tmp, uint8_t* qrcode) {
  TEST_ASSERT_TRUE(qrcodegen_encodeText(text, tmp, qrcode, qrcodegen_Ecc_MEDIUM, qrcodegen_VERSION_MIN, 10, qrcodegen_Mask_AUTO, true));
}

static void test_scan_finds_a_symbol(void) {
  uint8_t tmp[QR_SCRATCH_SIZE];
  uint8_t qrcode[QR_SCRATCH_SIZE];
  struct quirc_data data;
  const char* text = "ur:bytes/hello-world-1234567890";

  encode_to(text, tmp, qrcode);

  const int size = qrcodegen_getSize(qrcode);
  const int scale = 8;
  const int x0 = (QUIRC_WIDTH - (size * scale)) / 2;
  const int y0 = (QUIRC_HEIGHT - (size * scale)) / 2;

  draw(qrcode, size, scale, x0, y0, 0);
  scan_once(&qr, &data);

  TEST_ASSERT_EQUAL_INT((int)strlen(text), data.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(text, data.payload, strlen(text));
}

static void test_scan_finds_a_sheared_symbol(void) {
  uint8_t tmp[QR_SCRATCH_SIZE];
  uint8_t qrcode[QR_SCRATCH_SIZE];
  struct quirc_data data;
  const char* text = "ur:bytes/sheared";

  encode_to(text, tmp, qrcode);

  const int size = qrcodegen_getSize(qrcode);
  const int scale = 8;
  const int x0 = (QUIRC_WIDTH - (size * scale)) / 2;
  const int y0 = (QUIRC_HEIGHT - (size * scale)) / 2;

  draw(qrcode, size, scale, x0, y0, 12);
  scan_once(&qr, &data);

  TEST_ASSERT_EQUAL_INT((int)strlen(text), data.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(text, data.payload, strlen(text));
}

/* The binarisation was restructured so that the two running averages each get a pass of their
 * own: the first stores instead of accumulating into a zeroed row, the second finishes the
 * average and classifies in place. Which pixels see which average is unchanged, so the output
 * must be identical, pixel for pixel, including the luma sum the caller feeds the exposure
 * control. This is the original single pass, kept as the oracle. */
/* The adaptive threshold, verbatim from the revision the binarisation was restructured away
 * from, so that the restructured pass is pinned to the behaviour it has to preserve. */
#define THRESHOLD_S_DEN 8
#define THRESHOLD_T     5
#define THRESHOLD_S (QUIRC_WIDTH / THRESHOLD_S_DEN)
#define FRACMUL ((32768 * (THRESHOLD_S - 1)) / THRESHOLD_S)
#define FRACMUL2 ((0x100000 * (100 - THRESHOLD_T)) / (200 * THRESHOLD_S))

static uint32_t threshold_original(struct quirc *q)
{
    int x, y;
    int avg_w = 0;
    int avg_u = 0;
    uint32_t total_luma = 0;
    quirc_pixel_t *row = q->pixels;

    for (y = 0; y < QUIRC_HEIGHT; y++) {
        int row_average[QUIRC_WIDTH];

        memset(row_average, 0, QUIRC_WIDTH * 4);

        for (x = 0; x < QUIRC_WIDTH; x++) {
            int w, u;

            if (y & 1) {
                w = x;
                u = QUIRC_WIDTH - 1 - x;
            } else {
                w = QUIRC_WIDTH - 1 - x;
                u = x;
            }

//            avg_w = (avg_w * (threshold_s - 1)) / threshold_s + row[w];
//            avg_u = (avg_u * (threshold_s - 1)) / threshold_s + row[u];
            // The original mul/div operation sought to reduce the average value by a small fraction (e.g. 1/79)
            // This mul/shift approximation achieves the same goal with only a small percentage difference
            avg_w = ((avg_w * FRACMUL) >> 15) + row[w];
            avg_u = ((avg_u * FRACMUL) >> 15) + row[u];

            row_average[w] += avg_w;
            row_average[u] += avg_u;
        }

        for (x = 0; x < QUIRC_WIDTH; x++) {
            total_luma += row[x];
            //            if (row[x] < row_average[x] * (100 - THRESHOLD_T) / (200 * threshold_s))
            if (row[x] < ((row_average[x] * FRACMUL2) >> 20))
                row[x] = QUIRC_PIXEL_BLACK;
            else
                row[x] = QUIRC_PIXEL_WHITE;
        }

        row += QUIRC_WIDTH;
    }

    return total_luma;
} /* threshold() */
static void fill_frame(unsigned* state, int structured) {
  for (uint32_t i = 0; i < QR_FRAME_SIZE; i++) {
    if (structured) {
      /* A bright frame carrying blobs of several depths and edges, which is the shape a code in
       * the field presents, with pixel values straddling the eight-level band the region test
       * keys on. */
      const int x = (int)(i % QUIRC_WIDTH);
      const int y = (int)(i / QUIRC_WIDTH);
      const int blob = (((x / 37) + (y / 23)) & 3) == 0;
      const int edge = ((x % 37) < 3) || ((y % 23) < 3);

      if (blob && edge) {
        frame[i] = (quirc_pixel_t)(120 + (i % 9));
      } else if (blob) {
        frame[i] = (quirc_pixel_t)(30 + (i % 7));
      } else {
        frame[i] = (quirc_pixel_t)(200 + (i % 30));
      }
    } else {
      *state = (*state * 1103515245u) + 12345u;
      frame[i] = (quirc_pixel_t)((*state >> 16) & 0xff);
    }
  }
}

static void test_threshold_restructuring_is_exact(void) {
  static quirc_pixel_t want[QR_FRAME_SIZE];
  unsigned state = 20260215u;

  quirc_set_image(&qr, frame);

  for (int round = 0; round < 4; round++) {
    quirc_pixel_t source[QR_FRAME_SIZE];

    fill_frame(&state, round & 1);
    memcpy(source, frame, sizeof(source));

    const uint32_t want_threshold = threshold_original(&qr);
    memcpy(want, frame, sizeof(want));

    memcpy(frame, source, sizeof(source));
    TEST_ASSERT_EQUAL_UINT32(want_threshold, quirc_threshold(&qr));
    TEST_ASSERT_EQUAL_MEMORY(want, frame, sizeof(want));
  }
}

static void test_decode_refuses_bad_grid_sizes(void) {
  struct quirc_code code;
  struct quirc_data data;

  memset(&code, 0, sizeof(code));

  /* (size - 17) % 4 must hold, and 17 <= size for version 1. */
  code.size = 20;
  TEST_ASSERT_EQUAL_INT(QUIRC_ERROR_INVALID_GRID_SIZE, quirc_decode(&code, &data));

  code.size = 21 + 4 * QUIRC_MAX_VERSION;
  TEST_ASSERT_EQUAL_INT(QUIRC_ERROR_INVALID_VERSION, quirc_decode(&code, &data));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_decode_vectors);
  RUN_TEST(test_encoder_reproduces_reference_matrix);
  RUN_TEST(test_scan_finds_a_symbol);
  RUN_TEST(test_scan_finds_a_sheared_symbol);
  RUN_TEST(test_threshold_restructuring_is_exact);
  RUN_TEST(test_decode_refuses_bad_grid_sizes);
  return UNITY_END();
}
