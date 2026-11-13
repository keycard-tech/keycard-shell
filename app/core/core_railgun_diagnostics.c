#include "core_railgun_diagnostics.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "crypto/railgun_babyjubjub.h"
#include "crypto/railgun_poseidon_t6.h"
#include "hal.h"
#include "ui/ui.h"

static const uint8_t field[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
};

/* Full-width public BN254 Fr boundary vectors. */
static const uint8_t bn254_zero[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t bn254_one[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const uint8_t bn254_two[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};
static const uint8_t bn254_fr_minus_one[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00
};
static const uint8_t bn254_fr_minus_two[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff, 0xff, 0xff
};

static const struct {
  const char* label;
  const uint8_t* lhs;
  const uint8_t* rhs;
  const uint8_t* expected;
} bn254_boundary_vectors[] = {
    {"Fr-1 squared", bn254_fr_minus_one,
     bn254_fr_minus_one, bn254_one},
    {"Fr-1 times 2", bn254_fr_minus_one,
     bn254_two, bn254_fr_minus_two},
    {"Zero product", bn254_zero,
     bn254_fr_minus_one, bn254_zero},
};

static const uint8_t expected_poseidon[32] = {
    0x0d, 0xab, 0x94, 0x49, 0xe4, 0xa1, 0x39, 0x8a, 0x15, 0x22, 0x4c, 0x0b, 0x15, 0xa4, 0x9d, 0x59, 0x8b, 0x21, 0x74, 0xd3, 0x05, 0xa3, 0x16, 0xc9, 0x18, 0x12, 0x5f, 0x8f, 0xee, 0xb1, 0x23, 0xc0
};
static const uint8_t base_x[32] = {
    0x0b, 0xb7, 0x7a, 0x6a, 0xd6, 0x3e, 0x73, 0x9b, 0x4e, 0xac, 0xb2, 0xe0, 0x9d, 0x62, 0x77, 0xc1, 0x2a, 0xb8, 0xd8, 0x01, 0x05, 0x34, 0xe0, 0xb6, 0x28, 0x93, 0xf3, 0xf6, 0xbb, 0x95, 0x70, 0x51
};
static const uint8_t base_y[32] = {
    0x25, 0x79, 0x72, 0x03, 0xf7, 0xa0, 0xb2, 0x49, 0x25, 0x57, 0x2e, 0x1c, 0xd1, 0x6b, 0xf9, 0xed, 0xfc, 0xe0, 0x05, 0x1f, 0xb9, 0xe1, 0x33, 0x77, 0x4b, 0x3c, 0x25, 0x7a, 0x87, 0x2d, 0x7d, 0x8b
};
static const uint8_t double_x[32] = {
    0x16, 0x2d, 0x7e, 0x41, 0x79, 0x03, 0xfa, 0x1c, 0x82, 0xf2, 0xd2, 0x27, 0xe3, 0x5b, 0x84, 0x6b, 0x11, 0x33, 0xcf, 0xca, 0x4f, 0x55, 0x8b, 0x5f, 0xeb, 0x9f, 0xdc, 0xd5, 0xf8, 0x1d, 0xd9, 0x02
};
static const uint8_t double_y[32] = {
    0x01, 0x66, 0x6c, 0xaf, 0xbf, 0x0a, 0x30, 0xda, 0x8b, 0x9e, 0xbe, 0xaf, 0x84, 0x8a, 0x1d, 0xa0, 0x67, 0xa8, 0x92, 0x29, 0x6f, 0x10, 0x43, 0x18, 0x8e, 0x17, 0x05, 0x40, 0x2b, 0x6d, 0x68, 0x53
};

/* Public full-width reference vector from native RAILGUN tests. */
static const uint8_t full_width_scalar[32] = {
    0x0b, 0xa9, 0xf4, 0xde, 0x43, 0xd3, 0xc9, 0x12, 0x59, 0x0c, 0x6a, 0xb4, 0xf8, 0xe7, 0xf3, 0xc0, 0xc0, 0x22, 0x9e, 0x25, 0xc7, 0xdd, 0x05, 0x22, 0x03, 0xb9, 0x28, 0xfc, 0xdc, 0x87, 0xdf, 0xba
};
static const uint8_t full_width_x[32] = {
    0x23, 0x40, 0x56, 0xd9, 0x68, 0xba, 0xf1, 0x83, 0xfe, 0x8d, 0x23, 0x7d, 0x49, 0x6d, 0x1c, 0x04, 0x18, 0x82, 0x20, 0xcd, 0x33, 0xe8, 0xf8, 0xd1, 0x4d, 0xf9, 0xb8, 0x44, 0x79, 0x73, 0x6b, 0x20
};
static const uint8_t full_width_y[32] = {
    0x26, 0x24, 0x39, 0x3f, 0xad, 0x9b, 0x71, 0xc0, 0x4b, 0x3b, 0x14, 0xd8, 0xac, 0x45, 0x20, 0x2d, 0xbb, 0x4e, 0xaf, 0xf4, 0xc2, 0xd1, 0x35, 0x0c, 0x94, 0x53, 0xfc, 0x08, 0xd1, 0x86, 0x51, 0xfe
};

typedef struct {
  TickType_t started;
  TickType_t limit;
  bool expired;
} diagnostic_budget_t;

/* Soft deadline: checked between rounds or scalar bytes. */
static bool diagnostic_checkpoint(void* context) {
  diagnostic_budget_t* budget = context;

  if ((TickType_t)(xTaskGetTickCount() - budget->started)
      >= budget->limit) {
    budget->expired = true;
    return false;
  }

  return true;
}

static uint32_t elapsed_ms(TickType_t start) {
  TickType_t elapsed = xTaskGetTickCount() - start;
  return (uint32_t) elapsed * portTICK_PERIOD_MS;
}

static void append_text(
    char* out, size_t capacity, size_t* length, const char* text) {
  while (*text && *length + 1 < capacity) {
    out[(*length)++] = *text++;
  }

  out[*length] = '\0';
}

static void append_decimal(
    char* out, size_t capacity, size_t* length, uint32_t value) {
  char digits[10];
  size_t count = 0;

  do {
    digits[count++] = (char) ('0' + value % 10);
    value /= 10;
  } while (value != 0);

  while (count > 0 && *length + 1 < capacity) {
    out[(*length)++] = digits[--count];
  }

  out[*length] = '\0';
}

static void show_result(const char* name, bool passed, uint32_t ms) {
  char message[80] = {0};
  size_t length = 0;

  append_text(message, sizeof(message), &length, name);
  append_text(message, sizeof(message), &length,
              passed ? ": PASS (" : ": FAIL (");
  append_decimal(message, sizeof(message), &length, ms);
  append_text(message, sizeof(message), &length, " ms)");

  ui_info(passed ? ICON_INFO_SUCCESS : ICON_INFO_ERROR,
          LSTR(MENU_RAILGUN_DIAGNOSTICS), message, 0);
}

#ifndef RAILGUN_GIT_REV
#define RAILGUN_GIT_REV "unknown"
#endif

typedef enum {
  BENCH_NOT_RUN,
  BENCH_PASS,
  BENCH_FAIL,
  BENCH_TIMEOUT,
  BENCH_SKIPPED
} bench_status_t;

typedef struct {
  bench_status_t status;
  uint32_t time_ms;
} bench_result_t;

typedef struct {
  bench_result_t bn64;
  bench_result_t bnedge;
  bench_result_t poseidon;
  bench_result_t bj2;
  bench_result_t bj256;
} railgun_report_t;

static const char* benchmark_status(bench_status_t status) {
  switch (status) {
  case BENCH_PASS: return "pass";
  case BENCH_FAIL: return "fail";
  case BENCH_TIMEOUT: return "timeout";
  case BENCH_SKIPPED: return "skipped";
  default: return "not_run";
  }
}

static void append_benchmark_json(
    char* output, size_t capacity, size_t* length,
    const char* name, const bench_result_t* result) {
  append_text(output, capacity, length, "\"");
  append_text(output, capacity, length, name);
  append_text(output, capacity, length, "\":{\"s\":\"");
  append_text(output, capacity, length,
              benchmark_status(result->status));
  append_text(output, capacity, length, "\",\"ms\":");

  if (result->status == BENCH_NOT_RUN ||
      result->status == BENCH_SKIPPED) {
    append_text(output, capacity, length, "null");
  } else {
    append_decimal(output, capacity, length, result->time_ms);
  }

  append_text(output, capacity, length, "}");
}

static void finish_report(const railgun_report_t* report) {
  if (ui_prompt(LSTR(MENU_RAILGUN_DIAGNOSTICS),
                "Export benchmark results as QR?",
                UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    return;
  }

  /*
   * Fixed schema and fixed field names: bounded to <320 bytes.
   * No wallet material, secret scalar, or host connection.
   */
  char json[320] = {0};
  size_t length = 0;

  append_text(json, sizeof(json), &length,
              "{\"v\":1,\"rev\":\"");
  append_text(json, sizeof(json), &length, RAILGUN_GIT_REV);
  append_text(json, sizeof(json), &length, "\",");

  append_benchmark_json(
      json, sizeof(json), &length, "bn64", &report->bn64);
  append_text(json, sizeof(json), &length, ",");

  append_benchmark_json(
      json, sizeof(json), &length, "bnedge", &report->bnedge);
  append_text(json, sizeof(json), &length, ",");

  append_benchmark_json(
      json, sizeof(json), &length, "p6", &report->poseidon);
  append_text(json, sizeof(json), &length, ",");

  append_benchmark_json(
      json, sizeof(json), &length, "bj2", &report->bj2);
  append_text(json, sizeof(json), &length, ",");

  append_benchmark_json(
      json, sizeof(json), &length, "bj256", &report->bj256);

  append_text(json, sizeof(json), &length, "}");

  ui_display_msg_qr(
      LSTR(MENU_RAILGUN_DIAGNOSTICS),
      json, "Scan benchmark JSON");
}

void core_railgun_diagnostics_run(void) {
  railgun_report_t report = {0};
  uint8_t a[32] = {0};
  uint8_t b[32] = {0};
  uint8_t result[32] = {0};
  bool passed = true;

  a[31] = 7;
  b[31] = 11;

  TickType_t start = xTaskGetTickCount();

  for (unsigned i = 0; i < 64; ++i) {
    if (hal_bn_mul_mod(a, b, field, result) != HAL_SUCCESS) {
      passed = false;
      break;
    }

    for (unsigned j = 0; j < 31; ++j) {
      if (result[j] != 0) {
        passed = false;
      }
    }

    if (result[31] != 77) {
      passed = false;
    }

    if (!passed) {
      break;
    }
  }

  uint32_t ms = elapsed_ms(start);
  report.bn64.status = passed ? BENCH_PASS : BENCH_FAIL;
  report.bn64.time_ms = ms;
  show_result("BN254 PKA x64", passed, ms);

  if (!passed) {
    finish_report(&report);
    return;
  }

  /*
   * Correctness checks are timed separately from the existing
   * 64-operation PKA throughput benchmark.
   */
  start = xTaskGetTickCount();

  const char* failed_boundary = NULL;

  for (size_t i = 0;
       i < sizeof(bn254_boundary_vectors) /
           sizeof(bn254_boundary_vectors[0]); ++i) {
    if (hal_bn_mul_mod(
            bn254_boundary_vectors[i].lhs,
            bn254_boundary_vectors[i].rhs,
            field, result) != HAL_SUCCESS ||
        memcmp(result, bn254_boundary_vectors[i].expected, 32) != 0) {
      failed_boundary = bn254_boundary_vectors[i].label;
      break;
    }
  }

  ms = elapsed_ms(start);
  passed = failed_boundary == NULL;

  report.bnedge.status = passed ? BENCH_PASS : BENCH_FAIL;
  report.bnedge.time_ms = ms;

  show_result(
      passed ? "BN254 boundaries" : failed_boundary,
      passed, ms);

  if (!passed) {
    finish_report(&report);
    return;
  }

  uint8_t inputs[5][32] = {{0}};
  uint8_t hash[32];

  for (unsigned i = 0; i < 5; ++i) {
    inputs[i][31] = (uint8_t) (i + 1);
  }

  start = xTaskGetTickCount();
  diagnostic_budget_t poseidon_budget = {
      start, pdMS_TO_TICKS(120000), false
  };

  passed = railgun_poseidon_t6_hash_with_checkpoint(
      inputs, hash, diagnostic_checkpoint, &poseidon_budget)
      == HAL_SUCCESS &&
           memcmp(hash, expected_poseidon, 32) == 0;

  ms = elapsed_ms(start);
  report.poseidon.status = poseidon_budget.expired ? BENCH_TIMEOUT :
                           (passed ? BENCH_PASS : BENCH_FAIL);
  report.poseidon.time_ms = ms;
  show_result(
      poseidon_budget.expired ? "Poseidon timeout" : "Poseidon t6",
      passed, ms);

  if (!passed) {
    finish_report(&report);
    return;
  }

  uint8_t scalar[32] = {0};
  uint8_t out_x[32];
  uint8_t out_y[32];

  scalar[31] = 2;

  start = xTaskGetTickCount();
  diagnostic_budget_t small_budget = {
      start, pdMS_TO_TICKS(30000), false
  };

  passed = railgun_babyjubjub_public_mul_with_checkpoint(
      base_x, base_y, scalar, out_x, out_y,
      diagnostic_checkpoint, &small_budget) == HAL_SUCCESS;

  if (passed) {
    passed = memcmp(out_x, double_x, 32) == 0 &&
             memcmp(out_y, double_y, 32) == 0;
  }

  ms = elapsed_ms(start);
  report.bj2.status = small_budget.expired ? BENCH_TIMEOUT :
                      (passed ? BENCH_PASS : BENCH_FAIL);
  report.bj2.time_ms = ms;
  show_result(
      small_budget.expired ? "BabyJubjub timeout" : "BabyJubjub x2",
      passed, ms);

  if (!passed ||
      ui_prompt(LSTR(MENU_RAILGUN_DIAGNOSTICS),
                "Run full-width public test? May take minutes.",
                UI_INFO_CANCELLABLE) != CORE_EVT_UI_OK) {
    if (passed) {
      report.bj256.status = BENCH_SKIPPED;
    }
    finish_report(&report);
    return;
  }

  start = xTaskGetTickCount();
  diagnostic_budget_t full_budget = {
      start, pdMS_TO_TICKS(180000), false
  };

  passed = railgun_babyjubjub_public_mul_with_checkpoint(
      base_x, base_y, full_width_scalar,
      out_x, out_y, diagnostic_checkpoint,
      &full_budget) == HAL_SUCCESS;

  if (passed) {
    passed = memcmp(out_x, full_width_x, 32) == 0 &&
             memcmp(out_y, full_width_y, 32) == 0;
  }

  ms = elapsed_ms(start);
  report.bj256.status = full_budget.expired ? BENCH_TIMEOUT :
                        (passed ? BENCH_PASS : BENCH_FAIL);
  report.bj256.time_ms = ms;
  show_result(
      full_budget.expired ? "Full-width timeout" : "BabyJubjub full",
      passed, ms);
  finish_report(&report);
}
