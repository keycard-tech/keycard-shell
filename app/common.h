/*
 * This file is part of the OpenMV project.
 *
 * Copyright (c) 2013-2021 Ibrahim Abdelkader <iabdalkader@openmv.io>
 * Copyright (c) 2013-2021 Kwabena W. Agyeman <kwagyeman@openmv.io>
 *
 * This work is licensed under the MIT license, see the file LICENSE for details.
 *
 * Common macros.
 */
#ifndef __APP_COMMON_H__
#define __APP_COMMON_H__

#include <stdint.h>
#include <stddef.h>
#include "hal.h"

typedef struct {
  uint8_t* data;
  size_t len;
} data_t;

extern const uint8_t FW_SIGNATURE[64];
extern const uint8_t FW_VERSION[4];

#define APP_ALIGNED(x, a) x __attribute__((aligned(a)))
#define APP_SECTION(x, s) x __attribute__((section(s)))
#define APP_ALWAYS_INLINE inline __attribute__((always_inline))
#define APP_WEAK __attribute__((weak))

#ifdef TEST_APP
#define TEST_APP_ACCESSIBLE
#else
#define TEST_APP_ACCESSIBLE static
#endif

#define OMG_BREAK() __asm__ volatile ("BKPT")

#define APP_MAX(a,b)                    \
({                                      \
    __typeof__ (a) _a = (a);            \
    __typeof__ (b) _b = (b);            \
    _a > _b ? _a : _b;                  \
})

#define APP_MIN(a,b)                    \
({                                      \
    __typeof__ (a) _a = (a);            \
    __typeof__ (b) _b = (b);            \
    _a < _b ? _a : _b;                  \
})

#define APP_TASK(__NAME__) __NAME__##_task

#define _APP_DEF_TASK(__NAME__, __STACK_SIZE__) \
  void __NAME__##_task_entry(void* pvParameters); \
  static StaticTask_t __NAME__##_task_memory; \
  static StackType_t __NAME__##_task_stack[__STACK_SIZE__]

#define _APP_CREATE_TASK(__NAME__, __PRIO__) \
  xTaskCreateStatic(__NAME__##_task_entry, #__NAME__, (sizeof(__NAME__##_task_stack)/sizeof(uint32_t)), NULL, __PRIO__, __NAME__##_task_stack, &__NAME__##_task_memory)

#define APP_DEF_TASK(__NAME__, __STACK_SIZE__) \
  _APP_DEF_TASK(__NAME__, __STACK_SIZE__); \
  TaskHandle_t APP_TASK(__NAME__)

#define APP_CREATE_TASK(__NAME__, __PRIO__) \
  APP_TASK(__NAME__) = _APP_CREATE_TASK(__NAME__, __PRIO__)

#define APP_DEF_CREATE_TASK(__NAME__, __PRIO__, __STACK_SIZE__) \
  _APP_DEF_TASK(__NAME__, __STACK_SIZE__); \
  _APP_CREATE_TASK(__NAME__, __PRIO__)

#define APP_DEF_EXTERN_TASK(__NAME__) \
  extern TaskHandle_t APP_TASK(__NAME__)

static inline uint32_t rev32(uint32_t value) {
  __asm__ volatile (
      "REV %0, %0  \n"
      : "+r" (value)
      :
  );
  return value;
}

static inline uint32_t rev16(uint16_t value) {
  __asm__ volatile (
      "REV16 %0, %0  \n"
      : "+r" (value)
      :
  );
  return value;
}

static inline void rev32_all(uint32_t* out, uint32_t* in, size_t len) {
  len >>= 2;
  for (int i = 0; i < len; i++) {
    out[i] = rev32(in[i]);
  }
}

#endif //__APP_COMMON_H__
