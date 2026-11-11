#ifndef FREERTOS_H
#define FREERTOS_H

/* The host build has no kernel. What the ISO 7816 modules ask of it is one blocking wait for the
 * peripheral's completion notification, so this is the whole surface they use; the wait itself is
 * scripted in sc_host.c. A tick is one millisecond here and in pdMS_TO_TICKS, which is what the
 * firmware's own configuration would give at 1 kHz. */

#include <stdint.h>

typedef int32_t BaseType_t;
typedef uint32_t TickType_t;

#define pdPASS ((BaseType_t)1)
#define pdFAIL ((BaseType_t)0)

#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))

#endif
