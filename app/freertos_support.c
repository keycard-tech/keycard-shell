#include "FreeRTOS.h"
#include "task.h"
#include "common.h"
#include "hal.h"

void vApplicationTickHook(void) {
  hal_tick();
}

void vApplicationGetIdleTaskMemory(StaticTask_t **ppxIdleTaskTCBBuffer, StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize) {
  static StaticTask_t xIdleTaskTCBBuffer;
  static StackType_t xIdleStack[configMINIMAL_STACK_SIZE];
  *ppxIdleTaskTCBBuffer = &xIdleTaskTCBBuffer;
  *ppxIdleTaskStackBuffer = xIdleStack;
  *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}

#if (configUSE_TIMERS == 1)
void vApplicationGetTimerTaskMemory(StaticTask_t **ppxTimerTaskTCBBuffer, StackType_t **ppxTimerTaskStackBuffer, uint32_t *pulTimerTaskStackSize) {
  static StaticTask_t xTimerTaskTCB;
  static StackType_t uxTimerTaskStack[configTIMER_TASK_STACK_DEPTH];
  *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;
  *ppxTimerTaskStackBuffer = uxTimerTaskStack;
  *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
#endif

#if defined(__REDLIB__)
void __assertion_failed(char *failedExpr)
{
    for (;;)
    {
        OMG_BREAK();
    }
}
#else
void __assert_func(const char *file, int line, const char *func, const char *failedExpr)
{
    for (;;)
    {
      OMG_BREAK();
    }
}
#endif
