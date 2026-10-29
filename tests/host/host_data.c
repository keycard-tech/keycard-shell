#include <stdint.h>
#include "mem.h"

/*
 * Data that lives in app/mem.c on the target, which cannot be compiled off-target: it places
 * objects in linker-script sections (%nobits@) the host assembler rejects. The host build only
 * needs the constant, whose value is fully determined by its declaration in mem.h.
 */
const uint8_t ZERO32[32] __attribute__((aligned(4))) = {0};
