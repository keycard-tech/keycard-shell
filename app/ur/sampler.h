#ifndef _RANDOM_SAMPLER_
#define _RANDOM_SAMPLER_
#include "crypto/xoshiro256.h"
#include "ur.h"

void random_sampler_init(int len, double* out_probs, int* out_aliases);
int random_sampler_next(xoshiro_ctx_t* rng_ctx, int len, double* probs, int* aliases);

ur_desc_t fountain_part_indexes(uint32_t seq, uint32_t crc, int len, double* probs, int* aliases);

#endif
