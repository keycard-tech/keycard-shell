#ifndef __SLIP39_H__
#define __SLIP39_H__

#define SLIP39_WORDS_COUNT 1024

extern const char* const SLIP39_WORDLIST[SLIP39_WORDS_COUNT];

#include <stdint.h>
#include <stdlib.h>

#define ERROR_NOT_ENOUGH_MNEMONIC_WORDS        (-1)
#define ERROR_INVALID_MNEMONIC_CHECKSUM        (-2)
#define ERROR_SECRET_TOO_SHORT                 (-3)
#define ERROR_INVALID_GROUP_THRESHOLD          (-4)
#define ERROR_INVALID_SINGLETON_MEMBER         (-5)
#define ERROR_INSUFFICIENT_SPACE               (-6)
#define ERROR_INVALID_SECRET_LENGTH            (-7)
#define ERROR_INVALID_PASSPHRASE               (-8)
#define ERROR_INVALID_SHARD_SET                (-9)
#define ERROR_EMPTY_MNEMONIC_SET              (-10)
#define ERROR_DUPLICATE_MEMBER_INDEX          (-11)
#define ERROR_NOT_ENOUGH_MEMBER_SHARDS        (-12)
#define ERROR_INVALID_MEMBER_THRESHOLD        (-13)
#define ERROR_INVALID_PADDING                 (-14)
#define ERROR_NOT_ENOUGH_GROUPS               (-15)
#define ERROR_INVALID_SHARD_BUFFER            (-16)
#define ERROR_WRONG_GROUP             (-17)

#define SLIP39_NOEXT 0
#define SLIP39_EXT 16
#define SLIP39_ITERATION_DEF 1

#define SLIP39_RADIX_BITS 10
#define SLIP39_METADATA_LENGTH_WORDS 7

typedef struct {
  uint16_t identifier;
  uint8_t extendable;
  uint8_t iteration_exponent;
  uint8_t group_index;
  uint8_t group_threshold;
  uint8_t group_count;
  uint8_t member_index;
  uint8_t member_threshold;
  uint8_t value_length;
  uint8_t value[32];
} slip39_shard_t;

typedef struct group_descriptor_struct {
  uint8_t threshold;
  uint8_t count;
} slip39_group_desc_t;

typedef struct {
  uint8_t group_index;
  uint8_t group_threshold;
  uint8_t value_length;
  uint8_t value[32];
} slip39_group_t;

static inline size_t slip39_word_count_for_bytes(size_t bytes) {
  return (bytes * 8 + SLIP39_RADIX_BITS - 1) / SLIP39_RADIX_BITS;
}

static inline size_t slip39_byte_count_for_words(size_t words) {
  return (words * SLIP39_RADIX_BITS) / 8;
}

static inline size_t slip39_mnemonic_length(size_t secret_len) {
  return SLIP39_METADATA_LENGTH_WORDS + slip39_word_count_for_bytes(secret_len);
}

void slip39_encrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output);
void slip39_decrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output);

int slip39_encode_mnemonic(const slip39_shard_t* shard, uint16_t* destination, uint32_t destination_length);
int slip39_decode_mnemonic(const uint16_t* mnemonic, uint32_t mnemonic_length, slip39_shard_t* shard);

int slip39_count_shards(uint8_t group_threshold, const slip39_group_desc_t *groups, uint8_t groups_length);

int slip39_validate_shard_in_set(const slip39_shard_t* shard, const slip39_shard_t shards[], uint8_t shard_count);
int slip39_validate_shard_in_group(const slip39_shard_t* shard, const slip39_shard_t shards[], uint8_t shard_count);

int slip39_generate(uint8_t threshold, const uint8_t* ms, uint32_t ms_len, uint8_t* ems, slip39_shard_t shards[], uint8_t shard_count);

int slip39_combine_shards(const slip39_shard_t shards[], uint8_t shard_count, slip39_group_t* group);
int slip39_comebine_groups(slip39_group_t groups[], uint8_t group_count, uint8_t* secret, int secret_len);

int slip39_combine(const slip39_shard_t shards[], uint8_t shard_count, const char* passphrase, uint8_t* secret, int secret_len);

#endif
