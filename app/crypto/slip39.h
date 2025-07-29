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

#define SLIP39_NOEXT 0
#define SLIP39_EXT 16

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
} slip39_shard;

typedef struct group_struct {
  uint8_t group_index;
  uint8_t member_threshold;
  uint8_t count;
  uint8_t member_index[16];
  const uint8_t *value[16];
} slip39_group;

typedef struct group_descriptor_struct {
  uint8_t threshold;
  uint8_t count;
} group_descriptor;

int slip39_encode_mnemonic(const slip39_shard *shard, uint16_t *destination, uint32_t destination_length);
int slip39_decode_mnemonic(const uint16_t *mnemonic, uint32_t mnemonic_length, slip39_shard *shard);

int slip39_generate(uint8_t group_threshold, const group_descriptor *groups, uint8_t groups_length, const uint8_t *master_secret, uint32_t master_secret_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint32_t *mnemonic_length, uint16_t *mnemonics, uint32_t buffer_size);
int slip39_combine(const uint16_t **mnemonics, uint32_t mnemonics_words, uint32_t mnemonics_shards, const char *passphrase, uint8_t *buffer, uint32_t buffer_length);

#endif
