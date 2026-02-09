//
//  Contains code from:
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "slip39.h"
#include "memzero.h"
#include "pbkdf2.h"
#include "shamir.h"
#include "rand.h"

#include <string.h>

#define FEISTEL_BASE_ITERATION_COUNT 2500
#define FEISTEL_ROUND_COUNT 4

#define CUSTOMIZATION_NON_EXTENDABLE_LEN 6
#define CUSTOMIZATION_EXTENDABLE_LEN 17

#define MIN_STRENGTH_BYTES 16
#define MIN_MNEMONIC_LENGTH_WORDS 20

static const uint32_t RS1024_GEN[] = {
    0x00E0E040,
    0x01C1C080,
    0x03838100,
    0x07070200,
    0x0E0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x03F3F120,
};

static const uint8_t SLIP39_CUSTOMIZATION[] = {
    's', 'h', 'a', 'm', 'i', 'r', '_', 'e', 'x', 't', 'e', 'n', 'd', 'a', 'b', 'l', 'e'
};

static uint32_t rs1024_polymod(uint8_t ext, const uint16_t *values, uint32_t values_length) {
  uint32_t chk = 1;

  uint8_t customization_len = ext ? CUSTOMIZATION_EXTENDABLE_LEN : CUSTOMIZATION_NON_EXTENDABLE_LEN;

  for (uint32_t i = 0; i < customization_len; ++i) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10 ) ^ SLIP39_CUSTOMIZATION[i];
    for (unsigned int j = 0; j < 10; ++j, b >>= 1) {
      chk ^= RS1024_GEN[j] * (b&1);
    }
  }

  for (uint32_t i = 0; i < values_length; ++i) {
    uint32_t b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10 ) ^ values[i];
    for (unsigned int j = 0; j < 10; ++j, b>>=1) {
      chk ^= RS1024_GEN[j] * (b&1);
    }
  }

  return chk;
}

static void rs1024_create_checksum(uint8_t ext, uint16_t *values, uint32_t n) {
  values[n-3] = 0;
  values[n-2] = 0;
  values[n-1] = 0;

  uint32_t polymod = rs1024_polymod(ext, values, n) ^ 1;

  values[n-3] = (polymod >> 20) & 1023;
  values[n-2] = (polymod >> 10) & 1023;
  values[n-1] = (polymod) & 1023;
}


static uint8_t rs1024_verify_checksum(uint8_t ext, const uint16_t *values, uint32_t n) {
  return rs1024_polymod(ext, values, n) == 1;
}

static int32_t _get_salt(uint16_t identifier, uint8_t *result, uint32_t result_length) {
  if(result_length < 8) {
    return -1;
  }

  for(unsigned int i=0; i < CUSTOMIZATION_NON_EXTENDABLE_LEN; ++i) {
    result[i] = SLIP39_CUSTOMIZATION[i];
  }

  result[6] = identifier >> 8;
  result[7] = identifier & 0xff;
  return 8;
}

static void round_function(uint8_t i, const char *passphrase, uint8_t exp, const uint8_t *salt, uint32_t salt_length, const uint8_t *r, uint32_t r_length, uint8_t *dest, uint32_t dest_length) {
  size_t pass_length = strlen(passphrase) + 1;
  uint8_t pass[pass_length];
  memcpy(&pass[1], passphrase, (pass_length - 1));
  pass[0] = i;

  uint32_t iterations = FEISTEL_BASE_ITERATION_COUNT << exp;
  uint8_t saltr[salt_length + r_length];

  memcpy(saltr, salt, salt_length);
  memcpy(saltr + salt_length, r, r_length);

  pbkdf2_hmac_sha256(pass, pass_length, saltr, salt_length + r_length, iterations, dest, dest_length);
}

static void feistel(uint8_t forward, const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  uint32_t half_length = input_length / 2;
  uint8_t *l, *r, *t, f[half_length];
  uint8_t salt[8];

  memcpy(output, input + half_length, half_length);
  memcpy(output + half_length, input, half_length);

  r = output;
  l = output+half_length;

  if (!ext) {
    _get_salt(identifier, salt, 8);
  }

  for (uint8_t i = 0; i < FEISTEL_ROUND_COUNT; ++i) {
    uint8_t index;

    if (forward) {
      index = i;
    } else {
      index = FEISTEL_ROUND_COUNT - 1 - i;
    }

    round_function(index, passphrase, iteration_exponent, salt, ext ? 0 : 8, r, half_length, f, half_length);

    t = l;
    l = r;
    r = t;

    for(uint32_t j = 0; j < half_length; ++j) {
      r[j] = r[j] ^ f[j];
    }
  }
}

void slip39_encrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  feistel(1, input, input_length, passphrase, ext, iteration_exponent, identifier, output);
}

void slip39_decrypt(const uint8_t *input, uint32_t input_length, const char *passphrase, uint8_t ext, uint8_t iteration_exponent, uint16_t identifier, uint8_t *output) {
  feistel(0, input, input_length, passphrase, ext, iteration_exponent, identifier, output);
}

static int32_t slip39_words_for_data(const uint8_t *buffer, uint32_t size, uint16_t *words, uint32_t max) {
  uint32_t byte = 0;
  uint32_t word = 0;

  uint8_t bits = (size % 5) * 2;

  uint16_t i = 0;

  if(max < slip39_word_count_for_bytes(size)) {
    return ERROR_INSUFFICIENT_SPACE;
  }

  while(byte < size && word < max) {
    while(bits < 10) {
      i =  i << 8;
      bits += 8;

      if(byte < size) {
        i = i | buffer[byte++];
      }
    }

    words[word++] = (i >> (bits-10));
    i = i & ((1<<(bits-10))-1);
    bits -= 10;
  }

  return word;
}

static int32_t slip39_data_for_words(const uint16_t *words, uint32_t wordsize, uint8_t *buffer, size_t size) {
  uint32_t word = 0;
  int16_t bits = -2 * (wordsize % 4);

  if (bits < 0 && (words[0] & (1023 << (10 + bits)))) {
    return ERROR_INVALID_PADDING;
  }

  uint8_t discard_top_zeros = (wordsize % 4 == 0) && (wordsize & 4);
  uint32_t byte = 0;
  uint16_t i = 0;

  if(size < slip39_byte_count_for_words(wordsize)) {
    return ERROR_INSUFFICIENT_SPACE;
  }

  while (word < wordsize && byte < size) {
    i = (i << 10) | words[word++];
    bits += 10;

    if(discard_top_zeros && (i & 1020)==0) {
      discard_top_zeros = 0;
      bits -= 8;
    }

    while(bits >= 8 && byte < size) {
      buffer[byte++] = (i >> (bits -8));
      i = i & ((1<<(bits-8))-1);
      bits -= 8;
    }
  }

  return byte;
}

int slip39_encode_mnemonic(const slip39_shard_t *shard, uint16_t *destination, uint32_t destination_length) {
  uint16_t gt = (shard->group_threshold -1) & 15;
  uint16_t gc = (shard->group_count -1) & 15;
  uint16_t mi = (shard->member_index) & 15;
  uint16_t mt = (shard->member_threshold -1) & 15;

  destination[0] = (shard->identifier >> 5) & 1023;
  destination[1] = ((shard->identifier << 5) | shard->extendable | shard->iteration_exponent) & 1023;
  destination[2] = ((shard->group_index << 6) | (gt << 2) | (gc >> 2)) & 1023;
  destination[3] = ((gc << 8) | (mi << 4) | (mt)) & 1023;

  uint32_t words = slip39_words_for_data(shard->value, shard->value_length, destination+4, destination_length - SLIP39_METADATA_LENGTH_WORDS);
  rs1024_create_checksum(shard->extendable, destination, words + SLIP39_METADATA_LENGTH_WORDS);

  return words + SLIP39_METADATA_LENGTH_WORDS;
}

int slip39_decode_mnemonic(const uint16_t *mnemonic, uint32_t mnemonic_length, slip39_shard_t *shard) {
  if (mnemonic_length < MIN_MNEMONIC_LENGTH_WORDS) {
    return ERROR_NOT_ENOUGH_MNEMONIC_WORDS;
  }

  uint8_t ext = mnemonic[1] & 16;

  if (!rs1024_verify_checksum(ext, mnemonic, mnemonic_length) ) {
    return ERROR_INVALID_MNEMONIC_CHECKSUM;
  }

  uint8_t group_threshold = ((mnemonic[2] >> 2) & 15) + 1;
  uint8_t group_count = (((mnemonic[2] & 3) << 2) | ((mnemonic[3] >> 8) & 3)) + 1;

  if(group_threshold > group_count) {
    return ERROR_INVALID_GROUP_THRESHOLD;
  }

  shard->identifier = (mnemonic[0] << 5) | (mnemonic[1] >> 5);
  shard->extendable = ext;
  shard->iteration_exponent = mnemonic[1] & 15;
  shard->group_index = mnemonic[2] >> 6;
  shard->group_threshold = group_threshold;
  shard->group_count = group_count;
  shard->member_index = (mnemonic[3] >> 4) & 15;
  shard->member_threshold = (mnemonic[3] & 15) + 1;

  int32_t result = slip39_data_for_words(mnemonic+4, mnemonic_length - 7, shard->value, 32);

  if (result < 0) {
    return result;
  }

  shard->value_length = result;

  if (shard->value_length < MIN_STRENGTH_BYTES) {
    return ERROR_SECRET_TOO_SHORT;
  }

  if (shard->value_length % 2) {
    return ERROR_INVALID_SECRET_LENGTH;
  }

  return shard->value_length;
}

int slip39_count_shards(uint8_t group_threshold, const slip39_group_desc_t *groups, uint8_t groups_length) {
  uint16_t total_shards = 0;

  if (group_threshold > groups_length) {
    return ERROR_INVALID_GROUP_THRESHOLD;
  }

  for (uint8_t i = 0; i < groups_length; ++i) {
    total_shards += groups[i].count;
    if (groups[i].threshold > groups[i].count) {
      return ERROR_INVALID_MEMBER_THRESHOLD;
    }

    if ((groups[i].threshold == 1) && (groups[i].count > 1)) {
      return ERROR_INVALID_SINGLETON_MEMBER;
    }
  }

  return total_shards;
}

static void slip39_init_shards(uint8_t ext, uint8_t iteration_exponent, slip39_shard_t shards[], uint32_t shard_count) {
  uint16_t identifier = 0;
  random_buffer((uint8_t *)(&identifier), 2);
  identifier = identifier & ((1 << 15) - 1);

  for (int i = 0; i < shard_count; i++) {
    shards[i].identifier = identifier;
    shards[i].extendable = ext;
    shards[i].iteration_exponent = iteration_exponent;
  }
}

static int generate_shards(uint8_t group_threshold, const slip39_group_desc_t *groups, uint8_t groups_len, const uint8_t *ems, uint32_t ems_len, slip39_shard_t shards[]) {
  uint8_t group_shares[ems_len * groups_len];
  shamir_split_secret(group_threshold, groups_len, ems, ems_len, group_shares);

  uint8_t *group_share = group_shares;

  unsigned int shard_count = 0;
  slip39_shard_t *shard = &shards[shard_count];

  for (uint8_t i = 0; i < groups_len; ++i, group_share += ems_len) {
    uint8_t member_shares[ems_len *groups[i].count];
    shamir_split_secret(groups[i].threshold, groups[i].count, group_share, ems_len, member_shares);

    uint8_t *value = member_shares;
    for (uint8_t j = 0; j < groups[i].count; ++j, value += ems_len) {
      shard = &shards[shard_count];

      shard->group_threshold = group_threshold;
      shard->group_count = groups_len;
      shard->value_length = ems_len;
      shard->group_index = i;
      shard->member_threshold = groups[i].threshold;
      shard->member_index = j;
      memset(shard->value, 0, 32);
      memcpy(shard->value, value, ems_len);

      shard_count++;
    }

    memzero(member_shares, sizeof(member_shares));
  }

  memzero(group_shares, sizeof(group_shares));

  return shard_count;
}

int slip39_generate(uint8_t threshold, const uint8_t* ms, uint32_t ms_len, uint8_t* ems, slip39_shard_t shards[], uint8_t shard_count) {
  if (shard_count == 0) {
    return ERROR_INVALID_SHARD_SET;
  }

  if (((threshold == 1) && (shard_count > 1)) || (threshold > shard_count)) {
    return ERROR_INVALID_MEMBER_THRESHOLD;
  }

  if ((ms_len < MIN_STRENGTH_BYTES)) {
    return ERROR_SECRET_TOO_SHORT;
  }

  slip39_init_shards(SLIP39_EXT, SLIP39_ITERATION_DEF, shards, shard_count);
  slip39_encrypt(ms, ms_len, "", SLIP39_EXT, SLIP39_ITERATION_DEF, shards[0].identifier, ems);
  slip39_group_desc_t group = { .count = shard_count, .threshold = threshold };
  return generate_shards(1, &group, 1, ems, ms_len, shards);
}

int slip39_validate_shard_in_set(const slip39_shard_t* shard, const slip39_shard_t shards[], uint8_t shard_count) {
  if (shard_count == 0) {
    return 0;
  }

  if (shard->identifier != shards[0].identifier ||
      shard->extendable !=  shards[0].extendable ||
      shard->iteration_exponent !=  shards[0].iteration_exponent ||
      shard->group_threshold !=  shards[0].group_threshold ||
      shard->group_count !=  shards[0].group_count ||
      shard->value_length !=  shards[0].value_length) {
    return ERROR_INVALID_SHARD_SET;
  }

  return 0;
}

int slip39_validate_shard_in_group(const slip39_shard_t* shard, const slip39_shard_t shards[], uint8_t shard_count) {
  int err = slip39_validate_shard_in_set(shard, shards, shard_count);

  if (err < 0) {
    return err;
  }

  if ((shard->group_index != shards[0].group_index) || (shard->member_threshold != shards[0].member_threshold)) {
    return ERROR_WRONG_GROUP;
  }

  for (int i = 0; i < shard_count; i++) {
    if (shard->member_index == shards[i].member_index) {
      return ERROR_DUPLICATE_MEMBER_INDEX;
    }
  }

  return 0;
}

int slip39_combine_shards(const slip39_shard_t shards[], uint8_t shard_count, slip39_group_t* group) {
  if ((shard_count == 0) || (shard_count < shards[0].member_threshold)) {
    return ERROR_NOT_ENOUGH_MEMBER_SHARDS;
  }

  uint8_t share_indexes[shard_count];
  const uint8_t* share_values[shard_count];

  for (int i = 0; i < shard_count; i++) {
    share_indexes[i] = shards[i].member_index;
    share_values[i] = shards[i].value;
  }

  group->group_index = shards[0].group_index;
  group->group_threshold = shards[0].group_threshold;
  group->value_length = shards[0].value_length;
  return shamir_recover_secret(shards[0].member_threshold, share_indexes, share_values, shards[0].value_length, group->value);
}

int slip39_combine_groups(slip39_group_t groups[], uint8_t group_count, uint8_t* secret, int secret_len) {
  if ((group_count == 0) || (group_count < groups[0].group_threshold)) {
    return ERROR_NOT_ENOUGH_GROUPS;
  }

  if (secret_len < groups[0].value_length) {
    return ERROR_INSUFFICIENT_SPACE;
  }

  uint8_t group_indexes[group_count];
  const uint8_t* group_values[group_count];

  for (int i = 0; i < group_count; i++) {
    group_indexes[i] = groups[i].group_index;
    group_values[i] = groups[i].value;
  }

  return shamir_recover_secret(groups[0].group_threshold, group_indexes, group_values, groups[0].value_length, secret);
}

int slip39_combine(const slip39_shard_t shards[], uint8_t shard_count, uint8_t* secret, int secret_len) {
  if ((shard_count == 0) || (shard_count < shards[0].member_threshold)) {
    return ERROR_NOT_ENOUGH_MEMBER_SHARDS;
  }

  if (shards[0].group_threshold != 1) {
    return ERROR_INVALID_GROUP_THRESHOLD;
  }

  if (shards[0].value_length > secret_len) {
    return ERROR_INSUFFICIENT_SPACE;
  }

  slip39_group_t group;
  int err = slip39_combine_shards(shards, shard_count, &group);

  if (err < 0) {
    return err;
  }

  memcpy(secret, group.value, group.value_length);

  int ret = group.value_length;
  memzero(&group, sizeof(slip39_group_t));

  return ret;
}
