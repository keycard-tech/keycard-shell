#include <string.h>

#include "common.h"
#include "crypto/util.h"
#include "eip712.h"

struct eip712_string {
  const char *str;
  size_t len;
};

struct eip712_field {
  struct eip712_string name;
  struct eip712_string type;
};

struct eip712_type {
  struct eip712_string name;
  int field_count;
  struct eip712_field* fields;
  uint8_t type_hash[SHA3_256_DIGEST_LENGTH];
};

/* The heap the document and its parse share. Alignment is to a pointer because that is all any of
 * the types placed here needs, and because this file is also compiled for a 64-bit host, where the
 * same structs need 8 and a hardcoded 3 would both truncate the pointer and leave it misaligned. */
#define ALIGN_HEAP(__HEAP__, __HEAP_SIZE__)                     \
  do {                                                          \
    uintptr_t bound = sizeof(void*) - 1;                        \
    __HEAP__ = (uint8_t*) ((((uintptr_t) __HEAP__) + bound) & ~bound); \
    __HEAP_SIZE__ &= ~(size_t) bound;                           \
  } while (0)

static app_err_t eip712_hash_struct(uint8_t out[32], uint8_t* heap, size_t heap_size, int type, const struct eip712_type types[], int types_count, int data, const eip712_ctx_t* ctx);
static size_t eip712_encode_token(const eip712_ctx_t* ctx, uint8_t* out, int token, int indent);

static inline bool eip712_token_eq_str(const eip712_ctx_t* ctx, int index, const struct eip712_string* name) {
  int len = ctx->tokens[index].end - ctx->tokens[index].start;
  return (len == name->len) && (memcmp(&ctx->json[ctx->tokens[index].start], name->str, len) == 0);
}

static inline int eip712_token_eq(const eip712_ctx_t* ctx, int index, const char* key) {
  int len = ctx->tokens[index].end - ctx->tokens[index].start;
  size_t key_len = strlen(key);
  if (len != key_len) {
    return 0;
  }
  return memcmp(&ctx->json[ctx->tokens[index].start], key, len) == 0;
}

static inline int eip712_type_named(const struct eip712_string* type, const char* name) {
  size_t len = strlen(name);
  return (type->len == len) && (memcmp(type->str, name, len) == 0);
}

static int eip712_next_child(const eip712_ctx_t* ctx, int parent, int child) {
  int next = ((child == -1) ? parent : child) + 1;

  while ((next < ctx->token_count) && (ctx->tokens[next].parent > parent)) {
    next++;
  }

  return ((next < ctx->token_count) && (ctx->tokens[next].parent == parent)) ? next : -1;
}

/* The value a key holds, which is the token right after it. */
static inline int eip712_member_value(int key) {
  return key + 1;
}

/* A document's four members, wherever they appear in it, each holding what its name promises: a
 * "types" that is not an object is not a table of types. */
static app_err_t eip712_top_level(eip712_ctx_t* ctx) {
  int found = 0;

  for (int key = eip712_next_child(ctx, 0, -1); key != -1; key = eip712_next_child(ctx, 0, key)) {
    int value = eip712_member_value(key);

    if (eip712_token_eq(ctx, key, "types") && (ctx->tokens[value].type == JSMN_OBJECT)) {
      ctx->index.types = value;
      found |= 1;
    } else if (eip712_token_eq(ctx, key, "primaryType") && (ctx->tokens[value].type == JSMN_STRING)) {
      ctx->index.primary_type = value;
      found |= 2;
    } else if (eip712_token_eq(ctx, key, "domain") && (ctx->tokens[value].type == JSMN_OBJECT)) {
      ctx->index.domain = value;
      found |= 4;
    } else if (eip712_token_eq(ctx, key, "message") && (ctx->tokens[value].type == JSMN_OBJECT)) {
      ctx->index.message = value;
      found |= 8;
    }
  }

  return found == 0xf ? ERR_OK : ERR_DATA;
}

static inline void eip712_string_from_field(struct eip712_string* str, int index, const eip712_ctx_t* ctx) {
  str->str = &ctx->json[ctx->tokens[index].start];
  str->len = ctx->tokens[index].end - ctx->tokens[index].start;
}

static int eip712_parse_types(uint8_t* heap, size_t heap_size, int types_object, struct eip712_type types[], int types_count, const eip712_ctx_t* ctx) {
  int fields_size = 0;
  int current_type = 0;

  for (int key = eip712_next_child(ctx, types_object, -1); key != -1; key = eip712_next_child(ctx, types_object, key)) {
    int fields_token = eip712_member_value(key);

    if ((current_type == types_count) || (ctx->tokens[fields_token].type != JSMN_ARRAY)) {
      return -1;
    }

    eip712_string_from_field(&types[current_type].name, key, ctx);
    types[current_type].field_count = ctx->tokens[fields_token].size;

    size_t field_size = types[current_type].field_count * sizeof(struct eip712_field);
    fields_size += field_size;

    ALIGN_HEAP(heap, heap_size);

    if (field_size > heap_size) {
      return -1;
    }

    types[current_type].fields = (struct eip712_field*) heap;
    heap += field_size;
    heap_size -= field_size;

    int declared = 0;

    for (int element = eip712_next_child(ctx, fields_token, -1); element != -1; element = eip712_next_child(ctx, fields_token, element)) {
      if ((declared == types[current_type].field_count) || (ctx->tokens[element].type != JSMN_OBJECT)) {
        return -1;
      }

      struct eip712_field* field = &types[current_type].fields[declared++];
      field->name.str = NULL;
      field->type.str = NULL;

      for (int member = eip712_next_child(ctx, element, -1); member != -1; member = eip712_next_child(ctx, element, member)) {
        int value = eip712_member_value(member);

        if (ctx->tokens[value].type != JSMN_STRING) {
          continue;
        }

        if (eip712_token_eq(ctx, member, "name")) {
          eip712_string_from_field(&field->name, value, ctx);
        } else if (eip712_token_eq(ctx, member, "type")) {
          eip712_string_from_field(&field->type, value, ctx);
        }
      }

      if ((field->name.str == NULL) || (field->type.str == NULL)) {
        return -1;
      }
    }

    if (declared != types[current_type].field_count) {
      return -1;
    }

    current_type++;
  }

  return (current_type == types_count) ? fields_size : -1;
}

static inline int eip712_strcmp(const struct eip712_string* a, const struct eip712_string* b) {
  int res = memcmp(a->str, b->str, APP_MIN(a->len, b->len));
  return res != 0 ? res : a->len - b->len;
}

static inline int eip712_streq(const struct eip712_string* a, const struct eip712_string* b) {
  if (a->len == b->len) {
    return memcmp(a->str, b->str, a->len) == 0;
  }

  return 0;
}

static inline int eip712_is_array(const struct eip712_string* type) {
  return (type->len > 0) && (type->str[type->len - 1] == ']');
}

static inline int eip712_is_fixed_bytes(const struct eip712_string* type) {
  return (type->len > 5) && (strncmp(type->str, "bytes", 5) == 0) && !eip712_is_array(type);
}

static int eip712_bits_of(const struct eip712_string* type, size_t prefix, unsigned* bits) {
  if ((type->len == prefix)) {
    *bits = 256;
    return 1;
  }

  unsigned value = 0;

  for (size_t i = prefix; i < type->len; i++) {
    if ((type->str[i] < '0') || (type->str[i] > '9')) {
      return 0;
    }

    value = (value * 10) + (unsigned) (type->str[i] - '0');

    if (value > 256) {
      return 0;
    }
  }

  if ((value < 8) || ((value & 7) != 0)) {
    return 0;
  }

  *bits = value;
  return 1;
}

static int eip712_is_signed_type(const struct eip712_string* type, unsigned* bits) {
  return (type->len >= 3) && (strncmp(type->str, "int", 3) == 0) && !eip712_is_array(type)
    && eip712_bits_of(type, 3, bits);
}

static int eip712_is_unsigned_type(const struct eip712_string* type, unsigned* bits) {
  return (type->len >= 4) && (strncmp(type->str, "uint", 4) == 0) && !eip712_is_array(type)
    && eip712_bits_of(type, 4, bits);
}

static int eip712_fits_bits(const uint8_t mag[32], unsigned bits, bool negative) {
  const bool signed_256_floor = (bits == 256) && negative;
  const unsigned shift = signed_256_floor ? 255 : bits;

  if (shift >= 256) {
    return 1;
  }

  uint8_t limit[32];
  memset(limit, 0, sizeof(limit));
  limit[31 - (shift / 8)] = (uint8_t) (1 << (shift % 8));

  const int compare = compare_256(mag, limit);
  return (compare < 0) || ((compare == 0) && signed_256_floor);
}

static inline int eip712_is_hex_digit(char c) {
  return (((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')));
}

static int eip712_is_hex_string(const struct eip712_string* str) {
  if ((str->len < 3) || (str->str[0] != '0') || ((str->str[1] != 'x') && (str->str[1] != 'X'))) {
    return 0;
  }

  for (size_t i = 2; i < str->len; i++) {
    if (!eip712_is_hex_digit(str->str[i])) {
      return 0;
    }
  }

  return 1;
}

static inline int eip712_is_empty_hex(const struct eip712_string* str) {
  return (str->len == 2) && (str->str[0] == '0') && ((str->str[1] == 'x') || (str->str[1] == 'X'));
}

static inline int eip712_token_is_null(const eip712_ctx_t* ctx, int token) {
  return (ctx->tokens[token].type == JSMN_PRIMITIVE)
    && (ctx->json[ctx->tokens[token].start] == 'n');
}

static app_err_t eip712_inner_type(const struct eip712_string* array_type, struct eip712_string* inner_type) {
  inner_type->str = array_type->str;
  inner_type->len = array_type->len;

  while(inner_type->str[--inner_type->len] != '[') {
    if (inner_type->len == 0) {
      return ERR_DATA;
    }
  }

  return ERR_OK;
}

static int eip712_find_type(const struct eip712_type types[], int types_count, const struct eip712_string* type) {
  for (int i = types_count - 1; i >= 0; i--) {
    if (eip712_streq(type, &types[i].name)) {
      return i;
    }
  }

  return -1;
}

static app_err_t eip712_copy_bytes(int field_index, uint8_t* out, uint32_t* len, const eip712_ctx_t* ctx) {
  struct eip712_string tmpstr;
  eip712_string_from_field(&tmpstr, field_index, ctx);

  if ((tmpstr.len >= 2) && (tmpstr.str[0] == '0') && (tmpstr.str[1] == 'x')) {
    tmpstr.len -= 2;
    tmpstr.str += 2;

    *len = APP_MIN(((tmpstr.len + 1) / 2), *len);

    if (!base16_decode(tmpstr.str, out, ((*len) * 2))) {
      return ERR_DATA;
    }
  } else if (tmpstr.len == 0) {
    *len = 0;
  } else {
    return ERR_DATA;
  }

  return ERR_OK;
}

static app_err_t eip712_copy_uint(int field_index, uint8_t out[32], const eip712_ctx_t* ctx) {
  struct eip712_string tmpstr;
  eip712_string_from_field(&tmpstr, field_index, ctx);

  bool negative;

  if (!str_to_int256(tmpstr.str, tmpstr.len, out, &negative)) {
    return ERR_DATA;
  }

  if (negative) {
    negate_256(out);
  }

  return ERR_OK;
}

static inline size_t eip712_trim_magnitude(const uint8_t mag[32], const uint8_t** first) {
  size_t len = significant_256(mag);

  if (len == 0) {
    len = 1;
  }

  *first = &mag[32 - len];
  return len;
}

static void eip712_put_address(uint8_t out[32], const uint8_t* mag, size_t len) {
  memset(out, 0, 32);

  if (len <= 20) {
    memcpy(&out[32 - len], mag, len);
  } else {
    memcpy(&out[12], mag, 20);
  }
}

static void eip712_add_small(uint8_t* mag, size_t len, uint8_t d) {
  uint16_t carry = d;

  for (size_t i = len; (i > 0) && (carry != 0); i--) {
    carry += mag[i - 1];
    mag[i - 1] = (uint8_t) carry;
    carry >>= 8;
  }
}

static bool eip712_sub_small(uint8_t* mag, size_t len, uint8_t d) {
  if (d == 0) {
    return true;
  }

  bool enough = mag[len - 1] >= d;

  for (size_t i = 0; (i + 1 < len) && !enough; i++) {
    enough = mag[i] != 0;
  }

  if (!enough) {
    return false;
  }

  uint16_t borrow = d;

  for (size_t i = len; (i > 0) && (borrow != 0); i--) {
    uint16_t diff = (uint16_t) mag[i - 1] - borrow;
    mag[i - 1] = (uint8_t) diff;
    borrow = (diff > 0xff) ? 1 : 0;
  }

  return true;
}

static void eip712_neg_small(uint8_t* mag, size_t len, uint8_t d) {
  uint16_t carry = (uint16_t) d + 1;

  for (size_t i = len; i > 0; i--) {
    carry += (uint8_t) ~mag[i - 1];
    mag[i - 1] = (uint8_t) carry;
    carry >>= 8;
  }
}

#define EIP712_UNIT_BYTE 0
#define EIP712_UNIT_ESCAPE 1

static int eip712_next_unit(const char* s, size_t len, size_t* i, int* kind, uint32_t* value) {
  if (*i >= len) {
    return 0;
  }

  const char c = s[(*i)++];

  if (c != '\\') {
    *kind = EIP712_UNIT_BYTE;
    *value = (uint8_t) c;
    return 1;
  }

  if (*i == len) {
    return -1;
  }

  const char escape = s[(*i)++];

  switch (escape) {
  case 'b':
    *value = '\b';
    break;
  case 'f':
    *value = '\f';
    break;
  case 'n':
    *value = '\n';
    break;
  case 'r':
    *value = '\r';
    break;
  case 't':
    *value = '\t';
    break;
  case '"':
  case '/':
  case '\\':
    *value = (uint8_t) escape;
    break;

  case 'u': {
    uint16_t unit;

    if (((*i + 4) > len) || !base16_decode(&s[*i], (uint8_t*) &unit, 4)) {
      return -1;
    }

    *i += 4;
    *value = rev16(unit);

    if ((*value >= 0xd800) && (*value <= 0xdbff)) {
      uint16_t low;

      if (((*i + 6) <= len) && (s[*i] == '\\') && (s[*i + 1] == 'u')
          && base16_decode(&s[*i + 2], (uint8_t*) &low, 4)) {
        low = rev16(low);

        if ((low >= 0xdc00) && (low <= 0xdfff)) {
          *value = 0x10000 + ((*value - 0xd800) << 10) + (low - 0xdc00);
          *i += 6;
        }
      }
    }

    if ((*value >= 0xd800) && (*value <= 0xdfff)) {
      *value = 0xfffd;
    }

    *kind = EIP712_UNIT_ESCAPE;
    return 1;
  }

  default:
    return -1;
  }

  *kind = EIP712_UNIT_ESCAPE;
  return 1;
}

static app_err_t eip712_text_to_address(uint8_t out[32], const eip712_ctx_t* ctx, int val) {
  const char* s = &ctx->json[ctx->tokens[val].start];
  const size_t len = ctx->tokens[val].end - ctx->tokens[val].start;
  uint8_t mag[64];
  bool negative = false;
  size_t i = 0;
  int kind;
  uint32_t unit;

  memset(mag, 0, sizeof(mag));

  for (;;) {
    const int next = eip712_next_unit(s, len, &i, &kind, &unit);

    if (next == 0) {
      break;
    }

    if ((next < 0) || (unit > 0x7f)) {
      return ERR_DATA;
    }

    int digit = (int) unit - 48;

    if (digit >= 49) {
      digit = digit - 49 + 0xa;
    } else if (digit >= 17) {
      digit = digit - 17 + 0xa;
    }

    uint16_t carry = 0;

    for (int j = 63; j >= 0; j--) {
      uint16_t acc = (uint16_t) mag[j] * 10 + carry;
      mag[j] = (uint8_t) acc;
      carry = acc >> 8;
    }

    if (carry != 0) {
      return ERR_DATA;
    }

    if (digit < 0) {
      digit = -digit;

      if (negative) {
        eip712_add_small(mag, sizeof(mag), (uint8_t) digit);
      } else if (!eip712_sub_small(mag, sizeof(mag), (uint8_t) digit)) {
        eip712_neg_small(mag, sizeof(mag), (uint8_t) digit);
        negative = true;
      }
    } else if (negative) {
      if (!eip712_sub_small(mag, sizeof(mag), (uint8_t) digit)) {
        eip712_neg_small(mag, sizeof(mag), (uint8_t) digit);
        negative = false;
      }
    } else {
      eip712_add_small(mag, sizeof(mag), (uint8_t) digit);
    }
  }

  if (negative) {
    return ERR_DATA;
  }

  size_t significant = 0;

  for (size_t k = 0; k < sizeof(mag); k++) {
    if ((mag[k] != 0) || (significant != 0)) {
      mag[significant++] = mag[k];
    }
  }

  eip712_put_address(out, mag, significant);

  return ERR_OK;
}

static void eip712_hash_type(SHA3_CTX* sha3, const struct eip712_type* type) {
  static const uint8_t open = '(';
  static const uint8_t space = ' ';
  static const uint8_t comma = ',';
  static const uint8_t close = ')';

  keccak_Update(sha3, (const uint8_t*) type->name.str, type->name.len);
  keccak_Update(sha3, &open, 1);

  for(int j = 0; j < type->field_count; j++) {
    if (j > 0) {
      keccak_Update(sha3, &comma, 1);
    }

    keccak_Update(sha3, (const uint8_t*) type->fields[j].type.str, type->fields[j].type.len);
    keccak_Update(sha3, &space, 1);
    keccak_Update(sha3, (const uint8_t*) type->fields[j].name.str, type->fields[j].name.len);
  }

  keccak_Update(sha3, &close, 1);
}

static int eip712_insert(int insert, const struct eip712_type types[], int types_count, int references[], int *references_count) {
  for(int i = 0; i < *references_count; i++) {
    if (insert == references[i]) {
      return 0;
    }

    int cmp = eip712_strcmp(&types[insert].name, &types[references[i]].name);

    if (cmp < 0) {
      for (int j = (*references_count)++; j > i; j--) {
        references[j] = references[j-1];
      }

      references[i] = insert;

      return 1;
    }
  }

  references[(*references_count)++] = insert;

  return 1;
}

static struct eip712_string eip712_base_name(struct eip712_string type) {
  size_t len = 0;

  while (len < type.len) {
    const char c = type.str[len];

    if (!((c == '_') || ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')))) {
      break;
    }

    len++;
  }

  type.len = len;
  return type;
}

static app_err_t eip712_collect_references(int main_type, int current_type, const struct eip712_type types[], int types_count, int references[], int *references_count) {
  for (int j = 0; j < types[current_type].field_count; j++) {
    const struct eip712_string name = eip712_base_name(types[current_type].fields[j].type);

    int found = eip712_find_type(types, types_count, &name);

    if ((found == -1) || (found == main_type)) {
      continue;
    }

    if (eip712_insert(found, types, types_count, references, references_count)) {
      eip712_collect_references(main_type, found, types, types_count, references, references_count);
    }
  }

  return ERR_OK;
}

static app_err_t eip712_hash_types(uint8_t* heap, size_t heap_size, struct eip712_type types[], int types_count) {
  ALIGN_HEAP(heap, heap_size);

  if (heap_size < sizeof(SHA3_CTX)) {
    return ERR_DATA;
  }

  SHA3_CTX* sha3 = (SHA3_CTX*) heap;

  for (int i = 0; i < types_count; i++) {
    keccak_256_Init(sha3);

    eip712_hash_type(sha3, &types[i]);

    int references[types_count];
    int reference_count = 0;

    if (eip712_collect_references(i, i, types, types_count, references, &reference_count) != ERR_OK) {
      return ERR_DATA;
    }

    for (int j = 0; j < reference_count; j++) {
      eip712_hash_type(sha3, &types[references[j]]);
    }

    keccak_Final(sha3, types[i].type_hash);
  }

  return ERR_OK;
}

static int eip712_find_data(const struct eip712_string* name, int object, const eip712_ctx_t* ctx) {
  int found = -1;

  for (int key = eip712_next_child(ctx, object, -1); key != -1; key = eip712_next_child(ctx, object, key)) {
    if (eip712_token_eq_str(ctx, key, name)) {
      found = eip712_member_value(key);
    }
  }

  return found;
}

// This macro must only be used in the below functions
#define __DECL_SHA3_CTX() \
  ALIGN_HEAP(heap, heap_size); \
  if (heap_size < sizeof(SHA3_CTX)) { \
    return ERR_DATA; \
  } \
  SHA3_CTX* sha3 = (SHA3_CTX*) heap; \
  heap += sizeof(SHA3_CTX); \
  heap_size -= sizeof(SHA3_CTX); \
  keccak_256_Init(sha3)

static app_err_t eip712_number_token(int token, uint8_t mag[32], bool* negative, const eip712_ctx_t* ctx) {
  if (ctx->tokens[token].type != JSMN_PRIMITIVE) {
    return ERR_DATA;
  }

  struct eip712_string str;
  eip712_string_from_field(&str, token, ctx);

  if ((str.len > 78) || !str_to_int256(str.str, str.len, mag, negative)) {
    return ERR_DATA;
  }

  return ERR_OK;
}

static void eip712_update_utf8(SHA3_CTX* sha3, uint32_t codepoint) {
  APP_ALIGNED(uint8_t bytes[4], 4);
  size_t len;

  if (codepoint < 0x80) {
    bytes[0] = (uint8_t) codepoint;
    len = 1;
  } else if (codepoint < 0x800) {
    bytes[0] = (uint8_t) (0xc0 | (codepoint >> 6));
    bytes[1] = (uint8_t) (0x80 | (codepoint & 0x3f));
    len = 2;
  } else if (codepoint < 0x10000) {
    bytes[0] = (uint8_t) (0xe0 | (codepoint >> 12));
    bytes[1] = (uint8_t) (0x80 | ((codepoint >> 6) & 0x3f));
    bytes[2] = (uint8_t) (0x80 | (codepoint & 0x3f));
    len = 3;
  } else {
    bytes[0] = (uint8_t) (0xf0 | (codepoint >> 18));
    bytes[1] = (uint8_t) (0x80 | ((codepoint >> 12) & 0x3f));
    bytes[2] = (uint8_t) (0x80 | ((codepoint >> 6) & 0x3f));
    bytes[3] = (uint8_t) (0x80 | (codepoint & 0x3f));
    len = 4;
  }

  keccak_Update(sha3, bytes, len);
}

static app_err_t eip712_update_text(SHA3_CTX* sha3, const eip712_ctx_t* ctx, int token) {
  const char* s = &ctx->json[ctx->tokens[token].start];
  const size_t len = ctx->tokens[token].end - ctx->tokens[token].start;
  size_t i = 0;
  int kind;
  uint32_t value;

  for (;;) {
    const int next = eip712_next_unit(s, len, &i, &kind, &value);

    if (next == 0) {
      return ERR_OK;
    }

    if (next < 0) {
      return ERR_DATA;
    }

    if (kind == EIP712_UNIT_BYTE) {
      const uint8_t byte = (uint8_t) value;
      keccak_Update(sha3, &byte, 1);
    } else {
      eip712_update_utf8(sha3, value);
    }
  }
}

static bool eip712_update_hex(SHA3_CTX* sha3, const char* hex, size_t len, uint8_t* scratch) {
  if (len & 1) {
    uint8_t first;

    if (!base16_decode(hex, &first, 1)) {
      return false;
    }

    keccak_Update(sha3, &first, 1);
    hex++;
    len--;
  }

  while (len) {
    size_t chunk = APP_MIN(len, 64u);

    if (!base16_decode(hex, scratch, chunk)) {
      return false;
    }

    keccak_Update(sha3, scratch, chunk / 2);
    hex += chunk;
    len -= chunk;
  }

  return true;
}

static inline void eip712_put_left_aligned(uint8_t out[32], const uint8_t mag[32]) {
  const uint8_t* first;
  size_t len = eip712_trim_magnitude(mag, &first);

  memset(out, 0, 32);
  memcpy(out, first, len);
}

static app_err_t eip712_encode_atomic(uint8_t out[32], uint8_t* heap, size_t heap_size, const struct eip712_string* type, int val, const eip712_ctx_t* ctx) {
  uint8_t mag[32];
  bool negative;
  struct eip712_string str;

  if (eip712_type_named(type, "address")) {
    if (ctx->tokens[val].type == JSMN_STRING) {
      eip712_string_from_field(&str, val, ctx);

      if (eip712_is_hex_string(&str)) {
        size_t bytes = (str.len - 1) / 2;

        if (bytes > 20) {
          return ERR_DATA;
        }

        memset(out, 0, 32);
        return base16_decode(&str.str[2], &out[32 - bytes], str.len - 2) ? ERR_OK : ERR_DATA;
      }

      return eip712_text_to_address(out, ctx, val);
    }

    if ((eip712_number_token(val, mag, &negative, ctx) != ERR_OK) || negative) {
      return ERR_DATA;
    }

    size_t significant = significant_256(mag);
    eip712_put_address(out, &mag[32 - significant], significant);
    return ERR_OK;
  }

  if (eip712_type_named(type, "bool")) {
    if ((ctx->tokens[val].type != JSMN_PRIMITIVE) && (ctx->tokens[val].type != JSMN_STRING)) {
      return ERR_DATA;
    }

    eip712_string_from_field(&str, val, ctx);
    memset(out, 0, 32);

    if (eip712_type_named(&str, "true")) {
      out[31] = 1;
    } else if (!eip712_type_named(&str, "false")) {
      return ERR_DATA;
    }

    return ERR_OK;
  }

  if (eip712_type_named(type, "bytes")) {
    __DECL_SHA3_CTX();

    if (ctx->tokens[val].type == JSMN_STRING) {
      eip712_string_from_field(&str, val, ctx);

      if (eip712_is_hex_string(&str) || eip712_is_empty_hex(&str)) {
        if (!eip712_update_hex(sha3, &str.str[2], str.len - 2, out)) {
          return ERR_DATA;
        }
      } else if (eip712_update_text(sha3, ctx, val) != ERR_OK) {
        return ERR_DATA;
      }
    } else if ((eip712_number_token(val, mag, &negative, ctx) != ERR_OK) || negative) {
      return ERR_DATA;
    } else {
      const uint8_t* first;
      size_t len = eip712_trim_magnitude(mag, &first);
      keccak_Update(sha3, first, len);
    }

    keccak_Final(sha3, out);
    return ERR_OK;
  }

  if (eip712_is_fixed_bytes(type)) {
    memset(out, 0, 32);

    if (ctx->tokens[val].type == JSMN_STRING) {
      eip712_string_from_field(&str, val, ctx);

      if (!eip712_is_hex_string(&str) && !eip712_is_empty_hex(&str)) {
        return ERR_DATA;
      }

      if (((str.len - 1) / 2) > 32) {
        return ERR_DATA;
      }

      return base16_decode(&str.str[2], out, str.len - 2) ? ERR_OK : ERR_DATA;
    }

    if (eip712_number_token(val, mag, &negative, ctx) != ERR_OK) {
      return ERR_DATA;
    }

    /* A negative number is the array of zeros upstream encodes. */
    if (!negative) {
      eip712_put_left_aligned(out, mag);
    }

    return ERR_OK;
  }

  unsigned bits;
  bool signed_type = eip712_is_signed_type(type, &bits);

  if (signed_type || eip712_is_unsigned_type(type, &bits)) {
    if (ctx->tokens[val].type == JSMN_PRIMITIVE) {
      eip712_string_from_field(&str, val, ctx);

      /* BigInt(true) is 1, and the signed types reach BigInt directly; the unsigned ones go
       * through a numeric check that rejects a bool. */
      if (signed_type && (eip712_type_named(&str, "true") || eip712_type_named(&str, "false"))) {
        memset(out, 0, 32);
        out[31] = (str.str[0] == 't');
        return ERR_OK;
      }
    }

    if ((ctx->tokens[val].type != JSMN_STRING) && (ctx->tokens[val].type != JSMN_PRIMITIVE)) {
      return ERR_DATA;
    }

    eip712_string_from_field(&str, val, ctx);

    if (!str_to_int256(str.str, str.len, mag, &negative) || !eip712_fits_bits(mag, bits, negative)) {
      return ERR_DATA;
    }

    if (negative && !all_zero(mag, sizeof(mag))) {
      if (!signed_type) {
        return ERR_DATA;
      }

      negate_256(mag);
    }

    memcpy(out, mag, 32);
    return ERR_OK;
  }

  if (eip712_type_named(type, "string")) {
    __DECL_SHA3_CTX();

    if (ctx->tokens[val].type == JSMN_STRING) {
      if (eip712_update_text(sha3, ctx, val) != ERR_OK) {
        return ERR_DATA;
      }
    } else if (!eip712_token_is_null(ctx, val)) {
      if ((eip712_number_token(val, mag, &negative, ctx) != ERR_OK) || negative) {
        return ERR_DATA;
      }

      const uint8_t* first;
      size_t len = eip712_trim_magnitude(mag, &first);
      keccak_Update(sha3, first, len);
    }

    keccak_Final(sha3, out);
    return ERR_OK;
  }

  return ERR_DATA;
}

static app_err_t eip712_encode_field(uint8_t out[32], uint8_t* heap, size_t heap_size, const struct eip712_string *field_type, int field_val, const struct eip712_type types[], int types_count, const eip712_ctx_t* ctx) {
  int type = eip712_find_type(types, types_count, field_type);

  if (type != -1) {
    if (eip712_token_is_null(ctx, field_val)) {
      memset(out, 0, 32);
      return ERR_OK;
    }

    if (ctx->tokens[field_val].type != JSMN_OBJECT) {
      return ERR_DATA;
    }

    return eip712_hash_struct(out, heap, heap_size, type, types, types_count, field_val, ctx);
  }

  if (eip712_type_named(field_type, "function")) {
    return ERR_DATA;
  }

  if (!eip712_is_array(field_type)) {
    return eip712_encode_atomic(out, heap, heap_size, field_type, field_val, ctx);
  }

  if (ctx->tokens[field_val].type != JSMN_ARRAY) {
    return ERR_DATA;
  }

  uint8_t tmp[32];

  __DECL_SHA3_CTX();

  struct eip712_string inner_type;
  if (eip712_inner_type(field_type, &inner_type) != ERR_OK) {
    return ERR_DATA;
  }

  for (int element = eip712_next_child(ctx, field_val, -1); element != -1; element = eip712_next_child(ctx, field_val, element)) {
    if (eip712_encode_field(tmp, heap, heap_size, &inner_type, element, types, types_count, ctx) != ERR_OK) {
      return ERR_DATA;
    }

    keccak_Update(sha3, tmp, 32);
  }

  keccak_Final(sha3, out);

  return ERR_OK;
}

static app_err_t eip712_hash_struct(uint8_t out[32], uint8_t* heap, size_t heap_size, int type, const struct eip712_type types[], int types_count, int data, const eip712_ctx_t* ctx) {
  const struct eip712_type *t = &types[type];

  ALIGN_HEAP(heap, heap_size);

  size_t slots_len = t->field_count * sizeof(int);

  if (heap_size < slots_len) {
    return ERR_DATA;
  }

  int* values = (int*) heap;
  heap += slots_len;
  heap_size -= slots_len;

  for (int i = 0; i < t->field_count; i++) {
    values[i] = -1;
  }

  for (int key = eip712_next_child(ctx, data, -1); key != -1; key = eip712_next_child(ctx, data, key)) {
    for (int j = 0; j < t->field_count; j++) {
      if (eip712_token_eq_str(ctx, key, &t->fields[j].name)) {
        values[j] = eip712_member_value(key);
      }
    }
  }

  __DECL_SHA3_CTX();

  keccak_Update(sha3, t->type_hash, SHA3_256_DIGEST_LENGTH);

  for (int i = 0; i < t->field_count; i++) {
    APP_ALIGNED(uint8_t field[32], 4);

    if (values[i] == -1) {
      if (eip712_find_type(types, types_count, &t->fields[i].type) == -1) {
        return ERR_DATA;
      }

      memset(field, 0, sizeof(field));
    } else if (eip712_encode_field(field, heap, heap_size, &t->fields[i].type, values[i], types, types_count, ctx) != ERR_OK) {
      return ERR_DATA;
    }

    keccak_Update(sha3, field, sizeof(field));
  }

  keccak_Final(sha3, out);

  return ERR_OK;
}

app_err_t eip712_hash(eip712_ctx_t *ctx, SHA3_CTX *sha3, uint8_t* heap, size_t heap_size, const char* json, size_t json_len) {
  ALIGN_HEAP(heap, heap_size);
  ctx->tokens = (jsmntok_t *) heap;
  ctx->json = json;
  jsmn_parser parser;
  jsmn_init(&parser);
  ctx->token_count = jsmn_parse(&parser, json, json_len, (jsmntok_t*) ctx->tokens, heap_size/sizeof(jsmntok_t));

  if (ctx->token_count < 0) {
    return ERR_DATA;
  }

  size_t token_size = ctx->token_count * sizeof(jsmntok_t);
  heap += token_size;
  heap_size -= token_size;

  if ((ctx->tokens[0].type != JSMN_OBJECT) || (ctx->tokens[0].size < 4)) {
    return ERR_DATA;
  }

  if (eip712_top_level(ctx) != ERR_OK) {
    return ERR_DATA;
  }

  int types_count = ctx->tokens[ctx->index.types].size;
  size_t types_len = types_count * sizeof(struct eip712_type);
  ALIGN_HEAP(heap, heap_size);

  if (heap_size < types_len) {
    return ERR_DATA;
  }

  struct eip712_type* types = (struct eip712_type*) heap;
  heap += types_len;
  heap_size -= types_len;
  memset(types, 0, types_len);

  int fields_size = eip712_parse_types(heap, heap_size, ctx->index.types, types, types_count, ctx);

  if (fields_size < 0) {
    return ERR_DATA;
  }

  heap += fields_size;
  heap_size -= fields_size;

  if (eip712_hash_types(heap, heap_size, types, types_count) != ERR_OK) {
    return ERR_DATA;
  }

  struct eip712_string domain;
  domain.str = "EIP712Domain";
  domain.len = 12;

  int struct_idx = eip712_find_type(types, types_count, &domain);

  uint8_t tmp[32];

  if (struct_idx == -1) {
    static const char empty_domain[] = "EIP712Domain()";
    keccak_256((const unsigned char*) empty_domain, sizeof(empty_domain) - 1, tmp);
    keccak_256(tmp, 32, tmp);
  } else if (eip712_hash_struct(tmp, heap, heap_size, struct_idx, types, types_count, ctx->index.domain, ctx) != ERR_OK) {
    return ERR_DATA;
  }

  keccak_Update(sha3, tmp, 32);

  struct eip712_string primary;
  eip712_string_from_field(&primary, ctx->index.primary_type, ctx);

  if (!eip712_streq(&primary, &domain)) {
    struct_idx = eip712_find_type(types, types_count, &primary);

    if (struct_idx == -1) {
      return ERR_DATA;
    }

    app_err_t err = eip712_hash_struct(tmp, heap, heap_size, struct_idx, types, types_count, ctx->index.message, ctx);
    if (err != ERR_OK) {
      return err;
    }

    keccak_Update(sha3, tmp, 32);
  }

  return ERR_OK;
}

static inline size_t eip712_indent(uint8_t* out, int indent) {
  for(int i = 0; i < indent; i++) {
    *(out++) = '\t';
  }

  return indent;
}

static inline size_t eip712_encode_primitive(const eip712_ctx_t* ctx, uint8_t* out, int token) {
  size_t len = ctx->tokens[token].end - ctx->tokens[token].start;
  memcpy(out, &ctx->json[ctx->tokens[token].start], len);
  return len;
}

static size_t eip712_encode_array(const eip712_ctx_t* ctx, uint8_t* out, int array, int indent) {
  size_t size = 0;

  for (int element = eip712_next_child(ctx, array, -1); element != -1; element = eip712_next_child(ctx, array, element)) {
    size += eip712_indent(&out[size], indent);
    size += eip712_encode_token(ctx, &out[size], element, indent);
    out[size++] = '\n';
  }

  return size;
}

static size_t eip712_encode_object(const eip712_ctx_t* ctx, uint8_t* out, int object, int indent) {
  size_t size = 0;

  for (int key = eip712_next_child(ctx, object, -1); key != -1; key = eip712_next_child(ctx, object, key)) {
    size += eip712_indent(&out[size], indent);
    size += eip712_encode_primitive(ctx, &out[size], key);
    out[size++] = ':';
    out[size++] = ' ';
    size += eip712_encode_token(ctx, &out[size], eip712_member_value(key), indent);
    out[size++] = '\n';
  }

  return size;
}

static size_t eip712_encode_token(const eip712_ctx_t* ctx, uint8_t* out, int token, int indent) {
  size_t size = 0;

  switch (ctx->tokens[token].type) {
  case JSMN_OBJECT:
    out[size++] = '{';
    out[size++] = '\n';
    size += eip712_encode_object(ctx, &out[size], token, indent + 1);
    size += eip712_indent(&out[size], indent);
    out[size++] = '}';
    break;

  case JSMN_ARRAY:
    out[size++] = '[';
    out[size++] = '\n';
    size += eip712_encode_array(ctx, &out[size], token, indent + 1);
    size += eip712_indent(&out[size], indent);
    out[size++] = ']';
    break;

  default:
    size = eip712_encode_primitive(ctx, out, token);
    break;
  }

  return size;
}

size_t eip712_to_string(const eip712_ctx_t* ctx, uint8_t* out) {
  return eip712_encode_object(ctx, out, ctx->index.message, 0);
}

static inline void eip712_wrap_cstr(const char* cstr, struct eip712_string* out) {
  out->str = cstr;
  out->len = strlen(cstr);
}

int eip712_find_field(const eip712_ctx_t* ctx, int parent, const char* key) {
  struct eip712_string k;
  eip712_wrap_cstr(key, &k);
  return eip712_find_data(&k, parent, ctx);
}

app_err_t eip712_extract_string(const eip712_ctx_t* ctx, int parent, const char* key, char* out, int out_len) {
  int found = eip712_find_field(ctx, parent, key);

  if (found == -1) {
    return ERR_DATA;
  }

  int len = APP_MIN((out_len - 1), (ctx->tokens[found].end - ctx->tokens[found].start));
  memcpy(out, &ctx->json[ctx->tokens[found].start], len);
  out[len] = '\0';

  return ERR_OK;
}

app_err_t eip712_extract_uint256(const eip712_ctx_t* ctx, int parent, const char* key, uint8_t out[32]) {
  int found = eip712_find_field(ctx, parent, key);

  if (found == -1) {
    return ERR_DATA;
  }

  return eip712_copy_uint(found, out, ctx);
}

app_err_t eip712_extract_bytes(const eip712_ctx_t* ctx, int parent, const char* key, uint8_t* out, uint32_t* len) {
  int found = eip712_find_field(ctx, parent, key);

  if (found == -1) {
    return ERR_DATA;
  }

  return eip712_copy_bytes(found, out, len, ctx);
}

int eip712_field_eq(const eip712_ctx_t* ctx, int field, const char* str) {
  struct eip712_string str1;
  eip712_string_from_field(&str1, field, ctx);

  struct eip712_string str2;
  eip712_wrap_cstr(str, &str2);

  return eip712_streq(&str1, &str2);
}
