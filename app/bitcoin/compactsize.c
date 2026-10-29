#include <limits.h>
#include <string.h>
#include "compactsize.h"

#define MAX_SERIALIZE_SIZE 0x02000000

#define READERR() \
  {if (err)       \
    *err = PSBT_COMPACT_READ_ERROR; \
  return 0;}

uint32_t compactsize_peek_length(uint8_t chsize) {
  if (chsize < 253) {
    return sizeof(uint8_t);
  } else if (chsize == 253) {
    return sizeof(uint8_t) + sizeof(uint16_t);
  } else if (chsize == 254)
    return sizeof(uint8_t) + sizeof(uint32_t);
  else {
    return sizeof(uint8_t) + sizeof(uint64_t);
  }
}

uint32_t compactsize_length(uint64_t data) {
  if (data < 253) {
    return sizeof(uint8_t);
  } else if (data <= USHRT_MAX) {
    return sizeof(uint8_t) + sizeof(uint16_t);
  } else if (data <= UINT_MAX) {
    return sizeof(uint8_t) + sizeof(uint32_t);
  } else {
    return sizeof(uint8_t) + sizeof(uint64_t);
  }
}

inline static void serialize_uint8(uint8_t *dest, uint8_t data) {
  *dest = data;
}

inline static void serialize_uint16(uint8_t *dest, uint16_t data) {
  memcpy(dest, &data, sizeof(uint16_t));
}

inline static void serialize_uint32(uint8_t *dest, uint32_t data) {
  memcpy(dest, &data, sizeof(uint32_t));
}

inline static void serialize_uint64(uint8_t *dest, uint64_t data) {
  memcpy(dest, &data, sizeof(uint64_t));
}

inline static uint8_t deserialize_uint8(const uint8_t *src) {
  return *src;
}

inline static uint16_t deserialize_uint16(const uint8_t *src) {
  uint16_t data;
  memcpy(&data, src, sizeof(uint16_t));
  return data;
}

inline static uint32_t deserialize_uint32(const uint8_t *src) {
  uint32_t data;
  memcpy(&data, src, sizeof(uint32_t));
  return data;
}

inline static uint64_t deserialize_uint64(const uint8_t *src) {
  uint64_t data;
  memcpy(&data, src, sizeof(uint64_t));
  return data;
}

void compactsize_write(uint8_t *dest, uint64_t size)
{
  if (size < 253) {
    serialize_uint8(dest, size);
  } else if (size <= USHRT_MAX) {
    serialize_uint8(dest, 253);
    serialize_uint16(&dest[1], size);
  } else if (size <= UINT_MAX) {
    serialize_uint8(dest, 254);
    serialize_uint32(&dest[1], size);
  } else {
    serialize_uint8(dest, 255);
    serialize_uint64(&dest[1], size);
  }
}

uint64_t compactsize_read(const uint8_t *data, psbt_result_t *err) {
  const uint8_t *p = data;
  uint8_t chsize = deserialize_uint8(p++);
  uint64_t ret_size = 0;

  if (chsize < 253) {
    ret_size = chsize;
  } else if (chsize == 253) {
    ret_size = deserialize_uint16(p);
    if (ret_size < 253) {
      READERR();
    }

  } else if (chsize == 254) {
    ret_size = deserialize_uint32(p);

    if (ret_size < 0x10000u) {
      READERR();
    }
  } else {
    ret_size = deserialize_uint64(p);
    if (ret_size < 0x100000000ULL) {
      READERR();
    }
  }

  if (ret_size > (uint64_t) MAX_SERIALIZE_SIZE) {
    READERR();
  }

  if (err) {
    *err = PSBT_OK;
  }

  return ret_size;
}
