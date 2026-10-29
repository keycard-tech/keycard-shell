#ifndef VECTORS_COMPACTSIZE_H
#define VECTORS_COMPACTSIZE_H

/* spec: Bitcoin protocol variable length integer, the encoding psbt_tx.c reads and writes.
 * Each row is a boundary of one of the four width classes.
 *
 * readable is false above 0x02000000: compactsize_read() refuses any length larger than its
 * MAX_SERIALIZE_SIZE, so those rows must fail rather than round-trip.
 */
#include <stdbool.h>

typedef struct {
  unsigned long long value;
  const char* encoding;
  bool readable;
} compactsize_vector_t;

static const compactsize_vector_t COMPACTSIZE_VECTORS[] = {
  {0x0ULL, "00", true},
  {0xfcULL, "fc", true},
  {0xfdULL, "fdfd00", true},
  {0xfeffULL, "fdfffe", true},
  {0xffffULL, "fdffff", true},
  {0x10000ULL, "fe00000100", true},
  {0xffffffffULL, "feffffffff", false},
  {0x100000000ULL, "ff0000000001000000", false},
  {0xffffffffffffULL, "ffffffffffffff0000", false},
  {0x2000000ULL, "fe00000002", true},
  {0x2000001ULL, "fe01000002", false}
};

#define COMPACTSIZE_VECTOR_COUNT (sizeof(COMPACTSIZE_VECTORS) / sizeof(COMPACTSIZE_VECTORS[0]))

/* Encodings rejected because a shorter one represents the same value -- the rule Bitcoin Core's
 * ReadCompactSize() applies. These rows are built from that rule, not fetched from a document. */
static const char* const COMPACTSIZE_NONCANONICAL[] = {
  "fdfc00",
  "feffff0000",
  "ffffffffff00000000"
};

#define COMPACTSIZE_NONCANONICAL_COUNT (sizeof(COMPACTSIZE_NONCANONICAL) / sizeof(COMPACTSIZE_NONCANONICAL[0]))

#endif
