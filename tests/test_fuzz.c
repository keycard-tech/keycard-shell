/*
 * This file is part of ShellOS.
 *
 * Copyright (c) 2024, 2025 SideNote, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Every byte-eating parser in the firmware has a table of shapes somebody thought of: the applet's
 * replies, DER signatures, PSBTs, RLP transactions, raw transactions. Those tables pin what each parser
 * does on those shapes. This file asks about shapes nobody thought of, and the answer it wants is not
 * "correct" -- a mutated PSBT has no correct answer -- but:
 *
 *   no sanitizer report, the same verdict every time, and no write outside what the module owns.
 *
 * The class behind most of the findings in plans/host-tests.md is a length or a shape taken from input
 * and used as a bound, and that is exactly what mutating a known-interesting input produces: a compact
 * size that no longer matches what follows, a TLV length one past the buffer, a count byte that moved.
 * The corpora are the pinned vectors themselves, so every mutation starts one edit away from a shape a
 * person already decided mattered, which is where the off-by-ones live.
 *
 * Each mutated input is run twice, with the caller's objects poisoned 0x00 the first time and 0xff the
 * second, and these are asserted:
 *
 *  - The verdicts are equal. A parser whose answer to the same bytes depends on anything but those bytes
 *    carries state it should not.
 *  - Whatever the verdict says is defined is equal between the two runs. This stands in for an
 *    uninitialised-memory checker, which is not available here: a module that hands back a field it
 *    never wrote gives back the poison, and the two runs differ. It is also why the drivers read only
 *    what the verdict entitles them to -- a field left untouched on refusal is not a bug, and reading it
 *    would report the test's curiosity as the module's defect.
 *  - Pointers the module hands back lie inside the bytes it was given. A dangling one is the same class
 *    as an unchecked length, and it is how a parser leaks whatever else is in the buffer.
 *  - The input is untouched, except for the two readers whose API says they write into it (the PSBT
 *    reader normalises in place; the signature reader compresses the key it found, which is checked to
 *    be one byte and to be the key's first).
 *
 * Everything is deterministic. A crash is the sanitizers' report and names the parser in its stack
 * trace; replay it with FUZZ_SEED set to the seed printed on the last line and FUZZ_VERBOSE=1, which
 * prints each input and mutation as it is fed. Nothing here allocates, as nowhere else in the firmware:
 * the buffers are variable-sized automatic arrays, so a read past the last byte of an input is a read
 * past the end of an object and the sanitizers see it.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitcoin/bitcoin.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_ctx.h"
#include "bitcoin/tx.h"
#include "common.h"
#include "core/core_btc_sig.h"
#include "crypto/ecdsa.h"
#include "crypto/sha2.h"
#include "crypto/sha3.h"
#include "error.h"
#include "ethereum/ethUtils.h"
#include "ethereum/ethUstream.h"
#include "framework/test_util.h"
#include "keycard/application_info.h"
#include "keycard/signature.h"
#include "unity.h"
#include "util/tlv.h"

#include "vectors/vectors_ecdsa_der.h"
#include "vectors/vectors_ethereum.h"
#include "vectors/vectors_keycard_signature.h"
#include "vectors/vectors_psbt.h"
#include "vectors/vectors_psbt_ctx.h"
#include "vectors/vectors_tlv.h"
#include "vectors/vectors_tx.h"

/* The largest vector in any corpus -- a 4680 byte transaction -- with room for the bytes a mutation
 * appends. */
#define FUZZ_BLOB_MAX 8192
#define FUZZ_OUT_MAX 4096
#define FUZZ_ETH_DATA_CAPACITY 1024

/* One pass over every corpus input: unmutated, then once per mutation. */
#define FUZZ_OP_COUNT 6
#define FUZZ_PASS_COUNT (1 + FUZZ_OP_COUNT)

enum fuzz_op {
  FUZZ_OP_GIVEN = 0,
  FUZZ_OP_BITFLIP,
  FUZZ_OP_EDGE_BYTE,
  FUZZ_OP_TRUNCATE,
  FUZZ_OP_APPEND,
  FUZZ_OP_INSERT,
  FUZZ_OP_MOVE
};

static const char* const FUZZ_OP_NAMES[FUZZ_PASS_COUNT] = {"as given",    "bit flip",
                                                          "edge byte",   "truncated",
                                                          "bytes added", "region inserted",
                                                          "region moved"};

/* Two poisons, so a field the module never wrote reads differently between the two runs. */
#define FUZZ_POISON_A 0x00
#define FUZZ_POISON_B 0xff

/* The fingerprint a context is set up with, as in the PSBT context table. */
#define FUZZ_FINGERPRINT 0x11223344u

typedef struct {
  const char* corpus;
  const char* name;
  uint16_t a; /* what the reader needs that is not in the bytes: a tag, a length, an algorithm */
  uint16_t b;
} fuzz_blob_t;

typedef struct {
  uint8_t* out;
  size_t n;
} wbuf_t;

typedef struct {
  int64_t verdict;
} answer_t;

typedef answer_t (*driver_fn)(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                              uint8_t poison, wbuf_t* out);

static uint64_t rng_state;
static uint64_t seed_in_use;
static size_t inputs_seen;
static size_t calls_made;
static int verbose;

static const fuzz_blob_t* running;
static char message[512];
static char context[256];

static const char* blob_context(void) {
  snprintf(context, sizeof(context), "%s/%s", running->corpus, running->name);
  return context;
}

static uint64_t next_rand(void) {
  rng_state += 0x9e3779b97f4a7c15ULL;
  uint64_t z = rng_state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static size_t rand_below(size_t bound) {
  return bound == 0 ? 0 : (size_t)(next_rand() % bound);
}

static void report(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);
  TEST_FAIL_MESSAGE(message);
}

static void w_bytes(wbuf_t* w, const uint8_t* p, size_t n) {
  if (w->n + n > FUZZ_OUT_MAX) {
    report("%s: the fuzz driver overflowed its own answer buffer", blob_context());
  }
  if (n != 0) {
    memcpy(w->out + w->n, p, n);
  }
  w->n += n;
}

static void w_u32(wbuf_t* w, uint32_t v) {
  w_bytes(w, (const uint8_t*)&v, sizeof(v));
}

static void w_flag(wbuf_t* w, int v) {
  w_u32(w, (uint32_t)(v ? 1 : 0));
}

/* A claimed pointer has to lie inside the bytes the parser was given, and so has the object behind it. */
static void w_ptr(wbuf_t* w, const uint8_t* base, size_t base_len, const uint8_t* p, size_t n,
                  const char* what) {
  if (p == NULL) {
    w_flag(w, 0);
    return;
  }
  w_flag(w, 1);
  if (p < base || n > base_len || (size_t)(p - base) + n > base_len) {
    report("%s: %s (%zu bytes) points outside the bytes handed to the parser", blob_context(), what, n);
  }
  w_bytes(w, p, n);
}

/* ------------------------------------------------------------------ the drivers, one per parser */

static answer_t drv_der(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                        uint8_t poison, wbuf_t* out) {
  uint8_t sig[64];
  memset(sig, poison, sizeof(sig));

  const int ok = ecdsa_sig_from_der(in, len, sig);
  if (ok) {
    w_bytes(out, sig, sizeof(sig));
  }
  return (answer_t){ok};
}

static answer_t drv_tlv_header(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                               uint8_t poison, wbuf_t* out) {
  tlv_t tlv;
  uint16_t tag = 0;
  uint16_t length = 0;

  tlv_open(&tlv, in, len);
  const bool have_tag = tlv_read_tag(&tlv, &tag);
  w_flag(out, have_tag);
  if (have_tag) {
    w_u32(out, tag);
  }
  const bool have_len = tlv_read_length(&tlv, &length);
  w_flag(out, have_len);
  if (have_len) {
    w_u32(out, length);
  }
  return (answer_t){(have_tag ? 2 : 0) + (have_len ? 1 : 0)};
}

static answer_t drv_tlv_read(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                             uint8_t poison, wbuf_t* out) {
  tlv_t tlv;
  /* Exactly the size the caller in the firmware gives it, so that a value longer than the contract is
   * a write past an object and not a neighbour in a generous buffer. */
  uint8_t value[blob->b == 0 ? 1 : blob->b];
  uint16_t value_len = 0;

  memset(value, poison, sizeof(value));
  tlv_open(&tlv, in, len);
  const bool ok = tlv_read_primitive(&tlv, blob->a, blob->b, value, &value_len);
  if (ok) {
    if (value_len > blob->b) {
      report("%s: the reader counted %u bytes into a %u byte buffer", blob_context(), value_len, blob->b);
    }
    w_u32(out, value_len);
    w_bytes(out, value, value_len);
  }
  return (answer_t){ok};
}

static answer_t drv_tlv_fixed(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                              uint8_t poison, wbuf_t* out) {
  tlv_t tlv;
  uint8_t value[blob->b == 0 ? 1 : blob->b];

  memset(value, poison, sizeof(value));
  tlv_open(&tlv, in, len);
  const bool ok = tlv_read_fixed(&tlv, blob->a, blob->b, value);
  if (ok) {
    w_bytes(out, value, blob->b);
  }
  return (answer_t){ok};
}

static answer_t drv_app_info(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                             uint8_t poison, wbuf_t* out) {
  app_info_t info;

  memset(&info, poison, sizeof(info));
  const app_err_t err = application_info_parse(in, (uint16_t)len, &info);
  if (err != ERR_OK) {
    return (answer_t){err};
  }
  /* What the reply defined depends on which of its three answers this was, and the parse says so: a
   * bare public key is an uninitialised card and only status, version and the secure-channel key are
   * the card's answer; a card with no keys has an empty key UID primitive and leaves the UID itself
   * the caller's. Reading past that would report the parse's contract as a defect, so the three are
   * written differently -- which is also what the callers in the firmware do. */
  w_u32(out, (uint32_t)info.status);
  w_u32(out, info.version);
  if (info.status == NOT_INITIALIZED) {
    w_bytes(out, info.v3.sc_key, sizeof(info.v3.sc_key));
    return (answer_t){err};
  }
  w_u32(out, info.capabilities);
  if (info.status == INIT_WITH_KEYS) {
    w_bytes(out, info.key_uid, sizeof(info.key_uid));
  }
  /* The union is not compared. Which half a reply fills is the first tag inside the template, not the
   * version the card claims, and a mutation of the version -- which the parse does not act on -- would
   * make this reader ask for the half that was never written. The pinned table reads the right half of
   * every row, and a write into the wrong one is an ASan report either way. */
  return (answer_t){err};
}

static answer_t drv_app_status(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                               uint8_t poison, wbuf_t* out) {
  app_status_t status;

  memset(&status, poison, sizeof(status));
  const app_err_t err = application_status_parse(in, (uint16_t)len, &status);
  if (err != ERR_OK) {
    return (answer_t){err};
  }
  w_u32(out, status.pin_retries);
  w_u32(out, status.puk_retries);
  w_u32(out, status.has_key);
  return (answer_t){err};
}

static answer_t drv_sign_reply(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                               uint8_t poison, wbuf_t* out) {
  keycard_signature_t signature;

  memset(&signature, poison, sizeof(signature));
  const bool ok = keycard_read_signature_reply(in, (uint16_t)len, (keycard_sign_algo_t)blob->a, &signature);
  if (!ok) {
    return (answer_t){0};
  }
  w_u32(out, signature.sig_len);
  w_ptr(out, in, len, signature.sig, signature.sig_len, "signature");
  if (signature.key != NULL) {
    w_ptr(out, in, len, signature.key, 33, "public key");
  }
  return (answer_t){1};
}

/* The reply is the one buffer the signature reader writes into, to compress the key it found. That one
 * byte, and only that byte, may change. */
static answer_t drv_btc_sig(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                            uint8_t poison, wbuf_t* out) {
  uint8_t sig_val[DER_ECDSA_MAX_SIGNATURE_LEN + 1];
  psbt_record_t rec;

  memset(sig_val, poison, sizeof(sig_val));
  memset(&rec, poison, sizeof(rec));

  app_err_t err;
  if (blob->a == KEYCARD_SIGN_BIP340_SCHNORR) {
    err = core_btc_read_schnorr_signature(in, (uint16_t)len, &rec);
  } else {
    err = core_btc_read_signature(in, (uint16_t)len, (uint8_t)blob->b, sig_val, &rec);
  }
  if (err != ERR_OK) {
    return (answer_t){err};
  }

  size_t changed = 0, first = 0;
  for (size_t i = 0; i < len; i++) {
    if (in[i] != pristine[i]) {
      if (changed == 0) {
        first = i;
      }
      changed++;
    }
  }
  if (changed > 1) {
    report("%s: the signature reader rewrote %zu bytes of the reply", blob_context(), changed);
  }

  w_u32(out, (uint32_t)rec.scope);
  w_u32(out, (uint32_t)rec.type);
  w_u32(out, rec.key_size);
  w_ptr(out, in, len, rec.key, rec.key_size, "record key");
  if (changed == 1 && rec.key != in + first) {
    report("%s: the one byte the reply was rewritten at is not the record key's first", blob_context());
  }
  w_u32(out, (uint32_t)rec.val_size);
  if (blob->a == KEYCARD_SIGN_BIP340_SCHNORR) {
    w_ptr(out, in, len, rec.val, rec.val_size, "record value");
  } else {
    if (rec.val != sig_val) {
      report("%s: an ECDSA record value is not the signature buffer it was given", blob_context());
    }
    if (rec.val_size > sizeof(sig_val)) {
      report("%s: an ECDSA record claims %u signature bytes out of a %u byte buffer", blob_context(),
             (unsigned)rec.val_size, (unsigned)sizeof(sig_val));
    }
    w_bytes(out, sig_val, rec.val_size);
  }
  return (answer_t){err};
}

typedef struct {
  size_t elements;
  size_t records;
  size_t bytes;
  const uint8_t* base;
  size_t base_len;
} psbt_capture_t;

static psbt_capture_t capture;

static void capture_element(psbt_elem_t* elem) {
  capture.elements++;

  if (elem->type != PSBT_ELEM_RECORD) {
    return;
  }
  capture.records++;
  const psbt_record_t* rec = elem->elem.rec;
  capture.bytes += rec->key_size + rec->val_size;

  const uint8_t* parts[2] = {rec->key, rec->val};
  const size_t sizes[2] = {rec->key_size, rec->val_size};
  for (size_t i = 0; i < 2; i++) {
    if (parts[i] == NULL || sizes[i] == 0) {
      continue;
    }
    if (parts[i] < capture.base || (size_t)(parts[i] - capture.base) + sizes[i] > capture.base_len) {
      report("%s: a record %s points outside the PSBT it was read from", blob_context(),
             i == 0 ? "key" : "value");
    }
  }
}

static answer_t drv_psbt(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                         uint8_t poison, wbuf_t* out) {
  psbt_t psbt;

  capture = (psbt_capture_t){0, 0, 0, in, len};
  psbt_init(&psbt, in, len);
  const psbt_result_t res = psbt_read(in, len, &psbt, capture_element, NULL);
  if (res == PSBT_OK) {
    w_u32(out, (uint32_t)capture.elements);
    w_u32(out, (uint32_t)capture.records);
    w_u32(out, (uint32_t)capture.bytes);
  }
  return (answer_t){res};
}

/* The ingest a scanned PSBT goes through, and what the screen and the signature read afterwards: what
 * the input was taken to be, and whose key an output was filed under. */
static answer_t drv_psbt_ctx(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                             uint8_t poison, wbuf_t* out) {
  psbt_t psbt;
  btc_tx_ctx_t ctx;

  /* Zeroed, not poisoned: the device builds this context on a camera buffer and clears it before every
   * PSBT (core_btc_run), and the ingest counts into it rather than overwriting it, so a context of
   * 0xff... is a state the firmware never hands the parser and would be reporting the caller's own
   * initialisation as the parser's defect. What is still checked here is the answer -- determinism, and
   * every pointer the context ends up holding. */
  memset(&ctx, 0, sizeof(ctx));
  ctx.mfp = FUZZ_FINGERPRINT;

  psbt_init(&psbt, in, len);
  if (psbt_read(in, len, &psbt, btc_psbt_element, &ctx) != PSBT_OK) {
    return (answer_t){1};
  }
  if (ctx.error != ERR_OK) {
    return (answer_t){2 + ctx.error};
  }
  const app_err_t validated = btc_psbt_validate_inputs(&ctx);
  if (validated != ERR_OK) {
    return (answer_t){100 + validated};
  }

  w_u32(out, (uint32_t)ctx.input_count);
  w_u32(out, (uint32_t)ctx.output_count);
  w_flag(out, btc_psbt_any_can_sign(&ctx));

  for (size_t i = 0; i < ctx.input_count && i < 2; i++) {
    const psbt_input_data_t* d = &ctx.input_data[i];
    w_u32(out, (uint32_t)d->input_type);
    w_u32(out, d->sighash_flag);
    w_u32(out, d->master_fingerprint);
    w_flag(out, d->can_sign);
    w_flag(out, d->witness);
    w_flag(out, d->has_taproot_internal_key);
    w_flag(out, d->has_taproot_merkle_root);
    w_ptr(out, in, len, d->script_pubkey, d->script_pubkey_len, "input script");
    w_ptr(out, in, len, d->redeem_script, d->redeem_script_len, "input redeem script");
    w_ptr(out, in, len, d->witness_script, d->witness_script_len, "input witness script");
    w_u32(out, d->bip32_path_len);
    w_ptr(out, in, len, d->bip32_path, d->bip32_path_len, "input path");
    if (d->has_taproot_internal_key) {
      w_ptr(out, in, len, d->taproot_internal_key, 32, "input internal key");
    }
    if (d->has_taproot_merkle_root) {
      w_ptr(out, in, len, d->taproot_merkle_root, 32, "input merkle root");
    }
    if (d->can_sign) {
      w_ptr(out, in, len, d->amount, 8, "input amount");
    }
  }
  for (size_t i = 0; i < ctx.output_count && i < 2; i++) {
    const psbt_output_data_t* d = &ctx.output_data[i];
    w_u32(out, d->master_fingerprint);
    w_flag(out, d->change);
    w_u32(out, d->bip32_path_len);
    w_ptr(out, in, len, d->bip32_path, d->bip32_path_len, "output path");
  }
  return (answer_t){200};
}

static answer_t drv_tx(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                       uint8_t poison, wbuf_t* out) {
  uint8_t expected[SHA256_DIGEST_LENGTH];
  memset(expected, poison, sizeof(expected));

  /* The expected id is arbitrary here; what matters is that reading the transaction stays inside it. */
  const bool ok = btc_validate_tx_hash(in, len, expected);
  w_flag(out, ok);
  return (answer_t){ok};
}

static uint8_t eth_data[FUZZ_ETH_DATA_CAPACITY];

#define ETH_NOWHERE 0
#define ETH_FULL 1
#define ETH_TIGHT 2

static answer_t drv_eth(const fuzz_blob_t* blob, uint8_t* in, const uint8_t* pristine, size_t len,
                        uint8_t poison, wbuf_t* out) {
  txContext_t ctx;
  txContent_t content;
  SHA3_CTX sha3;

  /* Zeroed, not poisoned: core_eth's content is a cleared global, and the parser reads content.data
   * to decide whether it is copying or aliasing, so a field of 0xff is a state the firmware never
   * hands it. The payload buffer itself is poisoned, which is where a short copy shows. */
  memset(&content, 0, sizeof(content));
  memset(eth_data, poison, sizeof(eth_data));
  /* Three of the states core_eth puts the payload buffer in: no copy at all -- its APDU path parses
   * with data NULL and the payload is aliased -- room for the whole payload, and room for almost none,
   * which is what makes the parser's own bound observable. */
  switch (blob->a) {
  case ETH_NOWHERE:
    content.data = NULL;
    content.dataCapacity = 0;
    break;
  case ETH_TIGHT:
    content.data = eth_data;
    content.dataCapacity = 4;
    break;
  default:
    content.data = eth_data;
    content.dataCapacity = sizeof(eth_data);
    break;
  }
  content.chainID = 1;
  content.v = V_NONE;
  keccak_256_Init(&sha3);
  initTx(&ctx, &sha3, &content);

  /* As core_eth hands it over: the type byte is hashed by the caller and stripped, and a payload
   * starting 0xc0 or above is a legacy transaction with no type byte at all. */
  size_t offset = 0;
  if (len != 0 && in[0] <= MAX_TX_TYPE) {
    keccak_Update(&sha3, in, 1);
    ctx.txType = in[0];
    offset = 1;
  } else {
    ctx.txType = LEGACY;
  }

  const parserStatus_e status = processTx(&ctx, in + offset, (uint32_t)(len - offset));
  if (status != USTREAM_FINISHED) {
    return (answer_t){status};
  }

  /* An int256 is `length` bytes of the card's answer and, for the rest of the 32, the caller's own
   * memory: every reader in the tree takes the length with the pointer (bn_read_compact_be), so the
   * bytes past it are not part of the answer and are not compared. */
  w_u32(out, content.chainID);
  w_u32(out, content.v);
  w_u32(out, content.gasprice.length);
  w_bytes(out, content.gasprice.value, content.gasprice.length);
  w_u32(out, content.startgas.length);
  w_bytes(out, content.startgas.value, content.startgas.length);
  w_u32(out, content.value.length);
  w_bytes(out, content.value.value, content.value.length);
  w_bytes(out, content.destination, sizeof(content.destination));
  w_bytes(out, (const uint8_t*)&content.dataLength, sizeof(content.dataLength));
  /* The payload is either copied into the caller's buffer or aliased into the bytes being fed, which
   * is what the caller's data == NULL asks for. Either way the length has to fit wherever the pointer
   * ended up, and the bytes there are the answer. */
  if (content.data != NULL && content.dataLength != 0) {
    const int copied = (content.data >= eth_data) &&
                       (size_t)(content.data - eth_data) + content.dataLength <= sizeof(eth_data);
    const int aliased = (content.data >= in + offset) &&
                        (size_t)(content.data - (in + offset)) + content.dataLength <= len - offset;
    if (!copied && !aliased) {
      report("%s: the payload pointer and its %zu bytes are in neither the caller's buffer nor the "
             "transaction",
             blob_context(), content.dataLength);
    }
    if (copied && content.dataLength > content.dataCapacity) {
      report("%s: the parser counted %zu payload bytes into a %u byte buffer", blob_context(),
             content.dataLength, (unsigned)content.dataCapacity);
    }
    w_bytes(out, content.data, content.dataLength);
  }
  return (answer_t){status};
}

/* ------------------------------------------------------------------ the driver's driver */

static uint8_t base[FUZZ_BLOB_MAX];
static uint8_t mutated[FUZZ_BLOB_MAX];

static size_t mutate(size_t len, int op) {
  static const uint8_t EDGE[] = {0x00, 0x01, 0x02, 0x0f, 0x10, 0x4c, 0x80, 0xff};

  memcpy(mutated, base, len);
  if (op == FUZZ_OP_GIVEN || len == 0) {
    return len;
  }

  switch (op) {
  case FUZZ_OP_BITFLIP:
    mutated[rand_below(len)] ^= (uint8_t)(1u << rand_below(8));
    return len;
  case FUZZ_OP_EDGE_BYTE:
    mutated[rand_below(len)] = EDGE[rand_below(sizeof(EDGE))];
    return len;
  case FUZZ_OP_TRUNCATE:
    return rand_below(len + 1);
  case FUZZ_OP_APPEND: {
    const size_t k = 1 + rand_below(8);
    for (size_t i = 0; i < k; i++) {
      mutated[len + i] = (uint8_t)next_rand();
    }
    return len + k;
  }
  case FUZZ_OP_INSERT: {
    const size_t k = 1 + rand_below(4);
    const size_t at = rand_below(len + 1);
    const uint8_t fill = mutated[rand_below(len)];
    memmove(mutated + at + k, mutated + at, len - at);
    memset(mutated + at, fill, k);
    return len + k;
  }
  default: {
    const size_t k = 1 + rand_below(16);
    if (k >= len) {
      return len;
    }
    const size_t from = rand_below(len - k);
    const size_t to = rand_below(len - k);
    memmove(mutated + to, mutated + from, k);
    return len;
  }
  }
}

static void fuzz_one(const char* corpus, const char* name, size_t len, uint16_t a, uint16_t b, driver_fn drv,
                     int writable_input) {
  fuzz_blob_t blob = {corpus, name, a, b};
  inputs_seen++;

  for (int op = 0; op < FUZZ_PASS_COUNT; op++) {
    const size_t m = mutate(len, op);
    const size_t hold = m == 0 ? 1 : m;

    uint8_t source[hold];
    uint8_t in_a[hold];
    uint8_t in_b[hold];
    uint8_t out_a[FUZZ_OUT_MAX];
    uint8_t out_b[FUZZ_OUT_MAX];

    memcpy(source, mutated, m);
    memcpy(in_a, mutated, m);
    memcpy(in_b, mutated, m);

    running = &blob;
    if (verbose) {
      printf("%s/%s | %s | %zu bytes\n", corpus, name, FUZZ_OP_NAMES[op], m);
      fflush(stdout);
    }

    wbuf_t wa = {out_a, 0};
    const answer_t va = drv(&blob, in_a, source, m, FUZZ_POISON_A, &wa);
    calls_made++;
    wbuf_t wb = {out_b, 0};
    const answer_t vb = drv(&blob, in_b, source, m, FUZZ_POISON_B, &wb);
    calls_made++;

    if (va.verdict != vb.verdict) {
      report("%s/%s | %s | %zu bytes: the same bytes answered %lld and then %lld", corpus, name,
             FUZZ_OP_NAMES[op], m, (long long)va.verdict, (long long)vb.verdict);
    }
    if (wa.n != wb.n) {
      report("%s/%s | %s | %zu bytes: the answer is %zu bytes one run and %zu the next", corpus, name,
             FUZZ_OP_NAMES[op], m, wa.n, wb.n);
    }
    for (size_t i = 0; i < wa.n; i++) {
      if (out_a[i] != out_b[i]) {
        report("%s/%s | %s | %zu bytes: answer byte %zu is left over poison (0x%02x against 0x%02x), so "
               "the parser did not define it",
               corpus, name, FUZZ_OP_NAMES[op], m, i, out_a[i], out_b[i]);
      }
    }
    if (!writable_input && memcmp(source, in_a, m) != 0) {
      report("%s/%s | %s: the parser wrote into the bytes it was given", corpus, name, FUZZ_OP_NAMES[op]);
    }
  }
}

static void fuzz_hex(const char* corpus, const char* name, const char* hex, uint16_t a, uint16_t b,
                     driver_fn drv, int writable_input) {
  const size_t len = test_unhex(hex, base, sizeof(base));
  if (len >= sizeof(base)) {
    snprintf(message, sizeof(message), "%s/%s: vector does not fit the fuzz buffer", corpus, name);
    TEST_FAIL_MESSAGE(message);
  }
  fuzz_one(corpus, name, len, a, b, drv, writable_input);
}

static void fuzz_bytes(const char* corpus, const char* name, const uint8_t* bytes, size_t len,
                       driver_fn drv) {
  if (len >= sizeof(base)) {
    snprintf(message, sizeof(message), "%s/%s: vector does not fit the fuzz buffer", corpus, name);
    TEST_FAIL_MESSAGE(message);
  }
  memcpy(base, bytes, len);
  fuzz_one(corpus, name, len, 0, 0, drv, false);
}

/* ------------------------------------------------------------------ the corpora */

static void corpus_row(char* out, size_t cap, size_t index, const char* row) {
  snprintf(out, cap, "%zu:%s", index, row);
}

void setUp(void) {}

void tearDown(void) {}

static void test_fuzz_card_replies(void) {
  char name[192];

  for (size_t i = 0; i < DER_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, DER_CASES[i].comment);
    fuzz_hex("der", name, DER_CASES[i].hex, 0, 0, drv_der, false);
  }
  for (size_t i = 0; i < TLV_HEADER_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, TLV_HEADER_CASES[i].comment);
    fuzz_hex("tlv header", name, TLV_HEADER_CASES[i].hex, 0, 0, drv_tlv_header, false);
  }
  for (size_t i = 0; i < TLV_READ_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, TLV_READ_CASES[i].comment);
    fuzz_hex("tlv read", name, TLV_READ_CASES[i].hex, TLV_READ_CASES[i].tag, TLV_READ_CASES[i].max_len,
             drv_tlv_read, false);
  }
  for (size_t i = 0; i < TLV_FIXED_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, TLV_FIXED_CASES[i].comment);
    fuzz_hex("tlv fixed", name, TLV_FIXED_CASES[i].hex, TLV_FIXED_CASES[i].tag, TLV_FIXED_CASES[i].want_len,
             drv_tlv_fixed, false);
  }
  for (size_t i = 0; i < APP_INFO_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, APP_INFO_CASES[i].comment);
    fuzz_hex("application info", name, APP_INFO_CASES[i].response, 0, 0, drv_app_info, false);
  }
  for (size_t i = 0; i < APP_STATUS_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, APP_STATUS_CASES[i].comment);
    fuzz_hex("application status", name, APP_STATUS_CASES[i].response, 0, 0, drv_app_status, false);
  }
  for (size_t i = 0; i < SIGN_REPLY_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, SIGN_REPLY_CASES[i].comment);
    fuzz_hex("sign reply", name, SIGN_REPLY_CASES[i].hex, SIGN_REPLY_CASES[i].algo, 0, drv_sign_reply,
             false);
  }
  for (size_t i = 0; i < BTC_SIG_CASES_COUNT; i++) {
    corpus_row(name, sizeof(name), i, BTC_SIG_CASES[i].comment);
    fuzz_hex("btc sig record", name, BTC_SIG_CASES[i].hex, BTC_SIG_CASES[i].algo, BTC_SIG_CASES[i].sighash,
             drv_btc_sig, true);
  }
}

static void test_fuzz_wire(void) {
  char name[192];

  for (size_t i = 0; i < PSBT_VECTOR_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_VECTORS[i].name);
    fuzz_hex("psbt", name, PSBT_VECTORS[i].psbt, 0, 0, drv_psbt, true);
  }
  for (size_t i = 0; i < PSBT_SIGNER_REJECT_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_SIGNER_REJECTS[i].name);
    fuzz_hex("psbt signer rejects", name, PSBT_SIGNER_REJECTS[i].psbt, 0, 0, drv_psbt, true);
  }
  for (size_t i = 0; i < PSBT_REJECTED_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_REJECTED[i].name);
    fuzz_hex("psbt rejected", name, PSBT_REJECTED[i].psbt, 0, 0, drv_psbt, true);
  }
  for (size_t i = 0; i < PSBT_FIELD_INVALID_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_FIELD_INVALID[i].name);
    fuzz_hex("psbt invalid field", name, PSBT_FIELD_INVALID[i].psbt, 0, 0, drv_psbt, true);
  }
  for (size_t i = 0; i < PSBT_CTX_CASE_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_CTX_CASES[i].name);
    fuzz_bytes("psbt context", name, PSBT_CTX_CASES[i].psbt, PSBT_CTX_CASES[i].psbt_len, drv_psbt_ctx);
  }
  for (size_t i = 0; i < PSBT_CTX_RECORD_COUNT; i++) {
    corpus_row(name, sizeof(name), i, PSBT_CTX_RECORDS[i].name);
    fuzz_bytes("psbt records", name, PSBT_CTX_RECORDS[i].psbt, PSBT_CTX_RECORDS[i].psbt_len, drv_psbt_ctx);
  }
  static const struct {
    const char* where;
    uint16_t capacity;
  } payloads[] = {{"nowhere", ETH_NOWHERE}, {"full", ETH_FULL}, {"tight", ETH_TIGHT}};

  for (size_t i = 0; i < ETH_TX_CASES_COUNT; i++) {
    for (size_t p = 0; p < sizeof(payloads) / sizeof(payloads[0]); p++) {
      snprintf(name, sizeof(name), "%zu:%s payload %s", i, eth_tx_cases[i].name, payloads[p].where);
      fuzz_hex("eth tx", name, eth_tx_cases[i].rlp_hex, payloads[p].capacity, 0, drv_eth, false);
    }
  }
  for (size_t i = 0; i < ETH_REJECT_CASES_COUNT; i++) {
    for (size_t p = 0; p < sizeof(payloads) / sizeof(payloads[0]); p++) {
      snprintf(name, sizeof(name), "%zu:%s payload %s", i, eth_reject_cases[i].name, payloads[p].where);
      fuzz_hex("eth rejected", name, eth_reject_cases[i].rlp_hex, payloads[p].capacity, 0, drv_eth, false);
    }
  }
  for (size_t i = 0; i < TX_ID_VECTOR_COUNT; i++) {
    corpus_row(name, sizeof(name), i, TX_ID_VECTORS[i].name);
    fuzz_bytes("transaction", name, TX_ID_VECTORS[i].tx, TX_ID_VECTORS[i].tx_len, drv_tx);
  }
  for (size_t i = 0; i < TX_REJECT_VECTOR_COUNT; i++) {
    corpus_row(name, sizeof(name), i, TX_REJECT_VECTORS[i].name);
    fuzz_bytes("transaction rejected", name, TX_REJECT_VECTORS[i].tx, TX_REJECT_VECTORS[i].tx_len, drv_tx);
  }
}

/* A seed that found something stays in the list, so that the defect cannot come back quietly.
 * 0x...07 is the stream that reported the signed left shift in rlpDecodeLength(). */
static const uint64_t FUZZ_SEEDS[] = {0x656e74726f7079ULL, 0x7ULL, 0xdeadbeefULL, 0xabcdef0123456789ULL};

int main(void) {
  const char* env = getenv("FUZZ_SEED");
  verbose = getenv("FUZZ_VERBOSE") != NULL;

  UNITY_BEGIN();
  if (env != NULL) {
    seed_in_use = strtoull(env, NULL, 0);
    rng_state = seed_in_use;
    RUN_TEST(test_fuzz_card_replies);
    rng_state = seed_in_use ^ 0x9e3779b97f4a7c15ULL;
    RUN_TEST(test_fuzz_wire);
  } else {
    for (size_t i = 0; i < sizeof(FUZZ_SEEDS) / sizeof(FUZZ_SEEDS[0]); i++) {
      seed_in_use = FUZZ_SEEDS[i];
      rng_state = seed_in_use;
      RUN_TEST(test_fuzz_card_replies);
      rng_state = seed_in_use ^ 0x9e3779b97f4a7c15ULL;
      RUN_TEST(test_fuzz_wire);
    }
  }
  const int result = UNITY_END();
  printf("%zu seeds, %zu inputs, %zu parser calls\n", env != NULL ? 1 : sizeof(FUZZ_SEEDS) / sizeof(FUZZ_SEEDS[0]),
         inputs_seen, calls_made);
  return result;
}
