/* What the device takes an EIP-712 typed message to be.
 *
 * The device is a signer: a dapp sends a JSON document and the device hands the card the 32 bytes
 * a contract will check. Everything that decides those bytes arrives from outside, and a document
 * that hashes to something other than what the dapp computed produces a signature over content the
 * user never saw, or one nobody accepts.
 *
 * The expectations in vectors/vectors_eip712.h are MetaMask's eth-sig-util's, from its own fixture
 * and a run of the released package. That implementation is what the dapps feeding this device run,
 * and therefore what the verifying contract agrees with; the EIP leaves the interesting cases open:
 * a value of the wrong JSON type, a number outside its type's range, a `bytes` without its 0x, the
 * order in which a struct's referenced types are appended.
 *
 * The digest is what is compared, because the digest is what is signed: the domain separator and
 * the message hash go into one hash context, so a wrong encoding anywhere in either changes the 32
 * bytes. A document the reference refuses has to be refused here, since signing it would commit the
 * card to something no verifier can reproduce. */

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "crypto/sha3.h"
#include "error.h"
#include "ethereum/eip712.h"
#include "ethereum/eth_data.h"
#include "mem.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_eip712.h"

/* Half the heap the device hands the flow, which is what is left once the document is in it. */
#define HEAP_SIZE (MEM_HEAP_SIZE / 2)

static uint8_t heap[HEAP_SIZE];

void setUp(void) {}

void tearDown(void) {}

/* The flow core_eth_process_eip712() runs: the 0x19 0x01 prefix, then the document, then the
 * digest. The document is copied to an array of exactly its length first, so that a read past the
 * end of it is a read past the end of an addressed buffer. */
static app_err_t sign_flow(const char* json, size_t json_len, eip712_ctx_t* ctx, uint8_t out[32]) {
  char doc[json_len + 1];
  memcpy(doc, json, json_len);

  SHA3_CTX sha3;
  static const uint8_t magic[] = {0x19, 0x01};

  memset(ctx, 0, sizeof(*ctx));
  keccak_256_Init(&sha3);
  keccak_Update(&sha3, magic, sizeof(magic));
  app_err_t err = eip712_hash(ctx, &sha3, heap, sizeof(heap), doc, json_len);
  keccak_Final(&sha3, out);
  return err;
}

/* test_hex hands back one shared buffer, so the two sides of a comparison are copied out before
 * they are printed -- otherwise both lines show the same digest. */
static char* copy_hex(const uint8_t* digest, char out[65]) {
  strcpy(out, test_hex(digest, 32));
  return out;
}

/* One assert per case would stop at the first difference, and the worth of this table is the whole
 * set of them at once. */
static void test_reference_digests(void) {
  eip712_ctx_t ctx;
  uint8_t digest[32];
  char got[65], want[65];
  int failures = 0;

  for (size_t i = 0; i < EIP712_CASES_COUNT; i++) {
    const eip712_case_t* c = &EIP712_CASES[i];
    app_err_t err = sign_flow(c->json, strlen(c->json), &ctx, digest);

    if (!c->ok) {
      if (err == ERR_OK) {
        failures++;
        printf("%s accepted, reference refuses: %s\n  device %s\n", c->name, c->note,
             copy_hex(digest, got));
      }

      continue;
    }

    if (err != ERR_OK) {
      failures++;
      printf("%s refused (%d), reference digests %s\n", c->name, err, copy_hex(c->digest, want));
      continue;
    }

    if (memcmp(digest, c->digest, sizeof(digest)) != 0) {
      failures++;
      printf("%s\n  device    %s\n  reference %s\n  document  %s\n", c->name, copy_hex(digest, got),
             copy_hex(c->digest, want), c->json);
    }
  }

  printf("%u of %u documents differ from the reference\n", (unsigned) failures,
         (unsigned) EIP712_CASES_COUNT);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, failures, "device and eth-sig-util disagree; see above");
}

/* eip712_to_string writes over however much of the buffer it needs and says how much; terminating
 * it is the caller's doing. */
static const char* render(const eip712_ctx_t* ctx, uint8_t* out) {
  out[eip712_to_string(ctx, out)] = '\0';
  return (const char*) out;
}

/* What the user is shown comes out of the same tokens as what is signed, so the rendering is worth
 * pinning in its own right: every member of the message has to appear, in the document's order, and
 * nested members have to be distinguishable from the ones they sit in. The text is the document's
 * own, escapes and all, which is what makes the reference's decoding of a `\u` escape visible. */
static void test_display(void) {
  eip712_ctx_t ctx;
  uint8_t digest[32];
  uint8_t out[1024];

  /* A message is only hashed when its type is declared, so each document carries its own table. */
  static const char* flat =
      "{\"types\":{\"EIP712Domain\":[],\"M\":["
      "{\"name\":\"a\",\"type\":\"string\"},{\"name\":\"b\",\"type\":\"uint256\"},"
      "{\"name\":\"c\",\"type\":\"bool\"},{\"name\":\"d\",\"type\":\"string\"}],"
      "\"N\":[{\"name\":\"a\",\"type\":\"uint256\"}]},"
      "\"primaryType\":\"M\",\"domain\":{},"
      "\"message\":{\"a\":\"1\",\"b\":2,\"c\":true,\"d\":null}}";
  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(flat, strlen(flat), &ctx, digest));
  TEST_ASSERT_EQUAL_STRING("a: 1\nb: 2\nc: true\nd: null\n", render(&ctx, out));

  static const char* nested =
      "{\"types\":{\"EIP712Domain\":[],\"N\":[{\"name\":\"a\",\"type\":\"uint256\"}],\"M\":["
      "{\"name\":\"n\",\"type\":\"uint256\"},{\"name\":\"m\",\"type\":\"N\"},"
      "{\"name\":\"xs\",\"type\":\"uint256[]\"}]},"
      "\"primaryType\":\"M\",\"domain\":{},\"message\":{\"n\":1,\"m\":{\"a\":2},\"xs\":[1,2]}}";
  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(nested, strlen(nested), &ctx, digest));
  TEST_ASSERT_EQUAL_STRING("n: 1\nm: {\n\ta: 2\n}\nxs: [\n\t1\n\t2\n]\n", render(&ctx, out));

  static const char* escaped =
      "{\"types\":{\"EIP712Domain\":[],\"M\":[{\"name\":\"v\",\"type\":\"string\"}]},"
      "\"primaryType\":\"M\",\"domain\":{},\"message\":{\"v\":\"a\\u0041b\"}}";
  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(escaped, strlen(escaped), &ctx, digest));
  TEST_ASSERT_EQUAL_STRING("v: a\\u0041b\n", render(&ctx, out));
  /* Rendering again gives the same text: the dialog shows the message on one screen and hashes it
   * on the next, so the first pass may not consume what the second needs. */
  TEST_ASSERT_EQUAL_STRING("v: a\\u0041b\n", render(&ctx, out));
}

/* The dialog reads the domain out of the document to say what the signature is for, and dispatches
 * on the primary type. */
static void test_domain_read_out(void) {
  eip712_ctx_t ctx;
  uint8_t digest[32];
  char name[EIP712_MAX_NAME_LEN];  /* the row the dialog shows it in */
  uint8_t value[32];

  static const char* doc = "{\"types\":{"
                           "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},"
                           "{\"name\":\"chainId\",\"type\":\"uint256\"},"
                           "{\"name\":\"verifyingContract\",\"type\":\"address\"}],"
                           "\"M\":[{\"name\":\"n\",\"type\":\"uint256\"}]},"
                           "\"primaryType\":\"M\",\"domain\":{\"chainId\":1,\"name\":\"Ether Mail\","
                           "\"verifyingContract\":\"0x0102030405060708090a0b0c0d0e0f1011121314\"},"
                           "\"message\":{\"n\":1}}";
  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(doc, strlen(doc), &ctx, digest));

  /* A number in front of the name is a member like any other: it neither stops the search nor is
   * mistaken for the name itself. */
  TEST_ASSERT_EQUAL_INT(ERR_OK, eip712_extract_string(&ctx, ctx.index.domain, "name", name, sizeof(name)));
  TEST_ASSERT_EQUAL_STRING("Ether Mail", name);

  TEST_ASSERT_EQUAL_INT(ERR_OK, eip712_extract_uint256(&ctx, ctx.index.domain, "chainId", value));
  TEST_ASSERT_EQUAL_HEX8(1, value[31]);
  for (int i = 0; i < 31; i++) {
    TEST_ASSERT_EQUAL_HEX8(0, value[i]);
  }

  uint32_t len = sizeof(value);
  TEST_ASSERT_EQUAL_INT(ERR_OK, eip712_extract_bytes(&ctx, ctx.index.domain, "verifyingContract", value, &len));
  TEST_ASSERT_EQUAL_INT(20, len);
  TEST_ASSERT_EQUAL_HEX8_ARRAY((const uint8_t*) "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
                                                "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14", value, 20);

  int primary = eip712_find_field(&ctx, 0, "primaryType");
  TEST_ASSERT_TRUE(primary != -1);
  TEST_ASSERT_TRUE(eip712_field_eq(&ctx, primary, "M"));
  TEST_ASSERT_FALSE(eip712_field_eq(&ctx, primary, "Mail"));

  /* A key the document does not carry, and one that appears only as a value. */
  TEST_ASSERT_EQUAL(-1, eip712_find_field(&ctx, ctx.index.domain, "salt"));
  TEST_ASSERT_EQUAL_INT(ERR_DATA, eip712_extract_string(&ctx, ctx.index.domain, "version", name, sizeof(name)));
  TEST_ASSERT_EQUAL(-1, eip712_find_field(&ctx, ctx.index.message, "name"));
}

/* The name is shown in a fixed row of the dialog; the digest still commits to the whole thing, so
 * what the caller gets for a name longer than its buffer has to be defined rather than incidental. */
static void test_name_truncated_to_the_callers_buffer(void) {
  eip712_ctx_t ctx;
  uint8_t digest[32];
  char name[4];

  static const char* doc = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}]},"
                           "\"primaryType\":\"EIP712Domain\",\"domain\":{\"name\":\"a rather long "
                           "name\"},\"message\":{}}";
  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(doc, strlen(doc), &ctx, digest));
  TEST_ASSERT_EQUAL_INT(ERR_OK, eip712_extract_string(&ctx, ctx.index.domain, "name", name, sizeof(name)));
  TEST_ASSERT_EQUAL_STRING("a r", name);
}

/* The document and the parse of it share the heap the caller hands over, so the failure mode of a
 * document too big for what is left has to be a refusal at every size, not a write past the end. */
static void test_refused_when_the_heap_is_too_small(void) {
  eip712_ctx_t ctx;
  uint8_t digest[32];
  uint8_t small[512];

  static const char* doc = "{\"types\":{\"EIP712Domain\":[],\"M\":[{\"name\":\"n\",\"type\":\"uint256\"}]},"
                           "\"primaryType\":\"M\",\"domain\":{},\"message\":{\"n\":1}}";

  for (size_t size = 0; size <= sizeof(small); size += 7) {
    app_err_t err = eip712_hash(&ctx, &(SHA3_CTX){0}, small, size, doc, strlen(doc));
    TEST_ASSERT_EQUAL_MESSAGE(ERR_DATA, err, "a heap that cannot hold the parse must stop the flow");
  }

  TEST_ASSERT_EQUAL_INT(ERR_OK, sign_flow(doc, strlen(doc), &ctx, digest));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_reference_digests);
  RUN_TEST(test_display);
  RUN_TEST(test_domain_read_out);
  RUN_TEST(test_name_truncated_to_the_callers_buffer);
  RUN_TEST(test_refused_when_the_heap_is_too_small);
  return UNITY_END();
}
