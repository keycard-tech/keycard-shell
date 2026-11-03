#include <stdlib.h>
#include <string.h>

#include "crypto/addr_uri.h"
#include "framework/test_util.h"
#include "unity.h"
#include "vectors/vectors_addr_uri.h"

/* address_uri_parse() decides whether a scanned string may be acted on at all, and which address
 * the rest of the firmware will look at. The rows are the URIs BIP-21 and ERC-681 publish plus the
 * shapes that decide a refusal; what the splitter is not asked to do is judge whether the target
 * is an address -- that is the decoder's job, and several rows are accepted precisely so that the
 * decoder is the one to say no. */

typedef struct {
  addr_uri_t uri;
  uint8_t canary[16];
} guarded_t;

static guarded_t guarded;

void setUp(void) {
  memset(&guarded, 0, sizeof(guarded));
  memset(guarded.uri.address, 0x27, sizeof(guarded.uri.address));
  memset(guarded.canary, 0xA5, sizeof(guarded.canary));
}

void tearDown(void) {}

static void test_uri_cases(void) {
  for (size_t i = 0; i < ADDR_URI_CASES_COUNT; i++) {
    const addr_uri_case_t* v = &ADDR_URI_CASES[i];

    memset(&guarded, 0, sizeof(guarded));
    memset(guarded.uri.address, 0x27, sizeof(guarded.uri.address));

    const int accepted = address_uri_parse(v->uri, strlen(v->uri), &guarded.uri);

    TEST_ASSERT_EQUAL_INT_MESSAGE(v->accept, accepted, v->uri);
    if (!v->accept) {
      continue;
    }

    TEST_ASSERT_EQUAL_UINT_MESSAGE(v->scheme, guarded.uri.scheme, v->uri);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(v->address, guarded.uri.address, v->uri);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(v->index, guarded.uri.index, v->uri);
  }
}

/* Nothing is written outside the struct, whatever the input -- the target copy is the one place a
 * long URI could run past what the caller reserved. */
static void test_never_writes_past_the_struct(void) {
  for (size_t i = 0; i < ADDR_URI_CASES_COUNT; i++) {
    const addr_uri_case_t* v = &ADDR_URI_CASES[i];

    memset(&guarded, 0, sizeof(guarded));
    memset(guarded.canary, 0xA5, sizeof(guarded.canary));
    address_uri_parse(v->uri, strlen(v->uri), &guarded.uri);

    for (size_t pos = 0; pos < sizeof(guarded.canary); pos++) {
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xA5, guarded.canary[pos], v->uri);
    }
  }
}

/* Before the target is reached the module writes only scheme and index, so the target field is
 * left exactly as the caller left it; nothing is half-written. After the target has been copied the
 * query is what fails, and by then the field holds a plausible address -- the return value is the
 * only thing a caller may act on. */
static void test_refusal_leaves_no_target(void) {
  static const char* before[] = {"", "   ", "\t\r\n", ":", "http://example.com/", "bitcoin:",
                                 "bitcoin:?index=1"};
  static const char* after[] = {"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-x=1",
                                "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W#donate",
                                "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?lightning=lnbc1"};

  for (size_t i = 0; i < sizeof(before) / sizeof(before[0]); i++) {
    memset(&guarded, 0, sizeof(guarded));
    memset(guarded.uri.address, 0x27, sizeof(guarded.uri.address));

    TEST_ASSERT_FALSE_MESSAGE(address_uri_parse(before[i], strlen(before[i]), &guarded.uri),
                              before[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0x27, (unsigned char) guarded.uri.address[0], before[i]);
  }

  /* These are refused because of what follows the target, which has already been copied by then.
   * A caller that looked at the field instead of the verdict would see a plausible address, which
   * is why the return value is the whole answer. */
  for (size_t i = 0; i < sizeof(after) / sizeof(after[0]); i++) {
    memset(&guarded, 0, sizeof(guarded));

    TEST_ASSERT_FALSE_MESSAGE(address_uri_parse(after[i], strlen(after[i]), &guarded.uri),
                              after[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W", guarded.uri.address,
                                     after[i]);
  }
}

/* in is not required to be terminated: only in_len bytes are read. A heap buffer of exactly that
 * size makes any read past the end an ASan report, and slicing a longer string shows the tail is
 * genuinely ignored rather than found by scanning for a terminator. */
static void test_reads_only_in_len(void) {
  static const struct {
    const char* uri;
    const char* address;
  } cases[] = {
    {"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W", "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"},
    {"ethereum:0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359?value=2.014e18",
     "0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359"},
    {"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?index=12",
     "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const size_t len = strlen(cases[i].uri);
    char* exact = malloc(len);
    TEST_ASSERT_NOT_NULL(exact);
    memcpy(exact, cases[i].uri, len);

    memset(&guarded, 0, sizeof(guarded));
    TEST_ASSERT_TRUE(address_uri_parse(exact, len, &guarded.uri));
    TEST_ASSERT_EQUAL_STRING(cases[i].address, guarded.uri.address);
    free(exact);
  }

  static const char* longer = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?index=3?JUNK";
  const size_t used = strlen("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?index=3");

  memset(&guarded, 0, sizeof(guarded));
  TEST_ASSERT_TRUE(address_uri_parse(longer, used, &guarded.uri));
  TEST_ASSERT_EQUAL_STRING("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W", guarded.uri.address);
  TEST_ASSERT_EQUAL_UINT32(3, guarded.uri.index);
}

/* Both fields are set on entry, so a failed parse cannot leave the previous one's answer in a
 * reused struct. */
static void test_fields_reset_on_entry(void) {
  memset(&guarded, 0, sizeof(guarded));
  /* '@' after an ethereum target is ERC-681's chain id, not keycard's index: the two coexist, and
   * only the query one narrows the search. */
  const char* uri = "ethereum:0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359@1?index=7";
  TEST_ASSERT_TRUE(address_uri_parse(uri, strlen(uri), &guarded.uri));
  TEST_ASSERT_EQUAL_UINT(ADDR_URI_ETHEREUM, guarded.uri.scheme);
  TEST_ASSERT_EQUAL_STRING("0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359", guarded.uri.address);
  TEST_ASSERT_EQUAL_UINT32(7, guarded.uri.index);

  memset(&guarded, 0, sizeof(guarded));
  memset(guarded.uri.address, 0x27, sizeof(guarded.uri.address));
  TEST_ASSERT_FALSE(address_uri_parse("", 0, &guarded.uri));
  TEST_ASSERT_EQUAL_UINT(ADDR_URI_NONE, guarded.uri.scheme);
  TEST_ASSERT_EQUAL_UINT32(ADDR_URI_INDEX_NONE, guarded.uri.index);
}

/* The longest target that still fits, stored in full and terminated. */
static void test_longest_target(void) {
  char uri[8 + MAX_ADDR_LEN + 1];
  char want[MAX_ADDR_LEN + 1];

  memset(uri, 0, sizeof(uri));
  strcpy(uri, "bitcoin:");
  memset(uri + 8, '1', MAX_ADDR_LEN - 1);
  memset(want, '1', MAX_ADDR_LEN - 1);

  memset(&guarded, 0, sizeof(guarded));
  TEST_ASSERT_TRUE(address_uri_parse(uri, strlen(uri), &guarded.uri));
  TEST_ASSERT_EQUAL_UINT(MAX_ADDR_LEN - 1, strlen(guarded.uri.address));
  TEST_ASSERT_EQUAL_STRING(want, guarded.uri.address);
  TEST_ASSERT_EQUAL_UINT('\0', guarded.uri.address[MAX_ADDR_LEN - 1]);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_uri_cases);
  RUN_TEST(test_never_writes_past_the_struct);
  RUN_TEST(test_refusal_leaves_no_target);
  RUN_TEST(test_reads_only_in_len);
  RUN_TEST(test_fields_reset_on_entry);
  RUN_TEST(test_longest_target);
  return UNITY_END();
}
