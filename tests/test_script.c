/*
 * This file is part of ShellOS.
 *
 * Copyright (c) 2024, 2025 SideNote, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Every output a transaction can pay to, from a PSBT, arrives as bytes written by whatever built it.
 * This firmware reads those bytes to decide two things: what shape the output has, and what address to
 * show a person approving the payment. A shape wrong in the safe direction makes a payment
 * unspendable; wrong in the other, it puts an address on the screen that belongs to nobody the sender
 * intended.
 *
 * Both expectations come from outside app/crypto/script.c. The address for each row is published beside
 * the script it renders from -- Bitcoin Core's key_io vectors, the BIP-173 and BIP-350 appendices,
 * BIP-86's worked examples -- and the shape is derived from the BIP templates and cross-checked against
 * those pairs while generating. A row therefore makes two independent claims, one about the classifier
 * and one about the formatter, and neither restates what the code here does: a row can pass one and fail
 * the other, and then the two halves of the device disagree about what the output is.
 *
 * The rows without an address are most of what is here. Witness programs of version 2 through 16 are
 * real outputs and Core publishes addresses for some of them; this device renders none of them and must
 * say so rather than produce a bech32 string of a shape it cannot justify. Same for the single-byte
 * mutations: a script whose leading byte moved by one is no longer anything, and the answer to "what
 * address is this" is not an address. An output that classifies as nothing is the caller's problem --
 * what is tested here is that this function does not guess.
 */

#include <string.h>

#include "crypto/address.h"
#include "crypto/script.h"

#include "framework/test_util.h"
#include "vectors/vectors_script.h"

/* Room for the longest scriptPubKey in the table -- a bare multisig -- and for the rows built by
 * adding a byte to one. */
#define SCRIPT_BUF_LEN 128

void setUp(void) {}

void tearDown(void) {}

static void test_script_addresses(void) {
  /* Poisoned to a string no address can be, and re-checked after every refusal: a script this function
   * declines must leave nothing behind for a screen to display. */
  char out[MAX_ADDR_LEN];

  for (size_t i = 0; i < SCRIPT_CASE_COUNT; i++) {
    const script_case_t *row = &SCRIPT_CASES[i];
    uint8_t script[SCRIPT_BUF_LEN];
    const size_t len = test_unhex(row->script, script, sizeof(script));
    TEST_ASSERT_TRUE_MESSAGE(len < sizeof(script), row->name);

    memset(out, 'Z', sizeof(out));
    const int got = script_output_to_address(script, len, out);

    /* What the return means differs by branch -- the base58 path returns the character count, the
     * bech32 path a flag -- and every caller in the firmware tests it only for zero or nonzero. So
     * truthiness is the contract, and the string is what a person is actually shown. */
    if (row->address == NULL) {
      TEST_ASSERT_EQUAL_MESSAGE(0, got, row->name);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE('Z', out[0], row->name);
    } else {
      TEST_ASSERT_TRUE_MESSAGE(got != 0, row->name);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(row->address, out, row->name);
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(row->address, out, strlen(row->address) + 1, row->name);
    }

    /* Nothing past the end of the reply is touched -- MAX_ADDR_LEN is the buffer's size and the caller
     * is entitled to the rest of it either way. */
    TEST_ASSERT_EQUAL_UINT8_MESSAGE('Z', out[sizeof(out) - 1], row->name);

    /* All five predicates are checked on every row, not only the one whose bit is set: a script that is
     * P2PKH and also satisfies P2WPKH would reach two renderings, and one that matches nothing must
     * match nothing. It matters that this is separate from the address above -- segwit_addr_encode()
     * refuses a version 0 program that is not 20 or 32 bytes, so a predicate that stopped checking a
     * length or a version can still refuse to render, and only this claim sees it. */
    TEST_ASSERT_EQUAL_MESSAGE(0 != (row->classes & SCRIPT_P2PKH), script_is_p2pkh(script, len), row->name);
    TEST_ASSERT_EQUAL_MESSAGE(0 != (row->classes & SCRIPT_P2SH), script_is_p2sh(script, len), row->name);
    TEST_ASSERT_EQUAL_MESSAGE(0 != (row->classes & SCRIPT_P2WPKH), script_is_p2wpkh(script, len), row->name);
    TEST_ASSERT_EQUAL_MESSAGE(0 != (row->classes & SCRIPT_P2WSH), script_is_p2wsh(script, len), row->name);
    TEST_ASSERT_EQUAL_MESSAGE(0 != (row->classes & SCRIPT_P2TR), script_is_p2tr(script, len), row->name);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_script_addresses);
  return UNITY_END();
}
