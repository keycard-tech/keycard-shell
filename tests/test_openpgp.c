#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/sha2.h"
#include "framework/test_util.h"
#include "openpgp/openpgp_packet.h"
#include "openpgp/openpgp_protocol.h"
#include "openpgp/openpgp_v4.h"
#include "unity.h"
#include "vectors/vectors_openpgp.h"

/* Every output buffer is sized for what the call is asked to produce, so a write past the end is a
 * sanitiser report and not a quiet overwrite of the next local. */
#define OUT_MAX 1024

static uint8_t out[OUT_MAX];
static uint8_t digest[OPENPGP_SHA256_LEN];
static uint8_t canonical[2 * OPENPGP_MESSAGE_MAX_LEN];
static uint8_t sig_fields[OPENPGP_V4_UID_CERT_SIG_FIELDS_LEN];
/* A body long enough that its length will not fit the two-octet field OpenPGP gives it. */
static uint8_t big_key[UINT16_MAX + 1];
static openpgp_cert_target_t target;
static openpgp_request_t request;

void setUp(void) {
  memset(out, 0, sizeof(out));
  memset(digest, 0, sizeof(digest));
  memset(canonical, 0, sizeof(canonical));
  memset(sig_fields, 0, sizeof(sig_fields));
  memset(&target, 0, sizeof(target));
  memset(&request, 0, sizeof(request));
  memset(big_key, 0, sizeof(big_key));
  big_key[0] = OPENPGP_VERSION_4;
}

void tearDown(void) {}

static void test_public_key_body(void) {
  size_t len = 0;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_public_key_body(OPENPGP_KEY_POINT,
                                                            sizeof(OPENPGP_KEY_POINT),
                                                            OPENPGP_CREATION_TIME, out, sizeof(out),
                                                            &len));
  TEST_ASSERT_EQUAL_INT(OPENPGP_KEY_BODY_LEN, (int)len);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_KEY_BODY, out, len);

  /* The point travels as an MPI, whose header counts significant bits, so a 65-octet uncompressed
   * point is 515 bits and not 520 -- RFC 4880 3.2 -- which is what GnuPG exported. */
  TEST_ASSERT_EQUAL_HEX16(515, ((uint16_t)out[12] << 8) | out[13]);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_KEY_POINT, &out[14], sizeof(OPENPGP_KEY_POINT));

  /* Exactly the size it needs holds it; one octet less does not. */
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_public_key_body(OPENPGP_KEY_POINT,
                                                            sizeof(OPENPGP_KEY_POINT),
                                                            OPENPGP_CREATION_TIME, out, len, &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_public_key_body(OPENPGP_KEY_POINT,
                                                             sizeof(OPENPGP_KEY_POINT),
                                                             OPENPGP_CREATION_TIME, out, len - 1,
                                                             &len));

  /* Only a full uncompressed point becomes a body. */
  static const uint8_t compressed[OPENPGP_SECP256K1_POINT_LEN] = {0x02};
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_public_key_body(compressed, sizeof(compressed),
                                                             OPENPGP_CREATION_TIME, out, sizeof(out),
                                                             &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_public_key_body(OPENPGP_KEY_POINT,
                                                             OPENPGP_SECP256K1_POINT_LEN - 1,
                                                             OPENPGP_CREATION_TIME, out, sizeof(out),
                                                             &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_public_key_body(NULL, OPENPGP_SECP256K1_POINT_LEN,
                                                             OPENPGP_CREATION_TIME, out, sizeof(out),
                                                             &len));
}

static void test_primary_key_fingerprint(void) {
  uint8_t fingerprint[OPENPGP_V4_FINGERPRINT_LEN];
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_primary_key_fingerprint(OPENPGP_KEY_BODY,
                                                              OPENPGP_KEY_BODY_LEN, fingerprint));
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_FINGERPRINT, fingerprint, sizeof(fingerprint));

  /* One octet changed is a different key. */
  uint8_t changed[OPENPGP_KEY_BODY_LEN];
  memcpy(changed, OPENPGP_KEY_BODY, sizeof(changed));
  changed[sizeof(changed) - 1] ^= 1;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_primary_key_fingerprint(changed, sizeof(changed), fingerprint));
  TEST_ASSERT_TRUE(memcmp(OPENPGP_FINGERPRINT, fingerprint, sizeof(fingerprint)) != 0);

  /* A body that is not a version 4 key, or has no length, has no fingerprint. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_primary_key_fingerprint(changed, 0, fingerprint));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_primary_key_fingerprint(NULL, OPENPGP_KEY_BODY_LEN,
                                                               fingerprint));
}

static void test_certification_data(void) {
  size_t len = 0;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                               OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                               OPENPGP_UID_LEN, out, sizeof(out),
                                                               &len));
  TEST_ASSERT_EQUAL_INT(OPENPGP_CERT_DATA_LEN, (int)len);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_DATA, out, len);

  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                               OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                               OPENPGP_UID_LEN, out, len, &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                                OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                                OPENPGP_UID_LEN, out, len - 1, &len));

  /* The key length goes into a two-octet field, so a body that will not fit it is refused instead of
   * hashed under a truncated length -- which would be a second identity with one fingerprint. */
  static uint8_t big_out[UINT16_MAX + 512];
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_certification_data(big_key, UINT16_MAX, OPENPGP_UID,
                                                               OPENPGP_UID_LEN, big_out,
                                                               sizeof(big_out), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(big_key, UINT16_MAX + 1, OPENPGP_UID,
                                                                OPENPGP_UID_LEN, big_out,
                                                                sizeof(big_out), &len));

  /* A capacity that cannot hold the framing itself, let alone the body, and one that holds the key
   * but not the user ID. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                                OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                                OPENPGP_UID_LEN, out, 2, &len));
  /* Room for the 0x99 framing but not for the key body it announces. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                                OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                                OPENPGP_UID_LEN, out,
                                                                2 + OPENPGP_KEY_BODY_LEN, &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                                OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                                OPENPGP_UID_LEN, out,
                                                                3 + OPENPGP_KEY_BODY_LEN + 4, &len));

  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(NULL, OPENPGP_KEY_BODY_LEN,
                                                                OPENPGP_UID, OPENPGP_UID_LEN, out,
                                                                sizeof(out), &len));
  /* An empty user ID is not an identity to review. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_certification_data(OPENPGP_KEY_BODY,
                                                                OPENPGP_KEY_BODY_LEN, NULL, 0, out,
                                                                sizeof(out), &len));
}

static void test_certification_digest(void) {
  /* GnuPG recorded the first two octets of this hash in its own signature, and coincurve checked
   * that the signature verifies over the whole of it under an independent ECDSA implementation. */
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_digest(OPENPGP_CERT_DATA, OPENPGP_CERT_DATA_LEN,
                                             OPENPGP_CERT_MATERIAL, OPENPGP_CERT_MATERIAL_LEN,
                                             digest));
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_DIGEST, digest, sizeof(digest));

  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_digest(NULL, OPENPGP_CERT_DATA_LEN, OPENPGP_CERT_MATERIAL,
                                              OPENPGP_CERT_MATERIAL_LEN, digest));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_digest(OPENPGP_CERT_DATA, OPENPGP_CERT_DATA_LEN, NULL,
                                              OPENPGP_CERT_MATERIAL_LEN, digest));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_digest(OPENPGP_CERT_DATA, OPENPGP_CERT_DATA_LEN,
                                              OPENPGP_CERT_MATERIAL, 0, digest));

  /* Only a version 4 signature header defines this hash. */
  uint8_t v3[OPENPGP_CERT_MATERIAL_LEN];
  memcpy(v3, OPENPGP_CERT_MATERIAL, sizeof(v3));
  v3[0] = 3;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_digest(OPENPGP_CERT_DATA, OPENPGP_CERT_DATA_LEN, v3,
                                              sizeof(v3), digest));

  /* One octet more of user ID is a different identity, and therefore a different hash, with the
   * framing around it otherwise untouched. */
  uint8_t longer[3 + OPENPGP_KEY_BODY_LEN + 5 + OPENPGP_UID_LEN + 1];
  memcpy(longer, OPENPGP_CERT_DATA, OPENPGP_CERT_DATA_LEN);
  longer[OPENPGP_CERT_DATA_LEN] = '!';
  uint8_t other[OPENPGP_SHA256_LEN];
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_digest(longer, sizeof(longer), OPENPGP_CERT_MATERIAL,
                                             OPENPGP_CERT_MATERIAL_LEN, other));
  TEST_ASSERT_TRUE(memcmp(digest, other, sizeof(digest)) != 0);
}

static void test_sig_fields(void) {
  size_t len = 0;

  /* RFC 4880 5.2.3 puts version, signature type, public-key algorithm and hash algorithm in the
   * first four octets. GnuPG's own signatures say what this device's have to say: 04 01 13 08 for a
   * canonical text signature and 04 13 13 08 for a positive certification, ECDSA over SHA-256. */
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_sig_fields(OPENPGP_FINGERPRINT, OPENPGP_CREATION_TIME,
                                                       sig_fields, sizeof(sig_fields), &len));
  TEST_ASSERT_EQUAL_INT(OPENPGP_V4_SIG_FIELDS_LEN, (int)len);
  TEST_ASSERT_EQUAL_MEMORY(&OPENPGP_TEXTS[0].material, sig_fields, 4);
  TEST_ASSERT_EQUAL_HEX8(OPENPGP_SIG_TYPE_CANONICAL_TEXT, sig_fields[1]);
  TEST_ASSERT_EQUAL_HEX8(OPENPGP_SIG_HASHED_SUBPACKETS_LEN, sig_fields[5]);

  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_uid_cert_sig_fields(OPENPGP_FINGERPRINT,
                                                                OPENPGP_CREATION_TIME, sig_fields,
                                                                sizeof(sig_fields), &len));
  TEST_ASSERT_EQUAL_INT(OPENPGP_V4_UID_CERT_SIG_FIELDS_LEN, (int)len);
  TEST_ASSERT_EQUAL_MEMORY(&OPENPGP_CERT_MATERIAL, sig_fields, 4);
  TEST_ASSERT_EQUAL_HEX8(OPENPGP_SIG_TYPE_POSITIVE_CERT, sig_fields[1]);
  TEST_ASSERT_EQUAL_HEX8(OPENPGP_UID_CERT_HASHED_SUBPACKETS_LEN, sig_fields[5]);

  /* Two subpackets a real certification carries as well, byte for byte as GnuPG wrote them: the
   * issuer fingerprint, whose body is the fingerprint above, and the creation time, whose body is
   * the second the key was born. */
  TEST_ASSERT_TRUE(memmem(sig_fields, len, OPENPGP_CREATION_SUBPACKET,
                          OPENPGP_CREATION_SUBPACKET_LEN) != NULL);
  TEST_ASSERT_TRUE(memmem(sig_fields, len, OPENPGP_FINGERPRINT_SUBPACKET,
                          OPENPGP_FINGERPRINT_SUBPACKET_LEN) != NULL);

  /* A key flags subpacket is what a certification adds to a message signature's hashed area:
   * RFC 4880 5.2.3.21, and 0x03 is certify plus sign. */
  static const uint8_t key_flags[] = {0x02, 0x1b, 0x03};
  TEST_ASSERT_EQUAL_MEMORY(key_flags, &sig_fields[OPENPGP_V4_SIG_FIELDS_LEN], sizeof(key_flags));

  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_sig_fields(OPENPGP_FINGERPRINT, OPENPGP_CREATION_TIME,
                                                       sig_fields, OPENPGP_V4_SIG_FIELDS_LEN, &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_sig_fields(OPENPGP_FINGERPRINT, OPENPGP_CREATION_TIME,
                                                        sig_fields, OPENPGP_V4_SIG_FIELDS_LEN - 1,
                                                        &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_sig_fields_for_type(OPENPGP_SIG_TYPE_CANONICAL_TEXT,
                                                                 OPENPGP_FINGERPRINT,
                                                                 OPENPGP_CREATION_TIME, sig_fields,
                                                                 sizeof(sig_fields), NULL));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_sig_fields_for_type(OPENPGP_SIG_TYPE_POSITIVE_CERT,
                                                                 OPENPGP_FINGERPRINT,
                                                                 OPENPGP_CREATION_TIME, NULL,
                                                                 sizeof(sig_fields), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_uid_cert_sig_fields(NULL, OPENPGP_CREATION_TIME,
                                                                 sig_fields, sizeof(sig_fields),
                                                                 &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_uid_cert_sig_fields(OPENPGP_FINGERPRINT,
                                                                 OPENPGP_CREATION_TIME, sig_fields,
                                                                 OPENPGP_V4_SIG_FIELDS_LEN, &len));
}

static void test_text_signatures(void) {
  for (size_t i = 0; i < OPENPGP_TEXTS_COUNT; i++) {
    char what[48];
    snprintf(what, sizeof(what), "text %u", (unsigned)i);
    size_t canonical_len = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, openpgp_v4_canonicalize_text(OPENPGP_TEXTS[i].message,
                                                                  OPENPGP_TEXTS[i].message_len,
                                                                  canonical, sizeof(canonical),
                                                                  &canonical_len),
                                  what);
    /* A buffer exactly the length it just produced is a usable buffer: the growth from LF to CRLF is
     * counted, not guessed at. */
    size_t same_len = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, openpgp_v4_canonicalize_text(OPENPGP_TEXTS[i].message,
                                                                  OPENPGP_TEXTS[i].message_len,
                                                                  canonical, canonical_len,
                                                                  &same_len),
                                  what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, openpgp_v4_digest(canonical, canonical_len,
                                                       OPENPGP_TEXTS[i].material,
                                                       OPENPGP_TEXTS[i].material_len, digest),
                                  what);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(OPENPGP_TEXTS[i].digest, digest, sizeof(digest), what);
  }
}

static void test_binary_signature(void) {
  /* A binary document signature covers the octets as they came; there is no canonicalization on
   * that path to get wrong. */
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_digest(OPENPGP_BINARY_MESSAGE, OPENPGP_BINARY_MESSAGE_LEN,
                                             OPENPGP_BINARY_MATERIAL, OPENPGP_BINARY_MATERIAL_LEN,
                                             digest));
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_BINARY_DIGEST, digest, sizeof(digest));
}

static void test_canonicalize(void) {
  size_t len = 0;

  /* A CR that does not begin a CRLF has no agreed meaning, so the message is refused. GnuPG signs
   * that octet through as ordinary text: the divergence is in the vectors, and this device is the
   * stricter of the two. */
  for (size_t i = 0; i < OPENPGP_CANONICAL_REFUSALS_COUNT; i++) {
    TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(OPENPGP_CANONICAL_REFUSALS[i],
                                                           OPENPGP_CANONICAL_REFUSAL_LENS[i],
                                                           canonical, sizeof(canonical), &len));
  }

  static const uint8_t lf[] = {'a', '\n', 'b', '\n'};
  static const uint8_t crlf[] = {'a', '\r', '\n', 'b', '\r', '\n'};
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_canonicalize_text(lf, sizeof(lf), canonical, sizeof(canonical),
                                                        &len));
  TEST_ASSERT_EQUAL_INT((int)sizeof(crlf), (int)len);
  TEST_ASSERT_EQUAL_MEMORY(crlf, canonical, len);

  /* Text that already arrives with CRLF passes through, which is what makes a host that sends LF and
   * a host that sends CRLF produce one signature rather than two. */
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_canonicalize_text(crlf, sizeof(crlf), canonical, sizeof(crlf),
                                                        &len));
  TEST_ASSERT_EQUAL_MEMORY(crlf, canonical, len);

  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(lf, sizeof(lf), canonical, sizeof(crlf) - 1,
                                                         &len));

  /* A CR as the last octet has nothing to pair with. */
  static const uint8_t trailing_cr[] = {'x', '\r'};
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(trailing_cr, sizeof(trailing_cr), canonical,
                                                         sizeof(canonical), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(NULL, 3, canonical, sizeof(canonical), &len));

  /* A buffer that cannot hold the next plain octet, not just the next line ending. */
  static const uint8_t two[] = {'a', 'b'};
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(two, sizeof(two), canonical, 1, &len));

  /* A zero-capacity buffer takes nothing but a valid empty message. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_canonicalize_text(two, sizeof(two), canonical, 0, &len));
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_canonicalize_text(two, 0, canonical, 1, &len));

  /* A trailing space is part of the text. RFC 4880 5.2.4 asks only for line endings to be converted,
   * and the text signatures above are GnuPG's over text with trailing blanks kept in. */
  static const uint8_t spaced[] = {'x', ' ', ' '};
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_canonicalize_text(spaced, sizeof(spaced), canonical,
                                                        sizeof(canonical), &len));
  TEST_ASSERT_EQUAL_INT((int)sizeof(spaced), (int)len);
  TEST_ASSERT_EQUAL_MEMORY(spaced, canonical, len);
}

static void test_signature_packet(void) {
  size_t fields_len = 0;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_sig_fields(OPENPGP_FINGERPRINT, OPENPGP_CREATION_TIME,
                                                       sig_fields, sizeof(sig_fields), &fields_len));

  size_t len = 0;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                             OPENPGP_CERT_DIGEST,
                                                             OPENPGP_CERT_RAW_SIG,
                                                             OPENPGP_ISSUER_KEY_ID, out, sizeof(out),
                                                             &len));
  /* New-format header, tag 2. */
  TEST_ASSERT_EQUAL_HEX8(0xc2, out[0]);
  TEST_ASSERT_EQUAL_INT((int)out[1], (int)len - 2);

  /* Everything after the hashed area, against what GnuPG put into its own certification: the unhashed
   * issuer-key-id block, the two octets of the signed hash, and the two MPIs. */
  TEST_ASSERT_TRUE(len >= 2 + fields_len + OPENPGP_CERT_TAIL_LEN);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_TAIL, &out[len - OPENPGP_CERT_TAIL_LEN],
                           OPENPGP_CERT_TAIL_LEN);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_DIGEST, &out[len - OPENPGP_CERT_TAIL_LEN + 12], 2);

  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                             OPENPGP_CERT_DIGEST,
                                                             OPENPGP_CERT_RAW_SIG,
                                                             OPENPGP_ISSUER_KEY_ID, out, len, &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                              OPENPGP_CERT_DIGEST,
                                                              OPENPGP_CERT_RAW_SIG,
                                                              OPENPGP_ISSUER_KEY_ID, out, len - 1,
                                                              &len));

  /* A component of zero is not a signature, and a zero-length MPI would be a lie about one -- on
   * either side of the pair. */
  static const uint8_t zero[OPENPGP_RAW_ECDSA_LEN] = {0};
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                              OPENPGP_CERT_DIGEST, zero,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), &len));
  uint8_t zero_s[OPENPGP_RAW_ECDSA_LEN];
  memcpy(zero_s, OPENPGP_CERT_RAW_SIG, sizeof(zero_s));
  memset(&zero_s[32], 0, 32);
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                              OPENPGP_CERT_DIGEST, zero_s,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), &len));

  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(NULL, fields_len, OPENPGP_CERT_DIGEST,
                                                              OPENPGP_CERT_RAW_SIG,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len, NULL,
                                                              OPENPGP_CERT_RAW_SIG,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                              OPENPGP_CERT_DIGEST,
                                                              OPENPGP_CERT_RAW_SIG, NULL, out,
                                                              sizeof(out), &len));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                              OPENPGP_CERT_DIGEST,
                                                              OPENPGP_CERT_RAW_SIG,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), NULL));

  /* The hashed area is the message signature's or the certification's, and no other length. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_build_signature_packet(sig_fields, fields_len - 1,
                                                              OPENPGP_CERT_DIGEST,
                                                              OPENPGP_CERT_RAW_SIG,
                                                              OPENPGP_ISSUER_KEY_ID, out,
                                                              sizeof(out), &len));
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_uid_cert_sig_fields(OPENPGP_FINGERPRINT,
                                                                OPENPGP_CREATION_TIME, sig_fields,
                                                                sizeof(sig_fields), &fields_len));
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                             OPENPGP_CERT_DIGEST,
                                                             OPENPGP_CERT_RAW_SIG,
                                                             OPENPGP_ISSUER_KEY_ID, out,
                                                             sizeof(out), &len));
}

/* The significant bits of a big-endian value, which is what an MPI's header declares, RFC 4880 3.2. */
static size_t significant_bits(const uint8_t* value, size_t len) {
  size_t leading = 0;
  while (leading < len && value[leading] == 0) {
    leading++;
  }
  if (leading == len) {
    return 0;
  }
  size_t bits = (len - leading - 1) * 8;
  for (uint8_t top = value[leading]; top != 0; top >>= 1) {
    bits++;
  }
  return bits;
}

static void test_signature_packet_mpi(void) {
  /* About one signature in 256 has a component whose top octet is zero, and an MPI then carries
   * fewer octets than the 32 the secure element handed over. The bit count below is computed from
   * RFC 4880 3.2 rather than written down; GnuPG's own MPIs pin the unmodified case. */
  size_t fields_len = 0;
  TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_sig_fields(OPENPGP_FINGERPRINT, OPENPGP_CREATION_TIME,
                                                       sig_fields, sizeof(sig_fields), &fields_len));

  static const uint8_t tops[][3] = {
      {0x00, 0x7f, 0xff},
      {0x00, 0x01, 0x00},
      {0x00, 0x00, 0x80},
      {0x00, 0x00, 0x01},
      {0x01, 0x00, 0x00},
  };

  for (size_t i = 0; i < sizeof(tops) / sizeof(tops[0]); i++) {
    uint8_t raw[OPENPGP_RAW_ECDSA_LEN];
    memcpy(raw, OPENPGP_CERT_RAW_SIG, sizeof(raw));
    raw[0] = tops[i][0];
    raw[1] = tops[i][1];
    raw[2] = tops[i][2];

    size_t len = 0;
    TEST_ASSERT_EQUAL_INT(0, openpgp_v4_build_signature_packet(sig_fields, fields_len,
                                                               OPENPGP_CERT_DIGEST, raw,
                                                               OPENPGP_ISSUER_KEY_ID, out,
                                                               sizeof(out), &len));

    size_t bits = significant_bits(raw, 32);
    size_t octets = (bits + 7) / 8;
    const uint8_t* mpi = &out[2 + fields_len + 2 + OPENPGP_SIG_UNHASHED_SUBPACKETS_LEN + 2];
    TEST_ASSERT_EQUAL_HEX16_MESSAGE((uint16_t)bits, ((uint16_t)mpi[0] << 8) | mpi[1],
                                    "r's MPI declares its significant bits");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(raw + 32 - octets, &mpi[2], octets,
                                     "and carries exactly those octets");

    size_t s_bits = significant_bits(&raw[32], 32);
    size_t s_octets = (s_bits + 7) / 8;
    const uint8_t* mpi_s = &mpi[2 + octets];
    TEST_ASSERT_EQUAL_HEX16((uint16_t)s_bits, ((uint16_t)mpi_s[0] << 8) | mpi_s[1]);
    TEST_ASSERT_EQUAL_MEMORY(raw + 64 - s_octets, &mpi_s[2], s_octets);

    /* Nothing is left over at the end of the packet, and nothing is short. */
    TEST_ASSERT_EQUAL_INT((int)len,
                          2 + (int)fields_len + 2 + OPENPGP_SIG_UNHASHED_SUBPACKETS_LEN + 2 + 2 +
                              (int)octets + 2 + (int)s_octets);
  }
}

static void test_parse_cert_target(void) {
  for (size_t i = 0; i < OPENPGP_BUNDLES_COUNT; i++) {
    int rc = openpgp_parse_cert_target(OPENPGP_BUNDLES[i].packets, OPENPGP_BUNDLES[i].len, &target);
    if (!OPENPGP_BUNDLES[i].accepted) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, rc, OPENPGP_BUNDLES[i].what);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, OPENPGP_BUNDLES[i].what);
    TEST_ASSERT_EQUAL_INT(OPENPGP_KEY_BODY_LEN, (int)target.primary_key_body_len);
    TEST_ASSERT_EQUAL_MEMORY(OPENPGP_KEY_BODY, target.primary_key_body, target.primary_key_body_len);
    TEST_ASSERT_EQUAL_INT(OPENPGP_UID_LEN, (int)target.user_id_len);
    TEST_ASSERT_EQUAL_MEMORY(OPENPGP_UID, target.user_id, target.user_id_len);
    TEST_ASSERT_EQUAL_INT(OPENPGP_CERT_BODY_LEN, (int)target.self_cert_body_len);
    TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_BODY, target.self_cert_body, target.self_cert_body_len);
    TEST_ASSERT_EQUAL_HEX8(OPENPGP_SIG_TYPE, target.self_cert_type);
    TEST_ASSERT_TRUE(target.self_cert_packet + target.self_cert_packet_len ==
                     target.self_cert_body + target.self_cert_body_len);
  }
}

static void test_parse_cert_target_truncated(void) {
  const uint8_t* bundle = NULL;
  size_t len = 0;
  for (size_t i = 0; i < OPENPGP_BUNDLES_COUNT; i++) {
    if (OPENPGP_BUNDLES[i].accepted) {
      bundle = OPENPGP_BUNDLES[i].packets;
      len = OPENPGP_BUNDLES[i].len;
      break;
    }
  }
  TEST_ASSERT_TRUE(bundle != NULL);

  /* Every cut of a real bundle short of its full length is refused, so no packet is ever read that is
   * not entirely there. */
  for (size_t cut = 0; cut < len; cut++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, openpgp_parse_cert_target(bundle, cut, &target), "truncated");
  }
  TEST_ASSERT_EQUAL_INT(0, openpgp_parse_cert_target(bundle, len, &target));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_parse_cert_target(NULL, len, &target));

  uint8_t extra[OUT_MAX];
  memcpy(extra, bundle, len);
  extra[len] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_parse_cert_target(extra, len + 1, &target));
}

static void test_parse_request(void) {
  for (size_t i = 0; i < OPENPGP_REQUESTS_COUNT; i++) {
    int rc =
        openpgp_protocol_parse_request(OPENPGP_REQUESTS[i].cbor, OPENPGP_REQUESTS[i].len, &request);
    if (!OPENPGP_REQUESTS[i].accepted) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, rc, OPENPGP_REQUESTS[i].what);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, OPENPGP_REQUESTS[i].what);
    TEST_ASSERT_EQUAL_HEX8(OPENPGP_REQUESTS[i].operation, request.operation);
    if (request.operation == OPENPGP_OP_CREATE_IDENTITY) {
      TEST_ASSERT_EQUAL_INT((int)OPENPGP_REQUESTS[i].payload_len, (int)request.uid_len);
      TEST_ASSERT_EQUAL_MEMORY(OPENPGP_REQUESTS[i].payload, request.uid, request.uid_len);
      TEST_ASSERT_EQUAL_INT((int)OPENPGP_REQUESTS[i].creation_time, (int)request.creation_time);
    } else {
      TEST_ASSERT_EQUAL_INT((int)OPENPGP_REQUESTS[i].payload_len, (int)request.message_len);
      TEST_ASSERT_EQUAL_MEMORY(OPENPGP_REQUESTS[i].payload, request.message, request.message_len);
      TEST_ASSERT_EQUAL_INT((int)OPENPGP_REQUESTS[i].key_creation_time,
                            (int)request.key_creation_time);
      TEST_ASSERT_EQUAL_INT((int)OPENPGP_REQUESTS[i].signature_creation_time,
                            (int)request.signature_creation_time);
    }
  }
}

static void test_parse_request_truncated(void) {
  const openpgp_request_row_t* row = NULL;
  for (size_t i = 0; i < OPENPGP_REQUESTS_COUNT; i++) {
    if (OPENPGP_REQUESTS[i].accepted) {
      row = &OPENPGP_REQUESTS[i];
      break;
    }
  }
  TEST_ASSERT_TRUE(row != NULL);

  for (size_t cut = 0; cut < row->len; cut++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, openpgp_protocol_parse_request(row->cbor, cut, &request),
                                  "truncated request");
  }
  TEST_ASSERT_EQUAL_INT(-1, openpgp_protocol_parse_request(NULL, row->len, &request));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_protocol_parse_request(row->cbor, row->len, NULL));
}

static void test_verify_uid_self_cert_refusals(void) {
  /* Everything below stops before the public-key accelerator, which is the one thing a host build
   * cannot supply. Everything up to that handover is pinned by the certification digest row. */
  uint8_t sig[OPENPGP_CERT_BODY_LEN];
  size_t hashed_end = 6 + (size_t)(((uint16_t)OPENPGP_CERT_BODY[4] << 8) | OPENPGP_CERT_BODY[5]);
  size_t unhashed_at = hashed_end;
  size_t unhashed_len = (size_t)(((uint16_t)OPENPGP_CERT_BODY[unhashed_at] << 8) |
                                 OPENPGP_CERT_BODY[unhashed_at + 1]);
  size_t left16_at = unhashed_at + 2 + unhashed_len;
  size_t mpi_at = left16_at + 2;
  TEST_ASSERT_EQUAL_INT(OPENPGP_CERT_TAIL_LEN, (int)(2 + unhashed_len + 2 +
                                                    (OPENPGP_CERT_BODY_LEN - mpi_at)));
  TEST_ASSERT_TRUE(mpi_at + 2 <= sizeof(sig));

  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(NULL, OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            NULL, 0, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, NULL,
                                                            OPENPGP_CERT_BODY_LEN));

  /* A key this device cannot verify is refused before anything is hashed: version 3, a body too short
   * to hold the algorithm octets, or a curve that is not secp256k1. */
  uint8_t v3_key[OPENPGP_KEY_BODY_LEN];
  memcpy(v3_key, OPENPGP_KEY_BODY, sizeof(v3_key));
  v3_key[0] = 3;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(v3_key, sizeof(v3_key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, 5, OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
  uint8_t other_curve[OPENPGP_KEY_BODY_LEN];
  memcpy(other_curve, OPENPGP_KEY_BODY, sizeof(other_curve));
  other_curve[6] = 6; /* the OID length octet, so what follows is not 1.3.132.0.10 */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(other_curve, sizeof(other_curve),
                                                            OPENPGP_UID, OPENPGP_UID_LEN,
                                                            OPENPGP_CERT_BODY, OPENPGP_CERT_BODY_LEN));

  /* Not a certification: RFC 4880 5.2.1 makes 0x18 a subkey binding signature and 0x20 a key
   * revocation, and neither certifies a user ID. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[1] = 0x18;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[1] = 0x20;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));

  /* Not the algorithms this device implements, at the octet positions RFC 4880 5.2.3 fixes, and not
   * version 4 on either side of the pair. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[2] = 1;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[3] = 1;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[0] = 3;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));

  /* A hashed-subpacket length the body cannot hold, and a body too short to be a signature at all. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[4] = 0xff;
  sig[5] = 0xff;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig, 9));

  /* The signed-hash prefix is checked before the public-key operation, so a signature that does not
   * even claim this hash never reaches the curve. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_CERT_DIGEST, &OPENPGP_CERT_BODY[left16_at], 2);
  sig[left16_at] = (uint8_t)(OPENPGP_CERT_BODY[left16_at] ^ 0x01);
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));

  /* An unhashed area longer than the body, and MPIs whose declared bit count is not 32 octets'
   * worth: RFC 4880 3.2 makes the count meaningful, so both are refused. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[unhashed_at] = 0xff;
  sig[unhashed_at + 1] = 0xff;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[mpi_at] = 0x01;
  sig[mpi_at + 1] = 0x01;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[mpi_at] = 0x00;
  sig[mpi_at + 1] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));

  /* An MPI whose octets do not carry the number of significant bits it declares: the top octet is
   * zeroed while the count stays at 256, which RFC 4880 3.2 makes a contradiction, not a value. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  sig[mpi_at + 2] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            sizeof(sig)));

  /* Octets after the two MPIs are a fourth thing in the signature packet. */
  uint8_t trailing[OPENPGP_CERT_BODY_LEN + 1];
  memcpy(trailing, OPENPGP_CERT_BODY, OPENPGP_CERT_BODY_LEN);
  trailing[OPENPGP_CERT_BODY_LEN] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, trailing,
                                                            sizeof(trailing)));

  /* A certification whose signature stops before the second MPI. */
  memcpy(sig, OPENPGP_CERT_BODY, sizeof(sig));
  size_t r_octets = (size_t)((((uint16_t)OPENPGP_CERT_BODY[mpi_at] << 8) |
                              OPENPGP_CERT_BODY[mpi_at + 1]) +
                             7) /
                    8;
  TEST_ASSERT_EQUAL_INT(OPENPGP_CERT_BODY_LEN, (int)(mpi_at + 2 + r_octets + 2 + r_octets));
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN,
                                                            OPENPGP_UID, OPENPGP_UID_LEN, sig,
                                                            mpi_at + 2 + r_octets + 1));
}

static void test_verify_uid_self_cert_key_bodies(void) {
  /* openpgp_v4_verify_uid_self_cert takes the key body apart before it hashes anything, and every
   * refusal below happens there. The shapes are RFC 4880 3.2 and 5.5.2: an algorithm of 19 whose
   * OID is 1.3.132.0.10, then a point MPI of 515 bits whose octets begin with 0x04 and whose bit
   * count is the number of significant bits in them. */
  uint8_t key[OPENPGP_KEY_BODY_LEN];

  /* A point declared as 520 bits, which is 65 octets counted as octets rather than as significant
   * bits. It is the obvious way to get this wrong and it is not a valid MPI. */
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[12] = 0x02;
  key[13] = 0x08;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));

  /* A point declared in bits that is not 65 octets of point. */
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[13] = 0x00; /* 0 bits */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[13] = 0x01; /* 1 bit, one octet */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));

  /* An uncompressed point, or the MPI is not describing what is there. */
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[14] = 0x02;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));

  /* The leading octet of the X coordinate dropped would make the point 512 bits, and 512 bits of
   * point is not a point this device can place on the curve. */
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[12] = 0x02;
  key[13] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));

  /* Another curve: the OID length is right and the OID is not. */
  memcpy(key, OPENPGP_KEY_BODY, sizeof(key));
  key[11] ^= 0x01;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(key, sizeof(key), OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));

  /* A body that ends before the OID it announced, before the MPI header, or before the MPI. */
  for (size_t len = 8; len < OPENPGP_KEY_BODY_LEN; len++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1,
                                  openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY, len, OPENPGP_UID,
                                                                  OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                                  OPENPGP_CERT_BODY_LEN),
                                  "a key body cut short");
  }

  /* Trailing octets after the point are not part of the key. */
  uint8_t longer_key[OPENPGP_KEY_BODY_LEN + 1];
  memcpy(longer_key, OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN);
  longer_key[OPENPGP_KEY_BODY_LEN] = 0x00;
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(longer_key, sizeof(longer_key),
                                                            OPENPGP_UID, OPENPGP_UID_LEN,
                                                            OPENPGP_CERT_BODY, OPENPGP_CERT_BODY_LEN));

  /* A body whose length will not fit the two-octet field the fingerprint is framed with. */
  TEST_ASSERT_EQUAL_INT(-1, openpgp_v4_verify_uid_self_cert(big_key, UINT16_MAX + 1, OPENPGP_UID,
                                                            OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                            OPENPGP_CERT_BODY_LEN));
}

static void test_verify_uid_self_cert_truncated(void) {
  /* Every prefix of GnuPG's own certification body, from the shortest thing that looks like a v4
   * signature to one octet shy of the whole, is refused: the left-16 bits, the two MPIs and the end
   * of the body are all checked before the curve is asked anything. */
  for (size_t len = 10; len < OPENPGP_CERT_BODY_LEN; len++) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1,
                                  openpgp_v4_verify_uid_self_cert(OPENPGP_KEY_BODY,
                                                                  OPENPGP_KEY_BODY_LEN, OPENPGP_UID,
                                                                  OPENPGP_UID_LEN, OPENPGP_CERT_BODY,
                                                                  len),
                                  "a certification cut short");
  }
}

static void test_fingerprint_is_sha1_of_the_framing(void) {
  /* The framing computed here rather than by the module, against the fingerprint GnuPG publishes:
   * 0x99, the two-octet length, then the whole key body -- RFC 4880 12.1. */
  uint8_t framed[3 + OPENPGP_KEY_BODY_LEN];
  framed[0] = 0x99;
  framed[1] = (uint8_t)(OPENPGP_KEY_BODY_LEN >> 8);
  framed[2] = (uint8_t)OPENPGP_KEY_BODY_LEN;
  memcpy(&framed[3], OPENPGP_KEY_BODY, OPENPGP_KEY_BODY_LEN);

  uint8_t sha1[SHA1_DIGEST_LENGTH];
  sha1_Raw(framed, sizeof(framed), sha1);
  TEST_ASSERT_EQUAL_MEMORY(OPENPGP_FINGERPRINT, sha1, sizeof(sha1));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_public_key_body);
  RUN_TEST(test_primary_key_fingerprint);
  RUN_TEST(test_certification_data);
  RUN_TEST(test_certification_digest);
  RUN_TEST(test_sig_fields);
  RUN_TEST(test_text_signatures);
  RUN_TEST(test_binary_signature);
  RUN_TEST(test_canonicalize);
  RUN_TEST(test_signature_packet);
  RUN_TEST(test_signature_packet_mpi);
  RUN_TEST(test_parse_cert_target);
  RUN_TEST(test_parse_cert_target_truncated);
  RUN_TEST(test_parse_request);
  RUN_TEST(test_parse_request_truncated);
  RUN_TEST(test_verify_uid_self_cert_refusals);
  RUN_TEST(test_verify_uid_self_cert_key_bodies);
  RUN_TEST(test_verify_uid_self_cert_truncated);
  RUN_TEST(test_fingerprint_is_sha1_of_the_framing);
  return UNITY_END();
}
