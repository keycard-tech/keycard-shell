#ifndef VECTORS_KEYS_H
#define VECTORS_KEYS_H

/* reference: https://github.com/keycard-tech/keycard-eth-db/releases/download/20261111/shelldb-20261111.bin
 * sha256 50c13401b9ce0c15e921b52dd78ebfa77cc974692c6851b902d4dc25a22a3128
 *
 * updater_verify_db() digests the received database and checks the 64 bytes that follow it against
 * key_read_public(DB_VERIFICATION_KEY). That makes the embedded key a trust anchor, and this is the one
 * external thing that can say whether it is the right one: the release artifact, signed. A test verifies
 * the release signature with the key keys.c hands back -- so a swapped or mistyped key fails the release,
 * not just a self-consistent fixture.
 *
 * The same blob ships twice in a release: the asset here carries the production signature, the
 * reproduction zip carries db.bin signed with a throwaway key so the build is reproducible. Only the
 * signature differs, and generate.py refuses to emit this header when the two bodies diverge.
 */

#define DB_RELEASE_BODY_SHA256 "63dd9d51c8f174fb1b3a6a1ed9864326f90cb2a09856d0da6db6e5e84d02b41d"
#define DB_RELEASE_SIGNATURE "f9b9a9796a5728eddcb284df4f3647ff64e9d0bec217d9093a1004d4b2e4cf426ded15165ab7e3136297529dc6fac0b2fa6f789337210e43a0392ca0e9dac178"

#endif
