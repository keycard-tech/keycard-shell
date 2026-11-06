#ifndef VECTORS_KEYS_H
#define VECTORS_KEYS_H

/* reference: https://shell.keycard.tech/uploads/20260915/20260915.zip
 * sha256 0999eea9f7eee0b790b91bed5250c23d18dcfd98968fac64f10acdd54b307e51
 *
 * updater_verify_db() digests the received database and checks the 64 bytes that follow it against
 * key_read_public(DB_VERIFICATION_KEY). That makes the embedded key a trust anchor, and this is the one
 * external thing that can say whether it is the right one: the release artifact, signed. A test verifies
 * the release signature with the key keys.c hands back -- so a swapped or mistyped key fails the release,
 * not just a self-consistent fixture.
 */

#define DB_RELEASE_BODY_SHA256 "ca8279aa267611cd192c05bf4fca4b698c23f0549e404ac6d154b3922d1587ab"
#define DB_RELEASE_SIGNATURE "3e4ad82c68f26dcf856aa30a064bcfa93f17d856a6c6e92cf9f6effbe5cee28e60e090eab5cd9f638a6fd184106f8320902240795971f510e18d7e24dbf28f5b"

#endif
