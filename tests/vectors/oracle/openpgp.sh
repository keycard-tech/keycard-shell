#!/bin/sh
# Produces tests/vectors/openpgp_fixture/: OpenPGP packets made by GnuPG, which generate.py then
# re-derives expectations from, checks with coincurve, and emits as vectors.
#
#   ./tests/vectors/oracle/openpgp.sh [destination]
#
# Every byte in the fixture is GnuPG's output; the tests trust its bytes, not its opinions.
# Regenerating replaces the key and every signature with it, so regenerate deliberately and rebuild
# the vectors and the tests that read them in the same commit.
set -eu

DEST=${1:-tests/vectors/openpgp_fixture}
KEYRING=${TMPDIR:-/tmp}/openpgp-vectors-keyring
rm -rf "$KEYRING"
mkdir -p "$KEYRING"
chmod 700 "$KEYRING"
export GNUPGHOME=$KEYRING

cat > "$KEYRING/gen" <<'EOF'
Key-Type: ECDSA
Key-Curve: secp256k1
Key-Usage: sign,cert
Name-Real: Keycard Host Test
Name-Comment: An identity long enough that a user ID packet needs a two octet length, because a hostile host can send one and the packet parser must not be the thing that notices
Name-Email: openpgp-test@example.invalid
Expire-Date: 0
%no-protection
%commit
EOF

gpg --batch --generate-key "$KEYRING/gen"

mkdir -p "$DEST"
# Only the minimal export is read back. Asking for both forms invites a test to depend on the one
# nobody regenerates deliberately, so there is one export and it is the minimal one.
gpg --batch --export --export-options export-minimal > "$DEST/key-minimal.gpg"
gpg --batch --list-sigs --with-colons > "$DEST/report.txt"

# Canonical text signatures, over the line endings and the awkward octets a host can send. %b so
# that CRLF, tabs and a lone CR are all expressible.
i=0
sign_text() {
  i=$((i + 1))
  printf '%b' "$1" > "$KEYRING/msg"
  gpg --batch --detach-sign --textmode --output "$DEST/text-$i.sig" "$KEYRING/msg"
  printf '%b' "$1" > "$DEST/text-$i.msg"
}

sign_text 'hello world'
sign_text 'two\nlines\n'
sign_text 'crlf\r\nline\r\n'
sign_text 'trailing spaces   \n'
sign_text 'trailing tab\t\n'
sign_text 'From the river\nsecond line\n'
sign_text 'empty line\n\nafter it\n'
sign_text 'no final newline'
sign_text 'lone\rcr\n'
sign_text 'nul\0inside\n'
sign_text '\n'

# A binary detached signature, for the message path that does not canonicalize.
printf 'hello world' > "$DEST/binary.msg"
gpg --batch --detach-sign --output "$DEST/binary.sig" "$DEST/binary.msg"

rm -rf "$KEYRING"
echo "wrote $DEST (key $(awk -F: '$1=="fpr"{print $10; exit}' "$DEST/report.txt"))"
