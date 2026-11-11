#!/usr/bin/env python3
"""Generate the known-answer vector headers consumed by the native tests.

Every value in the emitted headers comes from one of two places, and each header says which:

  spec      fetched from the upstream document or word list, hashed below so a regenerated
            header can be audited against the same source
  reference computed by an independent implementation (CPython hashlib/hmac/zlib,
            pycryptodome, or the BIP's own reference code)
  oracle    computed by a released implementation run for the purpose, which is how a header can
            pin behaviour nobody else publishes; see oracle/ and the header that uses it

Run from anywhere; requires network unless the sources are already in tests/vectors/.cache/.

    uv run python tests/vectors/generate.py
"""

import base64
import hashlib
import hmac
import io
import itertools
import textwrap
import json
import os
import random
import struct

from asn1crypto import core as asn1_core
import re
import string
import sys
import unicodedata
import urllib.request
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"

SOURCES = {
    "rfc4880.txt": "https://www.rfc-editor.org/rfc/rfc4880.txt",
    "coldcard_multisig.html": "https://coldcard.com/docs/multisig/",
    "cc_export_1.txt": "https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/test/resources/com/sparrowwallet/sparrow/io/cc-multisig-export-1.txt",
    "cc_export_2.txt": "https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/test/resources/com/sparrowwallet/sparrow/io/cc-multisig-export-2.txt",
    "cc_export_missingkey.txt": "https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/test/resources/com/sparrowwallet/sparrow/io/cc-multisig-export-missingkey.txt",
    "cc_export_multideriv.txt": "https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/test/resources/com/sparrowwallet/sparrow/io/cc-multisig-export-multideriv.txt",
    "cc_export_nopolicy.txt": "https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/test/resources/com/sparrowwallet/sparrow/io/cc-multisig-export-nopolicy.txt",
    "bip39_wordlist.txt": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
    "bip39_vectors.json": "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json",
    "bip32.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki",
    "bip86.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0086.mediawiki",
    "base58.cpp": "https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/base58.cpp",
    "bip173.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0173.mediawiki",
    "bip67.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0067.mediawiki",
    "bip49.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0049.mediawiki",
    "bip350.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0350.mediawiki",
    "eip-155.md": "https://raw.githubusercontent.com/ethereum/EIPs/master/EIPS/eip-155.md",
    "erc-55.md": "https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-55.md",
    "bip-0021.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0021.mediawiki",
    "erc-681.md": "https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-681.md",
    "keycard_applet_4.java": "https://raw.githubusercontent.com/keycard-tech/status-keycard/master/src/main/java/im/status/keycard/KeycardApplet.java",
    "keycard_applet_3.java": "https://raw.githubusercontent.com/keycard-tech/status-keycard/3.2/src/main/java/im/status/keycard/KeycardApplet.java",
    "keycard_ident.java": "https://raw.githubusercontent.com/keycard-tech/status-keycard/master/src/main/java/im/status/keycard/IdentApplet.java",
    "keycard_shared_memory.java": "https://raw.githubusercontent.com/keycard-tech/status-keycard/master/src/main/java/im/status/keycard/SharedMemory.java",
    "keycard_scv2.java": "https://raw.githubusercontent.com/keycard-tech/status-keycard/master/src/main/java/im/status/keycard/SecureChannelV2.java",
    "slip39.md": "https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039.md",
    "slip39_wordlist.txt": "https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt",
    "slip39_vectors.json": "https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json",
    "rfc4231.txt": "https://www.rfc-editor.org/rfc/rfc4231.txt",
    "rfc5869.txt": "https://www.rfc-editor.org/rfc/rfc5869.txt",
    "rfc6979.txt": "https://www.rfc-editor.org/rfc/rfc6979.txt",
    "bip174.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0174.mediawiki",
    "bip371.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0371.mediawiki",
    "bip143.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0143.mediawiki",
    "bip341_wallet.json": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json",
    "bip13.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0013.mediawiki",
    "bip16.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0016.mediawiki",
    "bip86.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0086.mediawiki",
    "bip141.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0141.mediawiki",
    "bip341.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341.mediawiki",
    "eth_sig_util_sign_typed_data.test.ts": "https://raw.githubusercontent.com/MetaMask/eth-sig-util/main/src/sign-typed-data.test.ts",
    "eth_sig_util_sign_typed_data.snap": "https://raw.githubusercontent.com/MetaMask/eth-sig-util/main/src/__snapshots__/sign-typed-data.test.ts.snap",
    "eip712_example.js": "https://raw.githubusercontent.com/ethereum/EIPs/master/assets/eip-712/Example.js",
    "key_io_valid.json": "https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/key_io_valid.json",
    "bip340_vectors.csv": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv",
    "bc_multipart_ur.md": "https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2024-001-multipart-ur.md",
    "bc_ur_types_registry.md": "https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-006-urtypes.md",
    "bc_hdkey.md": "https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-007-hdkey.md",
    "bc_output_desc.md": "https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-010-output-desc.md",
    "bc_account.md": "https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-015-account.md",
    "bc_bytewords.c": "https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/src/bc-bytewords.c",
    "shell_db_20261111.zip": "https://github.com/keycard-tech/keycard-eth-db/releases/download/20261111/db-20261111-reproduction.zip",
    "shell_db_20261111.bin": "https://github.com/keycard-tech/keycard-eth-db/releases/download/20261111/shelldb-20261111.bin",
    "bc_bytewords_test.c": "https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/test/test.c",
    "erc-4527.md": "https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-4527.md",
    "cbor_tags.xhtml": "https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml",
    "fips-197.pdf": "https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf",
    "sp800-38c.pdf": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf",
}


def fetch_bytes(name: str) -> bytes:
    path = CACHE / name
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        print(f"fetch {SOURCES[name]}")
        path.write_bytes(urllib.request.urlopen(SOURCES[name]).read())
    return path.read_bytes()


def fetch(name: str) -> str:
    return fetch_bytes(name).decode("utf-8", errors="replace")


def provenance(name: str) -> str:
    digest = hashlib.sha256((CACHE / name).read_bytes()).hexdigest()
    return f"{SOURCES[name]}\n * sha256 {digest}"


def hexs(data: bytes) -> str:
    return data.hex()


C_ESCAPES = {
    ord("\\"): "\\\\",
    ord('"'): '\\"',
    ord("\t"): "\\t",
    ord("\r"): "\\r",
    ord("\n"): "\\n",
}


def cstr(value: str) -> str:
    """A C string literal. Control characters are escaped, because a bare newline or tab
    inside quotes does not survive a header being read again."""
    return '"' + value.translate(C_ESCAPES) + '"'


def wordlist_digest(url_name: str, words: list[str]) -> str:
    """The C word list is compared as a digest of the newline-joined list: same coverage, no
    2048-entry table in the test binary."""
    joined = ("\n".join(words) + "\n").encode()
    return hexs(hashlib.sha256(joined).digest())


# ---------------------------------------------------------------- hashing


def hash_vectors() -> str:
    from Crypto.Hash import keccak  # pycryptodome, listed in pyproject.toml

    messages = [
        b"",
        b"abc",
        b"a",
        b"A" * 55,  # one byte short of a SHA-2/SHA-3 rate boundary
        b"A" * 56,
        b"A" * 63,
        b"A" * 64,
        b"A" * 65,
        b"B" * 119,
        b"B" * 127,
        b"B" * 128,
        b"B" * 135,  # Keccak-256 / SHA3-256 rate is 136 bytes
        b"B" * 136,
        b"B" * 137,
        b"C" * 1000,
    ]

    rows = []
    for msg in messages:
        k = keccak.new(digest_bits=256)
        k.update(msg)
        rows.append(
            (
                hexs(msg),
                hexs(hashlib.sha256(msg).digest()),
                hexs(hashlib.sha512(msg).digest()),
                hexs(hashlib.sha1(msg).digest()),
                hexs(hashlib.new("ripemd160", msg).digest()),
                hexs(hashlib.sha3_256(msg).digest()),
                hexs(hashlib.sha3_512(msg).digest()),
                hexs(k.digest()),
                "%#010x" % zlib.crc32(msg),
            )
        )

    body = ",\n".join(
        "  {%s, %s, %s, %s, %s, %s, %s, %s, %s}" % tuple(cstr(v) for v in row) for row in rows
    )
    return f"""#ifndef VECTORS_HASH_H
#define VECTORS_HASH_H

/* reference: CPython hashlib (SHA-256/512, RIPEMD-160, SHA3-256/512), zlib.crc32,
 * pycryptodome keccak (SHA3-256 with Keccak padding, as used by Ethereum). Message
 * lengths straddle the buffer boundaries of every one of these constructions.
 */
typedef struct {{
  const char* msg;
  const char* sha256;
  const char* sha512;
  /* SHA-1 is dead for signatures but is what an OpenPGP v4 fingerprint is, RFC 4880 12.1. */
  const char* sha1;
  const char* ripemd160;
  const char* sha3_256;
  const char* sha3_512;
  const char* keccak_256;
  const char* crc32;
}} hash_kat_t;

static const hash_kat_t HASH_KAT[] = {{
{body}
}};

#define HASH_KAT_COUNT (sizeof(HASH_KAT) / sizeof(HASH_KAT[0]))

#endif
"""


# ------------------------------------------------------------------- hmac


def is_hexrun(text: str) -> bool:
    return bool(re.fullmatch(r"(0x)?[0-9a-fA-F \t]+", text))


def is_label_line(text: str) -> bool:
    """`Key = ...`, `HASH  SHA-256 ...` and prose all introduce or end a field; a wrapped
    value line is a run of hex that may carry a trailing `(N bytes)` annotation."""
    if "=" in text:
        return True
    head = text.split(None, 1)[0] if text.split() else ""
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", head)) and not is_hexrun(head)


def parse_fields(block: str, labels: set[str]) -> dict[str, str]:
    """RFC test vectors are `Label = value` with the value wrapped over the following lines
    and annotated in parentheses, which must be dropped before reading hex (the annotations
    contain hex-looking letters and digits)."""
    fields: dict[str, str] = {}
    current = None
    for line in block.splitlines():
        stripped = line.strip()
        head, _, after_eq = stripped.partition("=")
        head = head.strip() if "=" in stripped else (stripped.split() or [""])[0]
        if head in labels:
            current = head
            rest = after_eq if "=" in stripped else stripped[len(head):]
            fields.setdefault(current, "")
        elif current is None or not stripped or is_label_line(stripped):
            current = None
            continue
        else:
            rest = stripped
        rest = re.sub(r"\(.*?\)", "", rest).strip()
        if current in ("L", "Hash"):
            fields[current] = rest
        elif is_hexrun(rest):
            fields[current] += re.sub(r"[^0-9a-fA-F]", "", rest[2:] if rest.startswith("0x") else rest)
    return fields


def parse_rfc4231() -> list[dict]:
    """RFC 4231 section 4."""
    text = fetch("rfc4231.txt")
    labels = {"Key", "Data", "HMAC-SHA-256", "HMAC-SHA-512"}
    cases = []
    for block in re.split(r"\n4\.\d+\.  Test Case \d+\n", text)[1:]:
        fields = parse_fields(block.split("\n4.")[0], labels)
        if not labels.issubset(fields):
            continue
        case = {
            "key": fields["Key"].lower(),
            "data": fields["Data"].lower(),
            "sha256": fields["HMAC-SHA-256"].lower(),
            "sha512": fields["HMAC-SHA-512"].lower(),
        }
        key = bytes.fromhex(case["key"])
        data = bytes.fromhex(case["data"])
        for digest, field in ((hashlib.sha256, "sha256"), (hashlib.sha512, "sha512")):
            # Test case 5 is deliberately truncated, so the RFC mac is a prefix.
            assert hmac.new(key, data, digest).hexdigest().startswith(case[field]), case
        cases.append(case)
    return cases


def hmac_vectors() -> str:
    cases = parse_rfc4231()
    if len(cases) != 7:
        sys.exit(f"rfc4231: expected 7 test cases, parsed {len(cases)}")
    body = ",\n".join(
        "  {%s, %s, %s, %s}"
        % (cstr(c["key"]), cstr(c["data"]), cstr(c["sha256"]), cstr(c["sha512"]))
        for c in cases
    )
    return f"""#ifndef VECTORS_HMAC_H
#define VECTORS_HMAC_H

/* spec: {provenance('rfc4231.txt')}
 *
 * Case 6 uses a key longer than the block size, which is the path that hashes the key
 * before use.
 */
typedef struct {{
  const char* key;
  const char* data;
  const char* sha256;
  const char* sha512;
}} hmac_kat_t;

static const hmac_kat_t HMAC_KAT[] = {{
{body}
}};

#define HMAC_KAT_COUNT (sizeof(HMAC_KAT) / sizeof(HMAC_KAT[0]))

#endif
"""


# ------------------------------------------------------------------- hkdf


def parse_rfc5869() -> list[dict]:
    """RFC 5869 appendix A, SHA-256 cases only: hkdf.c implements SHA-256 and nothing else."""
    text = fetch("rfc5869.txt")
    appendix = text[text.index("A.  Test Vectors"):]
    labels = {"Hash", "IKM", "salt", "info", "L", "PRK", "OKM"}
    cases = []
    for block in re.split(r"\nA\.\d+\.  Test Case \d+\n", appendix)[1:]:
        fields = parse_fields(block.split("\nA.")[0], labels)
        if "SHA-256" not in fields.get("Hash", ""):
            continue
        cases.append(
            {
                "ikm": fields["IKM"].lower(),
                "salt": fields.get("salt", "").lower(),
                "info": fields.get("info", "").lower(),
                "l": int(fields["L"]),
                "prk": fields["PRK"].lower(),
                "okm": fields["OKM"].lower(),
            }
        )
    return cases


def hkdf_reference(salt: bytes, ikm: bytes, info: bytes, length: int) -> tuple[bytes, bytes]:
    """RFC 5869 extract-and-expand, used only to prove the appendix values were parsed intact."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return prk, okm[:length]


def hkdf_vectors() -> str:
    cases = parse_rfc5869()
    if len(cases) != 3:
        sys.exit(f"rfc5869: expected 3 SHA-256 test cases, parsed {len(cases)}")
    for case in cases:
        prk, okm = hkdf_reference(
            bytes.fromhex(case["salt"]),
            bytes.fromhex(case["ikm"]),
            bytes.fromhex(case["info"]),
            case["l"],
        )
        assert prk.hex() == case["prk"] and okm.hex() == case["okm"], case
    rows = [
        "  {%s, %s, %s, %d, %s, %s}"
        % (cstr(c["ikm"]), cstr(c["salt"]), cstr(c["info"]), c["l"], cstr(c["prk"]), cstr(c["okm"]))
        for c in cases
    ]
    return f"""#ifndef VECTORS_HKDF_H
#define VECTORS_HKDF_H

/* spec: {provenance('rfc5869.txt')}
 *
 * The three SHA-256 cases of appendix A. Case 3 has a salt longer than HashLen and empty
 * info; the row's lengths are the RFC's L values.
 */
typedef struct {{
  const char* ikm;
  const char* salt;
  const char* info;
  unsigned int l;
  const char* prk;
  const char* okm;
}} hkdf_kat_t;

static const hkdf_kat_t HKDF_KAT[] = {{
{",\n".join(rows)}
}};

#define HKDF_KAT_COUNT (sizeof(HKDF_KAT) / sizeof(HKDF_KAT[0]))

#endif
"""


# ------------------------------------------------------------------ bip39


def bip39_checksum_ok(words: list[str], index_of: dict[str, int]) -> bool:
    """BIP-39: the last bits of the concatenated 11-bit word indexes are the leading
    SHA-256 bits of the entropy."""
    try:
        bits = "".join(format(index_of[word], "011b") for word in words)
    except KeyError:
        return False
    ent = len(bits) * 32 // 33
    checksum_bits = int(bits[ent:], 2)
    entropy = bytes.frombits(bits[:ent]) if hasattr(bytes, "frombits") else int(bits[:ent], 2).to_bytes(ent // 8, "big")
    digest_bits = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> (256 - (ent // 32))
    return digest_bits == checksum_bits


def seedqr_standard(payload: bytes) -> tuple[bool, list[int]]:
    """A model of mnemonic_from_seedqr_standard.

    48 or 96 octets, four decimal digits per BIP-39 index, no separator and no checksum. What makes a
    model necessary rather than a guess is that the check is on the *value*: each octet is subtracted
    from '0' as a signed char, scaled by its position, and the sum is truncated to uint16_t before
    being compared against the word count. So ':' in the units place is 10 and accepted, and 0xff in
    the thousands place is -49000 which truncates to 16536 and is not.
    """
    if len(payload) not in (48, 96):
        return False, []
    indexes = []
    for i in range(0, len(payload), 4):
        value = 0
        for offset, weight in ((0, 1000), (1, 100), (2, 10), (3, 1)):
            octet = payload[i + offset]
            signed = octet - 0x100 if octet >= 0x80 else octet
            value += (signed - 0x30) * weight
        value &= 0xFFFF
        if value >= 2048:
            return False, []
        indexes.append(value)
    return True, indexes


def last_word_mask(indexes: list[int]) -> tuple[int, bytes]:
    """A model of mnemonic_last_word_mask: which last words make len words a valid checksum, for the
    first len - 1 indexes. Returns the candidate count and the 256 byte bitmap."""
    words = len(indexes) + 1
    checksum_bits = words // 3
    entropy_bytes = (words * 11 - checksum_bits) // 8
    count = 1 << (11 - checksum_bits)
    mask = bytearray(256)
    for tail in range(count):
        row = list(indexes) + [tail << checksum_bits]
        bits = bytearray(33)
        position = 0
        for index in row:
            for bit in range(10, -1, -1):
                if index & (1 << bit):
                    bits[position // 8] |= 1 << (7 - (position % 8))
                position += 1
        assert position == words * 11
        digest = hashlib.sha256(bytes(bits[:entropy_bytes])).digest()
        index = (tail << checksum_bits) | (digest[0] >> (8 - checksum_bits))
        mask[index // 8] |= 1 << (index % 8)
    return count, bytes(mask)


def seedqr_c_bytes(payload: bytes) -> str:
    """A C literal for bytes that may contain NUL, in a form where an escape can never be read
    together with a following digit: runs of ordinary digits stay plain, anything else becomes its
    own three-digit octal literal in its own concatenated string."""
    out, plain = [], ''
    for byte in payload:
        if 0x20 <= byte < 0x7f and byte != ord('"') and byte != ord('\\'):
            plain += chr(byte)
            continue
        if plain:
            out.append(f'"{plain}"')
            plain = ''
        out.append(f'"\\{byte:03o}"')
    if plain:
        out.append(f'"{plain}"')
    return ' '.join(out) if out else '""'


def seedqr_tables(entries, words: list[str], index_of: dict[str, int]) -> tuple[str, str]:
    """The standard-SeedQR rows: the Trezor mnemonics as digit strings with their published seeds,
    and the shapes a hostile or merely odd QR payload arrives in."""
    index_rows, row_entries = [], []

    def row(payload: bytes, indexes: list[int] | None, seed: str | None) -> None:
        if indexes is None:
            slot = -1
        else:
            slot = len(index_rows)
            index_rows.append('{ ' + ', '.join(f'0x{index:04x}' for index in indexes
                                               + [0] * (24 - len(indexes))) + ' }')
        row_entries.append(f'  {{{seedqr_c_bytes(payload)}, {len(payload)}, {slot}, "{seed or ""}"}}')

    for entropy_hex, mnemonic, seed, _xprv in entries:
        word_list = mnemonic.split()
        if len(word_list) not in (12, 24):  # the firmware implements 12 and 24 words only
            continue
        indexes = [index_of[word] for word in word_list]
        digits = ''.join(f'{index:04d}' for index in indexes)
        assert len(digits) in (48, 96) and digits.isdigit()
        row(digits.encode(), indexes, seed)

    # The last index that is a word, and the first that is not: 2047 is "zoo", 2048 is nothing.
    row(b'2047' * 12, [2047] * 12, None)
    row(b'2048' + b'0000' * 11, None, None)
    row(b'0000' * 11 + b'2048', None, None)

    # Lengths. 48 and 96 are the only accepted ones: an 18-word mnemonic is valid BIP-39 and is not a
    # SeedQR this firmware reads, and one digit more or less is not a scanned-string truncation but a
    # different string.
    for count in (0, 1, 47, 48 + 1, 72, 95, 96 + 1, 132):
        row(b'0' * count, None, None)

    # A scanned QR is not NUL-terminated, so an embedded NUL reaches the function as data rather than
    # as a terminator. NUL is -48 against '0', which lands far outside the word list.
    row(b'0000' * 12 + b'\0', None, None)
    row(b'\0' + b'0' * 47, None, None)
    row(b'000' + b'\0' + b'0' * 44, None, None)

    # Octets that are not digits, in each of the four positions and at both ends of the range they
    # can produce. Accepted or refused is the model's answer, and the rows exist to make that answer
    # visible: 1000 * (c - '0') is arithmetic on whatever is there, so ':' is ten and 'A' in the
    # hundreds place is seventeen hundred -- both in range, both accepted. A QR reader in numeric mode
    # cannot send either; the function is public and the next caller may not have one in front of it.
    odd = []
    for position in (0, 1, 2, 3):
        for char in (0x30, 0x39, 0x3a, 0x2f, 0x20, 0x2d, ord('A'), ord('a'), ord('z'), 0x80, 0xff):
            digits = bytearray(b'0000' * 12)
            digits[position] = char
            accepted, indexes = seedqr_standard(bytes(digits))
            odd.append((position, char, bytes(digits), accepted, indexes))
    for position, char, digits, accepted, indexes in odd:
        row(digits, indexes if accepted else None, None)

    # What this module claims independently of the model: the boundary words, the lengths, and that a
    # NUL is not a digit.
    assert seedqr_standard(b'0000' * 12) == (True, [0] * 12)
    assert seedqr_standard(b'2047' * 12)[0] and not seedqr_standard(b'2048' * 12)[0]
    assert not seedqr_standard(b'0' * 47)[0] and not seedqr_standard(b'0' * 49)[0]
    assert not seedqr_standard(b'\0' + b'0' * 47)[0]
    assert len(odd) == 44

    return (',\n'.join(index_rows), ',\n'.join(row_entries))


def last_word_tables(entries, index_of: dict[str, int]) -> tuple[str, str]:
    """One row per published mnemonic: its indexes except the last, the published last word, the
    candidate count the closed form gives, and a digest of the bitmap."""
    index_rows, rows = [], []
    for _entropy_hex, mnemonic, _seed, _xprv in entries:
        word_list = mnemonic.split()
        if len(word_list) not in (12, 24):
            continue
        indexes = [index_of[word] for word in word_list]
        count, mask = last_word_mask(indexes[:-1])
        # The published mnemonic is a valid one, so its own last word must be among the candidates.
        assert mask[indexes[-1] // 8] & (1 << (indexes[-1] % 8))
        # One candidate per value of the bits the last word carries, and none of them collide.
        assert count == 1 << (11 - len(word_list) // 3)
        assert sum(bin(byte).count('1') for byte in mask) == count
        slot = len(index_rows)
        index_rows.append('{ ' + ', '.join(f'0x{index:04x}' for index in indexes[:-1]
                                           + [0] * (24 - len(indexes) + 1)) + ' }')
        rows.append(f'  {{{len(word_list)}, 0x{indexes[-1]:04x}, {count}, '
                    f'"{hashlib.sha256(mask).hexdigest()}"}}')
    return ',\n'.join(index_rows), ',\n'.join(rows)


def bip39_vectors() -> str:
    words = fetch("bip39_wordlist.txt").split()
    entries = json.loads(fetch("bip39_vectors.json"))["english"]

    index_of = {word: i for i, word in enumerate(words)}
    prefix_groups: dict[str, list[str]] = {}
    for word in words:
        prefix_groups.setdefault(word[:4], []).append(word)

    rows = []
    for entropy_hex, mnemonic, seed, _xprv in entries:
        word_list = mnemonic.split()
        assert bip39_checksum_ok(word_list, index_of), mnemonic
        seed_derived = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", mnemonic).encode("utf-8"), b"mnemonicTREZOR", 2048, 64)
        assert seed_derived.hex() == seed, mnemonic
        # A replacement last word sharing the first four letters is the case the BIP-39
        # reference suite checks: the word is real, so only the checksum can reject it.
        last = word_list[-1]
        corrupt = next(
            (w for w in prefix_groups[last[:4]] if w != last and not bip39_checksum_ok(word_list[:-1] + [w], index_of)),
            next(w for w in words if w != last and not bip39_checksum_ok(word_list[:-1] + [w], index_of)),
        )
        rows.append(
            "  {%s, %s, %s, %s, %s}"
            % (
                cstr(entropy_hex),
                cstr(mnemonic),
                cstr(seed),
                cstr(" ".join(word_list[:-1] + [corrupt])),
                "true" if len(entropy_hex) // 2 in (16, 32) else "false",
            )
        )

    wordlist_sha = wordlist_digest("bip39_wordlist.txt", words)
    seedqr_index_rows, seedqr_rows = seedqr_tables(entries, words, index_of)
    last_word_index_rows, last_word_rows = last_word_tables(entries, index_of)

    return f"""#ifndef VECTORS_BIP39_H
#define VECTORS_BIP39_H

/* spec: {provenance('bip39_vectors.json')}
 *
 * One entry per official BIP-39 English vector: entropy, mnemonic, PBKDF2-HMAC-SHA512
 * seed (2048 rounds, salt "mnemonic" + passphrase "TREZOR"), and the same mnemonic with
 * its last word replaced by a different real word that must fail the checksum.
 *
 * supported is true for the entropy lengths this firmware implements (12 and 24 words);
 * the official vectors also cover 15, 18 and 21 word mnemonics.
 */
#include <stdbool.h>

typedef struct {{
  const char* entropy;
  const char* mnemonic;
  const char* seed;
  const char* corrupt_mnemonic;
  bool supported;
}} bip39_vector_t;

static const bip39_vector_t BIP39_VECTORS[] = {{
{",\n".join(rows)}
}};

#define BIP39_VECTOR_COUNT (sizeof(BIP39_VECTORS) / sizeof(BIP39_VECTORS[0]))

/* spec: {provenance('bip39_wordlist.txt')}
 *
 * Digest of the official list joined by '\n' with a trailing newline.
 */
#define BIP39_WORDLIST_COUNT 2048
#define BIP39_WORDLIST_SHA256 "{wordlist_sha}"

/* spec: SeedQR standard mode (four decimal digits per BIP-39 index, no separator, 48 or 96 of them)
 *       and the Trezor vectors above.
 *
 * A standard SeedQR is the word indexes written as four decimal digits each, so the digit string of a
 * published mnemonic is published data too: the rows with a seed are that string, and the seed is the
 * published one. digits/len is what a caller hands over (len is separate because a scanned QR is not
 * NUL-terminated and an embedded NUL is one of the cases); indexes is a row of SEEDQR_INDEXES, or -1
 * when the string must be refused; seed is the published seed those indexes must produce under the
 * passphrase the vectors use, or NULL for the strings that are not published mnemonics.
 *
 * The rows without a seed are what the function accepts or refuses for its own reasons. Two of its
 * properties are surprising and are pinned rather than fixed:
 *
 *   - it checks the *value*, not the character class: 1000*(c-'0') is arithmetic on whatever octet is
 *     there, so ':' is 10 and 'A' in the hundreds place is 1700, and both are in range. SeedQR from a
 *     QR reader arrives as NUMERIC data, so a real scanner cannot send that; the row is here because
 *     the function is public and the next caller may not have a scanner in front of it.
 *   - *out_len is written before the digits are examined, so a refusal part way through still reports
 *     a word count. The one caller in the firmware only reads it when the answer was true.
 */
typedef struct {{
  const char* digits;
  uint32_t len;
  int16_t indexes;
  const char* seed;
}} seedqr_row_t;

static const uint16_t SEEDQR_INDEXES[][24] = {{
{seedqr_index_rows}
}};

static const seedqr_row_t SEEDQR_ROWS[] = {{
{seedqr_rows}
}};

#define SEEDQR_ROW_COUNT (sizeof(SEEDQR_ROWS) / sizeof(SEEDQR_ROWS[0]))

/* spec: BIP-39's checksum (SHA-256 of the entropy, its first len/3 bits appended to the 11 bit word
 *       indexes) -- the same rule the vectors above were built with.
 *
 * The last word of a mnemonic is the only one the checksum constrains, so the words that could
 * complete a partially entered seed are computable from the words already there: the firmware does
 * that when the user has typed or scanned all but the last. indexes is a row of
 * LAST_WORD_INDEXES -- the published mnemonic minus its last word -- last is the published last word,
 * count is the number of completions (2 to the power of the bits the last word does not carry), and
 * mask_sha256 is the digest of the 256 byte candidate bitmap in index order.
 */
typedef struct {{
  uint32_t words;
  uint16_t last;
  uint32_t count;
  const char* mask_sha256;
}} last_word_row_t;

static const uint16_t LAST_WORD_INDEXES[][24] = {{
{last_word_index_rows}
}};

static const last_word_row_t LAST_WORD_ROWS[] = {{
{last_word_rows}
}};

#define LAST_WORD_ROW_COUNT (sizeof(LAST_WORD_ROWS) / sizeof(LAST_WORD_ROWS[0]))

#endif
"""


# ----------------------------------------------------------------- slip39


def slip39_vectors() -> str:
    words = fetch("slip39_wordlist.txt").split()
    entries = json.loads(fetch("slip39_vectors.json"))

    rows = []
    for desc, mnemonics, secret_hex, _xprv in entries:
        shares = ",".join(cstr(m) for m in mnemonics)
        rows.append(f"  {{{{{shares}}}, {len(mnemonics)}, {cstr(secret_hex)}, {cstr(desc)}}}")

    return f"""#ifndef VECTORS_SLIP39_H
#define VECTORS_SLIP39_H

/* spec: {provenance('slip39_vectors.json')}
 *
 * Passphrase "TREZOR" for every set, per the SLIP-39 test vector document. An empty
 * master secret marks a share set that must be rejected.
 */
#define SLIP39_VECTOR_MAX_SHARES 8
#define SLIP39_PASSPHRASE "TREZOR"

typedef struct {{
  const char* mnemonics[SLIP39_VECTOR_MAX_SHARES];
  unsigned int share_count;
  const char* master_secret;
  const char* description;
}} slip39_vector_t;

static const slip39_vector_t SLIP39_VECTORS[] = {{
{",\n".join(rows)}
}};

#define SLIP39_VECTOR_COUNT (sizeof(SLIP39_VECTORS) / sizeof(SLIP39_VECTORS[0]))

/* spec: {provenance('slip39_wordlist.txt')}
 *
 * Digest of the official list joined by '\n' with a trailing newline.
 */
#define SLIP39_WORDLIST_COUNT {len(words)}
#define SLIP39_WORDLIST_SHA256 "{wordlist_digest("slip39_wordlist.txt", words)}"

#endif
"""


# ----------------------------------------------------------------- base58


def base58_alphabet() -> str:
    """The base58 digit set, taken from Bitcoin Core's reference implementation."""
    match = re.search(r'(?:pszBase58|ALPHABET)[^"]*"([^"]{50,100})"', fetch("base58.cpp"))
    alphabet = match.group(1)
    assert len(alphabet) == 58 and len(set(alphabet)) == 58, alphabet
    return alphabet


B58_ALPHABET = base58_alphabet()


def b58decode(text: str) -> bytes:
    value = 0
    for char in text:
        value = value * 58 + B58_ALPHABET.index(char)
    out = value.to_bytes((value.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip(B58_ALPHABET[0]))
    return b"\x00" * pad + out


def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    value = int.from_bytes(data, "big")
    out = ""
    while value:
        value, rem = divmod(value, 58)
        out = B58_ALPHABET[rem] + out
    return B58_ALPHABET[0] * (len(data) - len(data.lstrip(b"\x00"))) + out


def parse_bip32_extended_keys() -> list[tuple[str, str]]:
    text = fetch("bip32.mediawiki")
    keys = re.findall(r"ext (?:prv|pub): ((?:xprv|xpub)[0-9A-HJ-NP-Za-km-z]+)", text)
    pairs = []
    for key in keys[:8]:
        payload = b58decode(key)
        assert len(payload) == 82, (key, len(payload))
        pairs.append((key, hexs(payload[:-4])))
    return pairs


def base58_vectors() -> str:
    pairs = parse_bip32_extended_keys()
    body = ",\n".join(
        "  {%s, %s}" % (cstr(key), cstr(payload)) for key, payload in pairs
    )

    legacy = []
    for key, payload in pairs:
        raw = b58decode(key)[:-4]
        pubkey = raw[45:78]
        h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
        for prefix in (0, 5):
            legacy.append(
                "  {%s, %d, %s}"
                % (cstr(hexs(h160)), prefix, cstr(b58check_encode(bytes([prefix]) + h160)))
            )

    return f"""#ifndef VECTORS_BASE58_H
#define VECTORS_BASE58_H

/* spec: {provenance('bip32.mediawiki')}
 *
 * The extended keys are the official BIP-32 serialisations; the payload is everything
 * before the 4-byte double-SHA256 checksum, decoded with the BIP-13 alphabet. They carry
 * leading zero bytes, big-endian magnitude and the alphabet boundary cases.
 */
typedef struct {{
  const char* encoded;
  const char* payload;
}} base58_vector_t;

static const base58_vector_t BASE58_VECTORS[] = {{
{body}
}};

#define BASE58_VECTOR_COUNT (sizeof(BASE58_VECTORS) / sizeof(BASE58_VECTORS[0]))

/* reference: BIP-13 base58check over CPython hashlib double SHA-256. */
typedef struct {{
  const char* hash160;
  unsigned char prefix;
  const char* address;
}} legacy_address_vector_t;

static const legacy_address_vector_t LEGACY_ADDRESS_VECTORS[] = {{
{",\n".join(legacy)}
}};

#define LEGACY_ADDRESS_VECTOR_COUNT (sizeof(LEGACY_ADDRESS_VECTORS) / sizeof(LEGACY_ADDRESS_VECTORS[0]))

/* spec: {provenance('base58.cpp')} */
#define B58_ALPHABET "{B58_ALPHABET}"

#endif
"""


# ------------------------------------------------------- bech32 / segwit


def parse_segwit_vectors(name: str) -> tuple[list[dict], list[str]]:
    """The test-vector appendix lists `<tt>address</tt>: <tt>scriptPubKey</tt>` for the valid
    cases and `<tt>address</tt>: reason` for the invalid ones."""
    text = fetch(name)
    appendix = text[text.index("Test vectors") :]
    valid, invalid = [], []
    for match in re.finditer(
        r"^[ \t]*\*[ \t]*<tt>([A-Za-z0-9]+)</tt>:[ \t]*(.*)$", appendix, re.M
    ):
        address, rest = match.group(1), match.group(2).strip()
        tt = re.match(r"<tt>([0-9a-fA-F]+)</tt>", rest)
        if tt:
            script = tt.group(1)
            witver_byte = int(script[0:2], 16)
            witver = witver_byte if witver_byte <= 16 else witver_byte - 0x50
            prog_len = int(script[2:4], 16)
            program = script[4 : 4 + prog_len * 2]
            assert len(program) == prog_len * 2, address
            valid.append(
                {
                    "address": address,
                    "hrp": address.lower().rsplit("1", 1)[0],
                    "witver": witver,
                    "program": program,
                }
            )
        elif rest.startswith("0x") or rest:
            invalid.append(address)
    return valid, invalid


def bech32_vectors() -> str:
    v173, i173 = parse_segwit_vectors("bip173.mediawiki")
    v350, i350 = parse_segwit_vectors("bip350.mediawiki")
    # BIP-350 restates the BIP-173 vectors and obsoletes its witness v1+ rows, which used the
    # bech32 checksum: those addresses are invalid today and BIP-350 lists the corrected ones.
    v350 = [row for row in v350 if row["witver"] != 0]
    v173 = [row for row in v173 if row["witver"] == 0]
    i350 = [row for row in i350 if row not in i173]

    def valid_rows(rows: list[dict]) -> str:
        return ",\n".join(
            "  {%s, %s, %d, %s}" % (cstr(r["address"]), cstr(r["hrp"]), r["witver"], cstr(r["program"]))
            for r in rows
        )

    def invalid_rows(rows: list[str]) -> str:
        return ",\n".join("  " + cstr(a) for a in rows)

    return f"""#ifndef VECTORS_BECH32_H
#define VECTORS_BECH32_H

/* spec: {provenance('bip173.mediawiki')}
 *         {provenance('bip350.mediawiki')}
 *
 * witness_program_t is the decoded form segwit_addr_decode() must return for the address;
 * the same rows drive the encoder in the other direction. Upper-case rows check that the
 * encoder accepts a mixed-case address, as the spec requires.
 *
 * The invalid rows are the ones each document lists as rejected for the mainnet prefix,
 * so they are all decoded with "bc" -- including the row whose stated reason is a wrong
 * human-readable part.
 */
#define SEGWIT_HRP "bc"

typedef struct {{
  const char* address;
  const char* hrp;
  int witver;
  const char* program;
}} witness_program_t;

static const witness_program_t BECH32_VALID[] = {{
{valid_rows(v173)}
}};

#define BECH32_VALID_COUNT (sizeof(BECH32_VALID) / sizeof(BECH32_VALID[0]))

static const char* const BECH32_INVALID[] = {{
{invalid_rows(i173)}
}};

#define BECH32_INVALID_COUNT (sizeof(BECH32_INVALID) / sizeof(BECH32_INVALID[0]))

static const witness_program_t BECH32M_VALID[] = {{
{valid_rows(v350)}
}};

#define BECH32M_VALID_COUNT (sizeof(BECH32M_VALID) / sizeof(BECH32M_VALID[0]))

static const char* const BECH32M_INVALID[] = {{
{invalid_rows(i350)}
}};

#define BECH32M_INVALID_COUNT (sizeof(BECH32M_INVALID) / sizeof(BECH32M_INVALID[0]))

#endif
"""


# -------------------------------------------------------------- compactsize


def compactsize_encode(value: int) -> str:
    """Bitcoin's variable length integer: one byte below 0xFD, otherwise FD/FE/FF followed by
    2/4/8 little-endian bytes."""
    if value < 0xFD:
        return hexs(value.to_bytes(1, "big"))
    if value <= 0xFFFF:
        return hexs(b"\xfd" + value.to_bytes(2, "little"))
    if value <= 0xFFFFFFFF:
        return hexs(b"\xfe" + value.to_bytes(4, "little"))
    return hexs(b"\xff" + value.to_bytes(8, "little"))


def compactsize_forced(value: int, width: int) -> str:
    """Encodes value with the prefix of a wider class than it needs, which is what makes an
    encoding non-canonical."""
    prefix = {2: b"\xfd", 4: b"\xfe", 8: b"\xff"}[width]
    return hexs(prefix + value.to_bytes(width, "little"))


def compactsize_vectors() -> str:
    values = [
        0,
        252,
        253,
        0xFEFF,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
        0xFFFFFFFFFFFF,
        0x02000000,
        0x02000001,
    ]
    cases = [(value, compactsize_encode(value)) for value in values]
    body = ",\n".join(
        "  {0x%xULL, %s, %s}" % (value, cstr(encoding), "true" if value <= 0x02000000 else "false")
        for value, encoding in cases
    )

    # The value is the one a shorter encoding covers, forced into the next width class.
    noncanonical = ",\n".join(
        "  " + cstr(encoding)
        for encoding in [
            compactsize_forced(252, 2),
            compactsize_forced(0xFFFF, 4),
            compactsize_forced(0xFFFFFFFF, 8),
        ]
    )
    return f"""#ifndef VECTORS_COMPACTSIZE_H
#define VECTORS_COMPACTSIZE_H

/* spec: Bitcoin protocol variable length integer, the encoding psbt_tx.c reads and writes.
 * Each row is a boundary of one of the four width classes.
 *
 * readable is false above 0x02000000: compactsize_read() refuses any length larger than its
 * MAX_SERIALIZE_SIZE, so those rows must fail rather than round-trip.
 */
#include <stdbool.h>

typedef struct {{
  unsigned long long value;
  const char* encoding;
  bool readable;
}} compactsize_vector_t;

static const compactsize_vector_t COMPACTSIZE_VECTORS[] = {{
{body}
}};

#define COMPACTSIZE_VECTOR_COUNT (sizeof(COMPACTSIZE_VECTORS) / sizeof(COMPACTSIZE_VECTORS[0]))

/* Encodings rejected because a shorter one represents the same value -- the rule Bitcoin Core's
 * ReadCompactSize() applies. These rows are built from that rule, not fetched from a document. */
static const char* const COMPACTSIZE_NONCANONICAL[] = {{
{noncanonical}
}};

#define COMPACTSIZE_NONCANONICAL_COUNT (sizeof(COMPACTSIZE_NONCANONICAL) / sizeof(COMPACTSIZE_NONCANONICAL[0]))

#endif
"""


# ---------------------------------------------------------------- addr_uri

# Expectations for the URI splitter. Nothing here is computed from the module: the inputs are the
# two specifications' own examples (asserted below to appear verbatim) plus forms that occur in
# practice, and each expectation is stated for the row or the group it belongs to.
#
#   accept  whether address_uri_parse() must return true
#   address the target it must hand back, verbatim -- case included, since base58 and the ERC-681
#           hexadecimal address are case-bearing
#   index   the keycard-specific ?index= narrowing, or None for "the caller picks the range"
#
# The policy is addr_uri.h's: a URI is acted on only if it cannot point somewhere other than the
# address in its path.

BIP21_ADDRESS = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"
ERC681_ADDRESS = "0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359"
ERC681_CONTRACT = "0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7"
ERC681_BENEFICIARY = "0x8e23ee67d1332ad560396262c48ffbb01f93d052"

URI_CASES = [
    # BIP-21's own examples. Its "Forward compatibility" section: a client that does not implement
    # a req- variable MUST consider the whole URI invalid; unknown non-req- variables may be
    # ignored. Nothing here but the path can move coins, so index stays None.
    ("bitcoin:" + BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?label=Luke-Jr" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?amount=20.3&label=Luke-Jr" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?amount=50&label=Luke-Jr&message=Donation%%20for%%20project%%20xyz" % BIP21_ADDRESS,
     True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999" % BIP21_ADDRESS,
     False, "bitcoin", "", None),
    ("bitcoin:%s?somethingyoudontunderstand=50&somethingelseyoudontget=999" % BIP21_ADDRESS,
     True, "bitcoin", BIP21_ADDRESS, None),
    # BIP-21: "The scheme component is case-insensitive... The rest of the URI is case-sensitive".
    # Upper case parameter keys are therefore not what the specification calls them -- refusing
    # them anyway is stricter than required, which is the safe direction for a destination key.
    ("BITCOIN:" + BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?LIGHTNING=lnbc1" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?REQ-x=1" % BIP21_ADDRESS, False, "bitcoin", "", None),
    # A second '?' is legal query data under RFC 3986; the keys before it are unaffected.
    ("bitcoin:%s?label=Steve?message=Comments" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    # A fragment right after the address is refused outright. A '#' further along is inside the
    # query, where it starts no parameter -- so the item that follows is an unknown key, not req-.
    ("bitcoin:%s#donate" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?amount=20.3#frag" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?#req-x=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    # Segwit addresses in bitcoin: URIs, from BIP-173. BIP-21's grammar says *base58 and predates
    # them; the case the vector publishes is preserved for the decoder to judge.
    ("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", True, "bitcoin",
     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None),
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", True, "",
     "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", None),

    # Query keys that name a destination of their own are refused whole -- one row per key in
    # OTHER_DESTINATION_KEYS, cross-checked below so a key added to that list without a vector
    # fails generation, plus the near misses that have to stay accepted because the match is on the
    # whole key. The Lightning spellings matter because LUD-16 and LUD-17 put a bolt11 invoice or
    # an LNURL next to an on-chain address.
    ("bitcoin:%s?lightning=lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf" % BIP21_ADDRESS,
     False, "bitcoin", "", None),
    ("bitcoin:%s?lno=LNO1QYR5HXW" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?lnurl=LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0D9EK2PP5V0XV" % BIP21_ADDRESS,
     False, "bitcoin", "", None),
    ("bitcoin:%s?lnurl" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?LNURL=x" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?lnurlx=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?sp=0200000001" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?pay=https://example.com/pay" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?bc=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" % BIP21_ADDRESS,
     False, "bitcoin", "", None),
    ("bitcoin:%s?tb=tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" % BIP21_ADDRESS,
     False, "bitcoin", "", None),
    ("bitcoin:%s?pop=deadbeef" % BIP21_ADDRESS, False, "bitcoin", "", None),
    # A valueless key still names the destination, and so does a key that merely starts with one.
    ("bitcoin:%s?lightning" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?lightningx=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?pay-1=2" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?xreq-y=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?req-" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?req-x&amount=1" % BIP21_ADDRESS, False, "bitcoin", "", None),

    # ERC-681: request = schema_prefix target_address [ "@" chain_id ] [ "/" function_name ]
    #                   [ "?" parameters ], schema_prefix = "ethereum" ":" [ "pay-" ].
    # The target_address is either the beneficiary or, when a function follows, the contract --
    # and a contract is never a payment target, so a path is refused.
    ("ethereum:%s?value=2.014e18" % ERC681_ADDRESS, True, "ethereum", ERC681_ADDRESS, None),
    ("ethereum:pay-%s" % ERC681_ADDRESS, True, "ethereum", ERC681_ADDRESS, None),
    ("ethereum:%s/transfer?address=%s&uint256=1" % (ERC681_CONTRACT, ERC681_BENEFICIARY),
     False, "ethereum", "", None),
    ("ethereum:%s/" % ERC681_CONTRACT, False, "ethereum", "", None),
    ("ethereum:%s/?value=1" % ERC681_CONTRACT, False, "ethereum", "", None),
    # The chain id is metadata, not a destination: it is dropped. An empty or non-numeric one is
    # still refused, because guessing which network a request meant is a destination choice.
    ("ethereum:%s@1" % ERC681_CONTRACT, True, "ethereum", ERC681_CONTRACT, None),
    ("ethereum:%s@137?value=1e18" % ERC681_CONTRACT, True, "ethereum", ERC681_CONTRACT, None),
    ("ethereum:%s@abc" % ERC681_CONTRACT, False, "ethereum", "", None),
    ("ethereum:%s@?value=1" % ERC681_CONTRACT, True, "ethereum", ERC681_CONTRACT, None),
    # "pay-" is part of the scheme prefix in the specification's grammar and lower case there; the
    # scheme is matched case-insensitively (RFC 3986) but the prefix is not, so an upper case PAY-
    # stays glued to what the caller then has to make of it.
    ("ETHEREUM:%s" % ERC681_ADDRESS, True, "ethereum", ERC681_ADDRESS, None),
    ("ethereum:PAY-%s" % ERC681_ADDRESS, True, "ethereum", "PAY-" + ERC681_ADDRESS, None),
    # ERC-681 allows an ENS name where the address goes, and says a client "may ... outright
    # reject" names that look like hexadecimal addresses. The splitter hands the name over and the
    # decoder in core.c is what refuses it, because it wants 0x plus forty hex digits.
    ("ethereum:vitalik.eth", True, "ethereum", "vitalik.eth", None),
    # BIP-21 lists "address" as a query key and ERC-681 uses it as transfer's beneficiary. On a URI
    # with no function the path target wins, so it is an unknown key here -- not an alias.
    ("ethereum:%s?address=%s" % (ERC681_ADDRESS, ERC681_BENEFICIARY), True, "ethereum",
     ERC681_ADDRESS, None),

    # keycard's own ?index= narrows which of its addresses the user is asked to confirm; it can
    # only make the search stricter, so it is checked for range rather than for meaning. index=0
    # is a real index and must not read as "absent".
    ("bitcoin:%s?index=0" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 0),
    ("bitcoin:%s?index=7&label=x" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 7),
    ("bitcoin:%s?label=x&index=7" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 7),
    ("bitcoin:%s?index=007" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 7),
    ("bitcoin:%s?index=4294967294" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 4294967294),
    ("bitcoin:%s?index=4294967295" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index=4294967296" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index=99999999999999999999" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index=" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?index=1&index=4294967295" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index=+1" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?index=1e3" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s?indexx=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    # Short keys, including ones shorter than the req- prefix itself.
    ("bitcoin:%s?x=1" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?x" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?a=1&b=2&c=3" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),

    # Forms with no scheme at all, and forms that only look like URIs. A colon always introduces a
    # scheme, so anything unknown before one is refused rather than treated as an address.
    (BIP21_ADDRESS, True, "", BIP21_ADDRESS, None),
    ("LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0D9EK2PP5V0XV" + "0" * 40, True, "",
     "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0D9EK2PP5V0XV" + "0" * 40, None),
    ("", False, "", "", None),
    ("   ", False, "", "", None),
    ("\t \r\n", False, "", "", None),
    ("bitcoin:", False, "bitcoin", "", None),
    ("bitcoin:?index=1", False, "bitcoin", "", None),
    (":%s" % BIP21_ADDRESS, False, "", "", None),
    ("http://example.com/%s" % BIP21_ADDRESS, False, "", "", None),
    # Without a colon there is no scheme to check, so the whole string is the target and whether it
    # means anything is the decoder's problem.
    ("mattermost", True, "", "mattermost", None),
    # Surrounding whitespace is what a scanned line or a clipboard tends to carry.
    ("  bitcoin:%s  \t\r\n" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("\nbitcoin:%s?index=2\n" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 2),
    # A colon after the target opens a query-ish tail rather than another scheme; the target is
    # still the path, and the tail is checked for destination keys like any other.
    ("bitcoin:%s:extra" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s:req-x=1" % BIP21_ADDRESS, False, "bitcoin", "", None),
    # Empty query items, and the delimiters that end a target.
    ("bitcoin:%s?" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    ("bitcoin:%s?&" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, None),
    # Only '?' opens a query, so a '&' that arrives before one is part of the target rather than a
    # separator. BIP-21's grammar makes it not base58 either, so what refuses such a URI is the
    # decoder -- the splitter's contract is to report the path, not to judge it.
    ("bitcoin:%s&&index=2" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS + "&&index=2", None),
    ("bitcoin:%s&index=2" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS + "&index=2", None),
    ("bitcoin:%s@123?index=2" % BIP21_ADDRESS, True, "bitcoin", BIP21_ADDRESS, 2),
    ("bitcoin:%s@123abc" % BIP21_ADDRESS, False, "bitcoin", "", None),
    ("bitcoin:%s/?x=1" % BIP21_ADDRESS, False, "bitcoin", "", None),

    # out.address is char[MAX_ADDR_LEN] and the copy is guarded by the header, so a target of
    # MAX_ADDR_LEN - 1 characters still leaves room for the terminator and longer does not.
    ("bitcoin:" + "1" * 89, True, "bitcoin", "1" * 89, None),
    ("bitcoin:" + "1" * 90, True, "bitcoin", "1" * 90, None),
    ("bitcoin:" + "1" * 91, False, "bitcoin", "", None),
    ("bitcoin:" + "1" * 500, False, "bitcoin", "", None),
]


def addr_uri_vectors() -> str:
    """Address URI splitting, against BIP-21, ERC-681 and the policy stated in addr_uri.h."""
    bip21 = fetch("bip-0021.mediawiki")
    erc681 = fetch("erc-681.md")

    for spec, needles in ((bip21, [BIP21_ADDRESS, ("bitcoin:%s?label=Luke-Jr" % BIP21_ADDRESS),
                                   ("bitcoin:%s?amount=20.3&label=Luke-Jr" % BIP21_ADDRESS),
                                   ("bitcoin:%s?amount=50&label=Luke-Jr&message=Donation%%20for%%20project%%20xyz" % BIP21_ADDRESS),
                                   ("bitcoin:%s?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999" % BIP21_ADDRESS),
                                   ("bitcoin:%s?somethingyoudontunderstand=50&somethingelseyoudontget=999" % BIP21_ADDRESS)]),
                          (erc681, [ERC681_ADDRESS, ERC681_CONTRACT, ERC681_BENEFICIARY,
                                    ("ethereum:%s?value=2.014e18" % ERC681_ADDRESS),
                                    ("ethereum:%s/transfer?address=%s&uint256=1" % (ERC681_CONTRACT, ERC681_BENEFICIARY))])):
        for needle in needles:
            assert needle in spec, needle

    bip173 = fetch("bip173.mediawiki")
    assert "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" in bip173.upper()

    # Every key the parser treats as naming another destination has to have a row of its own: the
    # list lives in the firmware, the reasons live here, and this is what keeps them together.
    listing = re.search(
        r"OTHER_DESTINATION_KEYS\[\] = \{(.*?)\};",
        (HERE.parents[1] / "app/crypto/addr_uri.c").read_text(),
        re.S,
    )
    keys = re.findall(r'"([^"]+)"', listing.group(1))
    assert len(keys) >= 7, keys
    refused = [uri for uri, accept, *_ in URI_CASES if not accept]
    for key in keys:
        assert any(u.endswith("?%s" % key) or ("?%s=" % key) in u for u in refused), key

    rows = []
    for uri, accept, scheme, address, index in URI_CASES:
        if scheme == "bitcoin":
            kind = "ADDR_URI_BITCOIN"
        elif scheme == "ethereum":
            kind = "ADDR_URI_ETHEREUM"
        else:
            kind = "ADDR_URI_NONE"
        rows.append(
            "  {%s, %d, %s, %s, %s}"
            % (cstr(uri), 1 if accept else 0, kind, cstr(address),
               "ADDR_URI_INDEX_NONE" if index is None else "%d" % index)
        )

    return f"""#ifndef VECTORS_ADDR_URI_H
#define VECTORS_ADDR_URI_H

/* spec: {provenance('bip-0021.mediawiki')}
 *     {provenance('erc-681.md')}
 *     {provenance('bip173.mediawiki')}
 *
 * Splitting an address URI into scheme, target and index. The URIs are the two documents' own
 * examples where they have them -- asserted while generating -- and the expected verdict for each
 * row follows those documents plus the rule addr_uri.h states: refuse a URI that could point
 * somewhere other than the target in its path. Where a row is accepted with a target the caller
 * cannot use (an ENS name, a LNURL, an upper case PAY- prefix), that is the splitter doing its
 * part and leaving the judgement to the decoder.
 */
typedef struct {{
  const char* uri;
  int accept;
  addr_uri_scheme_t scheme;
  const char* address;
  uint32_t index;
}} addr_uri_case_t;

static const addr_uri_case_t ADDR_URI_CASES[] = {{
{",\n".join(rows)}}};

#define ADDR_URI_CASES_COUNT (sizeof(ADDR_URI_CASES) / sizeof(ADDR_URI_CASES[0]))

#endif
"""


# ---------------------------------------------------------------- address


def erc55_vectors() -> list[tuple[str, str]]:
    """The addresses ERC-55 itself publishes, as (40 lowercase hex, mixed case).

    `mixed` is the string verbatim from the document where the document printed one -- the
    document prints four mixed-case addresses and asserts they are their own checksum. The
    rest come from the algorithm below, which the generator first checks against those four.
    """
    from Crypto.Hash import keccak

    text = fetch("erc-55.md")
    published: list[str] = []
    for seen in re.findall(r"0x([0-9A-Fa-f]{40})", text):
        if all(seen.lower() != other.lower() for other in published):
            published.append(seen)
    assert len(published) >= 8, published

    def checksum(address: str) -> str:
        digest = keccak.new(digest_bits=256, data=address.encode()).hexdigest()
        return "".join(
            char.upper() if char.isalpha() and int(nibble, 16) >= 8 else char
            for char, nibble in zip(address, digest)
        )

    mixed = [a for a in published if a != a.lower() and a != a.upper()]
    assert len(mixed) >= 4, mixed
    for address in mixed:
        assert checksum(address.lower()) == address, address

    return [(address.lower(), checksum(address.lower())) for address in published]


def prefix_version_cases() -> list[tuple[int, int, str]]:
    """Version numbers a base58check payload starts with, as (version, byte count, bytes).

    The 4-byte cases are the version bytes of the extended keys BIP-32 publishes, read off the
    prefix of those keys; the rest are chosen to sit on each side of the 1/2/3/4 byte boundaries
    `address_prefix_bytes_len()` uses.
    """
    cases = [
        (0x00000000, 1),
        (0x00000001, 1),
        (0x0000007F, 1),
        (0x00000080, 1),
        (0x000000FF, 1),
        (0x00000100, 2),
        (0x0000FFFF, 2),
        (0x00010000, 3),
        (0x00FFFFFF, 3),
        (0x01000000, 4),
        (0x7FFFFFFF, 4),
        (0xFFFFFFFF, 4),
    ]

    versions = set()
    for key, _payload in parse_bip32_extended_keys():
        versions.add(int.from_bytes(b58decode(key)[:-4][:4], "big"))
    assert versions == {0x0488B21E, 0x0488ADE4}, [hex(v) for v in versions]

    cases += [(version, 4) for version in sorted(versions)]
    return [(version, length, hexs(version.to_bytes(length, "big"))) for version, length in cases]


def address_vectors() -> str:
    """EIP-55 casing comes from eth_utils and the point decompression from coincurve
    (libsecp256k1), both over the public keys carried by the official BIP-32 keys."""
    import coincurve
    import eth_utils
    from Crypto.Hash import keccak

    rows = []
    for key, _payload in parse_bip32_extended_keys():
        if not key.startswith("xpub"):  # at offset 45 an xprv carries a private key
            continue
        compressed = b58decode(key)[:-4][45:78]
        uncompressed = coincurve.PublicKey(compressed).format(compressed=False)
        digest = keccak.new(digest_bits=256, data=uncompressed[1:]).digest()
        lowercase = digest[12:32].hex()
        checksummed = eth_utils.to_checksum_address("0x" + lowercase)[2:]
        rows.append(
            "  {%s, %s, %s, %s}"
            % (
                cstr(hexs(compressed)),
                cstr(hexs(uncompressed)),
                cstr(lowercase),
                cstr(checksummed),
            )
        )

    erc55 = ",\n".join(
        "  {%s, %s}" % (cstr(lower), cstr(mixed)) for lower, mixed in erc55_vectors()
    )
    prefixes = ",\n".join(
        "  {0x%08X, %d, %s}" % (version, length, cstr(raw))
        for version, length, raw in prefix_version_cases()
    )

    return f"""#ifndef VECTORS_ADDRESS_H
#define VECTORS_ADDRESS_H

/* reference: eth_utils.to_checksum_address (EIP-55) and coincurve/libsecp256k1 point
 * decompression, applied to the public keys inside {provenance('bip32.mediawiki')}
 *
 * eth_address is the 20 raw bytes without 0x; eth_address_checksummed is the EIP-55
 * mixed-case rendering, also without 0x.
 */
typedef struct {{
  const char* pubkey_compressed;
  const char* pubkey_uncompressed; /* 0x04 || x || y */
  const char* eth_address;
  const char* eth_address_checksummed;
}} eth_address_vector_t;

static const eth_address_vector_t ETH_ADDRESS_VECTORS[] = {{
{",\n".join(rows)}
}};

#define ETH_ADDRESS_VECTOR_COUNT (sizeof(ETH_ADDRESS_VECTORS) / sizeof(ETH_ADDRESS_VECTORS[0]))

/* spec: {provenance('erc-55.md')}
 *
 * The addresses the checksum document publishes. `lower` is those same bytes in the form the
 * document says carries no checksum, `mixed` the form that does, so a row pins both the encoder
 * and what the verifier must accept.
 */
typedef struct {{
  const char* lower;
  const char* mixed;
}} erc55_vector_t;

static const erc55_vector_t ERC55_VECTORS[] = {{
{erc55}
}};

#define ERC55_VECTOR_COUNT (sizeof(ERC55_VECTORS) / sizeof(ERC55_VECTORS[0]))

/* The version bytes of {provenance('bip32.mediawiki')}'s own keys for the 4 byte cases, the
 * boundaries of address_prefix_bytes_len() for the rest. `bytes` is the version written
 * big-endian over exactly `len` bytes, which is what address_check_prefix() reads back.
 */
typedef struct {{
  uint32_t version;
  unsigned char len;
  const char* bytes;
}} addr_prefix_vector_t;

static const addr_prefix_vector_t ADDR_PREFIX_VECTORS[] = {{
{prefixes}
}};

#define ADDR_PREFIX_VECTOR_COUNT (sizeof(ADDR_PREFIX_VECTORS) / sizeof(ADDR_PREFIX_VECTORS[0]))

#endif
"""


# ---------------------------------------------------------------- psbt


magic = b"\x70\x73\x62\x74\xff"


def parse_bip174_cases() -> list[dict]:
    """The three groups of cases in BIP-174's Test Vectors section."""
    text = fetch("bip174.mediawiki")
    start = text.index("==Test Vectors==")
    body = text[start : text.index("==Rationale==")]

    groups = {"invalid": "The following are invalid PSBTs:",
              "valid": "The following are valid PSBTs:",
              "signer": "Fails Signer checks"}
    marks = sorted(((body.index(label), name) for name, label in groups.items()))

    cases = []
    for position, (offset, name) in enumerate(marks):
        stop = marks[position + 1][0] if position + 1 < len(marks) else len(body)
        chunk = body[offset:stop]
        for block in chunk.split("* Case:")[1:]:
            title = block.split("\n")[0].strip()
            hex_match = re.search(r"Bytes in Hex:\s*<pre>(.*?)(?:</pre>|</pr>)", block, re.S)
            cases.append(
                {
                    "group": name,
                    "name": title,
                    "hex": "".join(hex_match.group(1).split()),
                }
            )
    return cases


def read_compactsize(data: bytes, pos: int) -> tuple[int, int]:
    """BIP-174 / Bitcoin Core ReadCompactSize, including the canonical encoding rule."""
    flag = data[pos]
    if flag < 0xFD:
        return flag, pos + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[flag]
    value = int.from_bytes(data[pos + 1 : pos + 1 + width], "little")
    if value < {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[flag]:
        raise ValueError("non-canonical compactsize")
    return value, pos + 1 + width


def parse_tx_counts(data: bytes) -> tuple[int, int]:
    if len(data) < 6:
        raise ValueError("truncated transaction")
    # marker 0x00 + flag 0x01. A legacy transaction with no inputs starts the same way
    # ("0 inputs, N outputs"), which is why the flag byte has to be checked; BIP-174 requires
    # the unsigned tx in the non-witness serialization either way.
    if data[4] == 0 and data[5] == 1:
        raise ValueError("unsigned tx uses witness serialization")

    pos = 4
    inputs, pos = read_compactsize(data, pos)
    for _ in range(inputs):
        pos += 36
        script_len, pos = read_compactsize(data, pos)
        pos += script_len + 4
    outputs, pos = read_compactsize(data, pos)
    for _ in range(outputs):
        pos += 8
        script_len, pos = read_compactsize(data, pos)
        pos += script_len
    pos += 4
    if pos != len(data):
        raise ValueError("transaction does not end at locktime")
    return inputs, outputs


def parse_psbt(data: bytes) -> tuple[list, int, int]:
    """Reference parse of a PSBT, returning the records as (scope, key, value) triples."""
    if data[:5] != b"\x70\x73\x62\x74\xff":
        raise ValueError("bad magic")

    pos = 5
    records: list[tuple[int, bytes, bytes]] = []

    def read_map(scope: int) -> int:
        nonlocal pos
        while data[pos] != 0:
            key_len, pos = read_compactsize(data, pos)
            key = data[pos : pos + key_len]
            pos += key_len
            value_len, pos = read_compactsize(data, pos)
            value = data[pos : pos + value_len]
            if len(value) != value_len:
                raise ValueError("value shorter than stated")
            pos += value_len
            records.append((scope, key, value))
        return pos + 1

    pos = read_map(0)
    unsigned = next((value for scope, key, value in records if scope == 0 and key == b"\x00"), None)
    if unsigned is None:
        raise ValueError("no unsigned tx")

    inputs, outputs = parse_tx_counts(unsigned)
    for _ in range(inputs):
        pos = read_map(1)
    for _ in range(outputs):
        pos = read_map(2)
    if pos != len(data):
        raise ValueError("trailing data after the last map")
    return records, inputs, outputs


def psbt_record_digest(records: list, inputs: int, outputs: int) -> str:
    """The recipe test_psbt.c replays, per record in parse order: scope byte, key type byte,
    little-endian length and bytes of the key after its type byte, then the same for the value.
    Then the input, output and record counts, so the test can compare a mismatching structure
    field by field before falling back to the digest."""
    ctx = hashlib.sha256()
    for scope, key, value in records:
        ctx.update(bytes([scope, key[0]]))
        ctx.update((len(key) - 1).to_bytes(4, "little"))
        ctx.update(key[1:])
        ctx.update(len(value).to_bytes(4, "little"))
        ctx.update(value)
    for count in (inputs, outputs, len(records)):
        ctx.update(count.to_bytes(4, "little"))
    return ctx.hexdigest()


def psbt_constructed_cases() -> list[dict]:
    """Cases BIP-174's own list does not have, built from its serialization grammar.

    A transaction with no inputs and two outputs, used here because a PSBT whose input maps are
    all absent exercises a parser's section bookkeeping without also being byte-ambiguous with
    the witness serialization ("0 inputs, 1 output" is the same bytes as marker 0x00 flag 0x01).
    """
    tx = bytes.fromhex(
        "02000000" "00" "02" + ("00" * 8 + "00") * 2 + "00000000"
    )
    keypair = bytes([1]) + bytes([0]) + bytes([len(tx)]) + tx
    record = bytes([1 + 33]) + bytes([2]) + bytes(range(1, 34)) + bytes([4]) + bytes([0xAA] * 4)

    empty_input_maps = magic + keypair + b"\x00" + record + b"\x00" + b"\x00"

    return [
        {
            "group": "valid",
            "name": "Constructed: no input maps, output maps with records",
            "hex": hexs(empty_input_maps),
        },
        {
            "group": "invalid",
            "name": "Constructed: empty map after the output maps",
            "hex": hexs(empty_input_maps + b"\x00"),
        },
        {
            "group": "invalid",
            "name": "Constructed: garbage after the last output map",
            "hex": hexs(empty_input_maps + b"\x01\x02\x03"),
        },
    ]


def psbt_vectors() -> str:
    parses, rejected, field_invalid = [], [], []

    for case in parse_bip174_cases() + psbt_constructed_cases():
        data = bytes.fromhex(case["hex"])
        try:
            records, inputs, outputs = parse_psbt(data)
            failure = None
        except (ValueError, IndexError, KeyError) as error:
            records, inputs, outputs, failure = [], 0, 0, str(error)

        row = {
            "name": case["name"],
            "hex": hexs(data),
            "inputs": inputs,
            "outputs": outputs,
            "records": len(records),
            "digest": psbt_record_digest(records, inputs, outputs),
        }

        if case["group"] in ("valid", "signer"):
            if failure:
                raise SystemExit(f"reference could not parse a {case['group']} case: {row['name']}: {failure}")
            parses.append((case["group"], row))
        elif failure:
            rejected.append(row)
        else:
            field_invalid.append(row)

    def rows(group):
        """group entries are (name, hex, inputs, outputs, records, digest) tuples."""
        return ",\n".join(
            "  {%s,\n   %s,\n   %d, %d, %d,\n   %s}"
            % (
                cstr(row["name"]),
                cstr(row["hex"]),
                row["inputs"],
                row["outputs"],
                row["records"],
                cstr(row["digest"]),
            )
            for row in group
        )

    valid = rows([row for kind, row in parses if kind == "valid"])
    signer = rows([row for kind, row in parses if kind == "signer"])

    return f"""#ifndef VECTORS_PSBT_H
#define VECTORS_PSBT_H

/* spec: {provenance("bip174.mediawiki")}
 *
 * Every case from BIP-174's Test Vectors section, decoded from the document's own hex. The
 * structure each parse must produce (inputs, outputs, records, digest) comes from the reference
 * parser in generate.py, not from psbt.c: records are digested in parse order as
 *   scope byte | key type byte | uint32_le key length | key | uint32_le value length | value
 * followed by the uint32_le input, output and record counts.
 *
 * PSBT_VECTORS        must parse, and the signer may sign them.
 * PSBT_SIGNER_REJECTS must parse, but a signer must refuse (BIP-174 "Fails Signer checks"; the
 *                     refusal itself lives in core_btc.c, not in the parser).
 * PSBT_REJECTED       must not parse. This is the subset the reference parser rejects, so the
 *                     violation is in the serialization format itself: the magic, canonical
 *                     compactsize encodings, key and value framing, the map separators and
 *                     their count against the unsigned tx, the unsigned tx key being exactly
 *                     its type byte, the unsigned tx in non-witness serialization, and nothing
 *                     following the last output map.
 * PSBT_FIELD_INVALID  are invalid because of the *contents* of known key types, or because a
 *                     duplicated key or a filled scriptSig breaks a rule about what a field
 *                     means. psbt.c is a structural parser and hands those to its caller, so
 *                     this group records that division of labour rather than endorsing it.
 */
typedef struct {{
  const char* name;
  const char* psbt;
  unsigned int inputs;
  unsigned int outputs;
  unsigned int records;
  const char* digest;
}} psbt_vector_t;

typedef struct {{
  const char* name;
  const char* psbt;
}} psbt_reject_vector_t;

static const psbt_vector_t PSBT_VECTORS[] = {{
{valid}
}};

#define PSBT_VECTOR_COUNT (sizeof(PSBT_VECTORS) / sizeof(PSBT_VECTORS[0]))

static const psbt_vector_t PSBT_SIGNER_REJECTS[] = {{
{signer}
}};

#define PSBT_SIGNER_REJECT_COUNT (sizeof(PSBT_SIGNER_REJECTS) / sizeof(PSBT_SIGNER_REJECTS[0]))

static const psbt_reject_vector_t PSBT_REJECTED[] = {{
{",\n".join("  {%s,\n   %s}" % (cstr(row["name"]), cstr(row["hex"])) for row in rejected)}
}};

#define PSBT_REJECTED_COUNT (sizeof(PSBT_REJECTED) / sizeof(PSBT_REJECTED[0]))

static const psbt_vector_t PSBT_FIELD_INVALID[] = {{
{rows(field_invalid)}
}};

#define PSBT_FIELD_INVALID_COUNT (sizeof(PSBT_FIELD_INVALID) / sizeof(PSBT_FIELD_INVALID[0]))

#endif
"""


def bytewords_words() -> list[str]:
    """Blockchain Commons' 256 words.

    Bytewords minimal -- what app/ur/bytewords.c implements, and what a UR payload carries -- is
    each word's first and last letter. The word list makes that pair unique per byte, which is
    what lets a decoder work from the two letters alone.
    """
    raw = re.search(r'bytewords = "([a-z]+)"', fetch("bc_bytewords.c")).group(1)
    assert len(raw) == 4 * 256, f"word list is {len(raw)} chars, expected 1024"
    words = [raw[i:i + 4] for i in range(0, len(raw), 4)]
    assert len({w[0] + w[3] for w in words}) == 256, "minimal codes are not unique"
    return words


def bytewords_minimal(words: list[str], payload: bytes) -> str:
    body = "".join(words[b][0] + words[b][3] for b in payload)
    checksum = zlib.crc32(payload) & 0xFFFFFFFF
    return body + "".join(words[b][0] + words[b][3] for b in checksum.to_bytes(4, "big"))


def bytewords_upstream_cases(words: list[str]) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """BC's own vectors, read out of the standard-form literals of its reference test.

    Those literals carry the payload as words, so the bytes, the checksum and the encoding are all
    upstream. Each one is re-derived from the word list here; a disagreement over a *good* vector
    stops generation. BC's own bad-checksum literal is kept as a negative case.
    """
    src = fetch("bc_bytewords_test.c").replace('"\n    "', "")
    index = {w: i for i, w in enumerate(words)}
    cases, rejected, seen = [], [], set()

    for literal in re.findall(r'"((?:[a-z]{4} ){3,}[a-z]{4})"', src):
        got = literal.split(" ")
        assert all(w in index for w in got), f"word outside the list: {got}"
        payload = bytes(index[w] for w in got[:-4])
        checksum = bytes(index[w] for w in got[-4:])
        minimal = "".join(w[0] + w[3] for w in got)
        assert bytewords_minimal(words, payload)[:-8] == minimal[:-8], "minimal form does not match"
        if int.from_bytes(checksum, "big") == zlib.crc32(payload):
            assert bytewords_minimal(words, payload) == minimal, "checksum letters do not match"

        if int.from_bytes(checksum, "big") != zlib.crc32(payload):
            rejected.append(("bc-bytewords literal with a corrupted checksum",
                             minimal.encode("ascii")))
            continue

        if minimal not in seen:
            seen.add(minimal)
            cases.append({
                "name": f"bc-bytewords vector, {len(payload)} bytes",
                "payload": hexs(payload),
                "encoded": minimal,
            })

    assert len(cases) == 2, f"expected BC's two vectors, found {len(cases)}"
    assert len(rejected) == 1, f"expected BC's one bad-checksum literal, found {len(rejected)}"
    return cases, rejected


def bytewords_vectors() -> str:
    words = bytewords_words()
    cases, upstream_rejected = bytewords_upstream_cases(words)

    for length in (1, 2, 3, 4, 5, 31, 32, 33, 64, 129):
        payload = bytes((i * 7 + 11) & 0xFF for i in range(length))
        cases.append({
            "name": f"reference payload, {length} bytes",
            "payload": hexs(payload),
            "encoded": bytewords_minimal(words, payload),
        })

    encoded = cases[0]["encoded"]
    flipped = "z" if encoded[0] != "z" else "q"
    last = "z" if encoded[-1] != "z" else "q"
    words_of = [encoded[i:i + 2] for i in range(0, len(encoded), 2)]
    spaced, hyphenated = " ".join(words_of), "-".join(words_of)

    invalid = [
        ("empty", b""),
        ("three words, no room for a checksum", encoded[:6].encode("ascii")),
        ("odd number of letters", encoded[:7].encode("ascii")),
        ("checksum of the empty payload", bytewords_minimal(words, b"").encode("ascii")),
        ("payload reversed, checksum left where it was",
         (bytewords_minimal(words, bytes.fromhex(cases[0]["payload"])[::-1])[:-8]
          + encoded[-8:]).encode("ascii")),
        ("first payload letter changed", (flipped + encoded[1:]).encode("ascii")),
        ("last checksum letter changed", (encoded[:-1] + last).encode("ascii")),
        ("standard style: spaces between the words", spaced.encode("ascii")),
        ("uri style: hyphens between the words", hyphenated.encode("ascii")),
        ("space between two words", (encoded[:2] + " " + encoded[2:]).encode("ascii")),
        ("digit among the letters", ("1" + encoded[1:]).encode("ascii")),
        ("nul byte among the letters", b"\x00" + encoded[2:].encode("ascii")),
        ("byte above ascii among the letters", b"\x80" + encoded[2:].encode("ascii")),
        ("0xff among the letters", b"\xff" + encoded[2:].encode("ascii")),
        ("high byte in every position", bytes([0xC3] * len(encoded))),
        ("letters that are not a word, in every position", b"Z" * len(encoded)),
    ] + upstream_rejected

    rows = ",\n".join(f"  {{ {cstr(c['name'])}, {cstr(c['payload'])}, {cstr(c['encoded'])} }}"
                     for c in cases)
    bad_rows = ",\n".join(f'  {{ {cstr(name)}, "{hexs(data)}" }}' for name, data in invalid)

    return HEADER % (
        provenance("bc_bytewords.c"),
        provenance("bc_bytewords_test.c"),
        "".join(w[0].upper() + w[3].upper() for w in words),
        rows,
        bad_rows,
    )


HEADER = """#ifndef VECTORS_BYTEWORDS_H
#define VECTORS_BYTEWORDS_H

/* spec: %s
 * spec: %s
 * reference: zlib.crc32 for the trailing four codes
 *
 * app/ur/bytewords.c implements bytewords minimal: two letters per byte with no separator, and
 * the CRC32 of the payload appended as four more codes. The letters are a word's first and last,
 * unique per byte, which is what makes a lone code decodable. Case is not significant to the
 * decoder; this implementation writes uppercase, the reference below writes lowercase, so compare
 * case-insensitively.
 */

/* Two letters per byte, uppercase: the whole vocabulary of the decoder, in byte order. */
#define BYTEWORDS_MINIMAL "%s"

typedef struct {
  const char* name;
  const char* payload;
  const char* encoded;
} bytewords_vector_t;

static const bytewords_vector_t BYTEWORDS_VECTORS[] = {
%s
};

#define BYTEWORDS_VECTOR_COUNT (sizeof(BYTEWORDS_VECTORS) / sizeof(BYTEWORDS_VECTORS[0]))

/* Every row here has to answer 0, no decoded length. The encodings are hex because several carry
 * bytes that are not letters: a decoder that indexes a table with letters scanned off a QR has to
 * answer those without reading outside the table. */
typedef struct {
  const char* name;
  const char* encoded;
} bytewords_invalid_t;

static const bytewords_invalid_t BYTEWORDS_INVALID[] = {
%s
};

#define BYTEWORDS_INVALID_COUNT (sizeof(BYTEWORDS_INVALID) / sizeof(BYTEWORDS_INVALID[0]))

#endif
"""


# QR symbols from segno, which shares no code with the vendored encoder (Nayuki port) or the
# vendored decoder (quirc). Encoding parameters are requested exactly -- no ECC boosting and a
# forced mask -- so the encoder under test can be asked for the same symbol. `mode` names the
# segment type segno must use, which is what makes the two encoders comparable; "auto" leaves it
# to segno and then only the decoder is pinned, because how a mixed payload is split into segments
# is implementation freedom.
QR_CASES = [
    ("01234567", 1, "L", 0, "numeric"),
    ("86753092109876543210", 2, "M", 3, "numeric"),
    ("0123456789" * 20, 8, "Q", 5, "numeric"),
    ("HELLO WORLD", 2, "H", 1, "alphanumeric"),
    ("AN16CHARS $%*+-./:", 2, "L", 7, "alphanumeric"),
    ("$%*+-./: 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ", 5, "Q", 2, "alphanumeric"),
    ("MAX", 2, "Q", 2, "byte"),
    ("MAX", 4, "M", 6, "byte"),
    ("MAX", 10, "H", 0, "byte"),
    ("MAX", 21, "L", 1, "byte"),
    ("UR:CRYPTO-PSBT/1-3/" + "Ab9 .,~-_x" * 9, 7, "L", 3, "auto"),
]

QR_ECC_QUIRC = {"M": 0, "L": 1, "H": 2, "Q": 3}
QR_MODE_QUIRC = {"numeric": 1, "alphanumeric": 2, "byte": 4}


def byte_capacity(version: int, ecc: str) -> int:
    """Longest byte-mode payload the symbol still holds, found by probing."""
    import segno

    length = 0

    while True:
        try:
            segno.make("a" * (length + 1), version=version, error=ecc, mask=0, mode="byte",
                       boost_error=False)
        except Exception:
            return length
        length += 1


def qrcode_vectors() -> str:
    import segno

    arrays = []
    rows = []

    for index, (payload, version, ecc, mask, mode) in enumerate(QR_CASES):
        if payload == "MAX":
            # Byte-mode rows are filled to capacity on purpose. When spare codewords are left over
            # the reference pads them 0x00 before starting the 0xEC/0x11 sequence that section
            # 8.4.10 prescribes, so only an exactly full data region says the same thing twice.
            length = byte_capacity(version, ecc)
            payload = "ur:bytes/" + "".join(chr(ord("a") + (i % 26)) for i in range(length - 9))

        symbol = segno.make(
            payload,
            version=version,
            error=ecc,
            mask=mask,
            mode=None if mode == "auto" else mode,
            boost_error=False,
        )
        if (symbol.version, symbol.error, symbol.mask, symbol.mode) != (version, ecc, mask, mode if mode != "auto" else symbol.mode):
            sys.exit(
                f"segno chose version={symbol.version} error={symbol.error} "
                f"mask={symbol.mask} mode={symbol.mode}"
            )

        matrix = symbol.matrix
        size = len(matrix)
        bits = bytearray((size * size + 7) // 8)

        for y in range(size):
            for x in range(size):
                if matrix[y][x]:
                    pos = y * size + x
                    bits[pos >> 3] |= 1 << (pos & 7)

        name = f"QR_MATRIX_{index}"
        body = ", ".join(f"0x{b:02x}" for b in bits)
        arrays.append(f"static const uint8_t {name}[{len(bits)}] = {{\n    {body},\n}};")
        rows.append(
            "  { %s, %s, %d, %d, %d, %d, %d, %d, %d },"
            % (
                cstr(payload),
                name,
                version,
                QR_ECC_QUIRC[ecc],
                mask,
                size,
                len(payload.encode()),
                QR_MODE_QUIRC[symbol.mode],
                0 if mode == "auto" else 1,
            )
        )

    oversized = []

    for version, ecc in ((26, "L"), (40, "L")):
        symbol = segno.make("ur:bytes/" + "a" * 10, version=version, error=ecc, mask=0,
                            boost_error=False)
        if symbol.version != version:
            sys.exit(f"segno chose version {symbol.version}, wanted {version}")

        matrix = symbol.matrix
        size = len(matrix)
        bits = bytearray((size * size + 7) // 8)

        for y in range(size):
            for x in range(size):
                if matrix[y][x]:
                    pos = y * size + x
                    bits[pos >> 3] |= 1 << (pos & 7)

        oversized.append("  { %d, QR_OVER_SIZE_%d }," % (size, version))
        arrays.append(
            "static const uint8_t QR_OVER_SIZE_%d[%d] = {\n    %s,\n};"
            % (version, len(bits), ", ".join(f"0x{b:02x}" for b in bits))
        )

    return """#ifndef VECTORS_QRCODE_H
#define VECTORS_QRCODE_H

#include <stdint.h>

/*
 * reference
 *
 * segno %s (https://segno.readthedocs.io/), an implementation sharing no code with the vendored
 * encoder or decoder. Each matrix is a module grid, row-major, one bit per module, bit set
 * meaning dark, in the layout struct quirc_code documents:
 *
 *   cell_bitmap[(y * size + x) >> 3] & (1 << ((y * size + x) & 7))
 *
 * ecc is a QUIRC_ECC_LEVEL_* value, data_type a QUIRC_DATA_TYPE_* value. Where the symbol was
 * made with an explicit segment type the encoder under test reproduces it module for module;
 * single_segment is 0 where the reference chose the segmentation itself, which a competing encoder
 * is free to do differently, so such a row pins only the decoder.
 */

%s

typedef struct {
  const char* payload;
  const uint8_t* matrix;
  uint8_t version;
  uint8_t ecc;
  uint8_t mask;
  uint8_t size;
  uint16_t payload_len;
  uint8_t data_type;
  uint8_t single_segment;
} qr_vector_t;

static const qr_vector_t QR_VECTORS[] = {
%s
};

#define QR_VECTORS_COUNT (sizeof(QR_VECTORS) / sizeof(QR_VECTORS[0]))

/* Symbols past the largest version the scanner sizes its buffers for. The grid the scanner
 * measures out of the image is what has to stay inside those buffers. */
typedef struct {
  uint8_t size;
  const uint8_t* matrix;
} qr_over_size_t;

static const qr_over_size_t QR_OVER_SIZE[] = {
%s
};

#define QR_OVER_SIZE_COUNT (sizeof(QR_OVER_SIZE) / sizeof(QR_OVER_SIZE[0]))

#endif
""" % (getattr(segno, "__version__", "unknown"), "\n\n".join(arrays), "\n".join(rows),
       "\n".join(oversized))



# -------------------------------------------------------------- transaction ids (tx.c)

# Block 840000, pinned by hash. The corpus is whatever a node reports for these transactions, so
# it must not move under a test run; the answers are cached like the spec sources are.
TX_BLOCK_HEIGHT = "840000"
TX_BLOCK_HASH = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
GENESIS_COINBASE_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
MEMPOOL = "https://mempool.space"


def fetch_api(name: str, path: str) -> str:
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"api_{name}"
    if not dest.exists():
        print(f"fetch {MEMPOOL}{path}")
        dest.write_bytes(urllib.request.urlopen(MEMPOOL + path, timeout=60).read())
    return dest.read_text().strip()


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def csb(value: int) -> bytes:
    """Canonical compactsize, the same rule read_compactsize() enforces."""
    if value < 0xFD:
        return bytes([value])
    for flag, width, floor in ((0xFD, 2, 0x10000), (0xFE, 4, 0x100000000), (0xFF, 8, 2 ** 64)):
        if value < floor:
            return bytes([flag]) + value.to_bytes(width, "little")
    raise ValueError(value)


def tx_parse(raw: bytes) -> dict:
    """Reference read of a transaction in either serialization, returning the ranges the id is
    made of, the witness range the id ignores, and the offsets a hostile splice can target.

    The id is computed here by hashing the non-witness serialization, which is what BIP-144
    defines it over; app/bitcoin/tx.c gets there by skipping the marker, the flag and the stacks
    with a cursor. Every real transaction is checked against the id a node reports for it, so the
    two derivations cannot both be wrong."""
    if len(raw) < 6:
        raise ValueError("shorter than the version plus two counts")

    witness = raw[4] == 0x00 and raw[5] == 0x01
    pos = 6 if witness else 4

    inputs, pos = read_compactsize(raw, pos)
    scripts_in, script_len_at = [], []
    for _ in range(inputs):
        pos += 36
        script_len_at.append(pos)
        script_len, pos = read_compactsize(raw, pos)
        scripts_in.append(script_len)
        pos += script_len + 4

    outputs, pos = read_compactsize(raw, pos)
    scripts_out = []
    for _ in range(outputs):
        pos += 8
        script_len, pos = read_compactsize(raw, pos)
        scripts_out.append(raw[pos:pos + script_len])
        pos += script_len

    stacks, witness_start, witness_end = [], pos, pos
    if witness:
        for _ in range(inputs):
            count, pos = read_compactsize(raw, pos)
            items = []
            for _ in range(count):
                item_len, pos = read_compactsize(raw, pos)
                items.append(raw[pos:pos + item_len])
                pos += item_len
            stacks.append(items)
        witness_end = pos

    if len(raw) - pos != 4:
        raise ValueError("serialization does not end at the locktime")

    head = 6 if witness else 4
    id_input = raw[:4] + raw[head:witness_start] + raw[len(raw) - 4:]
    return {
        "raw": raw,
        "witness": witness,
        "inputs": inputs,
        "outputs": outputs,
        "scripts_in": scripts_in,
        "scripts_out": scripts_out,
        "stacks": stacks,
        "script_len_at": script_len_at,
        "witness_start": witness_start,
        "witness_end": witness_end,
        "id": dsha256(id_input),
    }


def tx_shape(info: dict) -> str:
    return (f"{info['inputs']}in/{info['outputs']}out/{len(info['raw'])}B"
            f"/{'witness' if info['witness'] else 'legacy'}")


def tx_real_vectors() -> list:
    """Real transactions, each paired with the id a node reports for it. Selection is by shape:
    the cursor walk has to meet a legacy serialization, witness inputs with empty scriptSigs,
    several inputs, a taproot output, a length that needs the 0xFD prefix, and a transaction large
    enough for the input loop to turn more than a few times."""
    txids = json.loads(fetch_api(f"block_{TX_BLOCK_HEIGHT}_txids.json",
                                f"/api/block/{TX_BLOCK_HASH}/txids"))
    wanted = ["coinbase", "taproot", "legacy", "large", "many-inputs", "many-outputs", "witness"]
    picks: dict[str, tuple[str, dict]] = {}
    longest: tuple[int, str, dict] = (0, "", {})

    # A stride rather than the first pages, so one busy transaction type cannot fill the corpus.
    for index, txid in enumerate([txids[0]] + txids[1::13]):
        raw = bytes.fromhex(fetch_api(f"tx_{txid}.hex", f"/api/tx/{txid}/hex"))
        info = tx_parse(raw)
        if info["id"] != bytes.fromhex(txid)[::-1]:
            raise ValueError(f"{txid}: id computed here is not the one the node reports")

        tags = []
        if index == 0:
            tags.append("coinbase")
        if not info["witness"]:
            tags.append("legacy")
        if any(len(s) == 34 and s[0] == 0x51 for s in info["scripts_out"]):
            tags.append("taproot")
        if len(raw) >= 900:
            tags.append("large")
        if info["inputs"] >= 4:
            tags.append("many-inputs")
        if info["outputs"] >= 8:
            tags.append("many-outputs")
        if info["witness"]:
            tags.append("witness")

        here = max(info["scripts_in"] + [len(s) for s in info["scripts_out"]], default=0)
        if here > longest[0]:
            longest = (here, txid, info)

        for tag in wanted:
            if tag in tags and tag not in picks:
                picks[tag] = (txid, info)
                break
        if all(w in picks for w in wanted):
            break

    missing = [w for w in wanted if w not in picks]
    if missing:
        raise ValueError(f"the sampled part of block {TX_BLOCK_HEIGHT} held no {missing}")

    vectors = [{"name": f"node block {TX_BLOCK_HEIGHT} {tag} {tx_shape(info)} id {txid[:16]}",
                "tx": info["raw"], "id": info["id"],
                "witness_start": info["witness_start"], "witness_end": info["witness_end"]}
               for tag in wanted for txid, info in [picks[tag]]]

    # No transaction in the sample carried a script long enough to need the 0xFD length prefix --
    # 2024 scripts are short -- so that boundary is covered by the reference vectors instead, and
    # the longest script the sample did hold gets its own entry to record where the gap is.
    if longest[0] >= 24:
        vectors.append({"name": f"node block {TX_BLOCK_HEIGHT} longest script in the sample "
                                f"({longest[0]}B, {tx_shape(longest[2])}) id {longest[1][:16]}",
                        "tx": longest[2]["raw"], "id": longest[2]["id"],
                        "witness_start": longest[2]["witness_start"],
                        "witness_end": longest[2]["witness_end"]})

    # That the stacks are not part of the id is asserted in the test over every witness vector, by
    # mutating a stack byte and by eliding the whole range, rather than by carrying copies here.
    if all(not info["witness"] for _, info in picks.values()):
        raise ValueError("no witness transaction in the sample to vary")
    return vectors


def tx_spec_vectors() -> list:
    """The genesis coinbase, whose id is a constant of the system, and BIP-143's example
    transactions. Each BIP example is fetched back from a node by the id computed here, which is
    the only way a document that does not state ids can be checked against the chain."""
    genesis = bytes.fromhex(fetch_api("tx_genesis_coinbase.hex", f"/api/tx/{GENESIS_COINBASE_TXID}/hex"))
    info = tx_parse(genesis)
    if info["id"] != bytes.fromhex(GENESIS_COINBASE_TXID)[::-1]:
        raise ValueError("the genesis coinbase does not hash to its well-known id")
    vectors = [{"name": f"spec genesis coinbase {tx_shape(info)} id {GENESIS_COINBASE_TXID[:16]}",
                "tx": genesis, "id": info["id"],
                "witness_start": info["witness_start"], "witness_end": info["witness_end"]}]

    text = fetch("bip143.mediawiki")
    examples = []
    for line in text.splitlines():
        if "serialized signed transaction is" not in line:
            continue
        tail = line.split("is", 1)[1].strip().strip("*:").strip()
        if re.fullmatch(r"[0-9a-f]{200,}", tail):
            examples.append(tail)
        else:
            continue
    for number, hexs in enumerate(dict.fromkeys(examples), start=1):
        raw = bytes.fromhex(hexs)
        try:
            info = tx_parse(raw)
        except ValueError as exc:
            raise ValueError(f"BIP-143 example {number}: {exc}")
        shown = info["id"][::-1].hex()
        try:
            back = bytes.fromhex(fetch_api(f"tx_{shown}.hex", f"/api/tx/{shown}/hex"))
            where = "confirmed by a node" if back == raw else "the node has different bytes"
        except Exception:
            where = "not retrievable by id"
        vectors.append({"name": f"spec BIP-143 example {number} {tx_shape(info)} id {shown[:16]} ({where})",
                        "tx": raw, "id": info["id"],
                        "witness_start": info["witness_start"], "witness_end": info["witness_end"]})
    return vectors


PREV_TXID = bytes.fromhex("969fadd9e41bd53343edb61e1738ec2b36f6e7d1420d94a6af99801a88f7fff7")
P2PKH = bytes.fromhex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
LONG_OP_RETURN = b"\x6a" + b"ipfs" + bytes(range(250))


def tx_assemble(vin: list, vout: list, stacks=None, version: int = 1,
                locktime: int = 0) -> tuple[bytes, bytes]:
    """Assembles both serializations of one logical transaction: the witness form, with marker,
    flag and stacks, and the non-witness form whose hash is the id. vin items are
    (outpoint hash, vout index, scriptSig, sequence), vout items (amount, scriptPubKey)."""
    body = csb(len(vin))
    for txid, index, script, seq in vin:
        body += txid + index.to_bytes(4, "little") + csb(len(script)) + script + seq
    body += csb(len(vout))
    for amount, script in vout:
        body += amount.to_bytes(8, "little") + csb(len(script)) + script

    head = version.to_bytes(4, "little")
    tail = locktime.to_bytes(4, "little")
    plain = head + body + tail
    if stacks is None:
        return plain, plain

    witness = head + b"\x00\x01" + body
    for stack in stacks:
        witness += csb(len(stack))
        for item in stack:
            witness += csb(len(item)) + item
    return witness + tail, plain


def tx_synth_vectors() -> tuple[list, list]:
    """Shapes the chain sample does not contain, assembled byte by byte with the id taken from the
    non-witness serialization by definition. The rejects are splices into the first of them, so
    each is one edit away from a transaction that does validate and claims its id."""
    good, reject = [], []

    def add(name: str, serialization: bytes, id_input: bytes, info=None):
        parsed = info or tx_parse(serialization)
        expected = dsha256(id_input)
        if parsed["id"] != expected:
            raise ValueError(f"{name}: the reference read disagrees with the definition")
        good.append({"name": name, "tx": serialization, "id": expected,
                     "witness_start": parsed["witness_start"], "witness_end": parsed["witness_end"]})
        return parsed

    seq = b"\xff\xff\xff\xff"

    long_script = bytes(range(253))
    witness, plain = tx_assemble(
        [(PREV_TXID, 1, long_script, seq)],
        [(100000000, P2PKH), (0, LONG_OP_RETURN)],
        [[b"\x48" + bytes(71), b"\x21" + bytes(33)]])
    base = add(f"reference witness, scriptSig {len(long_script)}B needs the 0xFD prefix", witness, plain)
    add("reference same transaction without the witness serialization", plain, plain)

    empty_in, empty_plain = tx_assemble([], [(5000, P2PKH), (7000, P2PKH)], stacks=[])
    add("reference witness flag with no inputs", empty_in, empty_plain)

    mixed, mixed_plain = tx_assemble(
        [(PREV_TXID, 0, b"", seq), (PREV_TXID, 1, b"\x00", seq), (PREV_TXID, 2, bytes(100), seq)],
        [(999999, P2PKH + bytes(275))],
        [[bytes(72)], [], [bytes(1), bytes(2)]])
    add("reference witness, three inputs, output script needing 0xFD", mixed, mixed_plain)

    zero_item, zero_plain = tx_assemble([(PREV_TXID, 0, b"", seq)], [(1, P2PKH)],
                                        [[b"", bytes(33)]], locktime=0x12345678)
    add("reference witness with a zero-length stack item", zero_item, zero_plain)

    def splice(at: int, replacement: bytes) -> bytes:
        return base["raw"][:at] + replacement + base["raw"][at + 1:]

    script_at = base["script_len_at"][0]
    count_at = 4 + 2
    reject += [
        (f"script length 0xFF cut short of its eight bytes at offset {script_at}",
         splice(script_at, b"\xff\xff\xff\xff"), base["id"]),
        (f"script length 0xFF all ones, past the serialize limit",
         splice(script_at, b"\xff" + bytes(8)), base["id"]),
        ("script length FD FC 00, which is not a canonical encoding",
         splice(script_at, b"\xfd\xfc\x00"), base["id"]),
        ("input count 0x10000 with nothing behind it",
         splice(count_at, b"\xfe\x00\x00\x01\x00"), base["id"]),
        ("version, marker and flag only", base["raw"][:6], base["id"]),
        ("five bytes, under the version plus two counts", base["raw"][:5], base["id"]),
        ("flag 0x02, which is not a witness serialization",
         splice(5, b"\x02"), base["id"]),
    ]

    alias = (1).to_bytes(4, "little") + csb(0) + csb(1) + (1000).to_bytes(8, "little") + csb(len(P2PKH)) + P2PKH + bytes(4)
    reject.append(("legacy with no inputs and one output, claiming the whole-buffer hash: 00 01 is "
                   "also marker and flag, and Bitcoin Core's deserializer reads it that way too, so "
                   "it is hashed as a witness transaction and its id is not the plain double SHA256",
                   alias, dsha256(alias)))

    return good, reject


def tx_c_array(name: str, data: bytes) -> str:
    if not data:
        raise ValueError(f"{name}: an empty array is not valid C")
    lines = [", ".join(f"0x{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return f"static const uint8_t {name}[] = {{\n    " + ",\n    ".join(lines) + "\n};"


def psbt_tx_vectors() -> str:
    """The element stream psbt_btc_tx_parse() reports for the same corpus vectors_tx.h carries,
    read here by the reference parser so the expectations are not the app's own output.

    Each entry pins the shape of what a handler is handed -- per input its outpoint index,
    sequence and script length; per output its amount and script length; per input stack the
    length of every witness item -- and a SHA-256 over the bytes behind those numbers, so a parse
    that reports the right counts while pointing at the wrong offsets still fails."""
    good = tx_spec_vectors() + tx_real_vectors() + tx_synth_vectors()[0]
    arrays, rows = [], []

    for i, v in enumerate(good):
        raw = v["tx"]
        info = tx_parse(raw)
        if info["id"] != v["id"]:
            raise ValueError(f'{v["name"]}: the reference read disagrees with the id in the corpus')

        wit = info["witness"]
        pos = 6 if wit else 4
        ins, outs, stacks = [], [], []
        in_h, out_h, wit_h = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()

        count, pos = read_compactsize(raw, pos)
        for _ in range(count):
            txid, index = raw[pos:pos + 32], int.from_bytes(raw[pos + 32:pos + 36], "little")
            pos += 36
            slen, pos = read_compactsize(raw, pos)
            script, pos = raw[pos:pos + slen], pos + slen
            seq, pos = int.from_bytes(raw[pos:pos + 4], "little"), pos + 4
            ins.append(f"{index}:{seq}:{slen}")
            in_h.update(txid + script)

        count, pos = read_compactsize(raw, pos)
        for _ in range(count):
            amount, pos = int.from_bytes(raw[pos:pos + 8], "little"), pos + 8
            slen, pos = read_compactsize(raw, pos)
            script, pos = raw[pos:pos + slen], pos + slen
            outs.append(f"{amount}:{slen}")
            out_h.update(amount.to_bytes(8, "little") + script)

        items = 0
        if wit:
            for input_index in range(info["inputs"]):
                stack, pos = read_compactsize(raw, pos)
                for item_index in range(stack):
                    ilen, pos = read_compactsize(raw, pos)
                    wit_h.update(raw[pos:pos + ilen])
                    stacks.append(f"{input_index}.{item_index}:{ilen}")
                    pos += ilen
                    items += 1

        locktime, pos = int.from_bytes(raw[pos:pos + 4], "little"), pos + 4
        if pos != len(raw):
            raise ValueError(f'{v["name"]}: the walk ended {len(raw) - pos} bytes short')

        arrays.append(tx_c_array(f"psbt_tx_{i}", raw))
        arrays.append(tx_c_array(f"psbt_tx_{i}_in", in_h.digest()))
        arrays.append(tx_c_array(f"psbt_tx_{i}_out", out_h.digest()))
        arrays.append(tx_c_array(f"psbt_tx_{i}_wit", wit_h.digest()))
        shape = '"' + ";".join(stacks) + '"' if wit else "NULL"
        rows.append(f'    {{ "{v["name"]}", psbt_tx_{i}, sizeof(psbt_tx_{i}),\n'
                    f'      {int.from_bytes(raw[0:4], "little")}, {locktime}, {info["inputs"]}, {info["outputs"]}, '
                    f'{items},\n'
                    f'      "{";".join(ins)}", "{";".join(outs)}", {shape},\n'
                    f'      psbt_tx_{i}_in, psbt_tx_{i}_out, psbt_tx_{i}_wit }},')

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * What psbt_btc_tx_parse() hands its handler, over the transaction corpus described in
 * vectors_tx.h: spec (the genesis coinbase, BIP-143's examples confirmed by a node), node (block
 * %s), reference (assembled for shapes the chain does not offer). The trace is computed by the
 * generator's own walk of the serialization, so it is the app against BIP-141 and not against
 * itself, and every transaction in the corpus had its id confirmed before it got here.
 *
 *  - in_shape:  per input, "vout index:sequence:script length", separated by ';'
 *  - out_shape: per output, "amount in satoshis:script length", separated by ';'
 *  - wit_shape: per witness item, "input index.item index:length", separated by ';', in the order
 *    the parser reports them, or NULL for a transaction with no witness serialization. An input
 *    with an empty stack contributes nothing, which is what a mixed legacy and segwit
 *    transaction looks like on the wire
 *  - *_digest:  SHA-256 over the bytes behind those numbers in stream order: for inputs the
 *    32-byte outpoint hash and the scriptSig of each, for outputs the 8LE amount and the
 *    scriptPubKey, for the witness every item. Counts alone would pass a parser that pointed at
 *    the right place in the wrong transaction.
 *
 * %s
 */

#ifndef VECTORS_PSBT_TX_H
#define VECTORS_PSBT_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char* name;
  const uint8_t* tx;
  size_t tx_len;
  uint32_t version;
  uint32_t locktime;
  size_t inputs;
  size_t outputs;
  size_t witness_items;
  const char* in_shape;
  const char* out_shape;
  const char* wit_shape;
  const uint8_t* in_digest;
  const uint8_t* out_digest;
  const uint8_t* wit_digest;
} psbt_tx_vector_t;

%s
static const psbt_tx_vector_t PSBT_TX_VECTORS[] = {
%s
};

#define PSBT_TX_VECTOR_COUNT (sizeof(PSBT_TX_VECTORS) / sizeof(PSBT_TX_VECTORS[0]))

#endif
""" % (TX_BLOCK_HEIGHT, provenance("bip143.mediawiki"), "\n".join(arrays), "\n".join(rows))


def tx_vectors() -> str:
    synth_good, synth_reject = tx_synth_vectors()
    good = tx_spec_vectors() + tx_real_vectors() + synth_good
    arrays, rows = [], []
    for i, v in enumerate(good):
        arrays.append(tx_c_array(f"tx_ok_{i}", v["tx"]))
        arrays.append(tx_c_array(f"tx_ok_{i}_id", v["id"]))
        rows.append(f'    {{ "{v["name"]}", tx_ok_{i}, sizeof(tx_ok_{i}), tx_ok_{i}_id,\n'
                    f'      {v["witness_start"]}, {v["witness_end"]} }},')

    bad_arrays, bad_rows = [], []
    for i, (name, tx, claimed) in enumerate(synth_reject):
        bad_arrays.append(tx_c_array(f"tx_bad_{i}", tx))
        bad_arrays.append(tx_c_array(f"tx_bad_{i}_claim", claimed))
        bad_rows.append(f'    {{ "{name}", tx_bad_{i}, sizeof(tx_bad_{i}), tx_bad_{i}_claim }},')

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * Transaction ids, with the provenance of each entry in its name:
 *
 *   spec      the genesis coinbase, whose id is a constant of the system, and BIP-143's example
 *             transactions. Each of those is fetched back from a node by the id computed here, the
 *             only way to check a document that does not state ids.
 *   node      transactions from block %s (height %s), paired with the id that node reports.
 *   reference assembled byte by byte for shapes the sample does not contain, with the id taken
 *             from the non-witness serialization the way BIP-144 defines it.
 *
 * Ids are in internal order, the bytes SHA-256 emits: the reverse of how an id is written for
 * humans, and what a transaction's own outpoints and a PSBT carry, so btc_validate_tx_hash()
 * compares them unchanged.
 *
 * witness_start and witness_end bracket the witness stacks, the range the id does not cover; both
 * are 0 where there are none.
 */

#ifndef VECTORS_TX_H
#define VECTORS_TX_H

#include <stddef.h>
#include <stdint.h>

/* A transaction and the id it has to validate against. */
typedef struct {
  const char* name;
  const uint8_t* tx;
  size_t tx_len;
  const uint8_t* txid;
  size_t witness_start;
  size_t witness_end;
} tx_id_vector_t;

/* Bytes presented as some real transaction: mangled, truncated, or a serialization whose walk
 * stops part way. Each claims the id named in its entry and must not validate against it. */
typedef struct {
  const char* name;
  const uint8_t* tx;
  size_t tx_len;
  const uint8_t* claimed;
} tx_reject_vector_t;

%s

static const tx_id_vector_t TX_ID_VECTORS[] = {
%s
};

#define TX_ID_VECTOR_COUNT (sizeof(TX_ID_VECTORS) / sizeof(TX_ID_VECTORS[0]))

%s

static const tx_reject_vector_t TX_REJECT_VECTORS[] = {
%s
};

#define TX_REJECT_VECTOR_COUNT (sizeof(TX_REJECT_VECTORS) / sizeof(TX_REJECT_VECTORS[0]))

#endif
""" % (TX_BLOCK_HASH, TX_BLOCK_HEIGHT, "\n\n".join(arrays), "\n".join(rows),
       "\n\n".join(bad_arrays), "\n".join(bad_rows))

# ------------------------------------------------------- PSBT input context (psbt_ctx.c)

# The device's fingerprint, in the little-endian order a PSBT stores it.
MFP_OURS = bytes.fromhex("44332211")
MFP_OTHER = bytes.fromhex("88776655")
CTX_PUBKEY = bytes.fromhex("02aabb" + "cc" * 31)

CTX_P2PKH = bytes.fromhex("76a914" + "11" * 20 + "88ac")
CTX_P2WPKH = bytes.fromhex("0014" + "22" * 20)
CTX_P2TR = bytes.fromhex("5120" + "33" * 32)
CTX_WITNESS_SCRIPT = bytes.fromhex("2103" + "44" * 32 + "ac")
CTX_REDEEM_SCRIPT = bytes.fromhex("522103" + "55" * 32 + "2103" + "66" * 32 + "52ae")


def hash160(data: bytes) -> bytes:
    """sha256 then ripemd160, which is what Bitcoin calls HASH160."""
    try:
        h = hashlib.new("ripemd160")
    except ValueError:
        from Crypto.Hash import RIPEMD160
        h = RIPEMD160.new()
    h.update(hashlib.sha256(data).digest())
    return h.digest()


def prevtx(amount: int, script: bytes) -> tuple[bytes, bytes]:
    """One-input transaction whose output `amount`/`script` is spent, and that output's id in the
    internal order a transaction's outpoints carry."""
    inner, _ = tx_assemble([(bytes(32), 0, b"\x00", b"\xff\xff\xff\xff")], [(1, CTX_P2PKH)], version=2)
    inner_id = dsha256(inner)
    raw, _ = tx_assemble([(inner_id, 0, b"\x00", b"\xff\xff\xff\xff")],
                         [(amount, script), (2, CTX_P2PKH)], version=2)
    return raw, dsha256(raw)


def key_record(kind: int, value: bytes, key_data: bytes = b"") -> bytes:
    key = bytes([kind]) + key_data
    return csb(len(key)) + key + csb(len(value)) + value


def derivation(fingerprint: bytes) -> bytes:
    return key_record(0x06, fingerprint + (0x80000000).to_bytes(4, "little"), CTX_PUBKEY)


def tx_io_counts(unsigned: bytes) -> tuple[int, int]:
    pos = 4
    n_in, pos = read_compactsize(unsigned, pos)
    for _ in range(n_in):
        pos += 36
        script_len, pos = read_compactsize(unsigned, pos)
        pos += script_len + 4
    n_out, pos = read_compactsize(unsigned, pos)
    return n_in, n_out


def psbt_of(unsigned: bytes, input_maps: list, output_maps: list) -> bytes:
    # BIP-174 wants a map for every input and every output of the unsigned transaction, and the
    # parser stops short of FINALIZED when one is missing.
    n_in, n_out = tx_io_counts(unsigned)
    input_maps = list(input_maps) + [[]] * (n_in - len(input_maps))
    output_maps = list(output_maps) + [[]] * (n_out - len(output_maps))

    body = key_record(0, unsigned) + b"\x00"
    for records in input_maps:
        body += b"".join(records) + b"\x00"
    for records in output_maps:
        body += b"".join(records) + b"\x00"
    return b"\x70\x73\x62\x74\xff" + body


def ctx_vectors() -> str:
    """What the device takes an input to *be*: its value and scriptPubKey decide the signature and
    the number shown on the screen, and both arrive from records a wallet chose. The cases come from
    BIP-174's grammar and from the precedence Bitcoin Core's analyzer documents --
    non_witness_utxo wins when both fields are present -- not from this implementation."""
    prev_legacy, id_legacy = prevtx(100000000, CTX_P2PKH)
    prev_segwit, id_segwit = prevtx(100000000, CTX_P2WPKH)
    prev_p2sh, id_p2sh = prevtx(70000, bytes.fromhex("a914") + hash160(CTX_REDEEM_SCRIPT) + bytes.fromhex("87"))
    prev_p2wsh, id_p2wsh = prevtx(80000, bytes.fromhex("0020") + hashlib.sha256(CTX_WITNESS_SCRIPT).digest())

    def unsigned(prev_id: bytes, out_index: int = 0) -> bytes:
        raw, _ = tx_assemble([(prev_id, out_index, b"", b"\xff\xff\xff\xff")], [(90000000, CTX_P2WPKH)])
        return raw

    def ctx_out(amount: int, script: bytes) -> bytes:
        return amount.to_bytes(8, "little") + bytes([len(script)]) + script

    wrong = lambda b: bytes([b[0] ^ 0xFF]) + b[1:]

    cases = [
        # Each field on its own.
        ("witness_utxo only", unsigned(id_segwit), [[key_record(1, ctx_out(100000000, CTX_P2WPKH)), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),
        ("non_witness_utxo only", unsigned(id_legacy), [[key_record(0, prev_legacy), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_LEGACY", 100000000, CTX_P2PKH),

        # Both fields, agreeing, in both orders: the same answer either way.
        ("both fields agree, prevtx first", unsigned(id_segwit),
         [[key_record(0, prev_segwit), key_record(1, ctx_out(100000000, CTX_P2WPKH)), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),
        ("both fields agree, witness first", unsigned(id_segwit),
         [[key_record(1, ctx_out(100000000, CTX_P2WPKH)), key_record(0, prev_segwit), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),

        # Both fields, disagreeing, in both orders: the prevtx wins, because its id is the one
        # checked against the outpoint. Record order must not reach the value that is signed.
        ("both fields, witness claims more, prevtx first", unsigned(id_segwit),
         [[key_record(0, prev_segwit), key_record(1, ctx_out(900000000, CTX_P2WPKH)), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),
        ("both fields, witness claims more, witness first", unsigned(id_segwit),
         [[key_record(1, ctx_out(900000000, CTX_P2WPKH)), key_record(0, prev_segwit), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),
        ("both fields, witness claims another script, prevtx first", unsigned(id_segwit),
         [[key_record(0, prev_segwit), key_record(1, ctx_out(100000000, CTX_P2TR)), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),
        ("both fields, witness claims another script, witness first", unsigned(id_segwit),
         [[key_record(1, ctx_out(100000000, CTX_P2TR)), key_record(0, prev_segwit), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WPKH", 100000000, CTX_P2WPKH),

        # witness_utxo has to be a whole CTxOut.
        ("witness_utxo with a byte past the script", unsigned(id_segwit),
         [[key_record(1, ctx_out(100000000, CTX_P2WPKH) + b"\x00"), derivation(MFP_OURS)]], [], 0, "", 0, b""),
        ("witness_utxo shorter than its own length byte", unsigned(id_segwit),
         [[key_record(1, ctx_out(100000000, CTX_P2WPKH)[:-1] ), derivation(MFP_OURS)]], [], 0, "", 0, b""),
        ("witness_utxo with a 0xFD script length", unsigned(id_segwit),
         [[key_record(1, (100000000).to_bytes(8, "little") + b"\xfd\xfd\x00" + CTX_P2WPKH, ), derivation(MFP_OURS)]],
         [], 0, "", 0, b""),

        # The prevtx has to actually contain the output the outpoint names.
        ("outpoint names an output the prevtx does not have", unsigned(id_segwit, out_index=3),
         [[key_record(0, prev_segwit), key_record(1, ctx_out(900000000, CTX_P2WPKH)), derivation(MFP_OURS)]], [],
         0, "", 0, b""),

        # The prevtx has to be the transaction the outpoint names.
        ("prevtx is some other transaction", unsigned(id_segwit),
         [[key_record(0, prev_legacy), derivation(MFP_OURS)]], [], 0, "", 0, b""),
        ("no utxo record at all", unsigned(id_segwit), [[derivation(MFP_OURS)]], [], 0, "", 0, b""),
        ("input belongs to another device", unsigned(id_segwit),
         [[key_record(1, ctx_out(100000000, CTX_P2WPKH)), derivation(MFP_OTHER)]], [], 0, "", 0, b""),

        # Redeem and witness scripts have to hash to the output they are said to redeem.
        ("redeem script that hashes to the P2SH output", unsigned(id_p2sh),
         [[key_record(0, prev_p2sh), key_record(4, CTX_REDEEM_SCRIPT), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_LEGACY_WITH_REDEEM", 70000, bytes.fromhex("a914") + hash160(CTX_REDEEM_SCRIPT) + bytes.fromhex("87")),
        ("redeem script that does not", unsigned(id_p2sh),
         [[key_record(0, prev_p2sh), key_record(4, wrong(CTX_REDEEM_SCRIPT)), derivation(MFP_OURS)]], [],
         0, "", 0, b""),
        ("witness script that hashes to the P2WSH output", unsigned(id_p2wsh),
         [[key_record(1, ctx_out(80000, bytes.fromhex("0020") + hashlib.sha256(CTX_WITNESS_SCRIPT).digest())),
           key_record(5, CTX_WITNESS_SCRIPT), derivation(MFP_OURS)]], [],
         1, "BTC_INPUT_TYPE_P2WSH", 80000, bytes.fromhex("0020") + hashlib.sha256(CTX_WITNESS_SCRIPT).digest()),
        ("witness script that does not", unsigned(id_p2wsh),
         [[key_record(1, ctx_out(80000, bytes.fromhex("0020") + hashlib.sha256(CTX_WITNESS_SCRIPT).digest())),
           key_record(5, wrong(CTX_WITNESS_SCRIPT)), derivation(MFP_OURS)]], [],
         0, "", 0, b""),
    ]

    arrays, rows = [], []
    for i, (name, unsigned_tx, inputs, outputs, accept, kind, amount, script) in enumerate(cases):
        blob = psbt_of(unsigned_tx, inputs, outputs)
        arrays.append(tx_c_array(f"psbt_ctx_{i}", blob))
        rows.append(
            f'    {{ {cstr(name)}, psbt_ctx_{i}, sizeof(psbt_ctx_{i}), {accept},\n'
            f'      {kind if kind else "-1"}, {amount}ULL, "{hexs(script)}" }},')

    # ---- the fields themselves -------------------------------------------------------------
    #
    # BIP-174 stops at the pre-taproot key types; BIP-371 is what defines the taproot ones, and it
    # states their value layouts in the same table. Both are asserted here rather than trusted.
    bip371 = fetch("bip371.mediawiki")
    for token, num in (("PSBT_IN_TAP_BIP32_DERIVATION", "0x16"), ("PSBT_IN_TAP_INTERNAL_KEY", "0x17"),
                       ("PSBT_IN_TAP_MERKLE_ROOT", "0x18"), ("PSBT_OUT_TAP_INTERNAL_KEY", "0x05"),
                       ("PSBT_OUT_TAP_TREE", "0x06"), ("PSBT_OUT_TAP_BIP32_DERIVATION", "0x07")):
        assert f"<tt>{token} = {num}</tt>" in bip371, f"BIP-371 no longer numbers {token} {num}"
    assert ("<compact size uint number of hashes> <32 byte leaf hash>* <4 byte fingerprint> "
            "<32-bit little endian uint path element>*") in bip371
    assert "<tt><32 byte xonlypubkey></tt>" in bip371
    bip174 = fetch("bip174.mediawiki")
    assert "<tt><32-bit little endian uint sighash type></tt>" in bip174
    assert "Signers who cannot produce signatures with the sighash type must not provide a signature." in bip174

    prev_p2tr, id_p2tr = prevtx(50000, CTX_P2TR)

    INTERNAL_KEY = bytes.fromhex("77" * 32)
    MERKLE_ROOT = bytes.fromhex("88" * 32)
    LEAF_PUBKEY = bytes.fromhex("99" * 32)
    LEAF_HASH = bytes.fromhex("aa" * 32)
    PATH_M86 = [0x80000056, 0x80000000, 0x80000000, 0, 0]
    PATH_OTHER = [0x8000002C, 0x80000000, 0, 7]
    PATH_ONE = (0x80000000).to_bytes(4, "little")  # what the existing derivation() helper carries
    M86 = b"".join(e.to_bytes(4, "little") for e in PATH_M86)
    OTHER = b"".join(e.to_bytes(4, "little") for e in PATH_OTHER)
    def tap_derivation(fingerprint: bytes, path: list, leaf_hashes: list = ()) -> bytes:
        value = csb(len(leaf_hashes)) + b"".join(leaf_hashes) + fingerprint
        return key_record(0x16, value + b"".join(e.to_bytes(4, "little") for e in path), LEAF_PUBKEY)

    def out_derivation(fingerprint: bytes, path: list, kind: int = 2) -> bytes:
        value = fingerprint + b"".join(e.to_bytes(4, "little") for e in path)
        return key_record(kind, value, CTX_PUBKEY)

    def tap_out_derivation(fingerprint: bytes, path: list, leaf_hashes: list = (),
                           count: bytes = None) -> bytes:
        # BIP-371: key data is the x-only pubkey, and the value counts leaf hashes before the fingerprint.
        value = (csb(len(leaf_hashes)) if count is None else count) + b"".join(leaf_hashes)
        return key_record(7, value + fingerprint +
                          b"".join(e.to_bytes(4, "little") for e in path), INTERNAL_KEY)

    def unsigned_with_out(prev_id: bytes, script: bytes) -> bytes:
        raw, _ = tx_assemble([(prev_id, 0, b"", b"\xff\xff\xff\xff")], [(90000000, script)])
        return raw

    def witness(value: bytes) -> bytes:
        return key_record(1, value)

    def sighash_record(value: bytes) -> bytes:
        return key_record(3, value)

    def unsigned_n(prev_id: bytes, n_in: int, n_out: int) -> bytes:
        raw, _ = tx_assemble([(prev_id, i % 2, b"", b"\xff\xff\xff\xff") for i in range(n_in)],
                             [(90000000, CTX_P2WPKH) for _ in range(n_out)])
        return raw

    tap_in = [witness(ctx_out(50000, CTX_P2TR)), key_record(0x17, INTERNAL_KEY),
              tap_derivation(MFP_OURS, PATH_M86)]

    R = []

    def rec(name, inputs, outputs=(), *, unsigned_tx=None, stage=3, err="ERR_OK", n_in=1, n_out=1,
            itype=-1, sighash=0, mfp=None, path=None, internal=None, merkle=None, can_sign=0,
            out_mfp=None, out_path=None):
        R.append((name, psbt_of(unsigned_tx if unsigned_tx is not None else unsigned(id_p2tr),
                                inputs, outputs), stage, err, n_in, n_out, itype, sighash, mfp,
                  path, internal, merkle, can_sign, out_mfp, out_path))

    def rin(*records):
        return [list(records)]

    # What the taproot fields choose: BIP-371 hands the signer the internal key to tweak and the
    # derivation to sign with, and the device hashes both into the signature it asks the card for.
    rec("taproot key path", rin(*tap_in), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=M86,
        internal=INTERNAL_KEY, merkle=b"", can_sign=1)
    rec("taproot with a merkle root", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(0x18, MERKLE_ROOT),
        tap_derivation(MFP_OURS, PATH_M86)), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=M86,
        internal=INTERNAL_KEY, merkle=MERKLE_ROOT, can_sign=1)
    rec("taproot internal key of 31 bytes", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY[:-1]), tap_derivation(MFP_OURS, PATH_M86)), stage=1,
        err="ERR_DECODE")
    rec("taproot internal key of 33 bytes", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY + b"\x00"), tap_derivation(MFP_OURS, PATH_M86)), stage=1,
        err="ERR_DECODE")
    rec("taproot merkle root of 31 bytes", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(0x18, MERKLE_ROOT[:-1]),
        tap_derivation(MFP_OURS, PATH_M86)), stage=1, err="ERR_DECODE")
    rec("taproot derivation with no room for a fingerprint", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(0x16, b"\x00" + MFP_OURS[:3], LEAF_PUBKEY)),
        stage=1, err="ERR_DECODE")
    rec("taproot derivation with an empty path", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(0x16, b"\x00" + MFP_OURS, LEAF_PUBKEY)),
        itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=b"", internal=INTERNAL_KEY, can_sign=1)
    # A derivation carrying leaf hashes describes a script path, which this device cannot sign, and
    # BIP-371 puts the fingerprint behind those hashes: reading the record from the offsets a zero
    # count would put them at is what has to be impossible. It is passed over instead -- see the row
    # below for why that rather than a refusal.
    rec("taproot derivation carrying one leaf hash", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), tap_derivation(MFP_OURS, PATH_M86, [LEAF_HASH])),
        mfp=bytes(4), path=b"", can_sign=0)
    # The leaf hash that starts with our own fingerprint is the one that matters: read at the zero-count
    # offsets it claims the input for us, with the bytes behind it -- still inside the hash -- as the
    # derivation path. Nothing is recorded here, so nothing is signed.
    rec("taproot derivation whose leaf hash starts with our fingerprint", rin(
        witness(ctx_out(50000, CTX_P2TR)), key_record(0x17, INTERNAL_KEY),
        tap_derivation(MFP_OURS, PATH_M86, [MFP_OURS + bytes.fromhex("bb" * 28)])),
        mfp=bytes(4), path=b"", can_sign=0)
    rec("taproot derivation carrying three leaf hashes", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY),
        tap_derivation(MFP_OURS, PATH_M86, [LEAF_HASH, LEAF_HASH, LEAF_HASH])),
        mfp=bytes(4), path=b"", can_sign=0)
    rec("taproot derivation with a long-form leaf-hash count", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY),
        key_record(0x16, b"\xfd\x01\x00" + LEAF_HASH + MFP_OURS + M86, LEAF_PUBKEY)),
        mfp=bytes(4), path=b"", can_sign=0)
    # A miniscript or taproot-multisig wallet describes the other signers' script paths in the same
    # PSBT. Those records are the wallet's business and not this device's: its own input still signs.
    rec("our key path beside another signer's script path", [
        [witness(ctx_out(50000, CTX_P2TR)), key_record(0x17, INTERNAL_KEY),
         tap_derivation(MFP_OURS, PATH_M86)],
        [witness(ctx_out(60000, CTX_P2TR)),
         tap_derivation(MFP_OTHER, PATH_OTHER, [LEAF_HASH])]],
        unsigned_tx=unsigned_n(id_p2tr, 2, 1), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=M86,
        internal=INTERNAL_KEY, n_in=2, can_sign=1)
    # The internal key is only demanded when the signature is made, so validation lets this through:
    # the flow approves the transaction and then fails to sign it. Pinned as it stands.
    rec("taproot input with no internal key", rin(witness(ctx_out(50000, CTX_P2TR)),
        tap_derivation(MFP_OURS, PATH_M86)), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=M86,
        internal=b"", merkle=b"", can_sign=1)
    rec("taproot derivation in BIP-174's ordinary field", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(6, MFP_OURS + M86, CTX_PUBKEY)),
        itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=M86, internal=INTERNAL_KEY, can_sign=1)
    # Whichever derivation record arrives first claims the input: a second one is ignored once the
    # fingerprint is ours, so the two fields must not be able to disagree about the path.
    rec("both derivation fields, BIP-371's first", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), tap_derivation(MFP_OURS, PATH_M86),
        key_record(6, MFP_OURS + OTHER, CTX_PUBKEY)), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS,
        path=M86, internal=INTERNAL_KEY, can_sign=1)
    rec("both derivation fields, BIP-174's first", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(6, MFP_OURS + OTHER, CTX_PUBKEY),
        tap_derivation(MFP_OURS, PATH_M86)), itype="BTC_INPUT_TYPE_P2TR", mfp=MFP_OURS, path=OTHER,
        internal=INTERNAL_KEY, can_sign=1)

    # The sighash type is copied to the record that decides the digest, unvalidated.
    legacy_in = [key_record(0, prev_legacy), derivation(MFP_OURS)]
    rec("sighash type NONE", rin(sighash_record((2).to_bytes(4, "little")), *legacy_in),
        unsigned_tx=unsigned(id_legacy), itype="BTC_INPUT_TYPE_LEGACY", sighash=2, mfp=MFP_OURS,
        path=PATH_ONE, can_sign=1)
    rec("sighash type 0x05, which no scheme defines", rin(sighash_record((5).to_bytes(4, "little")),
        *legacy_in), unsigned_tx=unsigned(id_legacy), itype="BTC_INPUT_TYPE_LEGACY", sighash=5,
        mfp=MFP_OURS, path=PATH_ONE, can_sign=1)
    rec("sighash type of 3 bytes", rin(sighash_record(b"\x01\x00\x00"), *legacy_in),
        unsigned_tx=unsigned(id_legacy), stage=1, err="ERR_DECODE")
    rec("no sighash type on a legacy input", rin(*legacy_in), unsigned_tx=unsigned(id_legacy),
        itype="BTC_INPUT_TYPE_LEGACY", sighash=1, mfp=MFP_OURS, path=PATH_ONE,
        can_sign=1)

    rec("non_witness_utxo that does not parse", rin(key_record(0, prev_legacy[:-3]),
        derivation(MFP_OURS)), unsigned_tx=unsigned(id_legacy), stage=1, err="ERR_DECODE")
    rec("a record type the device does not know", rin(witness(ctx_out(100000000, CTX_P2WPKH)),
        key_record(0x7F, b"\x01\x02"), derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit),
        itype="BTC_INPUT_TYPE_P2WPKH", sighash=1, mfp=MFP_OURS, path=PATH_ONE, can_sign=1)

    # The two remaining length refusals, and the scripts a witness input may carry.
    rec("witness_utxo of 8 bytes", rin(key_record(1, b"\x00" * 8), derivation(MFP_OURS)),
        unsigned_tx=unsigned(id_segwit), stage=1, err="ERR_DECODE")
    rec("derivation of 3 bytes", rin(witness(ctx_out(100000000, CTX_P2WPKH)),
        key_record(6, MFP_OURS[:3], CTX_PUBKEY)), unsigned_tx=unsigned(id_segwit), stage=1,
        err="ERR_DECODE")

    NESTED_REDEEM = bytes.fromhex("0014") + hash160(bytes.fromhex("03" + "12" * 32))
    NESTED_P2SH = bytes.fromhex("a914") + hash160(NESTED_REDEEM) + bytes.fromhex("87")
    rec("nested P2SH-P2WPKH", rin(witness(ctx_out(1000000, NESTED_P2SH)),
        key_record(4, NESTED_REDEEM), derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit),
        itype="BTC_INPUT_TYPE_P2WPKH", sighash=1, mfp=MFP_OURS, path=PATH_ONE, can_sign=1)
    rec("nested P2SH whose redeem script hashes elsewhere", rin(witness(ctx_out(1000000, NESTED_P2SH)),
        key_record(4, NESTED_REDEEM[:-1] + b"\x00"), derivation(MFP_OURS)),
        unsigned_tx=unsigned(id_segwit), stage=2, err="ERR_DATA", can_sign=1)
    # Validation marks an input as ours from its fingerprint and only then proves the scripts, so a
    # refused input is still "can sign": btc_psbt_any_can_sign() answers whose key it is, not whether
    # the PSBT is signable. core_btc_validate acts on the error, not on the flag.
    # A redeem script is only a proof when the output is P2SH, and a witness script only when it is
    # P2WSH; anything else has to be refused rather than classified by the script next to it.
    rec("witness input with a redeem script and a P2WPKH output", rin(
        witness(ctx_out(100000000, CTX_P2WPKH)), key_record(4, NESTED_REDEEM),
        derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit), stage=2, err="ERR_DATA", can_sign=1)
    rec("witness input with a witness script and a P2SH output", rin(
        witness(ctx_out(1000000, NESTED_P2SH)), key_record(5, CTX_WITNESS_SCRIPT),
        derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit), stage=2, err="ERR_DATA", can_sign=1)

    # The two above refuse on a hash that does not match, which a matcher that skipped the script
    # type test would also do. These two match: a redeem script whose hash160 is the witness program
    # of a P2WPKH output, and a witness script whose sha256 lands in a P2SH output. Only the rule
    # about which proof fits which output separates them, and the answer is still refusal.
    # The redeem script is itself a P2WPKH script here, so a matcher that ignored the output type
    # would not merely hash the same answer: it would take the redeem script as the spending script,
    # classify the input P2WPKH and sign.
    P2WPKH_REDEEM = bytes.fromhex("0014") + hash160(bytes.fromhex("03" + "13" * 32))
    rec("a redeem script hashing to a P2WPKH witness program", rin(
        witness(ctx_out(100000000, bytes.fromhex("0014") + hash160(P2WPKH_REDEEM))),
        key_record(4, P2WPKH_REDEEM), derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit),
        stage=2, err="ERR_DATA", can_sign=1)
    rec("a witness script hashing into a P2SH output", rin(
        witness(ctx_out(1000000, bytes.fromhex("a914") +
                        hashlib.sha256(CTX_WITNESS_SCRIPT).digest()[:20] + bytes.fromhex("87"))),
        key_record(5, CTX_WITNESS_SCRIPT), derivation(MFP_OURS)), unsigned_tx=unsigned(id_segwit),
        stage=2, err="ERR_DATA", can_sign=1)
    rec("taproot merkle root of 33 bytes", rin(witness(ctx_out(50000, CTX_P2TR)),
        key_record(0x17, INTERNAL_KEY), key_record(0x18, MERKLE_ROOT + b"\x00"),
        tap_derivation(MFP_OURS, PATH_M86)), stage=1, err="ERR_DECODE")

    # BIP-174: the global unsigned transaction "must be in the old serialization format (without
    # witnesses)", so a witness serialization there is not a PSBT at all.
    witness_tx, _ = tx_assemble([(id_segwit, 0, b"", b"\xff\xff\xff\xff")],
                                [(90000000, CTX_P2WPKH)], stacks=[[b"\x01"]])
    rec("global unsigned tx in the witness serialization", rin(witness(ctx_out(100000000, CTX_P2WPKH)),
        derivation(MFP_OURS)), unsigned_tx=witness_tx, stage=0, err="ERR_DATA", n_in=0, n_out=0)

    # BTC_MAX_INPUTS and BTC_MAX_OUTPUTS bound the context, and the limit is reached by the unsigned
    # transaction's own counts, which arrive before any map.
    rec("more inputs than the context holds", [[derivation(MFP_OURS)]] + [[] for _ in range(40)],
        unsigned_tx=unsigned_n(id_segwit, 41, 1), stage=1, err="ERR_FULL", n_in=40)
    rec("more outputs than the context holds", rin(witness(ctx_out(100000000, CTX_P2WPKH)),
        derivation(MFP_OURS)), [[] for _ in range(41)], unsigned_tx=unsigned_n(id_segwit, 1, 41),
        stage=1, err="ERR_FULL", n_out=40)

    # Output records: the derivation is what the change check runs on.
    rec("output derivation, ours", [[]], rin(out_derivation(MFP_OURS, PATH_M86)),
        unsigned_tx=unsigned(id_segwit), out_mfp=MFP_OURS, out_path=M86)
    rec("output derivation, another device", [[]], rin(out_derivation(MFP_OTHER, PATH_OTHER)),
        unsigned_tx=unsigned(id_segwit), out_mfp=MFP_OTHER, out_path=OTHER)
    rec("output derivation of 3 bytes", [[]], rin(key_record(2, MFP_OURS[:3], CTX_PUBKEY)),
        unsigned_tx=unsigned(id_segwit), stage=1, err="ERR_DECODE")
    rec("P2TR change output, BIP-371's derivation", [[]],
        rin(tap_out_derivation(MFP_OURS, PATH_M86)), unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR),
        out_mfp=MFP_OURS, out_path=M86)
    rec("P2TR output, another device's BIP-371 derivation", [[]],
        rin(tap_out_derivation(MFP_OTHER, PATH_OTHER)), unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR),
        out_mfp=MFP_OTHER, out_path=OTHER)
    rec("P2TR change output with an empty path", [[]],
        rin(tap_out_derivation(MFP_OURS, [])), unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR),
        out_mfp=MFP_OURS, out_path=b"")
    # A leaf-bearing derivation implies a script tree whose merkle root tweaks the output key
    # (BIP-341) and is not in the PSBT, so such an output cannot be proved to be the device's change.
    rec("P2TR change output whose BIP-371 derivation carries a leaf hash", [[]],
        rin(tap_out_derivation(MFP_OURS, PATH_M86, [LEAF_HASH])),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DATA",
        out_mfp=bytes(4), out_path=b"")
    # A wallet describing a script tree names every signer's path, so one of these is not this device's
    # business to fail on. A leaf hash starting with our fingerprint is the row that matters: read at
    # the offsets a zero count implies, it claims the output with bytes of the hash as the path.
    rec("P2TR output derivation, another signer's script path", [[]],
        rin(tap_out_derivation(MFP_OTHER, PATH_OTHER, [LEAF_HASH])),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=bytes(4), out_path=b"")
    rec("P2TR output derivation whose leaf hash starts with our fingerprint", [[]],
        rin(tap_out_derivation(MFP_OTHER, PATH_OTHER, [MFP_OURS + bytes.fromhex("bb" * 28)])),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=bytes(4), out_path=b"")
    rec("P2TR output derivation with three leaf hashes", [[]],
        rin(tap_out_derivation(MFP_OTHER, PATH_OTHER, [LEAF_HASH] * 3)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=bytes(4), out_path=b"")
    # A count the value cannot hold, and a non-minimal count: compactsize_read() refuses the second, as
    # it does everywhere else in this PSBT.
    rec("P2TR output derivation with a count past its own value", [[]],
        rin(key_record(7, b"\x05" + LEAF_HASH + MFP_OURS + M86, INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    rec("P2TR output derivation with no room for a fingerprint", [[]],
        rin(key_record(7, b"\x00" + MFP_OURS[:3], INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    rec("P2TR output derivation with a long-form zero count", [[]],
        rin(key_record(7, b"\xfd\x00\x00" + MFP_OURS + M86, INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    rec("P2TR output derivation that is only a count", [[]],
        rin(key_record(7, b"\x00", INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    # A long-form count whose bytes the value does not have.
    rec("P2TR output derivation with a truncated long-form count", [[]],
        rin(key_record(7, b"\xfd\x01", INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    # ... and one whose read bytes are large, since compactsize_read's minimality check refuses the
    # row above on its own. Trusting the width here points the fingerprint far outside the PSBT.
    rec("P2TR output derivation with a truncated wide count", [[]],
        rin(key_record(7, b"\xfe\xff\xff\xff", INTERNAL_KEY)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), stage=1, err="ERR_DECODE",
        out_mfp=bytes(4), out_path=b"")
    # Whichever derivation names us first claims the output, so the two fields cannot disagree about
    # the path.
    rec("output derivation in both fields, BIP-371's first", [[]],
        rin(tap_out_derivation(MFP_OURS, PATH_M86), out_derivation(MFP_OTHER, PATH_OTHER)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=MFP_OURS, out_path=M86)
    rec("output derivation in both fields, BIP-174's first, neither of ours until the last",
        [[]], rin(out_derivation(MFP_OTHER, PATH_OTHER), tap_out_derivation(MFP_OURS, PATH_M86)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=MFP_OURS, out_path=M86)
    rec("output derivation in both fields, ours first", [[]],
        rin(out_derivation(MFP_OURS, PATH_OTHER), tap_out_derivation(MFP_OURS, PATH_M86)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=MFP_OURS, out_path=OTHER)
    # The internal key is what a signer of that output needs; this device signs inputs. It travels on
    # to the finalizer, malformed or not.
    rec("P2TR output internal key, which the device leaves alone", [[]],
        rin(key_record(5, INTERNAL_KEY), tap_out_derivation(MFP_OURS, PATH_M86)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=MFP_OURS, out_path=M86)
    rec("P2TR output internal key of 31 bytes", [[]],
        rin(key_record(5, INTERNAL_KEY[:-1]), tap_out_derivation(MFP_OURS, PATH_M86)),
        unsigned_tx=unsigned_with_out(id_p2tr, CTX_P2TR), out_mfp=MFP_OURS, out_path=M86)
    rec("unknown output record type", [[]], rin(key_record(0x7F, b"\x01\x02")),
        unsigned_tx=unsigned(id_segwit), out_mfp=bytes(4), out_path=b"")

    def opt(value):
        """NULL for a field the case does not answer; the record's own bytes for one it does."""
        return "NULL" if value is None else f'"{hexs(value)}"' 

    rec_arrays = []
    rec_rows = []
    for i, (name, blob, stage, err, n_in, n_out, itype, sighash, mfp, path, internal, merkle,
            can_sign, out_mfp, out_path) in enumerate(R):
        rec_arrays.append(tx_c_array(f"psbt_rec_{i}", blob))
        rec_rows.append(
            f'    {{ {cstr(name)}, psbt_rec_{i}, sizeof(psbt_rec_{i}), {stage}, {err},\n'
            f'      {n_in}, {n_out}, {itype}, {sighash}, {opt(mfp)}, {opt(path)},\n'
            f'      {opt(internal)}, {opt(merkle)}, {can_sign}, {opt(out_mfp)}, '
            f'{opt(out_path)} }},')

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * PSBTs built from BIP-174's grammar to pin what the device takes an input to be. Where two utxo
 * fields describe one input, the prevtx is authoritative -- the answer a verifying node computes --
 * whichever record the wallet wrote last.
 *
 * The second table pins the individual records, and for the taproot ones it is BIP-371 that numbers
 * the key types and states the value layouts: a taproot derivation is leaf hashes, then the 4 byte
 * master fingerprint, then the path as 32-bit little endian indices, and the internal key and the
 * merkle root are each exactly 32 bytes. The sighash type is BIP-174's 32-bit little endian
 * unsigned integer, which that document says a signer who cannot sign with it must not sign at all.
 */

#ifndef VECTORS_PSBT_CTX_H
#define VECTORS_PSBT_CTX_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char* name;
  const uint8_t* psbt;
  size_t psbt_len;
  int accept;              /* the flow has to take the PSBT, or refuse it */
  int input_type;          /* btc_input_type_t once accepted; -1 for a refused case */
  uint64_t amount;         /* the value taken as the input's, which the signature and the screen use */
  const char* script;      /* the scriptPubKey taken for it, empty when the case is refused */
} psbt_ctx_case_t;

%s

static const psbt_ctx_case_t PSBT_CTX_CASES[] = {
%s
};

#define PSBT_CTX_CASE_COUNT (sizeof(PSBT_CTX_CASES) / sizeof(PSBT_CTX_CASES[0]))

/* One PSBT per case, and where the device is expected to stop: 0 in psbt_read, 1 while the records
 * are taken in, 2 in btc_psbt_validate_inputs, 3 nowhere. Fields left NULL are not answered by the
 * case -- a record that never arrived is a different statement from one that resolved to nothing. */
typedef struct {
  const char* name;
  const uint8_t* psbt;
  size_t psbt_len;
  int stage;
  int err;                 /* app_err_t expected from that stage */
  int input_count;         /* what the context counted before it stopped */
  int output_count;
  int input_type;          /* -1 unless the case classifies input 0 */
  uint8_t sighash;         /* input 0's sighash_flag once validation has run */
  const char* in_mfp;    /* the four bytes a derivation record filed, compared as bytes */
  const char* in_path;     /* the bytes bip32_path points at; "" is a path of no elements */
  const char* in_internal_key;
  const char* in_merkle_root;
  int can_sign;            /* btc_psbt_any_can_sign */
  const char* out_mfp;     /* output 0 */
  const char* out_path;
} psbt_ctx_record_t;

%s

static const psbt_ctx_record_t PSBT_CTX_RECORDS[] = {
%s
};

#define PSBT_CTX_RECORD_COUNT (sizeof(PSBT_CTX_RECORDS) / sizeof(PSBT_CTX_RECORDS[0]))

#endif
""" % ("\n\n".join(arrays), "\n".join(rows), "\n\n".join(rec_arrays), "\n".join(rec_rows))

# ------------------------------------------------------- scriptPubKey classification (script.c)

# The five output forms, written the way the documents write them -- a script is of a form because
# its bytes match that pattern, which is the claim the predicates have to implement. P2PKH and P2SH
# come from BIP-16's templates, the witness forms from BIP-141's version-and-length rule and BIP-341's
# definition of a Taproot output.
SCRIPT_FORMS = (
    ("SCRIPT_P2PKH", re.compile(r"^76a914([0-9a-f]{40})88ac$")),
    ("SCRIPT_P2SH", re.compile(r"^a914([0-9a-f]{40})87$")),
    ("SCRIPT_P2WPKH", re.compile(r"^0014([0-9a-f]{40})$")),
    ("SCRIPT_P2WSH", re.compile(r"^0020([0-9a-f]{64})$")),
    ("SCRIPT_P2TR", re.compile(r"^5120([0-9a-f]{64})$")),
)


def script_form(script: str) -> tuple:
    """The one form a scriptPubKey matches, with its program, or (None, None) for one that matches no
    documented form."""
    hits = [(name, m.match(script).group(1)) for name, m in SCRIPT_FORMS if m.match(script)]
    assert len(hits) <= 1, (script, [h[0] for h in hits])
    return hits[0] if hits else (None, None)


def script_vectors() -> str:
    """A scriptPubKey is fifteen bytes of opinion about what a payment is: five shapes, each with an
    anchor byte whose meaning nothing checks at the call site, and the whole of them written by
    whoever built the transaction. Expectations are published pairs -- Bitcoin Core's key_io vectors
    give address and scriptPubKey together, BIP-173/350 and BIP-86 give them for the witness forms --
    and the classification is derived here from the BIP templates, never from the predicates under
    test. What has no published address is what the documents leave unclassified: a witness program
    of a version this firmware renders no address for, or of a length BIP-341 says leaves the output
    unencumbered."""
    bip141 = fetch("bip141.mediawiki")
    assert "It is interpreted as a pay-to-witness-public-key-hash (P2WPKH) program." in bip141
    assert "It is interpreted as a pay-to-witness-script-hash (P2WSH) program." in bip141
    assert "exactly a push of a version byte, plus a push of a witness program" in bip141
    bip341 = fetch("bip341.mediawiki")
    assert "A Taproot output is a native SegWit output" in bip341
    assert "version number 1, and a 32-byte witness program" in bip341
    assert "version 1 outputs with lengths other than 32 bytes" in bip341
    bip16 = fetch("bip16.mediawiki")
    assert "OP_HASH160 [20-byte-hash-value] OP_EQUAL" in bip16
    bip13 = fetch("bip13.mediawiki")
    assert "Version byte is 5 for a main-network address" in bip13

    # BIP-173 rules the encoder's casing, so the published form of a bech32 address is not always
    # what an encoder must emit: "Encoders MUST always output an all lowercase Bech32 string."
    bip173 = fetch("bip173.mediawiki")
    assert "Encoders MUST always output an all lowercase Bech32 string." in bip173
    witness_forms = ("SCRIPT_P2WPKH", "SCRIPT_P2WSH", "SCRIPT_P2TR")

    cases = []  # (name, script, expected address or None, form or None)
    unrendered = []  # published addresses for scripts no documented form covers
    rewritten = []  # rows whose published address is not the lowercase form
    seen = set()  # the appendices repeat some addresses between their sections

    def add(name, script, address=None):
        """Only a script that matches one of the five documented forms has an address to produce: a
        published address for anything else -- a future witness version -- is something this device
        renders no address for, and the expectation becomes a refusal.

        A bech32 address published in caps is expected back in lower case, which is the document's
        rule for encoders, not a tolerance for the code under test: mixed case is rejected on input,
        so an encoder emitting it would be producing something its own decoder refuses. Caps is only
        for presentation, and the row name keeps the string as printed.
        """
        if script in seen:
            return
        seen.add(script)
        form, _program = script_form(script)
        if address and form is None:
            unrendered.append(name)
            address = None
        if address and form in witness_forms:
            assert address == address.lower() or address == address.upper(), name
            if address != address.lower():
                rewritten.append(name)
            address = address.lower()
        cases.append((name, script, address, form))

    # Core's key_io vectors: the address and the scriptPubKey it renders from, published together.
    keyio = json.loads(fetch("key_io_valid.json"))
    main = [r for r in keyio if r[2].get("chain") == "main" and not r[2].get("isPrivkey")]
    assert len(main) >= 14, len(main)
    for address, script, _info in main:
        add("Core key_io " + address, script, address)

    # The address rule itself, checked against those published pairs before it is used to derive any:
    # Base58Check of the version byte and the 20-byte hash, version 0 for P2PKH and BIP-13's 5 for
    # P2SH.
    def legacy(version: int, program: str) -> str:
        return b58check_encode(bytes([version]) + bytes.fromhex(program))

    for address, script, _info in main:
        form, program = script_form(script)
        if form == "SCRIPT_P2PKH":
            assert legacy(0x00, program) == address, address
        elif form == "SCRIPT_P2SH":
            assert legacy(0x05, program) == address, address

    # A scriptPubKey carries no network: the same bytes on any chain, and this device renders the
    # mainnet address. Derived with the rule above, which the rows just checked against published
    # pairs -- including the P2SH case, where BIP-13's version byte is what makes the address begin
    # with a 3.
    for address, script, info in keyio:
        if info.get("isPrivkey") or info.get("chain") == "main":
            continue
        form, program = script_form(script)
        if form == "SCRIPT_P2PKH":
            add("testnet P2PKH script, mainnet rendering " + address, script, legacy(0x00, program))
        elif form == "SCRIPT_P2SH":
            add("testnet P2SH script, mainnet rendering " + address, script, legacy(0x05, program))

    # BIP-173 and BIP-350 publish address and scriptPubKey side by side; the mainnet rows are pairs,
    # and a witness version the firmware renders no address for is a refusal, not a guess.
    for row in parse_segwit_vectors("bip173.mediawiki")[0] + parse_segwit_vectors("bip350.mediawiki")[0]:
        if row["hrp"] != "bc":
            continue
        script = "%02x%02x%s" % (0x50 + row["witver"] if row["witver"] else 0,
                                 len(row["program"]) // 2, row["program"])
        add("BIP-%s v%d %s" % ("173" if row["witver"] == 0 else "350", row["witver"], row["address"]),
            script, row["address"])

    # BIP-86's example hierarchy, scriptPubKey and address printed together.
    bip86 = fetch("bip86.mediawiki")
    pairs = re.findall(r"scriptPubKey = ([0-9a-f]{68})\s+address += (bc1p[a-z0-9]+)", bip86)
    assert len(pairs) >= 3, pairs
    for script, address in pairs:
        add("BIP-86 " + address, script, address)

    # Every anchor byte of every form, moved, plus the lengths the documents rule out. These are the
    # single-byte edits a wallet's serialiser, or an attacker with a PSBT, can make, and the answer is
    # always the same: no address, because the output is not one of the five.
    sample = {}
    for name, script, address, form in cases:
        if form and form not in sample:
            sample[form] = script

    def shift(script: str, at: int, what: int = 0x01) -> str:
        raw = bytearray(bytes.fromhex(script))
        raw[at] ^= what
        return raw.hex()

    mutations = {
        "SCRIPT_P2PKH": [0, 1, 2, 23, 24],
        "SCRIPT_P2SH": [0, 1, 22],
        "SCRIPT_P2WPKH": [0, 1],
        "SCRIPT_P2WSH": [0, 1],
        "SCRIPT_P2TR": [0, 1],
    }
    for form, offsets in mutations.items():
        base = sample[form]
        for at in offsets:
            add("%s with byte %d moved" % (form, at), shift(base, at))
        add("%s one byte short" % form, base[:-2])
        add("%s one byte long" % form, base + "00")

    # Witness programs the documents place outside every form.
    program20 = "11" * 20
    program32 = "22" * 32
    add("witness v0 with a 19 byte program", "0013" + "11" * 19)
    add("witness v0 with a 21 byte program", "0015" + "11" * 21)
    add("witness v0 with a 31 byte program", "001f" + "11" * 31)
    add("witness v0 with a 33 byte program", "0021" + "11" * 33)
    add("witness v1 with a 31 byte program", "511f" + "11" * 31)
    add("witness v1 with a 33 byte program", "5121" + "11" * 33)
    add("witness v1 with a 40 byte program", "5128" + "11" * 40)
    add("witness v2 with a 32 byte program", "5220" + program32)
    add("witness v16 with a 20 byte program", "6014" + program20)
    add("witness version byte with no push", "00")
    add("push of a version byte and nothing else", "0014")
    add("empty scriptPubKey", "")
    add("OP_RETURN", "6a")
    add("OP_RETURN with 36 bytes of data", "6a24" + "59" * 36)
    add("bare public key and CHECKSIG", "2103" + "aa" * 32 + "ac")
    add("bare 2 of 3 multisig", "522103" + "aa" * 32 + "2103" + "bb" * 32 + "2103" + "cc" * 32 + "53ae")
    add("P2SH multisig redeem script", "522103" + "dd" * 32 + "2103" + "ee" * 32 + "53ae")
    # A P2PKH script with the P2SH trailer, and the reverse: both are 23 or 25 bytes and neither is a
    # form, so a predicate keyed on length alone would let one through.
    add("P2PKH head with the P2SH trailer", "76a914" + program20 + "87")
    add("P2SH head with the P2PKH trailer", "a914" + program20 + "88ac")

    rows = []
    for i, (name, script, address, form) in enumerate(cases):
        rows.append(
            "  { %s, %s, %s, %s },"
            % (cstr(name), cstr(script), cstr(address) if address else "NULL",
               form if form else "0")
        )

    accepted = sum(1 for _n, _s, a, _f in cases if a)
    classified = sum(1 for _n, _s, _a, f in cases if f)
    assert accepted == classified

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * scriptPubKey classification. The pairs are published, not computed here: Bitcoin Core's
 * key_io_valid vectors give an address together with the scriptPubKey it renders from, BIP-173 and
 * BIP-350 do the same for the witness forms, BIP-86 for the Taproot examples. The classification
 * column comes from the templates the documents state -- BIP-141's "If the version byte is 0, and
 * the witness program is 20 bytes ... P2WPKH" and its 32-byte P2WSH counterpart, BIP-16's
 * "OP_HASH160 [20-byte-hash-value] OP_EQUAL", BIP-341's "a native SegWit output ... with version
 * number 1, and a 32-byte witness program", together with that document's statement that version 1
 * outputs of other lengths remain unencumbered -- and the two columns are cross-checked against each
 * other while generating, so a row is never classified one way and rendered another.
 *
 * %d rows match one of the five forms and carry its address; the rest must produce no address at all
 * and leave the caller's buffer untouched, including %d published addresses belonging to witness
 * programs no documented form covers, which this device renders nothing for.
 *
 * Rows whose published bech32 address is printed in capitals -- %d of them here -- are expected back in
 * lower case, which is BIP-173's rule for an encoder: "Encoders MUST always output an all lowercase
 * Bech32 string." Caps is for presentation, outside the encoder.
 */

#ifndef VECTORS_SCRIPT_H
#define VECTORS_SCRIPT_H

#include <stddef.h>
#include <stdint.h>

/* One bit per predicate, so a row states which of the five a script must and must not satisfy. */
#define SCRIPT_P2PKH  0x01
#define SCRIPT_P2SH   0x02
#define SCRIPT_P2WPKH 0x04
#define SCRIPT_P2WSH  0x08
#define SCRIPT_P2TR   0x10

typedef struct {
  const char* name;
  const char* script;   /* the scriptPubKey; every byte of it arrives from a wallet */
  const char* address;  /* what script_output_to_address() has to produce, NULL for nothing */
  unsigned classes;     /* the SCRIPT_* bits that must be set, 0 for none of them */
} script_case_t;

static const script_case_t SCRIPT_CASES[] = {
%s
};

#define SCRIPT_CASE_COUNT (sizeof(SCRIPT_CASES) / sizeof(SCRIPT_CASES[0]))

#endif
""" % (classified, len(unrendered), len(rewritten), "\n".join(rows))



# ------------------------------------------------------- signature hashes (sighash.c)

def sighash_parse_tx(hexs: str) -> dict:
    """Version, inputs, outputs (as amount-and-script pairs) and locktime of a non-witness
    transaction serialization."""
    raw = bytes.fromhex(hexs)
    pos = 4
    n_in, pos = read_compactsize(raw, pos)
    inputs = []
    for _ in range(n_in):
        txid = raw[pos:pos + 32]
        index = int.from_bytes(raw[pos + 32:pos + 36], "little")
        pos += 36
        script_len, pos = read_compactsize(raw, pos)
        script = raw[pos:pos + script_len]
        pos += script_len
        sequence = raw[pos:pos + 4]
        pos += 4
        inputs.append({"txid": txid, "index": index, "script": script, "sequence": sequence})
    n_out, pos = read_compactsize(raw, pos)
    outputs = []
    for _ in range(n_out):
        amount = raw[pos:pos + 8]
        pos += 8
        script_len, pos = read_compactsize(raw, pos)
        outputs.append((amount, raw[pos:pos + script_len]))
        pos += script_len
    return {"version": raw[:4], "inputs": inputs, "outputs": outputs, "locktime": raw[pos:pos + 4]}


# ---------------------------------------------------------------------------
# The reference the two walkers are checked against.
#
#
# sighash_chain_cases() reads mainnet spends and keeps one only if the signature in its 
# scriptSig verifies over the digest computed below, so generation itself fails if this 
# reference drifts.
# ---------------------------------------------------------------------------

# BIP-340 Schnorr verification. A taproot digest is only meaningful as "the thing this signature was
# made over", so the vectors are accepted by verifying, not by copying. The verifier itself is checked
# against BIP-340's own test vectors before it is trusted with anything.
def tagged_hash(tag: str, data: bytes) -> bytes:
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + data).digest()


def lift_x(x: int):
    if x >= SECP256K1_P:
        return None
    y_square = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_square, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_square:
        return None
    # The serialization carries only the x coordinate and the convention that the point has an even
    # y; the other root of the same x is the negation.
    return x, y if y % 2 == 0 else SECP256K1_P - y


def schnorr_verify(message: bytes, signature: bytes, key: bytes) -> bool:
    if len(signature) != 64 or len(key) != 32 or len(message) != 32:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    point = lift_x(int.from_bytes(key, "big"))
    if point is None or r >= SECP256K1_P or s >= SECP256K1_N:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + key + message), "big") % SECP256K1_N
    r_point = ec_add(ec_mul(s, SECP256K1_G), ec_mul(SECP256K1_N - challenge, point))
    return r_point is not None and r_point[1] % 2 == 0 and r_point[0] % SECP256K1_P == r


def check_schnorr_verifier() -> None:
    import csv
    import io

    rows = csv.DictReader(io.StringIO(fetch("bip340_vectors.csv")))
    checked = 0
    for row in rows:
        signature, key, message = row["signature"], row["public key"], row["message"]
        if len(signature) != 128 or len(key) != 64 or len(message) != 64:
            continue  # rows that must fail on shape before any arithmetic happens
        want = row["verification result"] == "TRUE"
        if schnorr_verify(bytes.fromhex(message), bytes.fromhex(signature), bytes.fromhex(key)) != want:
            raise SystemExit(f"BIP-340 vector {row['index']}: the generator's verifier disagrees")
        checked += 1
    if checked < 10:
        raise SystemExit("BIP-340's vector file changed shape; the verifier is unchecked")


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
               0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
WITNESS_V0 = 0x00000041


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % SECP256K1_P == 0:
        return None
    if p == q:
        slope = 3 * p[0] * p[0] * pow(2 * p[1], SECP256K1_P - 2, SECP256K1_P) % SECP256K1_P
    else:
        slope = (q[1] - p[1]) * pow((q[0] - p[0]) % SECP256K1_P, SECP256K1_P - 2, SECP256K1_P) % SECP256K1_P
    x = (slope * slope - p[0] - q[0]) % SECP256K1_P
    return x, (slope * (p[0] - x) - p[1]) % SECP256K1_P


def ec_mul(k, point):
    acc, doubling = None, point
    while k:
        if k & 1:
            acc = ec_add(acc, doubling)
        doubling = ec_add(doubling, doubling)
        k >>= 1
    return acc


def compressed_pubkey(private: int) -> bytes:
    x, y = ec_mul(private, SECP256K1_G)
    return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")


def der_signature(raw: bytes) -> tuple[int, int]:
    if raw[0] != 0x30 or raw[2] != 0x02:
        raise ValueError("not a DER sequence")
    r_length = raw[3]
    r = int.from_bytes(raw[4:4 + r_length], "big")
    tail = 4 + r_length
    if raw[tail] != 0x02:
        raise ValueError("DER signature without a second integer")
    s_length = raw[tail + 1]
    return r, int.from_bytes(raw[tail + 2:tail + 2 + s_length], "big")


def ecdsa_verify(public: bytes, der: bytes, digest: bytes) -> bool:
    """ECDSA on secp256k1, used only to tie a digest to a coin that was really spent."""
    try:
        r, s = der_signature(der)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False
    x = int.from_bytes(public[1:], "big")
    y = pow((x * x * x + 7) % SECP256K1_P, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y % 2 != public[0] & 1:
        y = SECP256K1_P - y
    weight = pow(s, SECP256K1_N - 2, SECP256K1_N)
    z = int.from_bytes(digest, "big")
    point = ec_add(ec_mul(z * weight % SECP256K1_N, SECP256K1_G), ec_mul(r * weight % SECP256K1_N, (x, y)))
    return point is not None and point[0] % SECP256K1_N == r


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def p2pkh_script(public: bytes) -> bytes:
    return b"\x76\xa9\x14" + hash160(public) + b"\x88\xac"


def legacy_digest(tx: dict, script_code: bytes, in_: int, hash_type: int) -> bytes:
    """The pre-segwit signature hash, byte for byte as app/bitcoin/sighash.h documents it.

    The hash type is written whole, so an implementation that masked it to its base type or to one
    byte still produces a plausible-looking digest.
    """
    base = hash_type & 0x1F
    anyone_can_pay = bool(hash_type & 0x80)
    if base == 0x03 and in_ >= len(tx["outputs"]):
        # Bitcoin Core answers with the constant 1, which is a signature over nothing at all. The
        # device reports the case, so no vector here asks the legacy walker for a digest.
        raise ValueError("SIGHASH_SINGLE with no output at the input's index")
    inputs = [tx["inputs"][in_]] if anyone_can_pay else tx["inputs"]

    stream = bytearray(tx["version"])
    stream += csb(len(inputs))
    for position, entry in enumerate(inputs):
        sign_this = anyone_can_pay or position == in_
        stream += entry["txid"] + entry["index"].to_bytes(4, "little")
        # An input that is not being signed contributes an empty script, not the scriptCode with a
        # zero length -- the length prefix belongs to whichever script is written.
        stream += (csb(len(script_code)) + script_code) if sign_this else csb(0)
        blank_sequence = not sign_this and base in (0x02, 0x03)
        stream += b"\x00\x00\x00\x00" if blank_sequence else entry["sequence"]

    if base == 0x02:
        outputs = []
    elif base == 0x03:
        outputs = [tx["outputs"][position] if position == in_ else None
                   for position in range(in_ + 1)]
    else:
        outputs = tx["outputs"]
    stream += csb(len(outputs))
    for entry in outputs:
        if entry is None:
            # SIGHASH_SINGLE blanks the outputs before the signed one to "no amount, no script",
            # which is an amount of -1 and an empty script, not merely an empty script.
            stream += (2 ** 64 - 1).to_bytes(8, "little") + csb(0)
        else:
            amount, script = entry
            stream += amount + csb(len(script)) + script
    stream += tx["locktime"] + (hash_type & 0xFFFFFFFF).to_bytes(4, "little")
    return dsha256(bytes(stream))


def witness_digest(tx: dict, script_code: bytes, in_: int, hash_type: int, amount: bytes) -> bytes:
    """BIP-143's v0 digest. Unlike the legacy one it names no single input: prevouts, sequences and
    outputs each get their own hash over the whole transaction, and each is replaced by 32 zero bytes
    when the hash type leaves it out.

    SIGHASH_SINGLE with no output at the input's index is the interesting one: hashOutputs stays
    zero, exactly as for SIGHASH_NONE, because the preimage never names an output. Bitcoin Core's
    verifier computes the same thing, so the device signs this case -- the digest still commits to
    every input and to the other outputs. The legacy hash has no such answer, which is why the two
    walkers part ways here.
    """
    base = hash_type & 0x1F
    anyone_can_pay = bool(hash_type & 0x80)
    prevouts = b"".join(entry["txid"] + entry["index"].to_bytes(4, "little") for entry in tx["inputs"])
    sequences = b"".join(entry["sequence"] for entry in tx["inputs"])
    outputs = b"".join(value + csb(len(script)) + script for value, script in tx["outputs"])

    hash_prevouts = bytes(32) if anyone_can_pay else dsha256(prevouts)
    hash_sequence = bytes(32) if (anyone_can_pay or base != 0x01) else dsha256(sequences)
    if base == 0x01:
        hash_outputs = dsha256(outputs)
    elif base == 0x03 and in_ < len(tx["outputs"]):
        value, script = tx["outputs"][in_]
        hash_outputs = dsha256(value + csb(len(script)) + script)
    else:
        hash_outputs = bytes(32)

    stream = tx["version"] + hash_prevouts + hash_sequence
    stream += tx["inputs"][in_]["txid"] + tx["inputs"][in_]["index"].to_bytes(4, "little")
    stream += csb(len(script_code)) + script_code + amount + tx["inputs"][in_]["sequence"]
    stream += hash_outputs + tx["locktime"] + (hash_type & 0xFFFFFFFF).to_bytes(4, "little")
    return dsha256(bytes(stream))


def p2pkh_script_sig(script: bytes) -> tuple[bytes, bytes] | None:
    """<push signature> <push public key>, and nothing else."""
    if len(script) < 2 or not 0x41 <= script[0] <= 0x4E:
        return None
    signature = script[1:1 + script[0]]
    key_length = script[1 + script[0]]
    if key_length not in (0x21, 0x23, 0x41) or len(script) != 2 + script[0] + key_length:
        return None
    return signature, script[2 + script[0]:]


def sighash_chain_cases() -> list:
    """Legacy sighash digests anchored to coins that were really spent.

    Each named transaction is fetched, its P2PKH input's scriptSig is split into signature and
    public key, and the case is kept only if that signature verifies over the digest computed by
    legacy_digest() above. That is what makes this an oracle rather than a restatement of the
    walker: a digest here is the one a real coin was unlocked with. The scriptCode is rebuilt as the
    P2PKH script of that public key, which is what the redeeming script's OP_HASH160 compares.

    Both are single-input sighash-all spends, the shape mainnet actually offers: a multi-input
    legacy spend of the same vintage is rare enough in one block that asking for one made
    generation depend on luck. Multi-input shapes come from the sweep, against this same reference.
    """
    cases = []
    for txid in CHAIN_ANCHORS:
        raw = bytes.fromhex(fetch_api(f"tx_{txid}.hex", f"/api/tx/{txid}/hex"))
        tx = sighash_parse_tx(raw.hex())
        for index, entry in enumerate(tx["inputs"]):
            parts = p2pkh_script_sig(entry["script"])
            if parts is None:
                continue
            signature, public = parts
            if len(public) != 33:
                continue
            script_code = p2pkh_script(public)
            hash_type = signature[-1]
            digest = legacy_digest(tx, script_code, index, hash_type)
            if not ecdsa_verify(public, signature[:-1], digest):
                raise SystemExit(f"{txid}: input {index}: the reference cannot reproduce a signature "
                                 "mainnet accepted -- fix legacy_digest() before trusting anything else")
            cases.append({
                "name": f"chain spend in{index} of {len(tx['inputs'])}, ht 0x{hash_type:02x}",
                "tx": raw,
                "in": index,
                "hash_type": hash_type,
                "input_type": "BTC_INPUT_TYPE_LEGACY",
                "script": script_code.hex(),
                "redeem": "",
                "witness_script": "",
                "amount": "0000000000000000",
                "digest": digest.hex(),
            })
            break
    if len(cases) != len(CHAIN_ANCHORS):
        raise SystemExit("a chain anchor is no longer a P2PKH spend; pick another txid")
    return cases


# Confirmed mainnet transactions, each spending a P2PKH output. Fetching by id is stable; the
# verification inside sighash_chain_cases() is what keeps them meaningful.
CHAIN_ANCHORS = [
    "2bc250cc474c93675b7fd522838d56db85a9148f836ee2390365f106a3c9b387",
    "78770f590b20ba7a7c5fdf532a20888c7ac4781491d8f843b3d22c84d00e6e6d",
]


def sweep_tx(n_inputs: int, n_outputs: int, out_script: bytes, locktime: int) -> bytes:
    stream = bytearray((2).to_bytes(4, "little"))
    stream += csb(n_inputs)
    for i in range(n_inputs):
        stream += bytes([(i * 7) & 0xFF]) * 32 + i.to_bytes(4, "little") + csb(0)
        stream += (0xD0 + (i % 16)).to_bytes(4, "little")
    stream += csb(n_outputs)
    for i in range(n_outputs):
        stream += (1000 + i).to_bytes(8, "little") + csb(len(out_script)) + out_script
    stream += locktime.to_bytes(4, "little")
    return bytes(stream)


def sighash_sweep_cases() -> list:
    """Shape coverage. The legacy hash visits the inputs three times and the witness hash once
    each for prevouts, sequences and amounts, so a count written per iteration instead of once --
    or an item written twice -- is invisible with a single input."""
    public = compressed_pubkey(0x5C2F6B1E9D4A8731F0E6C2B5A7D94E1826C3F7A0B4D8E25C61F90347ABDE7C15)
    script_code = p2pkh_script(public)
    cases = []
    for n_inputs, n_outputs in [(1, 1), (1, 2), (2, 1), (2, 3), (3, 2), (19, 3), (2, 19), (40, 40)]:
        for hash_type in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            index = 1 if n_inputs > 1 else 0
            raw = sweep_tx(n_inputs, n_outputs, bytes([0x00, 0x14]) + bytes(23), 0)
            tx = sighash_parse_tx(raw.hex())
            digest = b"" if (hash_type & 0x1F) == 0x03 and index >= n_outputs \
                else legacy_digest(tx, script_code, index, hash_type)
            cases.append({
                "name": f"sweep {n_inputs}in {n_outputs}out ht 0x{hash_type:02x} in{index}",
                "tx": raw,
                "in": index,
                "hash_type": hash_type,
                "input_type": "BTC_INPUT_TYPE_LEGACY",
                "script": script_code.hex(),
                "redeem": "",
                "witness_script": "",
                "amount": "0000000000000000",
                "digest": digest.hex(),
            })
    # A legacy P2SH spend signs over the redeem script, not over the P2SH scriptPubKey that locks
    # it, which is the one thing the input type changes about the preimage.
    redeem = bytes([0x21]) + public + bytes([0xac])  # <key> CHECKSIG
    p2sh = b"\xa9\x14" + hash160(redeem) + b"\x87"
    for hash_type in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
        raw = sweep_tx(2, 2, p2sh, 0)
        tx = sighash_parse_tx(raw.hex())
        cases.append({
            "name": f"sweep p2sh legacy ht 0x{hash_type:02x}",
            "tx": raw,
            "in": 1,
            "hash_type": hash_type,
            "input_type": "BTC_INPUT_TYPE_LEGACY_WITH_REDEEM",
            "script": p2sh.hex(),
            "redeem": redeem.hex(),
            "witness_script": "",
            "amount": "0000000000000000",
            "digest": legacy_digest(tx, redeem, 1, hash_type).hex(),
        })

    # SIGHASH_SINGLE with no output at the input's index. The two schemes answer differently and
    # both answers are load-bearing, so both are pinned here.
    #
    # A witness input still has a preimage: hashOutputs is simply 32 zero bytes, which is what
    # Bitcoin Core's verifier hashes too, so the device signs and the result is spendable.
    #
    # A legacy input has none. Core returns the constant 1, and a signature over a constant is valid
    # for every transaction that spends the same outpoint with fewer outputs -- an amount and a
    # destination the user never saw. So the legacy walker reports the case instead of signing, and
    # no vector here asks it for a digest.
    for n_inputs, n_outputs, index in [(2, 1, 1), (3, 1, 2), (5, 3, 4), (40, 1, 39)]:
        raw = sweep_tx(n_inputs, n_outputs, bytes([0x00, 0x14]) + bytes(23), 0)
        tx = sighash_parse_tx(raw.hex())
        for hash_type in (0x03, 0x83):
            for kind, utxo_script, redeem_script, witness, value in (
                ("LEGACY", script_code.hex(), "", "", "0000000000000000"),
                ("LEGACY_WITH_REDEEM", p2sh.hex(), redeem.hex(), "", "0000000000000000"),
            ):
                cases.append({
                    "name": f"sweep single without output {kind} {n_inputs}in {n_outputs}out in{index} "
                            f"ht 0x{hash_type:02x}",
                    "tx": raw,
                    "in": index,
                    "hash_type": hash_type,
                    "input_type": f"BTC_INPUT_TYPE_{kind}",
                    "script": utxo_script,
                    "redeem": redeem_script,
                    "witness_script": witness,
                    "amount": value,
                    "digest": "",
                })
            for kind, utxo_script, redeem_script, witness, value in (
                ("P2WPKH", (bytes([0, 0x14]) + hash160(public)).hex(), "", "", "0100000000000000"),
                ("P2WSH", "", "", script_code.hex(), "0200000000000000"),
            ):
                cases.append({
                    "name": f"sweep single without output {kind} {n_inputs}in {n_outputs}out in{index} "
                            f"ht 0x{hash_type:02x}",
                    "tx": raw,
                    "in": index,
                    "hash_type": hash_type,
                    "input_type": f"BTC_INPUT_TYPE_{kind}",
                    "script": utxo_script,
                    "redeem": redeem_script,
                    "witness_script": witness,
                    "amount": value,
                    "digest": witness_digest(tx, script_code, index, hash_type,
                                             bytes.fromhex(value)).hex(),
                })

    # Past 0xfc the length prefixes widen mid-transaction, for the scriptCode as much as for an
    # output's scriptPubKey.
    long_code = b"\x76\xa9\x14" + bytes(250) + b"\x88\xac"
    raw = sweep_tx(2, 2, long_code, 0x76543210)
    cases.append({
        "name": "sweep oversized scriptCode and scriptPubKey",
        "tx": raw,
        "in": 0,
        "hash_type": 0x01,
        "input_type": "BTC_INPUT_TYPE_LEGACY",
        "script": long_code.hex(),
        "redeem": "",
        "witness_script": "",
        "amount": "0000000000000000",
        "digest": legacy_digest(sighash_parse_tx(raw.hex()), long_code, 0, 0x01).hex(),
    })
    for n_inputs, n_outputs in [(1, 1), (2, 1), (1, 2), (3, 3), (40, 40)]:
        for kind, script, redeem, witness_script, amount in (
            ("P2WPKH", (bytes([0, 0x14]) + hash160(public)).hex(), "", "", "0100000000000000"),
            ("P2WSH", "", "", script_code.hex(), "0200000000000000"),
        ):
            raw = sweep_tx(n_inputs, n_outputs, bytes([0x00, 0x14]) + bytes(23), 0)
            tx = sighash_parse_tx(raw.hex())
            digest = witness_digest(tx, script_code if kind == "P2WSH" else script_code,
                                    0, WITNESS_V0, bytes.fromhex(amount))
            cases.append({
                "name": f"witness sweep {n_inputs}in {n_outputs}out {kind} in0",
                "tx": raw,
                "in": 0,
                "hash_type": WITNESS_V0,
                "input_type": f"BTC_INPUT_TYPE_{kind}",
                "script": script,
                "redeem": redeem,
                "witness_script": witness_script,
                "amount": amount,
                "digest": digest.hex(),
            })
    return cases


VALID_TAPROOT_SIGHASH = (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83)


def taproot_common(tx: dict, utxos: list) -> tuple:
    """The five hash_* values a taproot digest commits to, in the order they enter the message."""
    digest = lambda data: hashlib.sha256(data).digest()  # untagged, single, as BIP-341 defines them
    prevouts = digest(b"".join(e["txid"] + e["index"].to_bytes(4, "little") for e in tx["inputs"]))
    amounts = digest(b"".join(u["amount"] for u in utxos))
    script_pubkeys = digest(b"".join(csb(len(u["spk"])) + u["spk"] for u in utxos))
    sequences = digest(b"".join(e["sequence"] for e in tx["inputs"]))
    outputs = digest(b"".join(a + csb(len(s)) + s for a, s in tx["outputs"]))
    return prevouts, amounts, script_pubkeys, sequences, outputs


def taproot_sigmsg(tx: dict, utxos: list, in_: int, hash_type: int) -> tuple:
    """BIP-341's SigMsg for one input, and the hash_* values that go into it.

    An input signing SIGHASH_SINGLE with no output at its own index has no message: the device
    reports it, so this raises rather than invent a digest.
    """
    base = hash_type & 0x03
    anyone_can_pay = bool(hash_type & 0x80)
    if base == 0x03 and in_ >= len(tx["outputs"]):
        raise ValueError("SIGHASH_SINGLE with no output at the input's index")
    prevouts, amounts, script_pubkeys, sequences, outputs = taproot_common(tx, utxos)

    msg = bytearray([0, hash_type])  # sighash epoch, then the byte the signature will carry
    msg += tx["version"] + tx["locktime"]
    if not anyone_can_pay:
        msg += prevouts + amounts + script_pubkeys + sequences
    if base not in (0x02, 0x03):
        msg += outputs
    msg += bytes([0])  # spend_type: key path, no annex, no leaf version
    if anyone_can_pay:
        entry, utxo = tx["inputs"][in_], utxos[in_]
        msg += entry["txid"] + entry["index"].to_bytes(4, "little") + utxo["amount"]
        msg += csb(len(utxo["spk"])) + utxo["spk"] + entry["sequence"]
    else:
        msg += in_.to_bytes(4, "little")
    if base == 0x03:
        amount, script = tx["outputs"][in_]
        msg += hashlib.sha256(amount + csb(len(script)) + script).digest()
    return bytes(msg), (prevouts, amounts, script_pubkeys, sequences, outputs)


def utxo_blob(utxos: list) -> str:
    """Every input's witness utxo, as [amount:8][script length:1][script] repeated."""
    stream = bytearray()
    for utxo in utxos:
        if len(utxo["spk"]) > 0xFF:
            raise ValueError("witness utxo script too long for the vector encoding")
        stream += utxo["amount"] + bytes([len(utxo["spk"])]) + utxo["spk"]
    return stream.hex()


def taproot_case(name, raw, tx, utxos, in_, hash_type, digest, common=""):
    return {
        "name": name,
        "tx": raw,
        "in": in_,
        "hash_type": hash_type,
        "input_type": "BTC_INPUT_TYPE_P2TR",
        "script": "",
        "redeem": "",
        "witness_script": "",
        "amount": "",
        "utxos": utxo_blob(utxos),
        "common": common,
        "digest": digest,
    }


def sighash_bip341_cases() -> list:
    """BIP-341's wallet vectors: one nine-input transaction, the witness utxo of each of its inputs,
    and for seven of those inputs the SigMsg the document states plus the witness the key produces.

    Two checks run here, and generation fails if either breaks: the SigMsg rebuilt by this file has
    to equal the document's byte for byte, and the document's signature has to verify over the tagged
    hash of it with that input's own output key. Every digest emitted below is therefore pinned by a
    Schnorr signature rather than by my reading of the document.

    The seven cover all defined sighash bytes, three of them on a transaction whose other inputs are
    legacy and P2WPKH spends -- the hash_* values cover every input either way.
    """
    check_schnorr_verifier()
    document = json.loads(fetch("bip341_wallet.json"))
    spending = document["keyPathSpending"][0]
    raw = bytes.fromhex(spending["given"]["rawUnsignedTx"])
    tx = sighash_parse_tx(raw.hex())
    utxos = [{"amount": u["amountSats"].to_bytes(8, "little"), "spk": bytes.fromhex(u["scriptPubKey"])}
             for u in spending["given"]["utxosSpent"]]

    common = ""
    for name, got in zip(("hashPrevouts", "hashAmounts", "hashScriptPubkeys", "hashSequences",
                          "hashOutputs"), taproot_common(tx, utxos)):
        if got.hex() != spending["intermediary"][name]:
            raise SystemExit(f"BIP-341: {name} computed here is not the document's")
        common += got.hex()

    cases = []
    for entry in spending["inputSpending"]:
        index = entry["given"]["txinIndex"]
        hash_type = entry["given"]["hashType"]
        message, _ = taproot_sigmsg(tx, utxos, index, hash_type)
        if message.hex() != entry["intermediary"]["sigMsg"]:
            raise SystemExit(f"BIP-341 input {index}: SigMsg differs from the document")
        digest = tagged_hash("TapSighash", message)
        witness = bytes.fromhex(entry["expected"]["witness"][0])
        if not schnorr_verify(digest, witness[:64], utxos[index]["spk"][2:]):
            raise SystemExit(f"BIP-341 input {index}: the document's signature does not verify")
        cases.append(taproot_case(f"BIP-341 key path in{index} ht 0x{hash_type:02x}", raw, tx, utxos,
                                  index, hash_type, digest.hex(), common))
    return cases


def taproot_utxos(count: int) -> list:
    """Deterministic P2TR witness utxos; the keys are real points but nothing here signs with them."""
    utxos = []
    for i in range(count):
        x, _ = ec_mul(0x4C0D + 0x1F00 * i, SECP256K1_G)
        utxos.append({"amount": (1000 * (i + 1)).to_bytes(8, "little"),
                      "spk": bytes([0x51, 0x20]) + x.to_bytes(32, "big")})
    return utxos


def sighash_taproot_sweep_cases() -> list:
    """Shapes the BIP's one transaction cannot supply: a single input, an input index SIGHASH_SINGLE
    has no output for, and sighash bytes the spec leaves undefined. The digest comes from the
    reference the BIP vectors just verified."""
    cases = []
    for n_inputs in (1, 2, 3):
        for n_outputs in (1, 3, 20):
            for hash_type in VALID_TAPROOT_SIGHASH + (0x04, 0x80, 0xFF):
                index = 1 if n_inputs > 1 else 0
                raw = sweep_tx(n_inputs, n_outputs, bytes([0x51, 0x20]) + bytes(32), 0x3C)
                tx = sighash_parse_tx(raw.hex())
                utxos = taproot_utxos(n_inputs)
                refuse = (hash_type not in VALID_TAPROOT_SIGHASH
                          or ((hash_type & 0x03) == 0x03 and index >= n_outputs))
                digest = ""
                if not refuse:
                    message, _ = taproot_sigmsg(tx, utxos, index, hash_type)
                    digest = tagged_hash("TapSighash", message).hex()
                cases.append(taproot_case(
                    f"taproot sweep {n_inputs}in {n_outputs}out ht 0x{hash_type:02x} in{index}",
                    raw, tx, utxos, index, hash_type, digest))
    return cases


def sighash_bip143_cases() -> list:
    """BIP-143's examples, each of which states the signature hash it produces.

    Every digest in the document is preceded by the fields that went into it -- outpoint, scriptCode,
    amount, nHashType -- sometimes as an indented listing, sometimes as a bare scriptCode line below
    it (the OP_CODESEPARATOR examples write "see below" in the listing). So each sigHash line is
    matched with the nearest preceding occurrence of each field, and the transaction is the most
    recent unsigned one named before it.

    The device derives a P2WPKH scriptCode from the witness program and hashes a P2WSH witness script
    verbatim, so the vectors carry the records the device reads, not the scriptCode the document
    prints. Which means these cases say nothing about the BIP's rule that a P2WSH scriptCode drops
    everything up to the last executed OP_CODESEPARATOR: the stripped script is what is handed over.
    """
    lines = fetch("bip143.mediawiki").splitlines()

    # Each example announces the transaction it signs, with the hex either on the same line or on
    # the next one. Record both so a digest can be matched to the unsigned transaction above it.
    marks = []
    for n, line in enumerate(lines):
        stripped = line.strip()
        if "unsigned transaction" not in stripped:
            continue
        inline = re.search(r"([0-9a-f]{40,})\s*$", stripped)
        if inline:
            marks.append((n, inline.group(1)))
            continue
        for follow in lines[n + 1:n + 4]:
            if re.fullmatch(r"[0-9a-f]{40,}", follow.strip()):
                marks.append((n, follow.strip()))
                break

    cases = []
    kind = None
    kinds = [(n, l.strip().strip("=").strip()) for n, l in enumerate(lines) if l.strip().startswith("===")]
    for i, line in enumerate(lines):
        match = re.match(r"\s*sigHash:\s*([0-9a-f]{64})", line)
        if not match:
            continue
        digest = match.group(1)
        kind = next((k for n, k in reversed(kinds) if n < i), None)
        tx_hex = next((h for n, h in reversed(marks) if n < i), None)
        if tx_hex is None:
            continue

        fields = {}
        for back in range(i - 1, max(i - 40, 0), -1):
            entry = re.match(r"\s*(outpoint|scriptCode|amount|nHashType):\s*([0-9a-f]{6,})\s*$", lines[back])
            if entry and entry.group(1) not in fields:
                fields[entry.group(1)] = entry.group(2)
            if len(fields) == 4:
                break
        if len(fields) != 4:
            continue

        tx = sighash_parse_tx(tx_hex)
        # The document names the input by its outpoint, not by its position in the spending
        # transaction -- and the two differ in three of the five examples.
        outpoint = bytes.fromhex(fields["outpoint"])
        matches = [n for n, inp in enumerate(tx["inputs"])
                   if inp["txid"] == outpoint[:32]
                   and inp["index"] == int.from_bytes(outpoint[32:36], "little")]
        if len(matches) != 1:
            continue
        in_ = matches[0]
        hash_type = int.from_bytes(bytes.fromhex(fields["nHashType"]), "little")
        script_code = bytes.fromhex(fields["scriptCode"])
        # The document prints the scriptCode with its compactsize length byte in front.
        declared, _ = read_compactsize(script_code, 0)
        if declared + 1 == len(script_code):
            script_code = script_code[1:]

        # A P2WPKH scriptCode is, by definition, the P2PKH script of the key; anything else signed
        # here is a witness script. (The section titles alone are not enough: the "No FindAndDelete"
        # examples are P2WSH spends and do not say so in the heading.)
        p2wpkh = len(script_code) == 25 and script_code[0] == 0x76 and script_code[1] == 0xa9
        p2wsh = not p2wpkh
        p2sh = kind.startswith("P2SH")
        if p2wsh:
            input_type = "BTC_INPUT_TYPE_P2WSH"
            witness_script, script, redeem = script_code.hex(), "", ""
        elif p2sh:
            input_type = "BTC_INPUT_TYPE_P2WPKH"
            witness_script, script = "", ""
            redeem = (bytes([0, 0x14]) + script_code[3:23]).hex()
        else:
            input_type = "BTC_INPUT_TYPE_P2WPKH"
            witness_script, redeem = "", ""
            script = (bytes([0, 0x14]) + script_code[3:23]).hex()

        if witness_digest(tx, script_code, in_, hash_type,
                          bytes.fromhex(fields["amount"])).hex() != digest:
            raise SystemExit(f"BIP-143 {kind} in{in_}: the reference does not reproduce the document")

        cases.append({
            "name": f"BIP-143 {kind} in{in_} ht {hash_type:#010x}",
            "tx": bytes.fromhex(tx_hex),
            "in": in_,
            "hash_type": hash_type,
            "input_type": input_type,
            "script": script,
            "redeem": redeem,
            "witness_script": witness_script,
            "amount": fields["amount"],
            "digest": digest,
        })
    return cases


def sighash_vectors() -> str:
    cases = (sighash_chain_cases() + sighash_sweep_cases() + sighash_bip143_cases()
             + sighash_bip341_cases() + sighash_taproot_sweep_cases())
    # A shape signed under several hash types is the same bytes once, so identical transactions
    # share one array.
    arrays, named, rows = [], {}, []
    for i, c in enumerate(cases):
        key = c["tx"].hex()
        if key not in named:
            named[key] = f"sighash_{len(arrays)}"
            arrays.append(tx_c_array(named[key], c["tx"]))
        rows.append(
            f'    {{ "{c["name"]}", {named[key]}, sizeof({named[key]}), {c["in"]},\n'
            f'      0x{c["hash_type"]:08x}U, {c["input_type"]},\n'
            f'      "{c["script"]}", "{c["redeem"]}", "{c["witness_script"]}", "{c["amount"]}",\n'
            # Only a taproot case names every input's utxo, or the hash_* values the document states.
            f'      "{c.get("utxos", "")}", "{c.get("common", "")}",\n'
            f'      "{c["digest"]}" }},')

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * The digest each signature commits to. The oracles, none of them this implementation:
 *
 *  - Two confirmed mainnet spends, fetched by transaction id. Each is kept only if the signature
 *    in its own scriptSig verifies over the digest the generator's reference computes, so a
 *    legacy digest here is one a real coin was unlocked with.
 *  - %s
 *    BIP-341's wallet vectors: one transaction, the witness utxo of every input, and for seven of
 *    those inputs the SigMsg the document states, the five hash_* values, and the resulting
 *    witness. The generator rebuilds the SigMsg, requires it to match, and BIP-340-verifies the
 *    document's signature against the input's own output key. That verifier is itself checked
 *    against %s before use.
 *  - %s
 *    BIP-143's examples, which state the signature hash each produces.
 *  - The reference the first two vouch for, over a sweep of shapes and hash types: several inputs,
 *    SIGHASH_NONE, SIGHASH_SINGLE, ANYONECANPAY, lengths that push a compactsize prefix past one
 *    byte, and the cases a walker must refuse (an empty digest), which are the undefined sighash
 *    bytes and SIGHASH_SINGLE with no output at the input's index.
 *
 * See the note above sighash_chain_cases() for why Bitcoin Core's sighash.json is not the oracle.
 */

#ifndef VECTORS_SIGHASH_H
#define VECTORS_SIGHASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char* name;
  const uint8_t* tx;         /* the unsigned (non-witness) spending transaction */
  size_t tx_len;
  size_t in;                 /* the input being signed */
  uint32_t hash_type;
  int input_type;            /* btc_input_type_t, which selects the walker under test */
  const char* script;        /* scriptPubKey of the spent output, hex */
  const char* redeem;        /* redeem script record, hex, empty when absent */
  const char* witness_script;/* witness script record, hex, empty when absent */
  const char* amount;        /* value of the spent output, 8 bytes little-endian hex; empty for legacy */
  /* Every input's witness utxo as [amount:8][script length:1][script], in input order. A taproot
   * digest commits to all of them, so the case has to carry them; the other walkers take the spent
   * output's fields from the four strings above and leave this empty. */
  const char* utxos;
  /* hash_prevouts, hash_amounts, hash_scriptpubkeys, hash_sequence, hash_outputs, concatenated:
   * what BIP-341 states and the taproot digest is built from. Empty when no document states them. */
  const char* common;
  const char* digest;        /* the signature hash, in the order the digest bytes come out */
                             /* empty means the walker must refuse the case */
} sighash_case_t;

%s

static const sighash_case_t SIGHASH_CASES[] = {
%s
};

#define SIGHASH_CASE_COUNT (sizeof(SIGHASH_CASES) / sizeof(SIGHASH_CASES[0]))

#endif
""" % (provenance("bip341_wallet.json"), provenance("bip340_vectors.csv"),
       provenance("bip143.mediawiki"), "\n\n".join(arrays), "\n".join(rows))


# --------------------------------------------------------------------------- bignum


# app/crypto/bignum.c documents the representation it uses, and every expectation below is computed
# from that document with CPython's integers: a bignum256 holds sum(limb[i] * 2**(29*i)). Nothing
# here mirrors the C, which is the point: the C is free to be wrong about its own doc. The domain is
# 2**261, not 2**256 -- nine 29-bit limbs -- and several functions are documented to work above the
# 256-bit mark where a bignum256 cannot be written as 32 bytes at all.

BN_LIMBS = 9
BN_BITS = 29
BN_BASE = 1 << BN_BITS
BN_DOMAIN = BN_BASE ** BN_LIMBS

SECP256K1_P = 2**256 - 2**32 - 977
SECP256K1_N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141


def bn_is_prime(n: int) -> bool:
    """Miller-Rabin on the first twelve prime bases.

    That set certifies numbers only below 3.3e24, so at 256 bits this is a screen and not a proof.
    It is here to catch a mistyped constant, which is the realistic failure: every modular
    expectation in this section rests on the modulus being prime -- bn_inverse uses Fermat and
    bn_sqrt needs p % 4 == 3 -- and both numbers are published, so passing the screen says the
    digits were copied correctly.
    """
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


assert bn_is_prime(SECP256K1_P) and bn_is_prime(SECP256K1_N)
assert 2**256 - 2**224 <= SECP256K1_P <= 2**256, "outside the prime range the file assumes"
assert SECP256K1_P % 4 == 3, "bn_sqrt requires prime % 4 == 3"


def bn_limbs(value: int) -> list:
    if not 0 <= value < BN_DOMAIN:
        raise ValueError(f"{hex(value)} does not fit the 261-bit domain")
    return [(value >> (BN_BITS * i)) & (BN_BASE - 1) for i in range(BN_LIMBS)]


def bn_raw_limbs(value: int) -> list:
    """Nine base-2**29 digits with the most significant one absorbing whatever is left over.

    bn_fast_mod is documented to take a number up to 2**264, and bn_normalize an unnormalized one;
    neither value can be expressed as 32 big-endian bytes, so those tables carry limbs.
    """
    if not 0 <= value < (1 << 32) * BN_BASE ** (BN_LIMBS - 1):
        raise ValueError(f"{hex(value)} does not fit nine limbs even unnormalized")
    limbs = [(value >> (BN_BITS * i)) & (BN_BASE - 1) for i in range(BN_LIMBS - 1)]
    limbs.append(value >> (BN_BITS * (BN_LIMBS - 1)))
    return limbs


def bn_unnormalized(value: int, spots: tuple) -> list:
    """Limbs for `value` with carries left unpropagated at `spots`, representing it exactly.

    Borrowing one whole limb out of the next one up keeps the sum unchanged while making the lower
    limb overflow, which is the only way an unnormalized number arises in practice.
    """
    limbs = bn_limbs(value)
    for i in spots:
        if limbs[i + 1] == 0:
            raise ValueError(f"cannot unnormalize limb {i} of {hex(value)}")
        limbs[i] += BN_BASE
        limbs[i + 1] -= 1
    return limbs


def bn_c(*limbs) -> str:
    return "{ " + ", ".join(f"0x{v:08X}u" for v in limbs) + " }"


def bn_hex(value: int) -> str:
    if not 0 <= value < 2**256:
        raise ValueError("not a 32-byte value")
    return value.to_bytes(32, "big").hex()


def bn_table(name: str, doc: str, rows: list) -> str:
    """One bn_op_t table: (name, a, b, modulus, k, out, extra), None becoming 0 or "".

    The operands are limbs rather than hex because a partly reduced number -- anything up to 2*prime
    -- needs 257 bits and cannot be written as 32 bytes. Only the modulus is hex, and it is always
    fully reduced.
    """
    body = ",\n".join(
        '  { "%s",\n    %s,\n    %s, "%s",\n    %u, %s, %u }' % (
            n, bn_c(*bn_limbs(a)) if a is not None else bn_c(*[0] * BN_LIMBS),
            bn_c(*bn_limbs(b)) if b is not None else bn_c(*[0] * BN_LIMBS),
            bn_hex(p) if p is not None else "", k, bn_c(*bn_limbs(out)), extra)
        for n, a, b, p, k, out, extra in rows)
    return (f"/* {doc} */\nstatic const bn_op_t {name}[] = {{\n{body}\n}};\n"
            f"#define {name.upper()}_COUNT (sizeof({name}) / sizeof({name}[0]))\n")


def bn_raw_table(name: str, doc: str, rows: list) -> str:
    body = ",\n".join('  { "%s",\n    %s, "%s",\n    %s }' % (
        n, bn_c(*inp), bn_hex(p) if p is not None else "", bn_c(*bn_limbs(out)))
        for n, inp, p, out in rows)
    return (f"/* {doc} */\nstatic const bn_raw_t {name}[] = {{\n{body}\n}};\n"
            f"#define {name.upper()}_COUNT (sizeof({name}) / sizeof({name}[0]))\n")


def bn_compact_table(rows: list) -> str:
    body = ",\n".join(
        '  { "compact_be %s in %d bytes",\n    %s, %u,\n    %s }' % (
            hex(value)[:10], length, bn_c(*bn_limbs(value % 2 ** (8 * length))), length,
            bn_c(*bn_limbs(value % 2 ** (8 * length))))
        for value, length in rows)
    return ("/* bn_read_compact_be: the number the last `length` bytes denote. */\n"
            "static const bn_compact_t compact_be_cases[] = {\n" + body + "\n};\n"
            "#define COMPACT_BE_CASES_COUNT (sizeof(compact_be_cases) / "
            "sizeof(compact_be_cases[0]))\n")


def bn_pow_mod_two_ways(base: int, expo: int, mod: int) -> int:
    """CPython's pow cross-checked against a left-to-right binary method before either is trusted."""
    result = 1
    for bit in bin(expo)[2:]:
        result = result * result % mod
        if bit == "1":
            result = result * base % mod
    if result != pow(base, expo, mod):
        raise SystemExit("the two modular exponentiations disagree")
    return result


def bn_format_model(amount: int, prefix, suffix, decimals: int, exponent: int, trailing: bool,
                    thousands: str, capacity: int):
    """The prototype bn_format carries as a comment, with two corrections the C insists on.

    A non-empty suffix is separated by a space, which the prototype omits, and a buffer that cannot
    hold the string plus its terminator gets nothing at all: the function fills it with NULs and
    returns 0. A prefix or suffix of None is the NULL pointer the C accepts.
    """
    value = amount * 10**exponent if exponent >= 0 else amount // 10 ** (-exponent)
    scale = 10**decimals
    integer, fraction = divmod(value, scale)
    group = thousands if thousands else ""
    text = f"{integer:,}".replace(",", group) if group else f"{integer}"
    if decimals:
        fractional = f".{fraction:0{decimals}d}"
        if not trailing:
            fractional = fractional.rstrip("0").rstrip(".")
    else:
        fractional = ""
    out = f"{prefix or ''}{text}{fractional}{(' ' + suffix) if suffix else ''}"
    return "" if len(out) + 1 > capacity else out


def bn_format_parse(text: str, prefix, suffix, decimals: int):
    """The integer a formatted string denotes, ignoring grouping and padding.

    This is the check that does not care how the digits were spelled, only that they are the amount's
    -- which is the one property a user can act on.
    """
    body = text[len(prefix or ""): len(text) - (len(suffix) + 1 if suffix else 0)]
    whole, dot, fraction = body.partition(".")
    if dot:
        fraction = fraction.ljust(decimals, "0")
    group = THOUSANDS_STRIP
    return int(whole.translate(group) or "0") * 10**decimals + (int(fraction) if fraction else 0)


THOUSANDS_STRIP = {ord(","): None, ord(" "): None, ord("."): None}


def bn_format_cases() -> str:
    """Amount formatting: what the user reads on the screen before approving.

    Each expectation is checked twice before it is emitted, once against the prototype above and once
    by parsing the string back into the number it must denote. The second catches a model that is
    self-consistent and wrong.
    """
    satoshi, ether = 10**8, 10**18
    rows = [
        # Written out by hand first, so the model is pinned to intent and not only to itself.
        (0, "", "BTC", 8, 0, False, ",", 32, "0 BTC"),
        (1, "", "BTC", 8, 0, False, ",", 32, "0.00000001 BTC"),
        (satoshi, "", "BTC", 8, 0, False, ",", 32, "1 BTC"),
        (satoshi + 1, "", "BTC", 8, 0, False, ",", 32, "1.00000001 BTC"),
        (10 * satoshi, "", "BTC", 8, 0, False, ",", 32, "10 BTC"),
        (123456789, "", "BTC", 8, 0, False, ",", 32, "1.23456789 BTC"),
        (1000 * satoshi, "", "BTC", 8, 0, False, ",", 32, "1,000 BTC"),
        (1234567 * satoshi, "", "BTC", 8, 0, False, ",", 32, "1,234,567 BTC"),
        (21000000 * satoshi, "", "BTC", 8, 0, False, ",", 32, "21,000,000 BTC"),
        (satoshi - 1, "", "BTC", 8, 0, False, ",", 32, "0.99999999 BTC"),
        (satoshi // 2, "", "BTC", 8, 0, False, ",", 32, "0.5 BTC"),
        (1, "", "BTC", 8, -1, False, ",", 32, "0 BTC"),
        (satoshi, "", "BTC", 8, 0, True, ",", 32, "1.00000000 BTC"),
        (satoshi // 100, "", "", 8, 0, False, ",", 32, "0.01"),
        (satoshi * 10, "", "", 8, 0, False, ",", 32, "10"),
        (satoshi * 1234567 + 89, "", "", 8, 0, False, ",", 32, "1,234,567.00000089"),
        (ether, "", "ETH", 18, 0, False, " ", 64, "1 ETH"),
        (ether + 1, "", "ETH", 18, 0, False, " ", 64, "1.000000000000000001 ETH"),
        (1234, "", "", 0, 3, False, ",", 32, "1,234,000"),
        (1234, "", "", 0, -1, False, ",", 32, "123"),
        (0, "", "", 0, -5, False, ",", 32, "0"),
        (9 ** 20, "", "", 0, 6, False, 0, 128, "12157665459056928801000000"),
        (5, "", "", 0, 0, False, ",", 1, ""),
        (5, "", "", 0, 0, False, ",", 2, "5"),
        (5, "", "", 0, 0, False, ",", 3, "5"),
        (5, "$", "CAD", 2, 0, False, ",", 11, "$0.05 CAD"),
        (5, "$", "CAD", 2, 0, False, ",", 9, ""),
        (505, "$", "CAD", 2, 0, False, ",", 12, "$5.05 CAD"),
        (10**25 - 1, "", "", 0, 0, False, ",", 64, "9,999,999,999,999,999,999,999,999"),
        (satoshi, None, None, 8, 0, False, 0, 32, "1"),
        (0, None, "XBT", 0, 0, False, 0, 32, "0 XBT"),
    ]

    rng = random.Random(0xF074)
    for _ in range(26):
        amount = rng.randrange(0, 2 ** rng.randrange(1, 257))
        decimals = rng.randrange(0, 19)
        exponent = rng.randrange(-6, 7)
        rows.append((amount, rng.choice(["", "$", "P ", None]), rng.choice(["", "BTC", "sat", None]),
                     decimals, exponent, rng.randrange(2) == 1,
                     rng.choice([",", " ", 0]), rng.choice([0, 1, 8, 24, 64, 128]), None))

    out = []
    for amount, prefix, suffix, decimals, exponent, trailing, thousands, cap, want in rows:
        text = bn_format_model(amount, prefix, suffix, decimals, exponent, trailing, thousands, cap)
        if want is not None and text != want:
            raise SystemExit(f"bn_format model produced {text!r}, expected {want!r}")
        if text:
            scaled = amount * 10**exponent if exponent >= 0 else amount // 10 ** (-exponent)
            if bn_format_parse(text, prefix, suffix, decimals) != scaled:
                raise SystemExit(f"bn_format {text!r} does not parse back to {scaled}")
        out.append((amount, prefix, suffix, decimals, exponent, trailing, thousands, cap, text))

    def emit(row):
        amount, prefix, suffix, decimals, exponent, trailing, thousands, cap, text = row
        name = (f"format {hex(amount)[:10]} d{decimals} e{exponent}"
                f"{' trailing' if trailing else ''}{' nul' if prefix is None or suffix is None else ''}"
                f"{' cap' + str(cap) if cap != 64 else ''}")
        return '  { "%s",\n    "%s", %s, %s,\n    %u, %d, %s, %s, %u,\n    "%s" },' % (
            name, bn_hex(amount), "NULL" if prefix is None else '"%s"' % prefix,
            "NULL" if suffix is None else '"%s"' % suffix, decimals, exponent,
            "true" if trailing else "false",
            "0" if not thousands else "'%s'" % thousands,
            cap, text)

    return ("/* Amount strings, as the screen shows them. expect is empty where the buffer cannot "
            "hold the\n * string and its terminator and bn_format must return 0 having written "
            "nothing useful.\n */\n"
            "static const bn_format_t format_cases[] = {\n"
            + "\n".join(emit(r) for r in out) + "\n};\n"
            "#define FORMAT_CASES_COUNT (sizeof(format_cases) / sizeof(format_cases[0]))\n")


def bignum_vectors() -> str:
    p, n = SECP256K1_P, SECP256K1_N
    rng = random.Random(0xB16B0B)

    # Values the file's contracts call "normalized": every limb below 2**29, so below 2**256.
    normal = [0, 1, 2, BN_BASE - 1, BN_BASE, BN_BASE + 1, 2**58 - 1, 2**32 - 1, 2**32, 2**64,
              2**128, 2**255, 2**256 - 1, p, p - 1, p + 1, n, n - 1]
    normal += [rng.randrange(0, 2**256) for _ in range(10)]
    tables = {}

    def add(table, name, a=None, b=None, mod=None, k=0, out=None, extra=0):
        tables.setdefault(table, []).append((name, a, b, mod, k, out, extra))

    for a in normal[:12]:
        for b in (0, 1, BN_BASE - 1, p - 1, 2**256 - 1):
            if a + b < BN_DOMAIN:
                add("add_cases", f"add {hex(a)[:10]} + {hex(b)[:10]}", a=a, b=b, out=a + b)

    for a in normal[:8]:
        for b in (0, 1, p - 1):
            add("addmod_cases", f"addmod {hex(a)[:10]} + {hex(b)[:10]}", a=a, b=b, mod=p,
                out=(a + b) % p)

    for a in (0, 1, BN_BASE - 1, 2**32 - 1, 2**255, 2**256 - 1, p, BN_DOMAIN - 1 - 7):
        for y in (0, 1, 2**29, 2**32 - BN_BASE):
            if a + y < BN_DOMAIN:
                add("addi_cases", f"addi {hex(a)[:10]} + {y}", a=a, k=y, out=a + y)

    # bn_subi asserts y < prime->val[0], which for secp256k1 is 2**29 - 977.
    for a in (0, 1, BN_BASE, 2**255, 2**256 - 1, p, p - 1):
        for y in (1, 2, (p & (BN_BASE - 1)) - 1):
            add("subi_cases", f"subi {hex(a)[:10]} - {y}", a=a, mod=p, k=y, out=a + p - y)

    for a in (0, 1, BN_BASE, BN_BASE - 1, 2**255, 2**256 - 1, p, p - 1, n):
        for b in (0, 1, a, BN_BASE, p):
            if b <= a:
                add("sub_cases", f"sub {hex(a)[:10]} - {hex(b)[:10]}", a=a, b=b, out=a - b)

    for x in (0, 1, p - 1, p, 2 * p - 1, 2**255, n):
        for y in (0, 1, p - 1, p, 2 * p - 1):
            add("subtractmod_cases", f"subtractmod {hex(x)[:8]} - {hex(y)[:8]}", a=x, b=y, mod=p,
                out=x + 2 * p - y)

    for x in normal[:8]:
        for k in (0, 1, 2, 3, 7, 8):
            add("mult_k_cases", f"mult_k {hex(x)[:10]} * {k}", a=x, mod=p, k=k, out=(x * k) % p)

    for x in (0, 1, 2, p - 1, p, p + 1, 2 * p - 1, 2**255, 2**256 - 1, p // 2, p // 2 + 1):
        add("mult_half_cases", f"mult_half {hex(x)[:10]}", a=x, mod=p,
            out=x // 2 if x % 2 == 0 else (x + p) // 2)

    for x in (0, 1, p - 1, p, p + 1, 2 * p - 1, 2**256 - 1, 2**255, n, 2 * n - 1):
        mod = p if x < 2 * p else n
        add("mod_cases", f"mod {hex(x)[:12]}", a=x, mod=mod, out=x % mod)

    for _ in range(12):
        k, x = rng.randrange(0, 2**256), rng.randrange(0, 2**256)
        add("multiply_cases", f"multiply {hex(k)[:8]} x {hex(x)[:8]}", a=k, b=x, mod=p,
            out=(k * x) % p)
    for k, x in ((0, 2**256 - 1), (1, 2**256 - 1), (p - 1, p - 1), (2**128, 2**128),
                 (2**256 - 1, 2**256 - 1), (n - 1, n - 1), (2**129 + 1, 2**127), (2, n)):
        add("multiply_cases", f"multiply {hex(k)[:8]} by {hex(x)[:8]}", a=k, b=x, mod=p,
            out=(k * x) % p)

    for x in (0, 1, p - 1, 2**255, 2**256 - 1, p // 2, rng.randrange(0, 2**256)):
        m = (-x * pow(p, -1, BN_BASE)) % BN_BASE
        add("divide_base_cases", f"divide_base {hex(x)[:10]}", a=x, mod=p, out=(x + m * p) >> BN_BITS)

    for base, expo in ((2, 0), (2, 1), (3, 255), (2, 256), (5, 2**8 - 1), (p - 1, 2**255),
                       (p - 1, 2**256 - 1), (0, 0), (7, 2**200 + 3), (n, n - 2)):
        add("power_mod_cases", f"power_mod {hex(base)[:8]} ^ {expo}", a=base, b=expo, mod=p,
            out=bn_pow_mod_two_ways(base, expo, p))
    for _ in range(10):
        base, expo = rng.randrange(0, 2**256), rng.randrange(0, 2**256)
        add("power_mod_cases", f"power_mod random {hex(base)[:8]}", a=base, b=expo, mod=p,
            out=bn_pow_mod_two_ways(base, expo, p))

    for _ in range(12):
        root = rng.randrange(1, p)
        x = root * root % p
        got = pow(x, (p + 1) // 4, p)
        if got * got % p != x:
            raise SystemExit("the square root formula does not round-trip")
        add("sqrt_cases", f"sqrt of {hex(root)[:8]} squared", a=x, mod=p, out=got)

    for x in (0, 1, p - 1, 2, 3, BN_BASE, 2**255, 2**256 - 1, n, n - 1):
        add("inverse_cases", f"inverse {hex(x)[:12]}", a=x, mod=p,
            out=0 if x % p == 0 else pow(x, p - 2, p))
    for _ in range(16):
        x = rng.randrange(1, p)
        inv = pow(x, p - 2, p)
        if x * inv % p != 1:
            raise SystemExit("the oracle's own inverse is wrong")
        add("inverse_cases", f"inverse random {hex(x)[:10]}", a=x, mod=p, out=inv)

    # bn_cnegate reduces first, then answers 2*prime - x when the condition is set and prime + x
    # when it is not; k carries the condition.
    for x in (0, 1, 2, p - 1, p, p + 1, 2 * p - 1, 2**255, 2**256 - 1, n, p // 2):
        reduced = x % p
        for cond in (0, 1):
            add("cnegate_cases", f"cnegate {hex(x)[:10]} cond {cond}", a=x, mod=p, k=cond,
                out=(2 * p - reduced) if cond else (p + reduced))

    for x in (0, 1, BN_BASE - 1, BN_BASE, 2**256 - 1, p, 10**18, 210000):
        for d in (1, 2, 10, 58, 1000, 61303):
            q, r = divmod(x, d)
            add("div_cases", f"div {hex(x)[:10]} by {d}", a=x, k=d, out=q, extra=r)
    for _ in range(8):
        x, d = rng.randrange(0, 2**256), rng.randrange(1, 61304)
        q, r = divmod(x, d)
        add("div_cases", f"div random by {d}", a=x, k=d, out=q, extra=r)

    # The raw tables: subject is the limb vector, so the operand is not 32 bytes.
    normalize = []
    for value in (0, 1, BN_BASE - 1, 2**255, p, BN_DOMAIN - 1):
        for spots in ((0,), (1, 3), tuple(range(BN_LIMBS - 1))):
            try:
                raw = bn_unnormalized(value, spots)
            except ValueError:
                continue
            normalize.append((f"normalize {hex(value)[:8]} at {spots}", raw, None, value))
    for _ in range(6):
        value = rng.randrange(0, BN_DOMAIN)
        spots = tuple(i for i in range(BN_LIMBS - 1) if rng.randrange(3) == 0)[:4] or (0,)
        try:
            normalize.append((f"normalize random {hex(value)[:8]}",
                              bn_unnormalized(value, spots), None, value))
        except ValueError:
            pass

    lshifts, rshifts, fast_mod = [], [], []
    for value in (0, 1, 2, BN_BASE - 1, BN_BASE, 2**255, 2**256 - 1, p, n, 2**260 - 1):
        if value * 2 < BN_DOMAIN:
            lshifts.append((f"lshift {hex(value)[:10]}", bn_raw_limbs(value), None, value * 2))
        rshifts.append((f"rshift {hex(value)[:10]}", bn_raw_limbs(value), None, value // 2))
    for value in (0, 1, p, p - 1, 2 * p, 2 * p + 1, 2**256 - 1, 2**256 + 2**255, 3 * 2**256 + 7,
                  (255 << 256) + p, 2**261 - 1, 2**264 - 1, p + (1 << 200)):
        fast_mod.append((f"fast_mod {hex(value)[:12]}", bn_raw_limbs(value), p,
                         value - (value >> 256) * p))

    header = """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * Expectations for app/crypto/bignum.c, computed with CPython's arbitrary-precision integers from
 * the representation that file documents (nine limbs, base 2**29, value = sum(limb[i] * 2**(29*i))).
 * CPython is the oracle: it shares no code, no limb width and no reduction trick with this module.
 *
 * The moduli are secp256k1's field prime, written here as 2**256 - 2**32 - 977 as SEC 2 does, and
 * its order. Both are proven prime by Miller-Rabin during generation, because bn_inverse uses
 * Fermat's little theorem and bn_sqrt needs p % 4 == 3 -- a composite modulus would make an
 * incorrect result look merely unusual. The test additionally checks the curve constants the
 * firmware ships against these two values.
 *
 * Two tables carry limbs instead of hex. bn_fast_mod is documented to accept up to 2**264 and
 * bn_normalize an unnormalized number, and neither can be spelled in 32 bytes.
 *
 * Amount strings are checked twice at generation time: against the prototype the function carries
 * as a comment, and by parsing the produced string back into the integer it must represent.
 */

#ifndef VECTORS_BIGNUM_H
#define VECTORS_BIGNUM_H

#include <stdbool.h>
#include <stdint.h>

#include "crypto/bignum.h"

typedef struct {
  const char* name;
  /* Operands are limbs rather than hex because a partly reduced number -- anything up to 2*prime --
   * needs 257 bits and cannot be written as 32 bytes. Empty limbs mean the operand is unused. */
  uint32_t a[BN_LIMBS];
  uint32_t b[BN_LIMBS];
  const char* p_hex;        /* the modulus, always fully reduced; empty when there is none */
  uint32_t k;               /* scalar operand: bn_mult_k's k, bn_addi's y, bn_long_division's d */
  uint32_t out[BN_LIMBS];   /* expected result, base 2**29 */
  uint32_t extra;           /* the remainder of bn_long_division */
} bn_op_t;

/* A number the function under test builds or accepts as raw limbs, because it does not fit 32
 * bytes (bn_fast_mod takes up to 2**264) or is deliberately unnormalized (bn_normalize). */
typedef struct {
  const char* name;
  uint32_t in[BN_LIMBS];
  const char* p_hex;
  uint32_t out[BN_LIMBS];
} bn_raw_t;

/* A value plus everything derived from its representation alone. */
typedef struct {
  const char* name;
  const char* hex;          /* 32 bytes big-endian */
  const char* le_hex;       /* the same value, 32 bytes little-endian */
  uint32_t limbs[BN_LIMBS];
  int bitcount;
  unsigned int digitcount;
} bn_value_t;

typedef struct {
  const char* name;
  const char* amount_hex;
  const char* prefix;
  const char* suffix;
  unsigned int decimals;
  int exponent;
  bool trailing;
  char thousands;
  unsigned int capacity;    /* size of the caller's buffer */
  const char* expect;       /* empty when bn_format must return 0 */
} bn_format_t;

/* bn_read_compact_be takes a big-endian number of any length up to 32 bytes; the value it denotes
 * is the one those bytes carry, as if the missing leading bytes were zero. */
typedef struct {
  const char* name;
  uint32_t in[BN_LIMBS];
  unsigned int length;
  uint32_t out[BN_LIMBS];
} bn_compact_t;

/* inverse_mod_power_two(a, n) = 1/a mod 2**n. a is odd, 1 <= n <= 32. */
static const uint32_t BN_INVERSE_POW2[][3] = {
@POW2@
};
#define BN_INVERSE_POW2_COUNT (sizeof(BN_INVERSE_POW2) / sizeof(BN_INVERSE_POW2[0]))

@VALUES@
@RAW@
@COMPACT@
@FORMAT@
@OPS@
#endif
"""

    values = []
    seen = set()
    named = [
        ("zero", 0), ("one", 1), ("two", 2), ("limb max", BN_BASE - 1),
        ("limb overflow", BN_BASE), ("two limbs full", 2**58 - 1), ("three limbs", 2**58),
        ("uint32 max", 2**32 - 1), ("uint32 wrap", 2**32), ("uint64 max", 2**64 - 1),
        ("bit 128", 2**128), ("bit 255", 2**255), ("bit 255 with tail", 2**255 + 0xDEADBEEF),
        ("2**256 - 1", 2**256 - 1), ("2**256 - 2", 2**256 - 2), ("secp256k1 p", p),
        ("secp256k1 p - 1", p - 1), ("secp256k1 p + 1", p + 1), ("secp256k1 n", n),
        ("secp256k1 n - 1", n - 1), ("ends and begins", 1 + (((2**256 - 1) >> 128) << 128)),
        ("alternating", int("ffff0000" * 8, 16)),
    ]
    for i in range(12):
        named.append((f"random {i}", rng.randrange(0, 2**256)))
    for i in range(6):
        named.append((f"random small {i}", rng.randrange(0, 10 ** rng.randrange(1, 12))))
    for name, value in named:
        if value in seen:
            continue
        seen.add(value)
        values.append('  { "%s",\n    "%s",\n    "%s",\n    %s,\n    %d, %uU },' % (
            name, bn_hex(value), value.to_bytes(32, "little").hex(), bn_c(*bn_limbs(value)),
            value.bit_length(), 1 if value == 0 else len(str(value))))

    pow2 = []
    for bits in list(range(1, 33)) + [1, 2, 3, 16, 31, 32]:
        for a in (1, 3, 5, BN_BASE - 1, 2**31 + 1, (1 << bits) - 1 if bits < 32 else 0xFFFFFFFF):
            a |= 1
            pow2.append("  { %u, %u, %u }" % (a & 0xFFFFFFFF, bits,
                                              pow(a, -1, 2**bits) & (2**bits - 1)))

    compact = []
    for value in (0, 1, 255, 2**32 - 1, 2**64, 210000, p, 2**256 - 1, rng.randrange(0, 2**256)):
        for length in (1, 4, 8, 13, 31, 32):
            compact.append((value, length))

    raw = "\n".join([
        bn_raw_table("normalize_cases",
                     "Carries left in the limbs; out is the same number normalized.", normalize),
        bn_raw_table("lshift_cases",
                     "bn_lshift doubles, for the inputs whose double still fits.", lshifts),
        bn_raw_table("rshift_cases", "bn_rshift halves, rounding down.", rshifts),
        bn_raw_table("fast_mod_cases",
                     "Partly reduced by the documented formula x - (x // 2**256) * prime, which "
                     "pins the value exactly.", fast_mod),
    ])
    ops = "\n".join(bn_table(name, DOC[name], tables[name]) for name in ORDER)
    return (header.replace("@POW2@", ",\n".join(pow2))
            .replace("@VALUES@",
                     "static const bn_value_t values[] = {\n" + "\n".join(values) + "\n};\n"
                     "#define VALUES_COUNT (sizeof(values) / sizeof(values[0]))\n")
            .replace("@RAW@", raw)
            .replace("@COMPACT@", bn_compact_table(compact))
            .replace("@FORMAT@", bn_format_cases())
            .replace("@OPS@", ops))


ORDER = ["add_cases", "addmod_cases", "addi_cases", "subi_cases", "sub_cases",
         "subtractmod_cases", "mult_k_cases", "mult_half_cases", "cnegate_cases", "mod_cases",
         "multiply_cases", "divide_base_cases", "power_mod_cases", "sqrt_cases", "inverse_cases",
         "div_cases"]

DOC = {
    "add_cases": "x += y, below 2**261, no modulus.",
    "addmod_cases": "x += y then partly reduced: out is the fully reduced value, and the test reduces "
                 "the result with bn_mod before comparing.",
    "addi_cases": "x += y for a uint32 y at most 2**32 - 2**29.",
    "subi_cases": "x = x + prime - y exactly, y below prime's lowest limb.",
    "sub_cases": "res = x - y with x >= y, no modulus.",
    "subtractmod_cases": "res = x + 2*prime - y exactly, which is what the file specifies rather than a "
                      "choice of reduction.",
    "mult_k_cases": "x = k*x % prime for k up to 8; partly reduced, so the test reduces first.",
    "mult_half_cases": "x = x/2 if even else (x + prime)/2.",
    "mod_cases": "fully reduced: out is exact.",
    "multiply_cases": "k*x % prime, partly reduced; the test reduces with bn_mod before comparing.",
    "divide_base_cases": "x / 2**29 % prime, computed as (x + m*prime) >> 29 with m the documented "
                      "multiple that makes the sum divisible.",
    "power_mod_cases": "x**e % prime, partly reduced; the test reduces with bn_mod before comparing.",
    "sqrt_cases": "x**((prime+1)/4) % prime for a square x, fully reduced.",
    "inverse_cases": "1/x % prime, fully reduced; zero stays zero, as the file states.",
    "cnegate_cases": "x negated modulo prime: 2*prime - x when the condition (k) is set, prime + x "
                  "when it is, after a reduction of x. Partly reduced either way.",
    "div_cases": "q = x / d and r = x % d for d up to 61303, exact.",
}


# --- Ethereum -----------------------------------------------------------------------------
#
# An RLP encoder and the four signing-preimage shapes, both written here from the specs, so the
# parser is checked against something that shares no code with it. The encoder is first required to
# reproduce EIP-155's published example transaction byte for byte; nothing else in this section is
# trusted until that has passed.

def eth_be(n: int) -> bytes:
    return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_header(n: int, base: int) -> bytes:
    if n < 56:
        return bytes([base + n])
    length = eth_be(n)
    return bytes([base + 55 + len(length)]) + length


def rlp_item(item) -> bytes:
    """RLP as defined in the Ethereum simple summary: strings below 56 bytes carry their length in
    the first byte, longer ones prefix it; a list is the concatenation of its encodings."""
    if isinstance(item, int):
        item = eth_be(item)
    elif isinstance(item, str):
        item = item.encode()
    if isinstance(item, list):
        body = b"".join(rlp_item(i) for i in item)
        return rlp_header(len(body), 0xC0) + body
    if len(item) == 1 and item[0] < 0x80:
        return item  # a single byte below 0x80 is its own encoding
    return rlp_header(len(item), 0x80) + item


def eth_keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak

    return keccak.new(digest_bits=256, data=data).digest()


def eip155_example() -> dict:
    """The example transaction EIP-155 publishes: fields, signing data, signing hash, v/r/s and the
    signed encoding, all read out of the spec text rather than transcribed here."""
    text = fetch("eip-155.md")
    blocks = re.findall(r"```\n(.*?)```", text, re.S)
    signing_data = signed_tx = None
    signing_hash = None
    vrs = None
    for block in blocks:
        body = block.strip()
        if not re.fullmatch(r"0x[0-9a-f]+", body):
            if body.startswith("("):
                vrs = tuple(int(x) for x in re.findall(r"\d+", body))
            continue
        if len(body) == 66:
            signing_hash = bytes.fromhex(body[2:])
            continue
        raw = bytes.fromhex(body[2:])
        if raw[0] == 0xEC:
            signing_data = raw
        elif raw[0] >= 0xC0:
            signed_tx = raw
    assert signing_data and signed_tx and signing_hash and vrs, "EIP-155 example not found in spec"
    nonce, gas_price, start_gas = 9, 20 * 10**9, 21000
    to = bytes.fromhex("3535353535353535353535353535353535353535")
    value, chain_id = 10**18, 1
    v, r, s = vrs
    assert v == chain_id * 2 + 35, "example is not EIP-155 bound"
    unsigned = rlp_item([nonce, gas_price, start_gas, to, value, b"", chain_id, 0, 0])
    assert unsigned == signing_data, "encoder disagrees with EIP-155 signing data"
    assert eth_keccak(unsigned) == signing_hash, "keccak disagrees with EIP-155 signing hash"
    full = rlp_item([nonce, gas_price, start_gas, to, value, b"", v, r, s])
    assert full == signed_tx, "encoder disagrees with EIP-155 signed transaction"
    return dict(raw=signed_tx, sign_data=unsigned, nonce=nonce, gas_price=gas_price,
                start_gas=start_gas, to=to, value=value, data=b"", v=v, r=r, s=s,
                sign_hash=signing_hash, chain_id=chain_id)


def eth_signed_hash(tx_type: int, fields: list) -> bytes:
    """The preimage whose hash the parser accumulates: the unsigned payload, type prefixed for the
    typed transactions (EIP-2718), unsigned trailing v/r/s dropped."""
    body = rlp_item(fields)
    return eth_keccak(bytes([tx_type]) + body if tx_type else body)


def eth_row(name, raw, sign_hash, chain_id, gasprice, startgas, value, to, data, v):
    """`fields` are the numbers as written on the wire; the parser lays a field's bytes at the start
    of a 32 byte array and records how many, and right-aligns a destination in 20."""
    def field(n):
        b = eth_be(n)
        assert len(b) <= 32, f"{name}: field wider than 32 bytes"
        return b

    gasprice_b, startgas_b, value_b = field(gasprice), field(startgas), field(value)
    to_b = to if isinstance(to, bytes) else bytes.fromhex(to)
    assert len(to_b) <= 20, f"{name}: destination longer than an address"
    data_b = data if isinstance(data, bytes) else bytes.fromhex(data)
    return dict(name=name, raw=raw, sign_hash=sign_hash, chain_id=chain_id,
                gasprice=gasprice_b, startgas=startgas_b, value=value_b,
                destination=to_b.rjust(20, b"\0"), data=data_b, v=v)


def ethereum_tx_cases() -> list:
    """The bytes a host sends to be signed: for a legacy transaction the EIP-155 signing preimage
    (nine elements, chain id in the seventh slot), for a typed one the type byte followed by the
    unsigned field list, with no trailing signature."""
    rows = []
    rng = random.Random(0xE74)

    spec = eip155_example()
    rows.append(eth_row("eip155 spec example, chain 1", spec["sign_data"], spec["sign_hash"], 1,
                        spec["gas_price"], spec["start_gas"], spec["value"], spec["to"], b"", 1))

    for chain_id in (1, 137, 10, 2**30 - 1):
        nonce = 0x1F if chain_id != 1 else 0
        gas_price, start_gas = 30 * 10**9, 52000
        value = 12345678901234567890 if chain_id != 1 else 0
        to = bytes.fromhex("dEaDAdeadbeEf00dC0FFee1234567890aBCdef12")
        data = b"\x09\xea\xed\x75" + bytes(rng.randrange(256) for _ in range(68))
        fields = [nonce, gas_price, start_gas, to, value, data, chain_id, 0, 0]
        preimage = rlp_item(fields)
        rows.append(eth_row(f"legacy chain {chain_id}", preimage, eth_keccak(preimage), chain_id,
                            gas_price, start_gas, value, to, data, chain_id))

    # Contract creation: an empty destination is legal and leaves all twenty bytes zero.
    init = bytes.fromhex("6060604052") + bytes(rng.randrange(256) for _ in range(120))
    fields = [1, 10**9, 3_000_000, b"", 0, init, 1, 0, 0]
    preimage = rlp_item(fields)
    rows.append(eth_row("legacy contract creation", preimage, eth_keccak(preimage), 1, 10**9,
                        3_000_000, 0, b"", init, 1))

    # Calldata long enough to span several transport chunks, and a payload whose length needs a
    # length-of-length byte of its own.
    long_call = bytes(rng.randrange(256) for _ in range(600))
    fields = [2, 10**12, 100_000, bytes.fromhex("2222222222222222222222222222222222222222"), 10**30,
              long_call, 1, 0, 0]
    preimage = rlp_item(fields)
    rows.append(eth_row("legacy long calldata", preimage, eth_keccak(preimage), 1, 10**12, 100_000,
                        10**30, bytes.fromhex("2222222222222222222222222222222222222222"),
                        long_call, 1))

    access_list = [[bytes.fromhex("0000000000000000000000000000000000000001"),
                    [eth_be(3), eth_be(7)]],
                   [bytes.fromhex("0000000000000000000000000000000000000002"), []]]

    nonce, gas_price, gas_limit, value = 5, 20 * 10**9, 21000, 7 * 10**17
    to = bytes.fromhex("1111111111111111111111111111111111111111")
    for chain_id in (1, 42161, 5000000):
        fields = [chain_id, nonce, gas_price, gas_limit, to, value, b"", []]
        rows.append(eth_row(f"eip2930 chain {chain_id}", bytes([1]) + rlp_item(fields),
                            eth_signed_hash(1, fields), chain_id, gas_price, gas_limit, value, to,
                            b"", 1))
    fields = [1, nonce, gas_price, gas_limit, to, value, b"\xde\xad", access_list]
    rows.append(eth_row("eip2930 access list", bytes([1]) + rlp_item(fields),
                        eth_signed_hash(1, fields), 1, gas_price, gas_limit, value, to,
                        b"\xde\xad", 1))

    max_priority, max_fee = 2 * 10**9, 100 * 10**9
    for chain_id in (1, 10, 8453):
        fields = [chain_id, nonce, max_priority, max_fee, gas_limit, to, value, b"", []]
        rows.append(eth_row(f"eip1559 chain {chain_id}", bytes([2]) + rlp_item(fields),
                            eth_signed_hash(2, fields), chain_id, max_fee, gas_limit, value, to,
                            b"", 1))

    # Widest fields the parser accepts, with an access list and long calldata.
    calldata = bytes(rng.randrange(256) for _ in range(600))
    max_fee_wide, gas_wide, value_wide = 2**256 - 1, 2**256 - 2, 2**256 - 1
    fields = [8453, 2**64, max_fee_wide, max_fee_wide, gas_wide, to, value_wide, calldata,
              access_list]
    rows.append(eth_row("eip1559 widest fields", bytes([2]) + rlp_item(fields),
                        eth_signed_hash(2, fields), 8453, max_fee_wide, gas_wide, value_wide, to,
                        calldata, 1))

    # EIP-7702: the authorization list is a list of lists, skipped but hashed.
    auth = [[1, bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0,
             eth_be(0x1234), eth_be(0x5678)]]
    fields = [1, nonce, max_priority, max_fee, gas_limit, to, value, b"", [], auth]
    rows.append(eth_row("eip7702 one authorization", bytes([4]) + rlp_item(fields),
                        eth_signed_hash(4, fields), 1, max_fee, gas_limit, value, to, b"", 1))
    return rows


def eth_reject_cases() -> list:
    """Inputs the parser must refuse, in the same preimage form a host would send them."""
    to = bytes.fromhex("1111111111111111111111111111111111111111")

    def legacy(to_field=to, nonce=1, gas_price=10**9, start_gas=21000, value=1, data=b"",
               chain_id=1, nine_element=True):
        fields = [nonce, gas_price, start_gas, to_field, value, data]
        if nine_element:
            fields += [chain_id, 0, 0]
        return rlp_item(fields)

    def typed(fields, tx_type=2):
        return bytes([tx_type]) + rlp_item(fields)

    out = []

    def add(name, raw):
        out.append((name, raw))

    # No chain binding in either of the two shapes it can take: the six-element list, and the
    # nine-element list whose chain id slot is empty.
    add("legacy pre EIP-155, six elements", legacy(nine_element=False))
    add("legacy with an empty chain id", legacy(chain_id=b""))

    add("legacy chain id 5 bytes", legacy(chain_id=2**32))
    add("legacy chain id that wraps v", legacy(chain_id=2**31))
    add("legacy destination 21 bytes", legacy(to_field=bytes(21)))
    add("legacy nonce 33 bytes", legacy(nonce=2**256))
    add("legacy gasprice 33 bytes", legacy(gas_price=2**256))
    add("legacy value 33 bytes", legacy(value=2**256))
    add("legacy payload is a string", rlp_item(b"hello"))

    base = [1, 1, 10**9, 10**9, 21000, to, 1, b"", []]
    add("eip1559 chain id 5 bytes", typed([2**32] + base[1:]))
    add("eip1559 chain id 33 bytes", typed([2**256 - 1] + base[1:]))
    add("eip1559 destination 21 bytes", typed(base[:5] + [bytes(21)] + base[6:]))
    add("eip1559 value 33 bytes", typed(base[:6] + [2**256] + base[7:]))
    add("eip1559 access list is not a list", typed(base[:8] + [eth_be(7)]))
    add("eip2930 chain id 5 bytes", typed([2**32] + base[1:], tx_type=1))
    add("eip7702 authorization list is not a list",
        typed(base[:8] + [[], eth_be(9)], tx_type=4))

    # A string length the file refuses outright: 0xbc needs five length bytes, above its 32 bit cap.
    add("string length above the 32 bit cap", rlp_item([1, 1, 1, b"\xbc" + b"\x00" * 4 + bytes(64)]))
    return out


def eth_array(values: bytes) -> str:
    return "{ " + ", ".join(f"0x{b:02x}" for b in values) + " }"


def ethereum_vectors() -> str:
    cases = ethereum_tx_cases()
    rejects = eth_reject_cases()

    body = ",\n".join(
        '  { "%s",\n    "%s", %u, %s, %u,\n    %s, %u, %s, %u,\n    %s, "%s", %u,\n    %s }' % (
            c["name"], c["raw"].hex(), c["chain_id"], eth_array(c["gasprice"]),
            len(c["gasprice"]), eth_array(c["startgas"]), len(c["startgas"]),
            eth_array(c["value"]), len(c["value"]), eth_array(c["destination"]),
            c["data"].hex(), len(c["data"]), eth_array(c["sign_hash"]))
        for c in cases)

    reject_body = ",\n".join('  { "%s",\n    "%s" }' % (n, raw.hex()) for n, raw in rejects)

    return """/* Generated by tests/vectors/generate.py -- do not edit.

 * reference: an RLP encoder and the EIP-2718 signing-preimage shapes written in this generator,
 * with keccak from pycryptodome. Before any other row is emitted the encoder must reproduce
 * EIP-155's published example transaction, its signing data and its signing hash, so the derived
 * rows inherit an anchor rather than trusting the encoder's own consistency.
 *
 * `hash` is what the parser must have fed to keccak when it reports the transaction done: the
 * unsigned payload, with the type byte for the typed transactions and without the trailing
 * signature. It is the bytes a signature commits to, which is why it is asserted and not merely
 * the parsed fields.
 *
 * A 256-bit field is stored left aligned in `gasprice`/`startgas`/`value` with the byte count
 * beside it, because that is where the parser puts the wire bytes; a destination is right aligned
 * in twenty, shorter addresses being padded on the left as the EVM does. A legacy transaction's
 * chain id ends up being `v` itself -- the parser records v there, not (v - 35) / 2 -- and a typed
 * one's is the chain id field. `v` is what the parser stores, which for the typed transactions is
 * the signature parity it never uses.
 */

#ifndef VECTORS_ETHEREUM_H
#define VECTORS_ETHEREUM_H

#include <stdint.h>

typedef struct {
  const char* name;
  const char* rlp_hex;        /* the transaction as the transport delivers it */
  uint32_t chain_id;
  uint8_t gasprice[32];
  unsigned int gasprice_len;
  uint8_t startgas[32];
  unsigned int startgas_len;
  uint8_t value[32];
  unsigned int value_len;
  uint8_t destination[20];
  const char* data_hex;
  unsigned int data_len;
  uint8_t hash[32];
} eth_tx_t;

static const eth_tx_t eth_tx_cases[] = {
@CASES@
};
#define ETH_TX_CASES_COUNT (sizeof(eth_tx_cases) / sizeof(eth_tx_cases[0]))

/* Transactions that must be refused. The EIP-2718 type is whatever the first byte implies, the way
 * the caller reads it: below 0x80 a typed transaction, at or above 0xc0 a legacy one. */
typedef struct {
  const char* name;
  const char* rlp_hex;
} eth_reject_t;

static const eth_reject_t eth_reject_cases[] = {
@REJECTS@
};
#define ETH_REJECT_CASES_COUNT (sizeof(eth_reject_cases) / sizeof(eth_reject_cases[0]))

#endif  /* VECTORS_ETHEREUM_H */
""".replace("@CASES@", body).replace("@REJECTS@", reject_body)

# ---------------------------------------------------------------- shamir

# The oracle here is SLIP-39's own "Sharing a secret" section, re-implemented below from the
# published formulas. shamir.c is an independent implementation of the same construction (bitsliced
# GF(2^8) rather than byte tables), so agreement between the two is a cross-check. That the C side
# is itself anchored elsewhere is worth stating: slip39.c reconstructs all of SLIP-39's published
# sets through shamir_interpolate(), so the field arithmetic already has to be right for those to
# pass -- these rows cover the paths those sets never reach.

RIDIJNDAEL = 0x11B  # x^8 + x^4 + x^3 + x + 1, named by SLIP-39 as the field polynomial


def gf_mul(a: int, b: int) -> int:
    """Carry-less multiply in GF(2)[x] reduced by the Rijndael polynomial."""
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= RIDIJNDAEL
    return out


def gf_inv(a: int) -> int:
    """Multiplicative inverse, by repeated squaring out to the group order 2^8 - 2."""
    if a == 0:
        raise ValueError("zero has no inverse")
    result, power, expo = 1, a, 254  # a^(2^8-2) is the inverse in a field of 2^8 elements
    while expo:
        if expo & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        expo >>= 1
    return result


def gf_eval(coeffs: list, x: int) -> int:
    """coeffs[0] is the constant term; Horner's rule."""
    out = 0
    for c in reversed(coeffs):
        out = gf_mul(out, x) ^ c
    return out


def slip39_interpolate(x: int, xs: list, ys: list):
    """Lagrange interpolation over GF(256), each byte of the share values a separate instance.

    Returns None when two share indices collide, which is the one input the interpolation cannot
    answer. Note that x equal to some xs[i] needs no special case in this formulation: the i-th
    basis polynomial evaluates to 1 there and to 0 for every other term.
    """
    length = len(ys[0])
    out = bytearray(length)
    for i in range(len(xs)):
        num, den = 1, 1
        for j in range(len(xs)):
            if i == j:
                continue
            num = gf_mul(num, x ^ xs[j])
            den = gf_mul(den, xs[i] ^ xs[j])
        if den == 0:
            return None
        factor = gf_mul(num, gf_inv(den))
        for k in range(length):
            out[k] ^= gf_mul(factor, ys[i][k])
    return bytes(out)


def lagrange_coefficient(i: int, xs: list, x: int) -> int:
    """The weight of share i when interpolating at x, so a change of d in share i moves the result
    by gf_mul(d, weight) -- the fact the near-miss search below is built on."""
    num, den = 1, 1
    for j in range(len(xs)):
        if i == j:
            continue
        num = gf_mul(num, x ^ xs[j])
        den = gf_mul(den, xs[i] ^ xs[j])
    return gf_mul(num, gf_inv(den))


def slip39_digest_byte_tampers(rng):
    """Four tampers, one per digest byte, in which the recovered secret is still the right secret.

    Changing byte p of every share moves the recovered secret by the Lagrange-weighted sum of the
    deltas and moves the digest share by another weighted sum. Pick deltas whose first sum is zero
    and whose second is not, and byte p of the digest share stops agreeing with the HMAC while the
    secret and R are untouched -- so the row is refused only if the comparison reaches byte p. One
    row per byte pins the comparison to the four bytes the spec asks for, without a search.
    """
    threshold, length = 3, 32
    secret = bytes(rng.randrange(256) for _ in range(length))
    shares, digest = slip39_split(threshold, threshold, secret, rng)
    xs = [x for x, _ in shares]
    ys = [y for _, y in shares]
    to_secret = [lagrange_coefficient(i, xs, 255) for i in range(threshold)]
    to_digest = [lagrange_coefficient(i, xs, 254) for i in range(threshold)]

    deltas = None
    for first in range(1, 256):
        for second in range(256):
            third = gf_mul(gf_mul(first, to_secret[0]) ^ gf_mul(second, to_secret[1]),
                           gf_inv(to_secret[2]))
            moved = gf_mul(first, to_digest[0]) ^ gf_mul(second, to_digest[1]) ^ gf_mul(third, to_digest[2])
            if moved:
                deltas, shift = [first, second, third], moved
                break
        if deltas:
            break
    assert deltas, "no delta leaves the secret alone and moves the digest"

    rows = []
    for position in range(4):
        tampered = []
        for i in range(threshold):
            value = bytearray(ys[i])
            value[position] ^= deltas[i]
            tampered.append(bytes(value))
        assert slip39_recover(threshold, xs, tampered) is None
        # The untouched parts of the check: the secret still comes out right, R is unchanged, and
        # every digest byte before `position` still matches the HMAC of it.
        recovered = slip39_interpolate(255, xs, tampered)
        moved_digest = slip39_interpolate(254, xs, tampered)
        mac = hmac.new(moved_digest[4:], recovered, hashlib.sha256).digest()
        assert recovered == secret
        assert moved_digest[4:] == digest[4:]
        assert moved_digest[:position] == mac[:position] and moved_digest[position] != mac[position]
        rows.append((threshold, xs, tampered, length, position + 1))
    return rows


def slip39_split(threshold: int, count: int, secret: bytes, rng):
    """SplitSecret() as specified: shares for indices 0..N-1, plus the digest share D.

    D is the share at index 254 that carries the integrity check; a real split never hands it out,
    but recovery vectors have to be able to say what it is.
    """
    length = len(secret)
    if threshold == 1:
        return [(i, bytes(secret)) for i in range(count)], None
    rand = bytes(rng.randrange(256) for _ in range(length - 4))
    digest = hmac.new(rand, secret, hashlib.sha256).digest()[:4] + rand
    points = {i: bytes(rng.randrange(256) for _ in range(length)) for i in range(threshold - 2)}
    points[254] = digest
    points[255] = bytes(secret)
    known_x = sorted(points)
    known_y = [points[x] for x in known_x]
    return [(i, slip39_interpolate(i, known_x, known_y)) for i in range(count)], digest


def slip39_recover(threshold: int, xs: list, ys: list):
    """RecoverSecret() as specified: the secret, or None where the spec says abort."""
    if threshold == 1:
        return ys[0]
    secret = slip39_interpolate(255, xs, ys)
    if secret is None:
        return None
    digest = slip39_interpolate(254, xs, ys)
    if digest is None:
        return None
    if hmac.new(digest[4:], secret, hashlib.sha256).digest()[:4] != digest[:4]:
        return None
    return secret


SHAMIR_OK = 0
SHAMIR_INTERP_FAILED = "SHAMIR_ERROR_INTERPOLATION_FAILURE"
SHAMIR_CHECKSUM_FAILED = "SHAMIR_ERROR_CHECKSUM_FAILURE"


def shamir_vectors() -> str:
    """Interpolation, the digest share and whole splits, against SLIP-39's published construction."""
    doc = fetch("slip39.md")
    # The four sentences everything below is built from. If one of them moves, the reading below has
    # to be re-done rather than quietly kept.
    for sentence in (
        "modulo the Rijndael irreducible polynomial",
        "the shared secret is stored as *f*(255)",
        "the first 4 bytes of HMAC-SHA256(key=*R*, msg=*S*) with the *n* &minus; 4 bytes of *R*",
        "If *T* is 1, then let *y<sub>i</sub>* = *S* for all *i*",
        "If *T* is 1, then let *S* = *y*<sub>1</sub> and return.",
    ):
        assert sentence in doc, sentence

    # The field arithmetic underneath everything, checked against the one product FIPS-197 prints:
    # { 0x53 } • { 0xca } = { 0x01 }.
    assert gf_mul(0x53, 0xCA) == 0x01 and all(gf_mul(a, gf_inv(a)) == 1 for a in range(1, 256))

    rng = random.Random(20251207)

    # Interpolation on its own, from a random polynomial: no digest and no sharing semantics, so a
    # disagreement here can only be field arithmetic or the basis polynomials.
    interp = []
    for count in (1, 2, 3, 4, 5, 8, 12, 16):
        for length in (16, 24, 32):
            # `count` points pin a polynomial of degree < count, hence count coefficients per byte.
            flat = [rng.randrange(256) for _ in range(length * count)]
            per_byte = [flat[k * count:(k + 1) * count] for k in range(length)]
            xs = rng.sample(range(1, 254), count)
            ys = [bytes(gf_eval(c, x) for c in per_byte) for x in xs]
            for result_index in (0, 1, 128, 254, 255):
                interp.append(
                    {
                        "comment": "f(%d) of a random polynomial of degree < %d, %d bytes"
                        % (result_index, count, length),
                        "result_index": result_index,
                        "xs": xs,
                        "ys": ys,
                        "expect": bytes(gf_eval(c, result_index) for c in per_byte),
                        "refuses": False,
                    }
                )

    # The value at a share's own index is that share. The formulation above needs no exception for
    # it; the bitsliced one has to special-case it, because its numerator runs over every share and
    # vanishes as soon as one index equals the result index.
    for count in (2, 3, 6):
        xs = [7, 254, 255, 0, 1, 128][:count]
        ys = [bytes(rng.randrange(256) for _ in range(16)) for _ in xs]
        for pick in range(count):
            interp.append(
                {
                    "comment": "interpolating at a share index returns that share",
                    "result_index": xs[pick],
                    "xs": xs,
                    "ys": ys,
                    "expect": ys[pick],
                    "refuses": False,
                }
            )

    for xs in ([7, 7, 30], [9, 9], [255, 20, 255, 21]):
        interp.append(
            {
                "comment": "repeated share index: the interpolation is undefined",
                "result_index": 255,
                "xs": xs,
                "ys": [bytes(rng.randrange(256) for _ in range(16)) for _ in xs],
                "expect": None,
                "refuses": False,
            }
        )

    interp.append(
        {
            "comment": "longer than SHAMIR_MAX_SECRET_SIZE is refused",
            "result_index": 255,
            "xs": [1, 2, 3],
            "ys": [bytes(33)] * 3,
            "expect": None,
            "refuses": True,
        }
    )

    # The digest share is one sentence of the spec. The HMAC underneath it is pinned to a published
    # RFC 4231 case first, so a key/message swap cannot slide through here unnoticed.
    rfc_key = bytes([0x0B] * 20)
    rfc_data = b"Hi There"
    rfc_mac = hmac.new(rfc_key, rfc_data, hashlib.sha256).hexdigest()
    assert rfc_mac == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", rfc_mac
    digests = [
        {
            "comment": "RFC 4231 case 1 key and data, first four bytes of the MAC",
            "random_data": rfc_key,
            "secret": rfc_data,
            "expect": bytes.fromhex(rfc_mac[:8]),
        }
    ]
    for rdlen, sslen in ((12, 16), (12, 24), (28, 32), (1, 16), (12, 32)):
        r = bytes(rng.randrange(256) for _ in range(rdlen))
        s = bytes(rng.randrange(256) for _ in range(sslen))
        digests.append(
            {
                "comment": "first four bytes of HMAC-SHA256(key=R(%d), msg=S(%d))" % (rdlen, sslen),
                "random_data": r,
                "secret": s,
                "expect": hmac.new(r, s, hashlib.sha256).digest()[:4],
            }
        )

    # Recovery over SplitSecret output: the thresholds and lengths SLIP-39 permits, several subsets
    # of a larger share set, and the ways a caller can be handed rubbish.
    recovers = []
    for threshold, count, length in (
        (1, 1, 16),
        (1, 5, 32),
        (2, 2, 16),
        (2, 3, 24),
        (3, 5, 16),
        (3, 5, 32),
        (4, 4, 24),
        (5, 5, 16),
        (6, 10, 32),
        (8, 8, 20),
        (12, 16, 32),
        (16, 16, 32),
    ):
        secret = bytes(rng.randrange(256) for _ in range(length))
        shares, digest = slip39_split(threshold, count, secret, rng)
        xs = [x for x, _ in shares]
        ys = [y for _, y in shares]

        if threshold == count:
            picks = [tuple(range(count))]
        else:
            picks = list(itertools.combinations(range(count), threshold))
            rng.shuffle(picks)
            picks = picks[:4]
        for pick in picks:
            chosen = [xs[i] for i in pick]
            values = [ys[i] for i in pick]
            assert slip39_recover(threshold, chosen, values) == secret
            recovers.append(
                {
                    "comment": "T=%d of N=%d, n=%d" % (threshold, count, length),
                    "threshold": threshold,
                    "xs": chosen,
                    "ys": values,
                    "expect": secret,
                    "error": SHAMIR_OK,
                    "digest_share": False,
                }
            )

        if digest is not None:
            # The integrity share is defined, not merely self-consistent: interpolating at 254 has
            # to give HMAC-SHA256(key=R, msg=S)[:4] || R for the R the split drew.
            assert digest[:4] == hmac.new(digest[4:], secret, hashlib.sha256).digest()[:4]
            recovers.append(
                {
                    "comment": "T=%d, n=%d: the share at index 254 is HMAC-SHA256(key=R, msg=S)[:4] || R"
                    % (threshold, length),
                    "threshold": threshold,
                    "xs": xs,
                    "ys": ys,
                    "expect": digest,
                    "error": SHAMIR_OK,
                    "digest_share": True,
                }
            )

        # One flipped byte in any share changes both the recovered secret and the digest share, so
        # the four digest bytes have to disagree with the HMAC of the secret that came out. T=1 is
        # the exception the spec itself makes, and it gets a row of its own below.
        for share in range(min(count, 3) if threshold > 1 else 0):
            others = [i for i in range(count) if i != share][: threshold - 1]
            chosen = [share] + others
            for position in (0, length // 2, length - 1):
                damaged = [ys[i] for i in chosen]
                damaged[0] = bytes(b ^ 0x80 if j == position else b
                                   for j, b in enumerate(damaged[0]))
                assert slip39_recover(threshold, [xs[i] for i in chosen], damaged) is None
                recovers.append(
                    {
                        "comment": "T=%d of N=%d, n=%d: share %d byte %d flipped"
                        % (threshold, count, length, share, position),
                        "threshold": threshold,
                        "xs": [xs[i] for i in chosen],
                        "ys": damaged,
                        "expect": None,
                        "error": SHAMIR_CHECKSUM_FAILED,
                        "digest_share": False,
                    }
                )

        if threshold >= 2:
            recovers.append(
                {
                    "comment": "T=%d, n=%d: repeated share index" % (threshold, length),
                    "threshold": threshold,
                    "xs": [xs[0]] * threshold,
                    "ys": ys[:threshold],
                    "expect": None,
                    "error": SHAMIR_INTERP_FAILED,
                    "digest_share": False,
                }
            )
        elif count > 1:
            # T=1 has no digest share at all by the spec's step 1, so a altered share is returned
            # rather than refused. Pinned because it is the one recovery path with no integrity
            # check, and because it follows from the published algorithm, not from the code.
            recovers.append(
                {
                    "comment": "T=1, n=%d: the single share is returned as-is, altered or not"
                    % length,
                    "threshold": 1,
                    "xs": [count - 1],
                    "ys": [ys[-1][:-1] + bytes([ys[-1][-1] ^ 0xFF])],
                    "expect": ys[-1][:-1] + bytes([ys[-1][-1] ^ 0xFF]),
                    "error": SHAMIR_OK,
                    "digest_share": False,
                }
            )

    for threshold, xs, ys, length, byte in slip39_digest_byte_tampers(rng):
        recovers.append(
            {
                "comment": "T=%d, n=%d: the secret is right, only digest byte %d disagrees -- "
                           "refused only if the check reaches byte %d"
                % (threshold, length, byte, byte),
                "threshold": threshold,
                "xs": xs,
                "ys": ys,
                "expect": None,
                "error": SHAMIR_CHECKSUM_FAILED,
                "digest_share": False,
            }
        )

    def row(comment, threshold, xs, ys, expect, error=SHAMIR_OK, digest_share=False):
        return "  {%s, %d, %s, {%s}, %s, %s, %d}" % (
            cstr(comment),
            threshold,
            cstr(hexs(bytes(xs))),
            ", ".join(cstr(hexs(y)) for y in ys),
            "NULL" if expect is None else cstr(hexs(expect)),
            error,
            1 if digest_share else 0,
        )

    interp_rows = [
        "  {%s, %d, %s, {%s}, %s, %d, %d}"
        % (
            cstr(c["comment"]),
            c["result_index"],
            cstr(hexs(bytes(c["xs"]))),
            ", ".join(cstr(hexs(y)) for y in c["ys"]),
            "NULL" if c["expect"] is None else cstr(hexs(c["expect"])),
            len(c["ys"][0]),
            1 if c["refuses"] else 0,
        )
        for c in interp
    ]
    digest_rows = [
        "  {%s, %s, %s, %s}"
        % (cstr(c["comment"]), cstr(hexs(c["random_data"])), cstr(hexs(c["secret"])),
           cstr(hexs(c["expect"])))
        for c in digests
    ]
    recover_rows = [
        row(c["comment"], c["threshold"], c["xs"], c["ys"], c["expect"], c["error"],
            c["digest_share"])
        for c in recovers
    ]

    return f"""#ifndef VECTORS_SHAMIR_H
#define VECTORS_SHAMIR_H

/* spec: {provenance('slip39.md')}
 *     {provenance('rfc4231.txt')}
 *
 * Shamir's secret sharing over GF(2^8), as SLIP-39 defines it: the field is GF(256) modulo the
 * Rijndael polynomial, the shared secret is f(255), and the share at index 254 is the first four
 * bytes of HMAC-SHA256(key=R, msg=S) followed by the random R that produced them.
 *
 * The values below are computed by a Python implementation of the spec's own formulas written
 * beside a bitsliced C one. SLIP-39's published test sets, which the SLIP-39 suite reconstructs
 * through the same interpolation, are what hold the C side to the specification; these rows reach
 * the paths those sets do not: a result index that collides with a share index, colliding share
 * indices, refused lengths, every threshold from 1 to 16, altered shares and the digest share read
 * back on its own.
 *
 * Share values and indices are hex; the count of shares is the length of `xs`.
 */
typedef struct {{
  const char* comment;
  uint8_t result_index;
  const char* xs;
  const char* ys[SHAMIR_MAX_SHARE_COUNT];
  const char* expect; /* NULL where the call must be refused */
  uint8_t length;
  /* The one refusal that is about the call rather than the mathematics: the length is beyond the
     maximum, so nothing at all is written to the caller's result buffer. */
  int refuses;
}} interpolate_case_t;

typedef struct {{
  const char* comment;
  const char* random_data;
  const char* secret;
  const char* expect;
}} digest_case_t;

typedef struct {{
  const char* comment;
  uint8_t threshold;
  const char* xs;
  const char* ys[SHAMIR_MAX_SHARE_COUNT];
  const char* expect_secret; /* NULL where recovery must fail */
  int32_t error;
  /* The row asks for the digest share at index 254 instead of the secret. */
  int digest_share;
}} recover_case_t;

static const interpolate_case_t INTERPOLATE_CASES[] = {{
{",\n".join(interp_rows)}}};

#define INTERPOLATE_CASES_COUNT (sizeof(INTERPOLATE_CASES) / sizeof(INTERPOLATE_CASES[0]))

static const digest_case_t DIGEST_CASES[] = {{
{",\n".join(digest_rows)}}};

#define DIGEST_CASES_COUNT (sizeof(DIGEST_CASES) / sizeof(DIGEST_CASES[0]))

static const recover_case_t RECOVER_CASES[] = {{
{",\n".join(recover_rows)}}};

#define RECOVER_CASES_COUNT (sizeof(RECOVER_CASES) / sizeof(RECOVER_CASES[0]))

#endif
"""



# ---------------------------------------------------------------- TLV

# tlv.c parses the bytes that come back from the secure element. Nothing bounds the buffer: every
# read takes a bare pointer, and the offset a caller walks next is taken from the length field it
# has just read, so a response that claims more than it carries reads on past the end. The vectors
# below are built from the applet's own source, because "what a genuine card sends" is the line the
# bounds must not cross: a bound that rejects one of these responses is a device that no longer
# pairs.
#
# The tag/length forms themselves are BER as X.690 defines them. Two form decisions are deliberate
# policy rather than BER: indefinite length (0x80) and a length-of-length beyond two bytes are
# refused even though they are legal BER, because the firmware cannot represent them -- and
# non-minimal long forms stay accepted, because BER allows them and the current reader does too.

APP_INFO_INSTANCE_UID_LEN = 16
APP_INFO_KEY_UID_LEN = 32
APP_INFO_PUBKEY_LEN = 65
APP_INFO_CERT_SIZE = 98


def javacard_constants(java: str) -> dict:
    """The applet's own `static final` tag and size constants, so the vectors use its numbers."""
    found = {}
    for name, value in re.findall(
        r"static final (?:byte|short|int) (\w+)\s*=\s*(?:\(byte\))?\s*([^;]+);", java
    ):
        value = value.strip()
        try:
            found[name] = int(value, 0)
        except ValueError:
            found[name] = value
    # Some constants are written as expressions over other constants, capabilities in particular.
    for _ in range(4):
        for name, value in list(found.items()):
            if not isinstance(value, str):
                continue
            expr = value.replace("(byte)", "").replace("(short)", "")
            for other, other_value in found.items():
                if isinstance(other_value, int):
                    expr = re.sub(r"\b%s\b" % other, str(other_value), expr)
            if re.fullmatch(r"[\d\s|&+*/()-]+", re.sub(r"0x[0-9a-fA-F]+", "0", expr)):
                found[name] = int(eval(expr))
    return {name: value for name, value in found.items() if isinstance(value, int)}


def applet_write_sequence(java: str, method: str) -> list:
    """Every `apduBuffer[off++] = ...` between `method` (a definition fragment, so the
    dispatch that merely calls it is not mistaken for it) and the end of its body.

    This is the response layout as the card writes it, before anyone interprets it.
    """
    start = java.index(method)
    body = java[start:java.index("\n  }", start)]
    return re.findall(r"apduBuffer\[off\+\+\] = ([^;]+);", body)


def tlv_length_bytes(length: int, long_form: bool) -> bytes:
    """The two forms the applet actually emits: short form, or 0x81 followed by one byte."""
    if not long_form:
        assert length <= 0x7F, length
        return bytes([length])
    assert length <= 0xFF, length
    return bytes([0x81, length])


def tlv(tag: int, value: bytes, long_form: bool = False) -> bytes:
    return bytes([tag]) + tlv_length_bytes(len(value), long_form) + value


def tlv_field(tag: int, value: bytes, long_form: bool = False):
    """The encoding plus the offset of its tag byte, so the length byte is the one after it.

    Only short-form fields are ever mutated, which is what makes that true.
    """
    encoded = tlv(tag, value, long_form)
    assert len(encoded) == 2 + len(value), "mutating a long-form field needs a different offset"
    return encoded, 0


def info_response_v4(constants: dict, initialized: bool, rng) -> tuple:
    """The GET APPLICATION INFO response of the 4.x applet, field for field."""
    version = constants["APPLICATION_VERSION"]
    app_status = 0x10 | 3  # APP_STATUS_INITIALIZED plus three PIN tries left
    if rng.random() < 0.5:
        app_status |= 0x20  # LEE mode
    capabilities = constants["APPLICATION_CAPABILITIES"] & 0xFF
    cert = bytes(rng.randrange(256) for _ in range(constants["CERT_LEN"]))
    key_uid = bytes(rng.randrange(256) for _ in range(constants["KEY_UID_LENGTH"]))
    parts = [
        ("appVersion", tlv_field(constants["TLV_INT"], version.to_bytes(2, "big")), 2),
        ("appStatus", tlv_field(constants["TLV_STATUS"], bytes([app_status])), 1),
        ("keyUID", tlv_field(constants["TLV_KEY_UID"], key_uid if initialized else b""), None),
        ("capabilities", tlv_field(constants["TLV_CAPABILITIES"], bytes([capabilities])), 1),
        ("certData", tlv_field(constants["TLV_CERT"], cert), 98),
    ]
    inner = b"".join(part[1][0] for part in parts)
    fields = []
    at = 0
    for name, (encoded, offset), want in parts:
        fields.append((name, at + offset, want))
        at += len(encoded)
    # The applet reserves a byte for the length and writes 0x81 ahead of it when the content will
    # not fit the short form; one marker, then the length byte.
    response = (
        bytes([constants["TLV_APPLICATION_INFO_TEMPLATE"]])
        + tlv_length_bytes(len(inner), len(inner) > 0x7F)
        + inner
    )
    header = len(response) - len(inner)
    fields = [(name, off + header, want) for name, off, want in fields]
    # The parser derives the status from the INITIALIZED bit and the key UID length together, and a
    # card with a PIN but no key yet sets the first without the second.
    if not app_status & 0x10:
        status = 0
    elif initialized:
        status = 2
    else:
        status = 1
    return response, fields, {
        "version": version,
        "status": status,
        "capabilities": capabilities,
        "key_uid": key_uid if initialized else b"",
        "primary": cert,
        "secondary": None,
        "free_pairing": -1,
        "app_status": app_status,
    }


def info_response_v3(constants: dict, uid_len: int, initialized: bool, rng) -> tuple:
    """The 3.2 applet's response: instance UID first, then the secure channel public key."""
    version = constants["APPLICATION_VERSION"]
    uid = bytes(rng.randrange(256) for _ in range(uid_len))
    sc_key = bytes(rng.randrange(256) for _ in range(APP_INFO_PUBKEY_LEN))  # uncompressed point
    free_pairing = rng.randrange(30)
    capabilities = constants["APPLICATION_CAPABILITIES"] & 0xFF
    key_uid = bytes(rng.randrange(256) for _ in range(constants["KEY_UID_LENGTH"]))
    parts = [
        ("instanceUID", tlv_field(constants["TLV_UID"], uid), 16),
        ("secureChannelPubKey", tlv_field(constants["TLV_PUB_KEY"], sc_key), 65),
        ("appVersion", tlv_field(constants["TLV_INT"], version.to_bytes(2, "big")), 2),
        ("freePairingSlots", tlv_field(constants["TLV_INT"], bytes([free_pairing])), 1),
        ("keyUID", tlv_field(constants["TLV_KEY_UID"], key_uid if initialized else b""), None),
        ("capabilities", tlv_field(constants["TLV_CAPABILITIES"], bytes([capabilities])), 1),
    ]
    inner = b"".join(part[1][0] for part in parts)
    fields, at = [], 0
    for name, (encoded, offset), want in parts:
        fields.append((name, at + offset, want))
        at += len(encoded)
    response = (
        bytes([constants["TLV_APPLICATION_INFO_TEMPLATE"]])
        + tlv_length_bytes(len(inner), len(inner) > 0x7F)
        + inner
    )
    header = len(response) - len(inner)
    fields = [(name, off + header, want) for name, off, want in fields]
    # A v3 response carries no status byte, so the key UID length is all the parser has: absent
    # means initialised without keys, which is what app_info_parse_v3 answers and what keycard.c's
    # three-way switch handles.
    return response, fields, {
        "version": version,
        "status": 2 if initialized else 1,
        "capabilities": capabilities,
        "key_uid": key_uid if initialized else b"",
        "primary": sc_key,
        "secondary": uid,
        "free_pairing": free_pairing,
        "app_status": -1,
    }


def status_response(constants: dict, pin_tries: int, puk_tries: int, has_key: bool) -> tuple:
    """GET STATUS: the 0xA3 template the applet writes, with its fixed length of 9."""
    body = (
        tlv(constants["TLV_INT"], bytes([pin_tries]))
        + tlv(constants["TLV_INT"], bytes([puk_tries]))
        + tlv(constants["TLV_BOOL"], bytes([0xFF if has_key else 0x00]))
    )
    response = bytes([constants["TLV_APPLICATION_STATUS_TEMPLATE"], len(body)]) + body
    return response, {"pin_retries": pin_tries, "puk_retries": puk_tries, "has_key": 0xFF if has_key else 0x00}


def tlv_vectors() -> str:
    """TLV header forms per X.690, primitive reads, and application info parsed from the applet's bytes."""
    applet4 = fetch("keycard_applet_4.java")
    applet3 = fetch("keycard_applet_3.java")
    ident = fetch("keycard_ident.java")
    shared = fetch("keycard_shared_memory.java")

    c4 = javacard_constants(applet4)
    c3 = javacard_constants(applet3)
    c4.update(javacard_constants(shared))
    c4["TLV_CERT"] = javacard_constants(ident)["TLV_CERT"]
    c3["CERT_LEN"] = javacard_constants(shared)["CERT_LEN"]

    # The layouts below are the applet's, not a guess at it: the sequence of bytes it writes is read
    # out of the source and compared to the sequence the vectors encode.
    writes4 = applet_write_sequence(applet4, "void selectApplet(")
    assert writes4[:1] == ["TLV_APPLICATION_INFO_TEMPLATE"], writes4
    for tag in ("TLV_INT", "TLV_STATUS", "TLV_KEY_UID", "TLV_CAPABILITIES", "IdentApplet.TLV_CERT"):
        assert tag in writes4, writes4
    writes3 = applet_write_sequence(applet3, "void selectApplet(")
    for tag in ("TLV_UID", "TLV_PUB_KEY", "TLV_INT", "TLV_KEY_UID"):
        assert tag in writes3, writes3
    assert c4["CERT_LEN"] == APP_INFO_CERT_SIZE, c4["CERT_LEN"]
    assert c4["KEY_UID_LENGTH"] == APP_INFO_KEY_UID_LEN
    assert c3["UID_LENGTH"] == APP_INFO_INSTANCE_UID_LEN

    rng = random.Random(20240311)

    # ---- header forms, read in isolation (every row long enough that no read runs off) ----
    filler = "00" * 8
    headers = [
        ("primitive, empty value", "0500" + filler, 0x05, 1, 0, 1),
        ("primitive, short form", "0405" + filler, 0x04, 1, 5, 1),
        ("short form reaches 127", "047f" + "00" * 127, 0x04, 1, 0x7F, 1),
        ("0x81 introduces one length byte", "048180" + "00" * 128, 0x04, 1, 0x80, 2),
        ("0x82 introduces two length bytes", "04820100" + "00" * 256, 0x04, 1, 0x100, 3),
        # X.690 permits these; the reader does not have to care, and rejecting them would be a
        # change the card could trip over, so they are accepted.
        ("non-minimal 0x81 form stays accepted", "048105" + filler, 0x04, 1, 5, 2),
        ("non-minimal 0x82 form stays accepted", "04820005" + filler, 0x04, 1, 5, 3),
        ("two-byte tag whose second byte ends it", "1f08" + "02" + filler, 0x1F08, 2, 2, 1),
        # A size of 0 below means the read is refused and the cursor does not move. Tag numbers
        # beyond two octets, indefinite lengths and lengths beyond two octets are all refused: not
        # used by Keycard, and accepting them costs the reader the alignment of everything after.
        ("two-byte tag whose second byte continues it", "1f88" + "03" + filler, 0, 0, 0, 0),
        ("three-byte tag", "1f9f08" + "02" + filler, 0, 0, 0, 0),
        ("indefinite length 0x80", "0480" + filler, 0x04, 1, 0, 0),
        ("length-of-length 3", "0483010203" + filler, 0x04, 1, 0, 0),
        ("length-of-length 15", "048f0102030405" + filler, 0x04, 1, 0, 0),
        # Headers that run past the response.
        ("tag byte alone", "04", 0x04, 1, 0, 0),
        ("0x81 with no length byte after it", "0481", 0x04, 1, 0, 0),
        ("0x82 with one of two length bytes", "048201", 0x04, 1, 0, 0),
        ("two-byte tag cut after its first byte", "1f", 0, 0, 0, 0),
        ("empty response", "", 0, 0, 0, 0),
    ]

    # ---- primitive reads ----
    reads = [
        ("value of the expected length", 0x80, 65, tlv(0x80, bytes(range(65))), 65, 65),
        # A primitive read asks for at most; a short value is fine. Insisting on an exact length is
        # the fixed variant's job, and it gets its own table below.
        ("a primitive is content with fewer bytes than the maximum", 0x80, 65, tlv(0x80, bytes(64)), 64, 64),
        ("value longer than the caller's max is refused", 0x80, 4, tlv(0x80, bytes(5)), None, 0),
        ("a different tag is refused", 0x80, 4, tlv(0x81, bytes(4)), None, 0),
        ("empty value against a max of zero", 0x8E, 0, tlv(0x8E, b""), 0, 0),
        ("long form value within max", 0x8A, 98, tlv(0x8A, bytes(range(98)), long_form=True), 98, 98),
        ("value shorter than its own length", 0x80, 65, tlv(0x80, bytes(65))[:-3], None, 0),
        ("empty value shorter than its own length", 0x80, 65, bytes([0x80, 0x05]), None, 0),
        ("tag alone", 0x80, 65, bytes([0x80]), None, 0),
        ("empty response", 0x80, 65, b"", None, 0),
        ("indefinite length", 0x80, 65, bytes([0x80, 0x80]), None, 0),
    ]

    fixed = [
        ("value of exactly the expected length", 0x80, 65, tlv(0x80, bytes(range(65))), True),
        ("fewer bytes than expected is refused", 0x80, 65, tlv(0x80, bytes(64)), False),
        ("more bytes than expected is refused", 0x80, 5, tlv(0x80, bytes(6)), False),
        ("a different tag is refused", 0x80, 4, tlv(0x81, bytes(4)), False),
        ("nothing expected, nothing given", 0x8E, 0, tlv(0x8E, b""), True),
        ("long form header at the exact length", 0x8A, 98, tlv(0x8A, bytes(range(98)), long_form=True), True),
        ("value shorter than its own length", 0x8A, 98, tlv(0x8A, bytes(98))[:-1], False),
        ("tag alone", 0x8A, 98, bytes([0x8A]), False),
        ("empty response", 0x8A, 98, b"", False),
    ]

    info_rows = []
    for label, constants, long_v3 in (("v4", c4, False), ("v3", c3, False)):
        for initialized in (True, False):
            if label == "v4":
                response, fields, expect = info_response_v4(constants, initialized, rng)
            else:
                response, fields, expect = info_response_v3(constants, constants["UID_LENGTH"],
                                                            initialized, rng)
            info_rows.append(
                {
                    "comment": "%s application info, %s key UID, %d byte template"
                    % (label, "with" if initialized else "without", len(response)),
                    "response": response,
                    "ok": 1,
                    "fields": fields,
                    **expect,
                }
            )

    # Every refusal in application_info.c, provoked in bounds: one field at a time given a
    # different tag or a length that is not the one expected, with trailing bytes so an inflated
    # length reads padding rather than past the buffer. A bounds change has to keep refusing all of
    # these and must not start refusing the genuine rows above.
    tail = bytes(32)
    for base in list(info_rows):
        if not base["ok"] or not base.get("fields"):
            continue
        response, fields = base["response"], base["fields"]
        for name, off, want in fields:
            mutated = bytearray(response)
            mutated[off] ^= 0x40
            info_rows.append({**base, "comment": "%s: %s carries a different tag"
                              % (base["comment"], name), "response": bytes(mutated) + tail,
                              "ok": 0, "fields": None})
            if want is None:
                # The key UID is a primitive read: only a value larger than the field is refused.
                mutated = bytearray(response)
                mutated[off + 1] = APP_INFO_KEY_UID_LEN + 1
                info_rows.append({**base, "comment": "%s: key UID longer than the field"
                                  % base["comment"], "response": bytes(mutated) + tail,
                                  "ok": 0, "fields": None})
                continue
            for delta, label in ((1, "one byte longer"), (0xFF, "one byte shorter")):
                mutated = bytearray(response)
                mutated[off + 1] = (mutated[off + 1] + delta) & 0xFF
                info_rows.append({**base, "comment": "%s: %s is %s than expected"
                                  % (base["comment"], name, label),
                                  "response": bytes(mutated) + tail, "ok": 0, "fields": None})

    # A v4 card that has no PIN yet sets neither status bit, which is the one path answering
    # NOT_INITIALIZED rather than reading the state off the key UID length.
    for base in list(info_rows):
        if base["ok"] and base["app_status"] >= 0x10 and base["status"] == 2:
            status_at = next(off + 2 for name, off, _ in base["fields"] if name == "appStatus")
            mutated = bytearray(base["response"])
            mutated[status_at] = 0x03
            info_rows.append({**base, "comment": "%s: appStatus without the INITIALIZED bit"
                              % base["comment"], "response": bytes(mutated), "status": 0,
                              "app_status": 0x03, "fields": None})
            break

    sc_key = bytes(rng.randrange(256) for _ in range(APP_INFO_PUBKEY_LEN))
    info_rows.append(
        {
            "comment": "uninitialised card answers with a bare public key",
            "response": tlv(c4["TLV_PUB_KEY"], sc_key),
            "ok": 1,
            "version": 0,
            "status": 0,
            # A bare public key reply carries no capabilities, and the parser leaves the field as it
            # found it: 0xFFFF says "not answered", which the test checks rather than a value.
            "capabilities": 0xFFFF,
            "key_uid": b"",
            "primary": sc_key,
            "secondary": None,
            "free_pairing": -1,
            "app_status": -1,
        }
    )

    v4_response = info_response_v4(c4, True, rng)[0]
    # Only a refusal the current reader reaches without walking off the end can live in this table;
    for response, comment in (
        (bytes([0xA5]) + v4_response[1:], "template tag is not 0xA4"),
    ):
        info_rows.append(
            {
                "comment": comment,
                "response": response,
                "ok": 0,
                "version": 0,
                "status": 0,
                "capabilities": 0,
                "key_uid": b"",
                "primary": None,
                "secondary": None,
                "free_pairing": -1,
                "app_status": -1,
            }
        )

    # The template tag is checked, and so is which version the first inner tag announces; both are
    # refusals that fit inside a short buffer.
    info_rows.append({**info_rows[0], "comment": "template announces neither v3 nor v4",
                      "response": bytes([0xA4, 0x03, 0x90, 0x00, 0x00]) + tail, "ok": 0,
                      "fields": None})

    for length, label in ((APP_INFO_PUBKEY_LEN - 1, "short"), (APP_INFO_PUBKEY_LEN + 1, "long")):
        info_rows.append({**info_rows[0], "comment": "bare public key reply, %s" % label,
                          "response": bytes([0x80, length]) + sc_key[:length] + tail, "ok": 0,
                          "fields": None})

    status_rows = []
    for pin_tries, puk_tries, has_key in ((3, 5, True), (0, 10, False), (10, 10, True)):
        response, expect = status_response(c4, pin_tries, puk_tries, has_key)
        status_rows.append({"comment": "status %d/%d key=%d" % (pin_tries, puk_tries, has_key),
                            "response": response, "ok": 1, **expect})
    # A template that declares nothing inside it is well formed BER and answers nothing.
    status_rows.append({**status_rows[0], "comment": "status template holds nothing",
                        "response": bytes([0xA3, 0x00]), "ok": 0})
    status_rows.append({**status_rows[0], "comment": "status template under-declares its contents",
                        "response": bytes([0xA3, 0x06]) + status_rows[0]["response"][2:], "ok": 0})

    # The three fixed reads inside the status template, each given a different tag or a length that
    # is not one byte, with trailing bytes so an inflated length does not read past the response.
    for base in [r for r in status_rows if r["ok"]]:
        for name, at in (("pinRetries", 2), ("pukRetries", 5), ("hasKey", 8)):
            mutated = bytearray(base["response"])
            mutated[at] ^= 0x40
            status_rows.append({**base, "comment": "%s: %s carries a different tag"
                                % (base["comment"], name), "response": bytes(mutated) + tail,
                                "ok": 0})
            for delta, label in ((1, "one byte longer"), (0xFF, "one byte shorter")):
                mutated = bytearray(base["response"])
                mutated[at + 1] = (mutated[at + 1] + delta) & 0xFF
                status_rows.append({**base, "comment": "%s: %s is %s than expected"
                                    % (base["comment"], name, label),
                                    "response": bytes(mutated) + tail, "ok": 0})

    status_rows.append(
        {"comment": "wrong template tag", "response": bytes([0xA4, 0x09]) + status_rows[0]["response"][2:],
         "ok": 0, "pin_retries": 0, "puk_retries": 0, "has_key": 0}
    )

    # ---- every prefix of a genuine response, plus the length lies ----
    info_rows.append({**info_rows[0], "fields": None, "ok": 0,
                      "comment": "info template holds nothing", "response": bytes([0xA4, 0x00])})
    # A template that claims fewer bytes than its fields occupy: the fields past the declaration are
    # bytes the card never said belonged to the response, so the parse stops at the declaration and
    # comes up short.
    info_rows.append({**info_rows[0], "fields": None, "ok": 0,
                      "comment": "info template under-declares its contents",
                      "response": bytes([0xA4, 0x0A]) + v4_response[3:]})

    # Every truncation of a response a genuine card sends, and every header that lies about how
    # much follows: 355 of the 360 of these made the unbounded reader walk past the response, so
    # they are assertions now that the reads carry a bound.
    for base in [r for r in info_rows if r["ok"]]:
        for cut in range(0, len(base["response"])):
            info_rows.append({**base, "fields": None, "ok": 0,
                              "comment": "%s truncated to %d of %d"
                              % (base["comment"], cut, len(base["response"])),
                              "response": base["response"][:cut]})
    for base in [r for r in status_rows if r["ok"]]:
        for cut in range(0, len(base["response"])):
            status_rows.append({**base, "ok": 0,
                                "comment": "%s truncated to %d of %d"
                                % (base["comment"], cut, len(base["response"])),
                                "response": base["response"][:cut]})

    header_rows = [
        "  {%s, %s, 0x%04x, %d, %d, %d}"
        % (cstr(c), cstr(h), tag, tag_size, length, length_size)
        for c, h, tag, tag_size, length, length_size in headers
    ]
    read_rows = []
    for c, tag, max_len, value, out_len, _ in reads:
        if out_len is None:
            read_rows.append("  {%s, 0x%04x, %d, %s, NULL, 0, 0}" % (cstr(c), tag, max_len, cstr(hexs(value))))
        else:
            read_rows.append(
                "  {%s, 0x%04x, %d, %s, %s, %d, %d}"
                % (cstr(c), tag, max_len, cstr(hexs(value)), cstr(hexs(value[1 + (2 if value[1] > 0x7f else 1):])),
                   1 + (2 if value[1] > 0x7f else 1) + out_len, out_len)
            )

    fixed_rows = []
    for c, tag, want, value, accepted in fixed:
        if accepted:
            consumed = 1 + (2 if value[1] > 0x7F else 1) + want
            fixed_rows.append("  {%s, 0x%04x, %d, %s, %d}" % (cstr(c), tag, want, cstr(hexs(value)), consumed))
        else:
            fixed_rows.append("  {%s, 0x%04x, %d, %s, 0}" % (cstr(c), tag, want, cstr(hexs(value))))

    def info_row(r):
        return "  {%s, %s, %d, %d, %d, %d, %s, %s, %s, %d, %d}" % (
            cstr(r["comment"]), cstr(hexs(r["response"])), r["ok"], r["version"], r["status"],
            r["capabilities"], cstr(hexs(r["key_uid"])),
            "NULL" if r["primary"] is None else cstr(hexs(r["primary"])),
            "NULL" if r["secondary"] is None else cstr(hexs(r["secondary"])),
            r["free_pairing"], r["app_status"],
        )

    return f"""#ifndef VECTORS_TLV_H
#define VECTORS_TLV_H

/* spec: {provenance('keycard_applet_4.java')}
 *     {provenance('keycard_applet_3.java')}
 *     {provenance('keycard_ident.java')}
 *     {provenance('keycard_shared_memory.java')}
 *
 * The bytes a Keycard answers with, and the BER forms a reader has to make sense of. The
 * application info and status responses are assembled from the applet's own source -- its tag
 * constants, its field order, and its choice of short or 0x81 length form -- which is read while
 * generating and compared to the layout emitted here. The primitives' cases follow X.690.
 *
 * Two forms are refused as policy rather than because BER forbids them: indefinite length (0x80)
 * and a length-of-length above 2, neither of which the firmware can represent. Non-minimal long
 * forms stay accepted, as BER allows.
 *
 * The PROBE rows are for the over-read harness, which runs each one in its own process so the
 * sanitizer can answer where the reader stops.
 */
typedef struct {{
  const char* comment;
  const char* hex;
  uint16_t tag;
  uint16_t tag_size;
  uint16_t length;
  uint16_t length_size;
}} tlv_header_case_t;

typedef struct {{
  const char* comment;
  uint16_t tag;
  uint16_t max_len;
  const char* hex;
  const char* out;      /* NULL when the read must be refused */
  uint16_t consumed;
  uint16_t out_len;
}} tlv_read_case_t;

typedef struct {{
  const char* comment;
  const char* response;
  int ok;
  uint16_t version;
  int status;
  uint16_t capabilities;
  const char* key_uid;
  const char* primary;   /* secure channel key (v3, bare) or certificate (v4) */
  const char* secondary; /* instance UID (v3) */
  int free_pairing;      /* v3 only, -1 otherwise */
  int app_status;        /* v4 only, -1 otherwise */
}} app_info_case_t;

typedef struct {{
  const char* comment;
  const char* response;
  int ok;
  uint8_t pin_retries;
  uint8_t puk_retries;
  uint8_t has_key;
}} app_status_case_t;

static const tlv_header_case_t TLV_HEADER_CASES[] = {{
{",\n".join(header_rows)}}};

#define TLV_HEADER_CASES_COUNT (sizeof(TLV_HEADER_CASES) / sizeof(TLV_HEADER_CASES[0]))

static const tlv_read_case_t TLV_READ_CASES[] = {{
{",\n".join(read_rows)}}};

#define TLV_READ_CASES_COUNT (sizeof(TLV_READ_CASES) / sizeof(TLV_READ_CASES[0]))

typedef struct {{
  const char* comment;
  uint16_t tag;
  uint16_t want_len;
  const char* hex;
  uint16_t consumed; /* TLV_INVALID when the read must be refused */
}} tlv_fixed_case_t;

static const tlv_fixed_case_t TLV_FIXED_CASES[] = {{
{",\n".join(fixed_rows)}}};

#define TLV_FIXED_CASES_COUNT (sizeof(TLV_FIXED_CASES) / sizeof(TLV_FIXED_CASES[0]))

static const app_info_case_t APP_INFO_CASES[] = {{
{",\n".join(info_row(r) for r in info_rows)}}};

#define APP_INFO_CASES_COUNT (sizeof(APP_INFO_CASES) / sizeof(APP_INFO_CASES[0]))

static const app_status_case_t APP_STATUS_CASES[] = {{
{",\n".join("  {%s, %s, %d, %d, %d, %d}" % (cstr(r["comment"]), cstr(hexs(r["response"])), r["ok"],
      r["pin_retries"], r["puk_retries"], r["has_key"]) for r in status_rows)}}};

#define APP_STATUS_CASES_COUNT (sizeof(APP_STATUS_CASES) / sizeof(APP_STATUS_CASES[0]))

#endif
"""



def der_model(der: bytes):
    """What ecdsa_sig_from_der has to answer, stated from X.690 and not from the C: a SEQUENCE of
    exactly two INTEGERs in the minimal length form, each at most 32 bytes once the octet that marks
    a positive value is skipped, and nothing trailing in the sequence. The firmware's one deliberate
    departure from DER is written in here too -- it removes a single leading zero, so an INTEGER
    padded with more than one is still read as the same number.

    Returns (accepted, 64-byte r||s).
    """
    if len(der) < 2 or der[0] != 0x30 or der[1] > 0x7F:
        return False, None
    end = 2 + der[1]
    if end > len(der):
        return False, None
    out = bytearray(64)
    pos = 2
    for i in (0, 1):
        if end < pos + 2 or der[pos] != 0x02 or der[pos + 1] > 0x7F:
            return False, None
        length = der[pos + 1]
        pos += 2
        if pos + length > end:
            return False, None
        if length and der[pos] == 0:
            pos += 1
            length -= 1
        if length > 32:
            return False, None
        out[32 * (i + 1) - length:32 * (i + 1)] = der[pos:pos + length]
        pos += length
    if pos != end:
        return False, None
    return True, bytes(out)


def der_int(value: bytes) -> bytes:
    stripped = value.lstrip(b"\x00") or b"\x00"
    if stripped[0] & 0x80:
        stripped = b"\x00" + stripped
    return bytes([0x02, len(stripped)]) + stripped


def der_seq(body: bytes) -> bytes:
    assert len(body) <= 0x7F
    return bytes([0x30, len(body)]) + body


class Asn1Sig(asn1_core.Sequence):
    _fields = [("r", asn1_core.Integer), ("s", asn1_core.Integer)]


def asn1_values(der: bytes):
    """asn1crypto's strict DER read, as a second opinion on the encodings it accepts at all."""
    try:
        parsed = Asn1Sig.load(der, strict=True)
        r, s = parsed["r"].native, parsed["s"].native
        if not 0 <= r < 2**256 or not 0 <= s < 2**256:
            return None
        return r, s
    except Exception:
        return None


def ecdsa_der_vectors() -> str:
    rng = random.Random(20250311)
    rows = []

    def add(comment: str, value: bytes) -> None:
        rows.append((comment, bytes(value)))

    valid = [(bytes(rng.randrange(256) for _ in range(32)), bytes(rng.randrange(256) for _ in range(32)))
             for _ in range(3)]
    # The padding rules live at the edges: a value that needs the sign octet, one that does not, one
    # that is all zeros, and one whose leading zero the encoder has to add twice over.
    valid += [
        (b"\x00" * 31 + b"\x01", b"\x00" * 31 + b"\x7f"),
        (b"\x00" * 30 + b"\x80\x00", b"\xff" * 32),
        (b"\x00" * 32, b"\x00" * 31 + b"\x05"),
        (b"\x00" * 31 + b"\x80", b"\x00" * 3 + b"\xde\xad\xbe\xef"),
    ]

    for index, (r, s) in enumerate(valid):
        base = der_seq(der_int(r) + der_int(s))
        add("signature %d" % index, base)
        for cut in range(0, len(base)):
            add("signature %d truncated to %d of %d" % (index, cut, len(base)), base[:cut])
        if index < 3:
            for at in range(len(base)):
                for delta, label in ((1, "up"), (-1, "down")):
                    mutated = bytearray(base)
                    mutated[at] = (mutated[at] + delta) & 0xFF
                    add("signature %d byte %d shifted %s" % (index, at, label), mutated)
            # The header bytes of each INTEGER, wherever the signature is long.
            else_ = 2 + len(der_int(r))
            for at in (2, 3, else_, else_ + 1):
                mutated = bytearray(base)
                mutated[at] ^= 0x40
                add("signature %d byte %d flipped" % (index, at), mutated)

    wide = der_seq(der_int(b"\x00" * 31 + b"\x01") + der_int(b"\xff" * 32))
    for comment, value in (
        ("long form sequence length", bytes([0x30, 0x81, len(wide) - 2]) + wide[2:]),
        ("long form integer length", bytes([0x30, 0x07, 0x02, 0x81, 0x01, 0x05, 0x02, 0x01, 0x05])),
        ("sequence with nothing in it", bytes([0x30, 0x00])),
        ("one integer, not two", bytes([0x30, 0x03, 0x02, 0x01, 0x05])),
        ("three integers", bytes([0x30, 0x09, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07])),
        ("octet trailing the two integers", bytes([0x30, 0x07, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x00])),
        ("octet after the sequence", wide + b"\x99"),
        ("integers with no content", bytes([0x30, 0x04, 0x02, 0x00, 0x02, 0x00])),
        ("integer padded with a sign octet", bytes([0x30, 0x27, 0x02, 0x21, 0x00] + [0x80] * 32 +
                                                   [0x02, 0x01, 0x05])),
        ("integer padded past the sign octet", bytes([0x30, 0x27, 0x02, 0x21, 0x00, 0x00] +
                                                     [0x80] * 31 + [0x02, 0x01, 0x05])),
        ("integer that needs no padding but has it", bytes([0x30, 0x06, 0x02, 0x02, 0x00, 0x05,
                                                            0x02, 0x01, 0x05])),
        ("integer of 33 bytes after its padding", bytes([0x30, 0x26, 0x02, 0x22, 0x00] + [0x80] * 33 +
                                                       [0x02, 0x01, 0x05])),
        ("sequence length short of its contents", bytes([0x30, 0x04, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06,
                                                         0x99, 0x99])),
        ("sequence length past the buffer", bytes([0x30, 0x08, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06])),
        ("sequence length one past the buffer", bytes([0x30, 0x07, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06])),
        ("sequence tag with the class bits changed", bytes([0x31, 0x05, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06])),
        ("integer tag replaced", bytes([0x30, 0x05, 0x03, 0x01, 0x05, 0x02, 0x01, 0x06])),
        ("nothing at all", b""),
        ("one byte", b"\x30"),
    ):
        add(comment, value)

    for i in range(150):
        add("random bytes %d" % i, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40))))

    accepted = 0
    for comment, value in rows:
        ok, sig = der_model(value)
        accepted += 1 if ok else 0
        if ok:
            strict = asn1_values(value)
            if strict is not None:
                assert sig == strict[0].to_bytes(32, "big") + strict[1].to_bytes(32, "big"), comment
    for r, s in valid:
        assert der_model(der_seq(der_int(r) + der_int(s)))[0], "a valid signature was refused"

    c_rows = []
    for comment, value in rows:
        ok, sig = der_model(value)
        c_rows.append("  {%s, %s, %d, %s}"
                      % (cstr(comment), cstr(hexs(value)), 1 if ok else 0,
                         cstr(hexs(sig)) if ok else "NULL"))

    return """#ifndef VECTORS_ECDSA_DER_H
#define VECTORS_ECDSA_DER_H

/* DER signatures: %d rows, %d of them the encodings that parse. Expectations come from der_model()
 * in generate.py, stated from X.690, and every row that asn1crypto's strict DER reader also accepts
 * is checked against it during generation. */

typedef struct {
  const char* comment;
  const char* hex;
  int ok;
  const char* sig;      /* the 64 bytes of r||s, NULL when the encoding must be refused */
} der_case_t;

static const der_case_t DER_CASES[] = {
%s};

#define DER_CASES_COUNT (sizeof(DER_CASES) / sizeof(DER_CASES[0]))

#endif
""" % (len(rows), accepted, ",\n".join(c_rows))




# ---------------------------------------------------------------- sign reply
SIGN_ECDSA = 0
SIGN_SCHNORR = 3
SIGN_PUBKEY_LEN = 65
SIGN_SCHNORR_SIG_LEN = 64
SIGN_RECOVERED_SIG_LEN = 65
TLV_SIGN_TEMPLATE = 0xA0
TLV_SIGN_PUB_KEY = 0x80
TLV_SIGN_SCHNORR = 0x88


def applet_sign_writes(java: str) -> dict:
    """What the SIGN command writes into the response buffer, keyed by where it writes it."""
    start = java.index("void sign(")
    body = java[start:java.index("\n  }", start)]
    found = {}
    for offset, value in re.findall(r"apduBuffer\[((?:[^\[\]]|\[[^\]]*\])*?)\]\s*=\s*([^;]+);", body):
        found[offset.replace("(short)", "").replace(" ", "")] = value.strip()
    return found


def ber_header(data: bytes, pos: int):
    """(tag, tag_size, length, length_size) of the object at pos, per X.690 8.1.2 and 8.1.3, or None.

    Indefinite length, more than two length octets and tag numbers over two octets are refused, which
    is the reader's stated policy rather than BER's.
    """
    if pos >= len(data):
        return None
    tag, tag_size = data[pos], 1
    if (tag & 0x1F) == 0x1F:
        if pos + 1 >= len(data) or data[pos + 1] & 0x80:
            return None
        tag, tag_size = (tag << 8) | data[pos + 1], 2
    pos += tag_size
    if pos >= len(data):
        return None
    first = data[pos]
    if first == 0x80:
        return None
    if first < 0x80:
        return tag, tag_size, first, 1
    octets = first - 0x80
    if octets > 2 or pos + 1 + octets > len(data):
        return None
    return tag, tag_size, int.from_bytes(data[pos + 1:pos + 1 + octets], "big"), 1 + octets


def sign_reply_model(reply: bytes, algo: int):
    """Where the key and the signature of a SIGN reply are, derived from the layout the applet writes:
    a template that declares its contents, holding a 0x80 public key and then the signature -- bare DER
    for ECDSA, a 0x88 primitive for BIP-340.

    Returns (parsed, key_off, sig_off, sig_len), leaving everything outside the declared template
    alone, since that is what a template declaring its length means.
    """
    if algo not in (SIGN_ECDSA, SIGN_SCHNORR):
        # The reply has a shape per algorithm -- bare DER, or a 0x88 primitive -- and an algorithm
        # the card does not sign with has neither, so nothing here says where its signature is.
        return False, 0, 0, 0

    head = ber_header(reply, 0)
    if head is None:
        return False, None, 0, 0

    if (algo == SIGN_ECDSA) and (head[0] == TLV_SIGN_PUB_KEY):
        # The documented reply that needs no key: a bare 0x80 whose contents are the signature with
        # its recovery id appended. key_off None is the parse answering "no public key came".
        body = head[1] + head[3]
        if (head[2] != SIGN_RECOVERED_SIG_LEN) or (body + head[2] > len(reply)):
            return False, None, 0, 0
        return True, None, body, head[2]

    if head[0] != TLV_SIGN_TEMPLATE:
        return False, None, 0, 0
    declared, start = head[2], head[1] + head[3]
    if start + declared > len(reply):
        return False, 0, 0, 0
    end = start + declared

    key = ber_header(reply, start)
    if key is None or key[0] != TLV_SIGN_PUB_KEY or key[2] != SIGN_PUBKEY_LEN:
        return False, None, 0, 0
    key_off = start + key[1] + key[3]
    if key_off + SIGN_PUBKEY_LEN > end:
        return False, None, 0, 0

    body = key_off + SIGN_PUBKEY_LEN
    if algo == SIGN_SCHNORR:
        sig = ber_header(reply, body)
        if sig is None or sig[0] != TLV_SIGN_SCHNORR or sig[2] != SIGN_SCHNORR_SIG_LEN:
            return False, None, 0, 0
        sig_off = body + sig[1] + sig[3]
        if sig_off + SIGN_SCHNORR_SIG_LEN > end:
            return False, None, 0, 0
        return True, key_off, sig_off, SIGN_SCHNORR_SIG_LEN

    if body >= end:
        return False, None, 0, 0
    return True, key_off, body, end - body


def sign_reply(key: bytes, body: bytes, declared: int = None, template: int = TLV_SIGN_TEMPLATE) -> bytes:
    content = bytes([TLV_SIGN_PUB_KEY, len(key)]) + key + body
    if declared is None:
        declared = len(content)
    return bytes([template]) + bytes([0x81, declared]) + content



BTC_DER_MAX = 72
BTC_SIGHASH = 0x01
BTC_COMPRESSED_LEN = 33


def der_raw(length: int, value: bytes) -> bytes:
    """An INTEGER declaring `length` and holding `value`, which need not agree: the record layer has to
    cope with encodings a signer would never produce."""
    return bytes([0x02, length]) + value


def der_declared(body_len: int, body: bytes, sequence: int = 0x30) -> bytes:
    """A DER sequence declaring body_len while holding len(body): the two are what the record layer
    has to reconcile."""
    return bytes([sequence, body_len]) + body


def btc_sig_model(reply: bytes, algo: int, sighash: int):
    """What BIP-174 wants from the reply, stated from the record rather than from the C: a partial
    signature is keyed by the compressed form of the key the card named, and its value is the DER
    followed by the sighash byte. A taproot key signature names no key and its value is the 64 bytes.

    A reply that carries its own recovery id names no key, and a record keyed by nothing is not a
    record, so those are refused here whatever the reply parser made of them.

    Returns (written, key, value).
    """
    ok, key_off, sig_off, sig_len = sign_reply_model(reply, algo)
    if not ok:
        return False, None, None

    if algo == SIGN_SCHNORR:
        return True, None, reply[sig_off:sig_off + sig_len]
    if key_off is None:
        return False, None, None

    key = reply[key_off:key_off + SIGN_PUBKEY_LEN]
    der = reply[sig_off:sig_len + sig_off]
    if len(der) < 2 or der[0] != 0x30:
        return False, None, None
    der_len = der[1] + 2
    if der[1] > BTC_DER_MAX - 2 or der_len > len(der):
        return False, None, None

    compressed = bytes([0x02 | (key[64] & 1)]) + key[1:BTC_COMPRESSED_LEN]
    return True, compressed, der[:der_len] + bytes([sighash])


def btc_sig_rows(rows: list) -> list:
    """The reply corpus as the record layer sees it, plus the DER lengths it has to make sense of and
    the sighash byte it appends. Rows are (comment, reply, algo, sighash)."""
    key = bytes([0x04]) + bytes(range(1, SIGN_PUBKEY_LEN))
    widest = der_declared(70, der_raw(33, bytes(33)) + der_raw(33, bytes(33)))
    typical = der_declared(69, der_raw(33, bytes(33)) + der_raw(32, bytes(32)))
    narrow = der_declared(8, der_raw(2, b"\x05\x07") + der_raw(2, b"\x09\x0b"))

    out = [(comment, reply, algo, BTC_SIGHASH) for comment, reply, algo in rows]
    for der, label in (
        (widest, "widest legitimate DER"),
        (typical, "one integer padded, one not"),
        (narrow, "small integers"),
        (der_declared(71, der_raw(34, bytes(34)) + der_raw(33, bytes(33))),
         "DER of 73 bytes, past the cap"),
        (der_declared(74, bytes(70)), "DER declaring bytes it does not hold"),
        (der_declared(6, der_raw(2, b"\x05\x07") + der_raw(3, b"\x00\x05\x07")),
         "DER declaring less than the template holds"),
        (der_declared(1, b"\x05"), "sequence holding one byte"),
        (der_declared(6, der_raw(2, b"\x05\x07") + b"\x02\x02", sequence=0x31), "not a sequence"),
        (b"\x30", "sequence tag alone"),
        (b"", "no signature at all"),
    ):
        out.append(("BTC: %s" % label, sign_reply(key, der), SIGN_ECDSA, BTC_SIGHASH))

    for sighash in (0x00, 0x02, 0x03, 0x81, 0xFF):
        out.append(("BTC: sighash byte 0x%02x" % sighash, sign_reply(key, widest), SIGN_ECDSA, sighash))
    return out


def btc_sig_table(rows4: list) -> tuple:
    c_rows, accepted = [], 0
    for comment, reply, algo, sighash in rows4:
        if algo not in (SIGN_ECDSA, SIGN_SCHNORR):
            # The record layer fixes the algorithm by which it reads, so there is no record to expect
            # from an algorithm it is never called with. Those replies stay in the reply table, where
            # the gate is the question.
            continue
        ok, key, val = btc_sig_model(reply, algo, sighash)
        accepted += 1 if ok else 0
        c_rows.append("  {%s, %s, %d, 0x%02x, %d, %s, %s, %d}"
                      % (cstr(comment), cstr(hexs(reply)), algo, sighash, 1 if ok else 0,
                         "NULL" if not ok or key is None else cstr(hexs(key)),
                         "NULL" if not ok or val is None else cstr(hexs(val)),
                         0 if val is None else len(val)))
    return ",\n".join(c_rows), accepted

def sign_reply_vectors() -> str:
    """The reply to SIGN, laid out as the applet writes it, plus the shapes around it."""
    applet = fetch("keycard_applet_4.java")
    writes = applet_sign_writes(applet)
    assert writes["OFFSET_CDATA"] == "TLV_SIGNATURE_TEMPLATE", writes
    assert writes["(OFFSET_CDATA+3)"] == "TLV_PUB_KEY", writes
    assert writes["(OFFSET_CDATA+4)"] == "Crypto.KEY_PUB_SIZE", writes
    assert writes["(OFFSET_CDATA+1)"] == "(byte) 0x81", writes
    assert writes["(OFFSET_CDATA+2)"] == "(byte) (outLen - 3)", writes
    # The signature begins where the template header, the key's header and the key itself end, and the
    # applet states that offset instead of counting it out.
    anchor = re.search(r"SIGN_HASH_OFF\s*=\s*\(OFFSET_CDATA\s*\+\s*(\d+)\s*\+\s*Crypto\.KEY_PUB_SIZE\)",
                       applet)
    assert anchor and int(anchor.group(1)) == 3 + 2, anchor and anchor.group(0)

    constants = javacard_constants(applet)
    assert constants["TLV_SIGNATURE_TEMPLATE"] == TLV_SIGN_TEMPLATE
    assert constants["TLV_PUB_KEY"] == TLV_SIGN_PUB_KEY
    # Crypto.KEY_PUB_SIZE is the Java Card platform's uncompressed point length; the card's own secure
    # channel states the same number where it is not a platform constant.
    assert javacard_constants(fetch("keycard_scv2.java"))["PUBKEY_SIZE"] == SIGN_PUBKEY_LEN

    rng = random.Random(20250417)
    key = bytes([0x04]) + bytes(rng.randrange(256) for _ in range(SIGN_PUBKEY_LEN - 1))
    schnorr = bytes(rng.randrange(256) for _ in range(SIGN_SCHNORR_SIG_LEN))

    def signature(r: bytes, s: bytes) -> bytes:
        return der_seq(der_int(r) + der_int(s))

    ecdsa = [
        signature(bytes(rng.randrange(256) for _ in range(32)),
                  bytes(rng.randrange(256) for _ in range(32))),
        signature(b"\x00" * 31 + b"\x80", b"\xff" * 31 + b"\x01"),
        signature(b"\x00" * 30 + b"\x05\x07", b"\x00" * 31 + b"\x7f"),
    ]
    for der in ecdsa:
        assert der_model(der)[0], hexs(der)

    rows = []

    def add(comment: str, reply: bytes, algo: int) -> None:
        rows.append((comment, bytes(reply), algo))

    full = sign_reply(key, ecdsa[0])
    add("ECDSA reply, %d byte DER" % len(ecdsa[0]), full, SIGN_ECDSA)
    add("ECDSA reply, short r and s", sign_reply(key, ecdsa[2]), SIGN_ECDSA)
    add("ECDSA reply, both integers padded", sign_reply(key, ecdsa[1]), SIGN_ECDSA)
    taproot = sign_reply(key, tlv(TLV_SIGN_SCHNORR, schnorr))
    add("BIP-340 reply", taproot, SIGN_SCHNORR)

    for cut in range(len(full)):
        add("ECDSA reply truncated to %d of %d" % (cut, len(full)), full[:cut], SIGN_ECDSA)
    for cut in range(len(taproot)):
        add("BIP-340 reply truncated to %d of %d" % (cut, len(taproot)), taproot[:cut], SIGN_SCHNORR)

    for tag, label in ((0xA1, "template tag is 0xA1"), (0x80, "template tag is a bare public key"),
                       (0x30, "template tag is a DER sequence")):
        add(label, sign_reply(key, ecdsa[2], template=tag), SIGN_ECDSA)

    small = sign_reply(key, ecdsa[2])
    content = small[3:]
    for form, label in ((bytes([len(content)]), "short form template length"),
                        (bytes([0x80]), "indefinite template length 0x80"),
                        (bytes([0x82, 0x00, len(content)]), "template length introduced by 0x82"),
                        (bytes([0x83, 0x00, 0x00, len(content)]), "template length introduced by 0x83")):
        add(label, bytes([TLV_SIGN_TEMPLATE]) + form + content, SIGN_ECDSA)

    declared = len(full) - 3
    for delta, label in ((1, "one past the reply"), (2, "two past the reply"),
                         (-1, "one byte short of the DER"), (-2, "two bytes short of the DER")):
        add("template declares %s" % label,
            bytes([TLV_SIGN_TEMPLATE, 0x81, declared + delta]) + full[3:], SIGN_ECDSA)
    add("template declares the key and nothing else",
        bytes([TLV_SIGN_TEMPLATE, 0x81, 67]) + full[3:], SIGN_ECDSA)
    add("template declares less than the key",
        bytes([TLV_SIGN_TEMPLATE, 0x81, 66]) + full[3:], SIGN_ECDSA)
    add("template declares nothing", bytes([TLV_SIGN_TEMPLATE, 0x81, 0x00]), SIGN_ECDSA)

    for tag in (0x81, 0x88, 0x02):
        add("public key carries tag 0x%02x" % tag,
            bytes([TLV_SIGN_TEMPLATE, 0x81, declared, tag, 65]) + full[5:], SIGN_ECDSA)
    for length, label in ((64, "64 bytes"), (66, "66 bytes"), (0, "no bytes")):
        add("public key declares %s" % label,
            bytes([TLV_SIGN_TEMPLATE, 0x81, declared, TLV_SIGN_PUB_KEY, length]) + full[5:], SIGN_ECDSA)
    add("public key length in long form",
        bytes([TLV_SIGN_TEMPLATE, 0x81, declared + 1, TLV_SIGN_PUB_KEY, 0x81, 65]) + full[5:],
        SIGN_ECDSA)

    add("ECDSA reply read as BIP-340", full, SIGN_SCHNORR)
    add("BIP-340 reply read as ECDSA", taproot, SIGN_ECDSA)
    add("ECDSA reply read as EdDSA", full, 1)
    add("ECDSA reply read as BLS", full, 2)

    for length, label in ((63, "one byte short"), (65, "one byte long"), (0, "empty")):
        # The object declares what it holds, so the only reason left to refuse it is the length.
        body = bytes([TLV_SIGN_SCHNORR, length]) + (schnorr + b"\x99")[:length]
        add("BIP-340 signature is %s (%d bytes declared)" % (label, length),
            sign_reply(key, body), SIGN_SCHNORR)
    add("BIP-340 signature length in long form",
        sign_reply(key, bytes([TLV_SIGN_SCHNORR, 0x81, 64]) + schnorr), SIGN_SCHNORR)
    add("BIP-340 signature carries another tag", taproot[:70] + b"\x89" + taproot[71:], SIGN_SCHNORR)

    # The reply that carries its recovery id instead of a public key: 0x80, and 65 bytes of r||s||v.
    r, s_value = ecdsa[0][4:36], ecdsa[0][39:71]
    detached = bytes([TLV_SIGN_PUB_KEY, SIGN_RECOVERED_SIG_LEN]) + r + s_value + b"\x00"
    add("bare signature with its recovery id", detached, SIGN_ECDSA)
    for cut in range(len(detached)):
        add("bare signature truncated to %d of %d" % (cut, len(detached)), detached[:cut], SIGN_ECDSA)
    for recovery_id in (0, 1, 2, 3, 0xFF):
        add("bare signature, recovery id 0x%02x" % recovery_id, detached[:-1] + bytes([recovery_id]),
            SIGN_ECDSA)
    for length, label in ((SIGN_RECOVERED_SIG_LEN - 1, "one byte short"),
                          (SIGN_RECOVERED_SIG_LEN + 1, "one byte long"), (0, "empty")):
        add("bare signature declares %s" % label,
            bytes([TLV_SIGN_PUB_KEY, length]) + (r + s_value)[:length], SIGN_ECDSA)
    add("bare signature length in long form",
        bytes([TLV_SIGN_PUB_KEY, 0x81, SIGN_RECOVERED_SIG_LEN]) + detached[2:], SIGN_ECDSA)
    add("bare signature, indefinite length", bytes([TLV_SIGN_PUB_KEY, 0x80]) + detached[2:], SIGN_ECDSA)
    add("bare signature read as BIP-340", detached, SIGN_SCHNORR)
    add("bytes trail a bare signature", detached + b"\x90\x00", SIGN_ECDSA)

    add("bytes trail the template", full + bytes([0x90, 0x00]), SIGN_ECDSA)
    add("empty response", b"", SIGN_ECDSA)
    add("template tag alone", bytes([TLV_SIGN_TEMPLATE]), SIGN_ECDSA)

    accepted = [r for r in rows if sign_reply_model(r[1], r[2])[0]]

    c_rows = []
    for comment, reply, algo in rows:
        ok, key_off, sig_off, sig_len = sign_reply_model(reply, algo)
        detached_answer = ok and key_off is None
        expect_key = "NULL" if not ok or detached_answer else cstr(
            hexs(reply[key_off:key_off + SIGN_PUBKEY_LEN]))
        expect_sig = "NULL" if not ok else cstr(hexs(reply[sig_off:sig_off + sig_len]))
        # What the DER reader makes of the bytes the reply hands it, which is how the test notices a
        # signature picked up at the wrong offset. -1 where the question does not arise.
        verdict = -1
        if ok and algo == SIGN_ECDSA and not detached_answer:
            verdict = 1 if der_model(reply[sig_off:sig_off + sig_len])[0] else 0
        c_rows.append("  {%s, %s, %d, %d, %s, %s, %d, %d, %d}"
                      % (cstr(comment), cstr(hexs(reply)), algo, 1 if ok else 0,
                         expect_key, expect_sig, sig_len, verdict, 1 if detached_answer else 0))

    rows_c = ",\n".join(c_rows)
    btc_c, btc_accepted = btc_sig_table(btc_sig_rows(rows))

    return f"""#ifndef VECTORS_KEYCARD_SIGNATURE_H
#define VECTORS_KEYCARD_SIGNATURE_H

/* spec: {provenance('keycard_applet_4.java')}
 *     {provenance('keycard_scv2.java')}
 *
 * The reply to SIGN, and what keycard_read_signature_reply has to answer about it. The layout is the
 * applet's own: 0xA0 introducing a template that declares its length, holding 0x80 and the 65 byte
 * public key, and the signature from wherever the key ends -- the offset the applet calls
 * SIGN_HASH_OFF. The template always takes the 0x81 length form, because the applet writes that byte
 * rather than choosing one.
 *
 * An ECDSA reply comes in a second documented shape, with no template and no public key: 0x80 and the
 * signature with its recovery id appended, so nothing is left to recover and the reader names no key.
 * Those 65 bytes are the length of a public key by arithmetic alone, and by nothing else.
 *
 * The signature is bare DER for ECDSA. For BIP-340 the card library wraps it in a 0x88 primitive,
 * and that wrapping is the one shape rule here the applet source does not state: it happens inside
 * the elliptic curve library, which is a separate artifact.
 *
 * Expectations come from sign_reply_model() in generate.py, written from the layout above and not
 * from the C. A reply is judged on its shape; whether the DER inside it is a signature is the DER
 * reader's question, asked in test_ecdsa_der.c.
 */
typedef struct {{
  const char* comment;
  const char* hex;
  uint8_t algo;
  int ok;
  const char* key;      /* NULL when the reply is refused, or names no key */
  const char* sig;
  uint16_t sig_len;
  int sig_der;          /* 1/0: whether that is a DER signature, -1 when the question does not arise */
  int key_absent;       /* 1 when a reply of that shape is expected to name no key */
}} sign_reply_case_t;

static const sign_reply_case_t SIGN_REPLY_CASES[] = {{
{rows_c}
}};

#define SIGN_REPLY_CASES_COUNT (sizeof(SIGN_REPLY_CASES) / sizeof(SIGN_REPLY_CASES[0]))
#define SIGN_REPLY_ACCEPTED {len(accepted)}
#define SIGN_REPLY_PUBKEY_LEN {SIGN_PUBKEY_LEN}

/* The same replies as BIP-174 input records: {len(btc_c.split(chr(10)))} rows, {btc_accepted} of them
 * a record. `key` is the compressed public key the record is filed under -- absent for taproot, and
 * absent from a reply that carries its own recovery id, which is why no record is built from one.
 * `val` is the DER with the sighash byte after it, or the 64 bytes of a BIP-340 signature. Expectations
 * come from btc_sig_model(), stated from the record and not from the C. */
typedef struct {{
  const char* comment;
  const char* hex;
  uint8_t algo;
  uint8_t sighash;
  int ok;
  const char* key;   /* NULL when the record carries no key, or none is written */
  const char* val;
  uint16_t val_len;
}} btc_sig_case_t;

static const btc_sig_case_t BTC_SIG_CASES[] = {{
{btc_c}}};

#define BTC_SIG_CASES_COUNT (sizeof(BTC_SIG_CASES) / sizeof(BTC_SIG_CASES[0]))
#define BTC_SIG_ACCEPTED {btc_accepted}

#endif\t/* VECTORS_KEYCARD_SIGNATURE_H */
"""

# ---------------------------------------------------------------- eip712
#
# The device turns an EIP-712 typed-data document into the 32 bytes the card signs. What those
# bytes should be is taken from MetaMask's eth-sig-util, because that is what the dapps handing
# this document to the device compute with, and so what the contract checking the signature agrees
# with. The EIP text does not say what a `bytes` value arrives as without its 0x, whether a number
# outside its type's range is encoded or refused, in what order a struct's dependencies are
# appended, or what a value of the wrong JSON type does; the implementation settles all of that.
#
#   eth_sig_util_sign_typed_data.test.ts   the fixtures: inputs, and the typed data of each case
#   eth_sig_util_sign_typed_data.snap      the encodeData / eip712Hash the suite expects
#
# A snapshot key carries the case title, the input value and its JS type, so pairing a row with the
# wrong expectation trips an assert here rather than producing a quietly wrong header.
#
# The device is compared on the digest, not on encodeData, because the digest is what it hands the
# card. hashStruct(Message) is keccak256(encodeData), so each encodeData snapshot gives a
# hashStruct, and hashStructs are what the 0x19 0x01 prefix is applied to. The rows that carry a
# single field declare an empty EIP712Domain, whose separator the six published eip712Hash cases
# pin independently: the minimal one is hashStruct over that same empty struct.

EIP712_TEST = "eth_sig_util_sign_typed_data.test.ts"
EIP712_SNAP = "eth_sig_util_sign_typed_data.snap"

# The fixture builds these two with a template literal over Number.MAX_SAFE_INTEGER.toString(16).
EIP712_JS_CONSTS = {
    "MAX_SAFE_INTEGER_PLUS_ONE_CHAR_AS_HEX": "0x1fffffffffffff1",
    "MAX_SAFE_INTEGER_AS_HEX": "0x1fffffffffffff",
}

EIP712_ATOMS = frozenset(
    ["bool", "address", "string", "bytes"]
    + [f"bytes{i}" for i in range(1, 33)]
    + [f"uint{8 * i}" for i in range(1, 33)]
    + [f"int{8 * i}" for i in range(1, 33)]
    + ["uint", "int"]  # the fixture uses these too; ethereumjs-abi reads them as 256 bit
)


class Eip712Buffer(str):
    """A Buffer in the fixture, given to the device as the hex string of the same bytes.

    The reference hex-decodes a string into those same bytes, so the expectation the snapshot holds
    still applies. `js_name` and `js_type` are what the snapshot key was built from, which is not
    the hex form (`String(Buffer.from('10','utf8'))` is `10`)."""

    def __new__(cls, data: bytes):
        self = super().__new__(cls, "0x" + data.hex())
        self.raw = data
        return self

    @property
    def js_name(self) -> str:
        return self.raw.decode("utf-8", "replace")

    @property
    def js_type(self) -> str:
        return "Buffer"


def js_name(value) -> str:
    """String(value) as the fixture's test titles render it."""
    if isinstance(value, Eip712Buffer):
        return value.js_name
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def js_type(value) -> str:
    if isinstance(value, Eip712Buffer):
        return value.js_type
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    return "number"


def eip712_literal(text: str, at: int) -> tuple[str, int]:
    """The JS literal starting at text[at], and the index just past it. Braces inside a string
    do not count, which is the only reason this is not a count of characters."""
    depth = 0
    quote = None
    i = at
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return text[at : i + 1], i + 1
        i += 1
    raise AssertionError(f"unbalanced literal at {at}")


def js_read(literal: str):
    """One of the fixture's JS literals, as Python data.

    Only the constructs the fixture itself uses are translated, and the leftovers are checked for,
    because a row built on a mistranslated literal would pin an expectation nobody holds."""
    src = re.sub(r"//[^\n]*", "", literal)
    buffers: list[bytes] = []

    def take(data: bytes) -> str:
        """A Buffer cannot survive json.loads, so it is parked and restored afterwards."""
        buffers.append(data)
        return '"@@JSRAW%d@@"' % (len(buffers) - 1)

    src = re.sub(
        r"Buffer\.from\(new Int32Array\(\[([0-9,\s]+)\]\)\)",
        lambda m: take(b"".join(struct.pack("<i", int(v)) for v in m.group(1).split(",") if v.strip())),
        src,
    )
    src = re.sub(r"Buffer\.from\('([^']*)',\s*'utf8'\)", lambda m: take(m.group(1).encode("utf-8")), src)
    for name, value in EIP712_JS_CONSTS.items():
        src = src.replace(name, '"%s"' % value)
    src = src.replace("Number.MAX_SAFE_INTEGER", "9007199254740991")
    src = src.replace("Number.MIN_SAFE_INTEGER", "-9007199254740991")
    src = re.sub(r"'([^'\\]*)'", r'"\1"', src)
    src = re.sub(r"([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)(\s*:)", r'\1"\2"\3', src)
    src = re.sub(r",(\s*[}\]])", r"\1", src)
    for left in ("Buffer", "Number.", "as any", "'"):
        assert left not in src, f"{left} left in {src[:200]}"
    return js_read_restore(json.loads(src), buffers)


def js_read_restore(node, buffers: list):
    if isinstance(node, str) and node.startswith("@@JSRAW"):
        return Eip712Buffer(buffers[int(node[len("@@JSRAW") : -2])])
    if isinstance(node, list):
        return [js_read_restore(item, buffers) for item in node]
    if isinstance(node, dict):
        return {key: js_read_restore(value, buffers) for key, value in node.items()}
    return node


_SNAPSHOTS: dict[str, str] | None = None


def snapshots() -> dict[str, str]:
    """The jest snapshot file as {case title: expected value}."""
    global _SNAPSHOTS
    if _SNAPSHOTS is None:
        text = fetch(EIP712_SNAP)
        out = {k.strip(): v.strip().strip('"') for k, v in re.findall(r"^exports\[`([^`]*)`\] = `(.*?)`;", text, re.M | re.S)}
        assert len(out) > 600, len(out)
        _SNAPSHOTS = out
    return _SNAPSHOTS


def eip712_it_bodies(text: str, start: int, end: int) -> list[tuple[str, str]]:
    """The (title, body) of every it() in text[start:end], in file order."""
    out = []
    for m in re.finditer(r"\bit\('([^']+)', function \(\) \{", text[start:end]):
        nxt = text.find("\n    it(", start + m.end())
        stop = text.find("\n  });", start + m.end())
        out.append((m.group(1), text[start + m.end() : min(x for x in (nxt, stop, end) if x != -1)]))
    return out


def eip712_hash_cases() -> list[tuple[str, dict]]:
    """The suite's V4 eip712Hash cases, each with the typed data its snapshot digest belongs to."""
    text = fetch(EIP712_TEST)
    v4 = text.index("describe('V4', function", text.index("describe('TypedDataUtils.eip712Hash'"))
    end = text.index("describe('bool encoding'", v4)
    cases = []
    for title, body in eip712_it_bodies(text, v4, end):
        if "toMatchSnapshot" not in body:
            continue
        at = body.index("eip712Hash(")
        lit, _ = eip712_literal(body, body.index("{", at))
        typed = js_read(lit)
        key = f"TypedDataUtils.eip712Hash V4 {title} 1"
        assert key in snapshots(), key
        cases.append((title, typed, snapshots()[key]))
    assert len(cases) == 6, len(cases)
    return cases


def eip712_encode_data_cases() -> list[tuple[str, dict]]:
    """The named V4 encodeData cases whose fixture states types, primaryType and message."""
    text = fetch(EIP712_TEST)
    v4 = text.index("describe('V4', function", text.index("describe('TypedDataUtils.encodeData'"))
    end = text.index("describe('V3/V4 identical", v4)
    wanted = [
        "should encode data with custom type",
        "should encode data with a recursive data type",
        "should encode data with a custom data type array",
        "should encode data when given extraneous types",
        "should encode data with a dynamic property set to null",
    ]
    cases = []
    for title, body in eip712_it_bodies(text, v4, end):
        if title not in wanted:
            continue
        types = js_read(eip712_literal(body, body.index("= {", body.index("const types")) + 2)[0])
        primary = re.search(r"const primaryType = '([^']+)'", body)
        if primary:
            primary = primary.group(1)
        else:
            primary = re.search(r"encodeData\(\s*'([^']+)'", body).group(1)
        message = js_read(eip712_literal(body, body.index("= {", body.index("const message")) + 2)[0])
        cases.append((title, {"types": types, "primaryType": primary, "domain": {}, "message": message}))
    assert sorted(t for t, _ in cases) == sorted(wanted), [t for t, _ in cases]
    return cases


def eip712_example_data() -> dict[str, list]:
    """The fixture's per-type table of inputs, in the order its tests run them."""
    text = fetch(EIP712_TEST)
    at = text.index("const encodeDataExamples = {") + len("const encodeDataExamples = ")
    lit, _ = eip712_literal(text, at)
    out = js_read(lit)
    for required in ("address", "bool", "bytes", "bytes1", "bytes32", "int8", "int256", "string", "uint8", "uint256"):
        assert required in out, required
    return out


# The model below is written from EIP-712's own description of encodeType/encodeData/hashStruct and
# is checked against the reference below before a single row is emitted. Its job is the domain
# separator and the rows the fixture does not cover; where it and the fixture disagree the fixture
# wins, because the fixture is what a verifier agrees with.


# The digest of a typed-data document is what MetaMask's eth-sig-util computes, from two sources:
#
#   * the published snapshots of its own fixture, at main (version 9.0.0, unreleased);
#   * a run of the released 8.2.0 over documents this file defines, which is how rows nobody else
#     publishes get an expectation.
#
# The two agree on every case the snapshot covers, apart from a `bool` given the string "false":
# 8.2.0 hands the value to the ABI encoder, which takes its truthiness, while main rejects anything
# but a boolean and the strings "true" and "false". The device follows main, so those rows are not
# taken from the run.
#
# The run is a separate step because it needs node:
#
#   python3 generate.py --eip712-documents          # writes .cache/eip712_documents.json
#   node oracle/eip712_reference.mjs                # writes .cache/eip712_reference.json
#
# and then generate.py reads the dump back. Each row says which of the two it came from.

EIP712_DOCUMENTS = ".cache/eip712_documents.json"
EIP712_DUMP = ".cache/eip712_reference.json"

EIP712_TYPES = [
    "bool", "string", "bytes", "bytes1", "bytes2", "bytes4", "bytes20", "bytes31", "bytes32",
    "address", "uint8", "uint16", "uint24", "uint32", "uint64", "uint128", "uint256", "uint",
    "int8", "int16", "int64", "int128", "int256", "int",
]

# Every form a JSON document can hold a field value in, including the ones EIP-712 does not
# describe and the reference nevertheless encodes.
EIP712_VALUES: list = [
    0, 1, -1, 10, 255, 256, True, False, None,
    "0", "1", "10", "-1", "0x", "0x0", "0x10", "0x101", "0X10", "0xzz", " 1",
    "9007199254740991", 9007199254740991, "0x1fffffffffffff",
    "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    "-57896044618658097711785492504343953926634992332820282019728792003956564819968",
    "-57896044618658097711785492504343953926634992332820282019728792003956564819969",
    "-0", "+1", "1e3", "", "a\tb", "Hello!",
    "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    "CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
]

# Cells left out of the run, and why. Each is a place where the released library and main differ,
# or where the device cannot reach the value the reference would compute.
EIP712_MATRIX_SKIPPED = [
    "a non-ASCII string in an address field: the reference sums UTF-16 code units, which escapes "
    "outside what the device's JSON reader decodes reach; the device refuses the value",
]


def eip712_matrix_cells() -> list[tuple[str, object]]:
    cells: list[tuple[str, object]] = []

    for type_name in EIP712_TYPES:
        for value in EIP712_VALUES:
            if type_name == "address" and isinstance(value, str) and not value.isascii():
                continue

            cells.append((type_name, value))

    return cells


EIP712_MAIL_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"},
    ],
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"},
    ],
}

EIP712_MAIL_DOMAIN = {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
}

EIP712_MAIL_MESSAGE = {
    "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!",
}

EIP712_MAIL = {
    "types": EIP712_MAIL_TYPES,
    "primaryType": "Mail",
    "domain": EIP712_MAIL_DOMAIN,
    "message": EIP712_MAIL_MESSAGE,
}

EIP712_DOMAIN_ALL = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
    {"name": "salt", "type": "bytes32"},
]


def eip712_json(typed: dict) -> str:
    return json.dumps(typed, separators=(",", ":"), ensure_ascii=False)


def eip712_one(type_name: str, value) -> dict:
    """A document with one field of one type, over a domain that declares nothing."""
    return {
        "types": {"EIP712Domain": [], "Message": [{"name": "data", "type": type_name}]},
        "primaryType": "Message",
        "domain": {},
        "message": {"data": value},
    }


# The fixture builds its `salt` with Buffer.from(new Int32Array([1, 2, 3])). What the reference ends
# up encoding is the array's elements as bytes, 0x010203, which the run confirms: the digest it
# produces for the documents that carry it is the published one.
EIP712_BUFFER_SALT = "0x010203"


def eip712_jsonable(value):
    """A fixture value as JSON. The one JS-only form the fixture uses is the salt above."""
    if isinstance(value, Eip712Buffer):
        assert str(value) == "0x010000000200000003000000", str(value)
        return EIP712_BUFFER_SALT

    if isinstance(value, dict):
        return {key: eip712_jsonable(item) for key, item in value.items()}

    if isinstance(value, list):
        return [eip712_jsonable(item) for item in value]

    return value


def eip712_raw_one(type_name: str, value_json: str) -> str:
    """A one-field document spelled out as text, so that what the parser is handed is exactly what
    is written here. `value_json` is the JSON for the value, quotes included."""
    return (
        '{"types":{"EIP712Domain":[],"Message":[{"name":"data","type":"'
        + type_name
        + '"}]},"primaryType":"Message","domain":{},"message":{"data":'
        + value_json
        + "}}"
    )


def eip712_documents() -> list[dict]:
    """Every document the corpus covers, as text: the device and the reference are given the same
    bytes, so a form that only one of them can express cannot sneak in."""
    docs: list[dict] = []

    def add(name: str, typed: dict):
        docs.append({"name": name, "json": eip712_json(typed)})

    def raw(name: str, text: str):
        docs.append({"name": name, "json": text})

    add("eip712_example_mail", EIP712_MAIL)

    # The fixture's own whole-document cases, whose digests its snapshots publish.
    for title, typed, _ in eip712_hash_cases():
        add("snap_" + eip712_case_name(title), eip712_jsonable(typed))

    for order in (
        ["message", "types", "domain", "primaryType"],
        ["primaryType", "domain", "message", "types"],
        ["domain", "message", "primaryType", "types"],
    ):
        add("mail_reordered_" + "_".join(key[:4] for key in order), {key: EIP712_MAIL[key] for key in order})

    for index, (type_name, value) in enumerate(eip712_matrix_cells()):
        add(f"atom_{type_name}_{index}", eip712_one(type_name, value))

    # The same table as arrays, which is where the per-element rules get exercised again.
    for type_name in EIP712_TYPES:
        values = [value for name, value in eip712_matrix_cells() if name == type_name]
        if values:
            add(f"atom_array_{type_name}", eip712_one(type_name + "[]", values))

    named: list[tuple[str, dict]] = [
        # Structs, arrays of them, and the dependency set that goes into the type hash.
        ("mail_two_postboxes", {
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "sender", "type": "string"}, {"name": "bodies", "type": "string[]"}],
                "Postbox": [{"name": "mails", "type": "Mail[]"}],
                "Holder": [
                    {"name": "one", "type": "Postbox"},
                    {"name": "many", "type": "Postbox[]"},
                    {"name": "count", "type": "uint256"},
                ],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {
                "one": {"mails": [{"sender": "a", "bodies": ["x"]}]},
                "many": [
                    {"mails": [{"sender": "b", "bodies": []}, {"sender": "c", "bodies": ["y", "z"]}]},
                    {"mails": []},
                ],
                "count": 3,
            },
        }),
        ("mail_empty_array", {
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "sender", "type": "string"}, {"name": "bodies", "type": "string[]"}],
                "Holder": [{"name": "mails", "type": "Mail[]"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"mails": []},
        }),
        ("mail_two_dimensional_array", {
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "sender", "type": "string"}],
                "Holder": [{"name": "mails", "type": "Mail[][]"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"mails": [[{"sender": "a"}], [{"sender": "b"}, {"sender": "c"}], []]},
        }),
        ("mail_missing_struct_member", {
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "sender", "type": "string"}],
                "Holder": [{"name": "mail", "type": "Mail"}, {"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1},
        }),
        ("mail_null_struct_member", {
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "sender", "type": "string"}],
                "Holder": [{"name": "mail", "type": "Mail"}, {"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"mail": None, "n": 1},
        }),
        ("mail_missing_atomic_member", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {},
        }),
        ("mail_extra_message_member", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1, "unDeclared": "ignored"},
        }),
        # A type that is referenced is part of the type hash; one that is not is not. The names are
        # chosen so that the alphabetical order differs from the order they are declared in.
        ("deps_reference_order", {
            "types": {
                "EIP712Domain": [],
                "Holder": [
                    {"name": "zulu", "type": "Zulu"},
                    {"name": "alpha", "type": "Alpha"},
                    {"name": "mike", "type": "Mike[]"},
                ],
                "Zulu": [{"name": "n", "type": "uint256"}],
                "Alpha": [{"name": "n", "type": "uint256"}],
                "Mike": [{"name": "n", "type": "uint256"}],
                "Unreferenced": [{"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {
                "zulu": {"n": 1},
                "alpha": {"n": 2},
                "mike": [{"n": 3}, {"n": 4}],
            },
        }),
        ("deps_nested_only", {
            "types": {
                "EIP712Domain": [],
                "Holder": [{"name": "outer", "type": "Outer"}],
                "Outer": [{"name": "inner", "type": "Inner"}],
                "Inner": [{"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"outer": {"inner": {"n": 7}}},
        }),
        # A type that names itself: it is not part of its own encodeType, and a document can carry
        # a value of it as long as the data bottoms out.
        ("deps_self_recursive", {
            "types": {
                "EIP712Domain": [],
                "Node": [
                    {"name": "value", "type": "uint256"},
                    {"name": "next", "type": "Node"},
                ],
            },
            "primaryType": "Node",
            "domain": {},
            "message": {"value": 1, "next": {"value": 2, "next": None}},
        }),
        ("deps_self_recursive_array", {
            "types": {
                "EIP712Domain": [],
                "Node": [
                    {"name": "value", "type": "uint256"},
                    {"name": "next", "type": "Node[]"},
                ],
            },
            "primaryType": "Node",
            "domain": {},
            "message": {"value": 1, "next": [{"value": 2, "next": []}]},
        }),
        ("deps_mutual_recursion", {
            "types": {
                "EIP712Domain": [],
                "A": [{"name": "n", "type": "uint256"}, {"name": "b", "type": "B"}],
                "B": [{"name": "n", "type": "uint256"}, {"name": "a", "type": "A"}],
            },
            "primaryType": "A",
            "domain": {},
            "message": {"n": 1, "b": {"n": 2, "a": None}},
        }),
        # A struct name is whatever is declared, whatever its case.
        ("name_lowercase_struct", {
            "types": {
                "EIP712Domain": [],
                "wrapper": [{"name": "n", "type": "uint256"}],
                "Holder": [{"name": "w", "type": "wrapper"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"w": {"n": 1}},
        }),
        ("name_underscore_struct", {
            "types": {
                "EIP712Domain": [],
                "_inner": [{"name": "n", "type": "uint256"}],
                "Holder": [{"name": "w", "type": "_inner"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"w": {"n": 1}},
        }),
        ("name_type_called_string", {
            "types": {
                "EIP712Domain": [],
                "string": [{"name": "n", "type": "uint256"}],
                "Holder": [{"name": "w", "type": "string"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"w": {"n": 1}},
        }),
        # The domain, which is hashed before the message.
        ("domain_all_fields", {
            "types": {"EIP712Domain": EIP712_DOMAIN_ALL, "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {
                "name": "examples.example",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "salt": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            },
            "message": {"n": 1},
        }),
        ("domain_custom_fields", {
            "types": {
                "EIP712Domain": [{"name": "description", "type": "string"}, {"name": "cid", "type": "uint256"}],
                "Holder": [{"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {"description": "a domain of one's own", "cid": 42},
            "message": {"n": 1},
        }),
        ("domain_primary_is_domain", {
            "types": {"EIP712Domain": EIP712_DOMAIN_ALL},
            "primaryType": "EIP712Domain",
            "domain": {
                "name": "example.metamask.io",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "salt": "0x010203",
            },
            "message": {},
        }),
        ("domain_primary_is_domain_with_message", {
            "types": {"EIP712Domain": EIP712_DOMAIN_ALL, "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "EIP712Domain",
            "domain": {
                "name": "example.metamask.io",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "salt": "0x010203",
            },
            "message": {"n": 1},
        }),
        ("domain_primary_is_domain_missing_members", {
            "types": {"EIP712Domain": EIP712_DOMAIN_ALL},
            "primaryType": "EIP712Domain",
            "domain": {"name": "only a name"},
            "message": {},
        }),
        ("domain_missing_from_types", {
            "types": {"Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1},
        }),
        ("domain_primary_unknown", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "NothingLikeIt",
            "domain": {},
            "message": {"n": 1},
        }),
        # Text written with JSON escapes, which a JSON parser settles into something the document
        # does not spell out. Hand-built, because json.dumps() would escape the backslash and turn
        # the escape into a literal backslash; these are the bytes the reference's JSON.parse sees.
        ("text_escape_two_byte", eip712_raw_one("string", '"caf\\u00e9"')),
        ("text_escape_boundary_7ff", eip712_raw_one("string", '"\\u07ff"')),
        ("text_escape_boundary_800", eip712_raw_one("string", '"\\u0800"')),
        ("text_escape_boundary_fff", eip712_raw_one("string", '"\\u0fff"')),
        ("text_escape_boundary_1000", eip712_raw_one("string", '"\\u1000"')),
        ("text_escape_boundary_7fff", eip712_raw_one("string", '"\\u7fff"')),
        ("text_escape_boundary_8000", eip712_raw_one("string", '"\\u8000"')),
        ("text_escape_boundary_ffff", eip712_raw_one("string", '"\\uffff"')),
        ("text_escape_surrogate_pair", eip712_raw_one("string", '"\\ud83d\\ude00"')),
        ("text_escape_lone_high_surrogate", eip712_raw_one("bytes", '"\\ud83d"')),
        ("text_escape_lone_low_surrogate", eip712_raw_one("bytes", '"\\ude00"')),
        ("text_escape_nul", eip712_raw_one("string", '"a\\u0000b"')),
        ("text_escape_controls", eip712_raw_one("string", '"\\b\\f\\n\\r\\t"')),
        ("text_escape_quote_and_slash", eip712_raw_one("string", '"a\\"b\\\\c\\/d"')),
        ("text_escape_then_text", eip712_raw_one("bytes", '"caf\\u00e9 \\ud83d\\ude00"')),
        ("address_escape", eip712_raw_one("address", '"a\\tb"')),
        ("address_escape_u", eip712_raw_one("address", '"a\\u0009b"')),
        # Text as the document writes it, no escapes in it.
        ("text_raw_equals_escape", eip712_one("string", "café")),
        ("text_empty", eip712_one("string", "")),
        ("bytes_hex_long", eip712_one("bytes", "0x" + "ab" * 200)),
        ("bytes_hex_odd", eip712_one("bytes", "0x102030405060708090a")),
        ("bytes32_hex_odd", eip712_one("bytes32", "0x10203")),
        # Two ways of writing one document that a JSON parser settles the same way.
        ("dupe_message_key", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1},
        }),
        ("dupe_domain_key", {
            "types": {"EIP712Domain": [{"name": "name", "type": "string"}], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {"name": "last one wins"},
            "message": {"n": 1},
        }),
        ("dupe_types_entry", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1},
        }),
        ("dupe_field_name", {
            "types": {
                "EIP712Domain": [],
                "Holder": [{"name": "n", "type": "uint256"}, {"name": "n", "type": "uint256"}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 9},
        }),
        ("key_named_value", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "a", "type": "string"}, {"name": "b", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {},
            "message": {"a": "b", "b": 1},
        }),
        ("value_before_key", {
            "types": {"EIP712Domain": [], "Holder": [{"name": "n", "type": "uint256"}]},
            "primaryType": "Holder",
            "domain": {"chainId": 1, "name": "a number came first"},
            "message": {"n": 1},
        }),
        ("field_extra_member", {
            "types": {
                "EIP712Domain": [],
                "Holder": [{"name": "n", "type": "uint256", "since": 4}],
            },
            "primaryType": "Holder",
            "domain": {},
            "message": {"n": 1},
        }),
    ]

    for name, document in named:
        # A str here is already the JSON text of a document, escapes and all.
        if isinstance(document, str):
            raw(name, document)
        else:
            add(name, document)

    # Documents a JSON parser or the reference stops at. The device has to refuse them too.
    malformed: list[tuple[str, str]] = [
        ("bad_empty", ""),
        ("bad_object_only", "{}"),
        ("bad_array", "[]"),
        ("bad_string", '"Mail"'),
        ("bad_number", "42"),
        ("bad_null", "null"),
        ("bad_no_types", '{"primaryType":"M","domain":{},"message":{}}'),
        ("bad_no_primary", '{"types":{"EIP712Domain":[]},"domain":{},"message":{}}'),
        ("bad_no_domain", '{"types":{"EIP712Domain":[]},"primaryType":"M","message":{}}'),
        ("bad_no_message", '{"types":{"EIP712Domain":[]},"primaryType":"M","domain":{}}'),
        ("bad_types_array", '{"types":[],"primaryType":"M","domain":{},"message":{}}'),
        ("bad_types_string", '{"types":"M","primaryType":"M","domain":{},"message":{}}'),
        ("bad_types_value", '{"types":{"EIP712Domain":{}},"primaryType":"M","domain":{},"message":{}}'),
        ("bad_field_not_object", '{"types":{"EIP712Domain":[],"M":["n"]},"primaryType":"M","domain":{},"message":{}}'),
        ("bad_field_no_type", '{"types":{"EIP712Domain":[],"M":[{"name":"n"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_field_no_name", '{"types":{"EIP712Domain":[],"M":[{"type":"uint256"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_field_type_number", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":7}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_primary_not_string", '{"types":{"EIP712Domain":[]},"primaryType":7,"domain":{},"message":{}}'),
        ("bad_domain_array", '{"types":{"EIP712Domain":[]},"primaryType":"M","domain":[],"message":{}}'),
        ("bad_message_array", '{"types":{"EIP712Domain":[]},"primaryType":"M","domain":{},"message":[]}'),
        ("bad_truncated", '{"types":{"EIP712Domain":[]},"primaryType":"M","dom'),
        ("bad_trailing_junk", '{"types":{"EIP712Domain":[]},"primaryType":"M","domain":{},"message":{}} }x'),
        ("bad_unknown_type", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"nothere"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_unknown_array_type", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"nothere[]"}]},"primaryType":"M","domain":{},"message":{"n":[1]}}'),
        ("bad_bits_not_multiple", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint33"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_bits_zero", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint0"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_bits_leading_zero", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint08"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_negative_uint", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8"}]},"primaryType":"M","domain":{},"message":{"n":-1}}'),
        ("bad_uint_out_of_range", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8"}]},"primaryType":"M","domain":{},"message":{"n":256}}'),
        ("bad_int_out_of_range", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"int8"}]},"primaryType":"M","domain":{},"message":{"n":-256}}'),
        ("bad_bool_number", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"bool"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_bool_null", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"bool"}]},"primaryType":"M","domain":{},"message":{"n":null}}'),
        ("bad_bytes_text", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"bytes4"}]},"primaryType":"M","domain":{},"message":{"n":"not hex"}}'),
        ("bad_bytes_too_long", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"bytes32"}]},"primaryType":"M","domain":{},"message":{"n":"0x' + '11' * 33 + '"}}'),
        ("bad_address_too_long", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"address"}]},"primaryType":"M","domain":{},"message":{"n":"0x' + '22' * 21 + '"}}'),
        ("bad_string_number_bool", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"string"}]},"primaryType":"M","domain":{},"message":{"n":true}}'),
        ("bad_string_negative_number", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"string"}]},"primaryType":"M","domain":{},"message":{"n":-1}}'),
        ("bad_array_for_atomic", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8"}]},"primaryType":"M","domain":{},"message":{"n":[1]}}'),
        ("bad_atomic_for_array", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8[]"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_struct_for_atomic_value", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8"}]},"primaryType":"M","domain":{},"message":{"n":{"a":1}}}'),
        ("bad_array_element_missing", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8[]"}]},"primaryType":"M","domain":{},"message":{"n":[1,2}}'),
        ("bad_bad_escape", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"string"}]},"primaryType":"M","domain":{},"message":{"n":"a\\qb"}}'),
        ("bad_short_escape", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"string"}]},"primaryType":"M","domain":{},"message":{"n":"a\\u12"}}'),
        ("bad_trailing_escape", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"string"}]},"primaryType":"M","domain":{},"message":{"n":"a\\\\"}}'),
        ("bad_function_type", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"function"}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_open_bracket_type", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint8["}]},"primaryType":"M","domain":{},"message":{"n":1}}'),
        ("bad_number_forms", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"uint256"}]},"primaryType":"M","domain":{},"message":{"n":1.5}}'),
        ("bad_negative_hex", '{"types":{"EIP712Domain":[],"M":[{"name":"n","type":"int256"}]},"primaryType":"M","domain":{},"message":{"n":"-0x10"}}'),
    ]

    for name, text in malformed:
        raw(name, text)

    seen: set[str] = set()
    for document in docs:
        assert document["name"] not in seen, document["name"]
        seen.add(document["name"])

    return docs


def eip712_dump() -> tuple[str, dict[str, dict]]:
    """What the released reference made of each document, and the version that made it. Run the two
    commands above to (re)build it; no digest here is computed by this file."""
    path = CACHE / "eip712_reference.json"

    if not path.exists():
        raise SystemExit(
            "missing .cache/eip712_reference.json:\n"
            "  python3 generate.py --eip712-documents\n"
            "  node oracle/eip712_reference.mjs"
        )

    dump = json.loads(path.read_text())
    return dump["version"], {row["name"]: row for row in dump["rows"]}


def eip712_published_hash() -> dict[str, bytes]:
    """The digests upstream publishes for whole documents: the fixture's named eip712Hash cases and
    the EIP's own example file. Keyed by the name of the document they belong to."""
    out: dict[str, bytes] = {"eip712_example_mail": eip712_mail_digest()}

    for title, _, published in eip712_hash_cases():
        out["snap_" + eip712_case_name(title)] = bytes.fromhex(published)

    return out


def eip712_case_name(title: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.+-]", "_", title)


def eip712_mail_digest() -> bytes:
    """What the EIP's example file asserts its own document signs."""
    text = fetch("eip712_example.js")
    found = re.search(r"bufferToHex\(signHash\(\)\)\)\.to\.equal\('0x([0-9a-f]{64})'", text)
    assert found, "signHash expectation not found in eip712_example.js"
    return bytes.fromhex(found.group(1))


def eip712_published_single_field() -> dict[str, bytes]:
    """Digests built out of the published encodeData snapshots alone: the fixture gives the field's
    encoding, and the separator of a domain that declares no fields closes the hash struct. The
    published minimal typed message is a hash struct over exactly that domain, which is what pins
    the separator used here.
    """
    empty_domain = eth_keccak(eth_keccak(b"EIP712Domain()"))
    out: dict[str, bytes] = {}

    for type_name, inputs in eip712_example_data().items():
        for value in inputs:
            if isinstance(value, Eip712Buffer):
                continue
            key = (
                f'TypedDataUtils.encodeData V4 example data type "{type_name}" '
                f'should encode "{js_name(value)}" (type "{js_type(value)}") 1'
            )
            encoded = bytes.fromhex(snapshots()[key])
            assert len(encoded) == 64, key
            digest = eth_keccak(b"\x19\x01" + empty_domain + eth_keccak(encoded))
            out[json.dumps(eip712_one(type_name, value), separators=(",", ":"), ensure_ascii=False)] = digest

        array_key = (
            f'TypedDataUtils.encodeData V4 example data type "{type_name}" '
            f"should encode array of all {type_name} example data 1"
        )
        if array_key in snapshots():
            inputs_plain = [value for value in inputs if not isinstance(value, Eip712Buffer)]

            if len(inputs_plain) == len(inputs):
                encoded = bytes.fromhex(snapshots()[array_key])
                digest = eth_keccak(b"\x19\x01" + empty_domain + eth_keccak(encoded))
                out[
                    json.dumps(
                        eip712_one(type_name + "[]", inputs_plain), separators=(",", ":"), ensure_ascii=False
                    )
                ] = digest

    return out


def comment_block(entries: list[str], indent: str = " *   - ") -> str:
    """Each entry as one or more wrapped lines of a C comment."""
    out = []

    for entry in entries:
        line = indent
        for word in entry.split():
            if len(line) + len(word) + 1 > 92:
                out.append(line.rstrip())
                line = indent.replace("- ", "  ")
            line += word + " "
        out.append(line.rstrip())

    return "\n" + "\n".join(out)


def eip712_vectors() -> str:
    version, dump = eip712_dump()
    documents = eip712_documents()
    missing = [document["name"] for document in documents if document["name"] not in dump]
    assert not missing, f"the reference dump does not cover: {missing[:5]}"

    published_hash = eip712_published_hash()
    published_field = eip712_published_single_field()
    checked = 0
    rows: list[tuple[str, str, bytes, str]] = []  # name, json, digest, note

    for document in documents:
        name = document["name"]
        row = dump[name]
        json_text = document["json"]

        if row["digest"] is None:
            rows.append((name, json_text, b"", row["error"]))
            continue

        digest = bytes.fromhex(row["digest"])

        # Where upstream publishes a value, it is the expectation and the run is checked against it.
        expect = published_hash.get(name) or published_field.get(json_text)

        if expect is not None:
            assert expect == digest, f"{name}: run {digest.hex()} published {expect.hex()}"
            checked += 1

        rows.append((name, json_text, digest, ""))

    divergences = comment_block(EIP712_MATRIX_SKIPPED)
    refuses = sum(1 for row in rows if not row[2])
    body = ",\n".join(
        f'  {{"{name}", {cstr(document)}, {"true" if digest else "false"}, '
        f'{{{", ".join("0x%02x" % b for b in digest)}}}, {cstr(note)}}}'
        for name, document, digest, note in rows
    )

    return f"""#ifndef VECTORS_EIP712_H
#define VECTORS_EIP712_H

/* What a typed-data document is worth, by MetaMask's eth-sig-util: the digest the device has to
 * hand the card, keccak256(0x19 0x01 || hashStruct(domain) || hashStruct(message)), or a statement
 * that the document has none and must be refused.
 *
 * {len(rows)} documents. No expectation here is restated from the C under test.
 *
 * Where a digest comes from:
 *  - {len(published_hash)} documents published by upstream's fixture and by the EIP's own example
 *    file;
 *  - {len(published_field)} documents whose single field's encodeData is published by upstream's
 *    fixture, composed with the separator of a domain that declares no fields;
 *  - the rest from a run of @metamask/eth-sig-util {version} (oracle/eip712_reference.mjs), which
 *    reproduces every one of the {checked} documents the two sources above cover.
 *
 * Left out of the corpus, where the device cannot reach what the reference computes:{divergences}
 */
#include <stdbool.h>
#include <stdint.h>

typedef struct {{
  const char* name;
  const char* json;
  bool ok;
  uint8_t digest[32];
  const char* note;   /* why the reference refused, for a row that has no digest */
}} eip712_case_t;

static const eip712_case_t EIP712_CASES[] = {{
{body}
}};

#define EIP712_CASES_COUNT (sizeof(EIP712_CASES) / sizeof(EIP712_CASES[0]))


#endif\t/* VECTORS_EIP712_H */
"""


# ------------------------------------------------------- multipart UR (ur.c, sampler.c, ur_encode.c)


class Xoshiro256:
    """The generator BCR-2024-001 names, seeded as that document seeds it: the sha256 of the seed
    bytes read as four big-endian words. Used only to rebuild the message the document's own
    vectors were computed over; the vectors themselves are parsed out of the document."""

    MASK = (1 << 64) - 1

    def __init__(self, seed: bytes):
        digest = hashlib.sha256(seed).digest()
        self.s = [int.from_bytes(digest[i * 8:i * 8 + 8], "big") for i in range(4)]

    def next(self) -> int:
        s = self.s
        five = (s[1] * 5) & self.MASK
        result = ((((five << 7) | (five >> 57)) & self.MASK) * 9) & self.MASK
        carry = (s[1] << 17) & self.MASK
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= carry
        s[3] = ((s[3] << 45) | (s[3] >> 19)) & self.MASK
        return result

    def next_double(self) -> float:
        return self.next() / float(1 << 64)

    def next_bytes(self, count: int) -> bytes:
        return bytes(int(self.next_double() * 256) for _ in range(count))


def mur_message(length: int, seed: str = "Wolf") -> bytes:
    """makeMessage(len:seed:) of the document's test vectors."""
    return Xoshiro256(seed.encode()).next_bytes(length)


def cbor_uint(value: int) -> bytes:
    """A CBOR unsigned integer in the shortest form that holds it, which is what the document's own
    part serialization uses: 12 inline as 0x0c, 100 as 0x18 0x64, 0x12345678 as 0x1a and four."""
    if value < 24:
        return bytes([value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < (1 << (8 * width)):
            return bytes([additional]) + value.to_bytes(width, "big")
    raise ValueError(value)


def cbor_head(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if length < (1 << (8 * width)):
            return bytes([(major << 5) | additional]) + length.to_bytes(width, "big")
    raise ValueError(length)


def cbor_part(seq_num: int, seq_len: int, message_len: int, checksum: int, data: bytes) -> bytes:
    return (cbor_head(4, 5) + cbor_uint(seq_num) + cbor_uint(seq_len) + cbor_uint(message_len)
            + cbor_uint(checksum) + cbor_head(2, len(data)) + data)


def parse_mur_rng_stream(paper: str) -> list[int]:
    block = paper[paper.index("func testRNG1"):paper.index("func testRNG2")]
    stream = re.search(r"let expectedNumbers = \[([0-9, ]+)\]", block)
    assert stream, "testRNG1 lost its expected stream"
    return [int(v) for v in stream.group(1).split(",")]


def parse_mur_parts(paper: str) -> list[tuple[int, int, int, int, bytes]]:
    rows = []
    for line in paper.splitlines():
        match = re.match(
            r'\s*"seqNum:(\d+), seqLen:(\d+), messageLen:(\d+), checksum:(\d+), data:([0-9a-f]+)"',
            line)
        if match:
            seq_num, seq_len, message_len, checksum, data = match.groups()
            rows.append((int(seq_num), int(seq_len), int(message_len), int(checksum),
                         bytes.fromhex(data)))
    return rows


def parse_mur_fragment_choices(paper: str) -> list[list[int]]:
    block = paper[paper.index("let expectedFragmentIndexes"):]
    block = block[:block.index("\n    ]")]
    return [[int(v) for v in inner.split(",")] for inner in re.findall(r"\[([0-9, ]+)\]", block)]


def parse_mur_part_cbor(paper: str) -> tuple[tuple[int, int, int, int, bytes], bytes]:
    """The one part the document gives as fields and as CBOR together."""
    block = paper[paper.index("func testCBOR"):]
    fields = re.search(r"seqNum: (\d+), seqLen: (\d+), messageLen: (\d+), checksum: (0x[0-9a-fA-F]+),"
                       r" data: Data\(\[([0-9, ]+)\]\)", block)
    hexed = re.search(r'cbor\.hex, "([0-9a-f]+)"', block)
    assert fields and hexed, "the part serialization vector changed shape"
    data = bytes(int(v) for v in fields.group(5).split(","))
    return ((int(fields.group(1)), int(fields.group(2)), int(fields.group(3)), int(fields.group(4), 0),
             data), bytes.fromhex(hexed.group(1)))


PUBLISHED_PAIR = re.compile(
    r"\* As a hex string[^:]*:\s*```([0-9a-f\n ]+?)```"
    r"\s*\* As a UR:\s*```\s*(ur:[a-z0-9-]+/[A-Za-z0-9]+)\s*```")


def parse_published_pairs(source: str) -> list[tuple[str, str, bytes]]:
    """The examples a document publishes twice, once as CBOR hex and once as UR text."""
    pairs = []
    for hex_run, ur in PUBLISHED_PAIR.findall(fetch(source)):
        cbor = bytes.fromhex("".join(hex_run.split()))
        pairs.append((ur[len("ur:"):ur.index("/")], ur, cbor))
    return pairs


def parse_registry_labels() -> dict[str, list[str]]:
    """The type registry, keyed by the current label: every spelling it lists for that type, struck
    out ones included, so a device label can be checked against the whole list."""
    labels = {}
    for line in fetch("bc_ur_types_registry.md").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        names = re.findall(r"`([a-z0-9-]+)`", cells[1])
        if names:
            labels[names[0]] = names
    return labels


def c_array(data: bytes, per_line: int = 12, indent: str = "   ") -> str:
    chunks = [", ".join(f"0x{b:02x}" for b in data[i:i + per_line])
              for i in range(0, len(data), per_line)]
    return indent + (",\n" + indent).join(chunks)


def ur_part_row(part: tuple[int, int, int, int, bytes]) -> str:
    seq_num, seq_len, message_len, checksum, data = part
    return (f"  {{{seq_num}, {seq_len}, {message_len}, {checksum}u,\n"
            f"   {{ {c_array(data, 12, '   ')} }}}},")


def ur_choice_row(seq_num: int, choice: list[int]) -> str:
    bits = 0
    for index in choice:
        bits |= 1 << index
    return f"  {{{seq_num}, 0x{bits:03x}}},"


UR_REGISTRY_TYPES = ("psbt", "hdkey", "output-descriptor", "account-descriptor")


def ur_registry_rows(registry: dict[str, list[str]]) -> str:
    rows = []
    for name in UR_REGISTRY_TYPES:
        assert name in registry, f"the type registry no longer lists {name}"
        listed = registry[name] + ([""] * (3 - len(registry[name])))
        rows.append("  {" + ", ".join(f'"{n}"' for n in listed[:3]) + "},")
    return "\n".join(rows)


# --- UR decoding -----------------------------------------------------------------------------
#
# The decoders that camera bytes reach: app/qrcode/qrscan.c hands a scanned UR straight to
# cbor_decode_eth_sign_request, cbor_decode_psbt / cbor_decode_tagged_psbt,
# cbor_decode_btc_sign_request and cbor_decode_dev_auth. Those four are the entry points, so this
# section builds payloads for them and says which ones the schema admits.
#
# Nothing here is a round trip through the code under test: the CBOR is built by the encoders above,
# which share no code with the generated decoders, and the verdict for each row comes from the schema
# documents asserted below -- ERC-4527 for the Ethereum type, the repo's own cddl/ur.cddl for the two
# families no outside document defines (btc-sign-request and dev-auth). A row that is accepted with a
# value a caller cannot use says so.

def cbor_int(value: int) -> bytes:
    if value >= 0:
        return cbor_uint(value)
    return cbor_head(1, -1 - value)


def cbor_bytes(data: bytes) -> bytes:
    return cbor_head(2, len(data)) + data


def cbor_text(text: str) -> bytes:
    raw = text.encode()
    return cbor_head(3, len(raw)) + raw


def cbor_tag(tag: int, inner: bytes) -> bytes:
    return cbor_head(6, tag) + inner


def cbor_array(items: list[bytes]) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


def cbor_map(pairs: list[tuple[int, bytes]]) -> bytes:
    """A definite-length map whose keys are already in the ascending order canonical CBOR wants."""
    return cbor_head(5, len(pairs)) + b"".join(cbor_uint(k) + v for k, v in pairs)


def cbor_head_wide(major: int, length: int) -> bytes:
    """The same length in the next head width up: not canonical, and the point of several rows."""
    if length < 24:
        return bytes([(major << 5) | 24, length])
    if length < 256:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    raise ValueError(length)


def cbor_uuid(raw: bytes) -> bytes:
    return cbor_tag(37, cbor_bytes(raw))


def cbor_keypath(components: list[tuple[int | None, bool]], fingerprint: int | None = None,
                 depth: int | None = None) -> bytes:
    """#6.304(crypto-keypath). path-component is a CDDL *group*, so inside [0*10 path-component] it
    splices into the enclosing array: five components are ten elements, index then is-hardened, and
    a component with no index contributes only its bool. The paper's own example says so -- see the
    tag 40304 keypath in bc_hdkey.md, which is array(10) over 44', 60', 0', 0, 0."""
    flat: list[bytes] = []
    for index, hardened in components:
        if index is not None:
            flat.append(cbor_int(index))
        flat.append(b"\xf5" if hardened else b"\xf4")
    pairs = [(1, cbor_head(4, len(flat)) + b"".join(flat))]
    if fingerprint is not None:
        pairs.append((2, cbor_uint(fingerprint)))
    if depth is not None:
        pairs.append((3, cbor_uint(depth)))
    return cbor_tag(304, cbor_map(pairs))


def ur_decode_spec_checks() -> tuple[str, str]:
    """The documents the rows below are read from, checked while generating so a header cannot be
    regenerated against a spec that stopped saying what these rows assume."""
    erc = fetch("erc-4527.md")
    for label, num in (("request-id", 1), ("sign-data", 2), ("data-type", 3), ("chain-id", 4),
                       ("derivation-path", 5), ("address", 6)):
        assert re.search(rf"^{label} = {num}\b", erc, re.M), \
            f"ERC-4527 no longer labels {label} as {num}, so the eth rows would be encoding a map "\
            f"the schema does not describe"
    assert re.search(r"derivation-path: #\d\.304\(crypto-keypath\)", erc), \
        "ERC-4527 no longer tags the derivation path 304"
    assert "eth-address-bytes = bytes .size 20" in erc, "the address is no longer exactly 20 bytes"
    assert re.search(r"^eth-transaction-data\s*=\s*1", erc, re.M) and \
           re.search(r"^eth-typed-transaction\s*=\s*4", erc, re.M), \
        "the data-type choice is no longer 1..4"
    assert "data-type: #3.401(sign-data-type)" in erc and "type: int .default 1" in erc, \
        "ERC-4527's data-type is no longer a defaulted int behind a #3.401, so the note in the " \
        "header about how the shell models data-type needs rewriting"

    iana = fetch("cbor_tags.xhtml")
    assert re.search(r"<td>37</td>\s*<td>byte string</td>\s*<td>Binary UUID", iana), \
        "tag 37 is no longer a byte string holding a Binary UUID in the IANA registry"

    cddl = (HERE.parent.parent / "cddl" / "ur.cddl").read_text()
    assert "#6.304(crypto-keypath)" in cddl
    for line in ("request-id = 1", "sign-data = 2", "data-type = 3", "chain-id = 4",
                 "derivation-path = 5", "address = 6", "uuid = #6.37(bstr)",
                 "components: [0*10 path-component]", "btc-derivation-paths: [0*1 #6.304(crypto-keypath)]",
                 "challenge: bstr .size 32", "auth-sig: bstr .size 64", "eth-address-bytes = bstr .size 20"):
        assert line in cddl, f"cddl/ur.cddl no longer carries {line!r}"
    return erc, iana


def ur_decode_vectors() -> str:
    erc, iana = ur_decode_spec_checks()
    cddl = (HERE.parent.parent / "cddl" / "ur.cddl").read_text()

    tx_data = bytes(range(24))
    typed = b"\x19\x01\x04hello"
    addr = bytearray(20)
    addr[0], addr[19] = 0xab, 0xcd
    addr = bytes(addr)
    uid = bytes(range(16))
    NO_INDEX = 0xFFFFFFFF
    path_m = [(44, True), (60, True), (0, True), (0, False), (0, False)]

    # --- rows: (name, cbor, accept, constraint, expectations) -------------------------------
    eth = []

    def eth_row(name, cbor, accept, constraint="", **expect):
        eth.append((name, cbor, accept, constraint, expect))

    eth_row("minimal: sign-data, data-type 1, an empty keypath",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([]))]), 1,
            sign_data=tx_data, data_type=1, path_count=0)
    eth_row("all seven fields, m/44'/60'/0'/0/0",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_uint(1)), (5, cbor_keypath(path_m)), (6, cbor_bytes(addr)),
                      (7, cbor_text("MetaMask"))]), 1,
            request_id=uid, sign_data=tx_data, data_type=1, chain_id=1, has_chain_id=1,
            path_index=[44, 60, 0, 0, 0], path_hardened=[1, 1, 1, 0, 0], address=addr, origin="MetaMask")
    eth_row("typed data, chain id 137, keypath with fingerprint and depth",
            cbor_map([(2, cbor_bytes(typed)), (3, cbor_uint(2)), (4, cbor_uint(137)),
                      (5, cbor_keypath([(84, True)], fingerprint=0x12345678, depth=3))]), 1,
            sign_data=typed, data_type=2, chain_id=137, has_chain_id=1,
            path_index=[84], path_hardened=[1], source_fingerprint=0x12345678, depth=3)
    eth_row("raw bytes type, negative chain id",
            cbor_map([(2, cbor_bytes(b"\x00")), (3, cbor_uint(3)), (4, cbor_int(-1)),
                      (5, cbor_keypath([]))]), 1,
            sign_data=b"\x00", data_type=3, chain_id=-1, has_chain_id=1, path_count=0)
    eth_row("empty sign-data is a bstr with no size constraint",
            cbor_map([(2, cbor_bytes(b"")), (3, cbor_uint(4)), (5, cbor_keypath([]))]), 1,
            sign_data=b"", data_type=4, path_count=0)
    eth_row("ten components, the most the schema allows",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([(i, False) for i in range(10)]))]), 1,
            sign_data=tx_data, data_type=1, path_index=list(range(10)), path_hardened=[0] * 10)
    eth_row("a hardened marker with no child index, so the component is one long",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([(None, True), (7, False)]))]), 1,
            sign_data=tx_data, data_type=1, path_index=[None, 7], path_hardened=[1, 0])
    eth_row("origin as an empty string",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)), (5, cbor_keypath([])),
                      (7, cbor_text(""))]), 1,
            sign_data=tx_data, data_type=1, path_count=0, origin="")
    eth_row("tag 37 around a short bstr: the registry says a UUID is 16 bytes, the schema does not",
            cbor_map([(1, cbor_uuid(b"\x01\x02\x03")), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([]))]), 1,
            request_id=b"\x01\x02\x03", sign_data=tx_data, data_type=1, path_count=0)

    eth_row("data-type 5 is outside the choice",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(5)), (5, cbor_keypath([]))]), 0,
            "sign-data-type is 1..4")
    eth_row("data-type 0",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(0)), (5, cbor_keypath([]))]), 0,
            "sign-data-type is 1..4")
    eth_row("no sign-data", cbor_map([(3, cbor_uint(1)), (5, cbor_keypath([]))]), 0,
            "sign-data is required")
    eth_row("no data-type", cbor_map([(2, cbor_bytes(tx_data)), (5, cbor_keypath([]))]), 0,
            "data-type is required")
    eth_row("no derivation-path", cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1))]), 0,
            "derivation-path is required")
    eth_row("derivation-path without its tag",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_map([(1, cbor_array([]))]))]), 0,
            "derivation-path is #6.304(crypto-keypath)")
    eth_row("derivation-path tagged with another tag",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_tag(303, cbor_map([(1, cbor_array([]))])))]), 0,
            "derivation-path is #6.304(crypto-keypath)")
    eth_row("address is 20 bytes, so 19 is refused",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)), (5, cbor_keypath([])),
                      (6, cbor_bytes(bytes(19)))]), 0, "eth-address-bytes = bstr .size 20")
    eth_row("address is 20 bytes, so 21 is refused",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)), (5, cbor_keypath([])),
                      (6, cbor_bytes(bytes(21)))]), 0, "eth-address-bytes = bstr .size 20")
    eth_row("eleven components is one past the bound",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([(i, False) for i in range(11)]))]), 0,
            "components: [0*10 path-component]")
    eth_row("a request-id that is a bare bstr, not tag 37",
            cbor_map([(1, cbor_bytes(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([]))]), 0, "uuid = #6.37(bstr)")
    eth_row("child index at 2^31: the schema bounds it below, nothing enforces it",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([(2**31, False)]))]), 1,
            "child-index = uint31 = uint32 .lt 2^31, and the index is handed to the caller anyway",
            sign_data=tx_data, data_type=1, path_index=[2**31], path_hardened=[0])
    eth_row("a negative child index",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([(-1, False)]))]), 0, "child-index is a uint31")
    keypath_hardened_as_int = cbor_tag(304, cbor_map([
        (1, cbor_array([cbor_uint(0), cbor_uint(1)])),
    ]))
    eth_row("is-hardened as an integer rather than a bool",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)), (5, keypath_hardened_as_int)]), 0,
            "is-hardened = bool")
    eth_row("the keypath tag the type paper uses now, 40304, is not the one this schema declares",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_tag(40304, cbor_map([(1, cbor_array([]))])))]), 0,
            "cddl/ur.cddl tags crypto-keypath 304; BCR-2020-007 has since moved it to 40304")
    eth_row("keypath depth 256 is past uint8",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([], depth=256))]), 0, "depth: uint8 = uint .size 1")
    eth_row("source-fingerprint 0: .gt 0 is not enforced either",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([], fingerprint=0))]), 1,
            "source-fingerprint: uint32 .gt 0, dropped by the generator like the .lt on child-index",
            sign_data=tx_data, data_type=1, path_count=0, source_fingerprint=0)
    eth_row("sign-data as text rather than bstr",
            cbor_map([(2, cbor_text("nope")), (3, cbor_uint(1)), (5, cbor_keypath([]))]), 0,
            "sign-data-bytes = bstr")
    eth_row("the whole request as an array instead of a map",
            cbor_array([cbor_bytes(tx_data), cbor_uint(1), cbor_keypath([])]), 0,
            "eth-sign-request is a map")
    eth_row("an empty map", cbor_map([]), 0, "sign-data, data-type and derivation-path are required")
    eth_row("no bytes at all", b"", 0, "there is nothing to decode")
    eth_row("trailing bytes after a complete request",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (5, cbor_keypath([]))]) + b"\x00", 1,
            "the decoder stops at the first whole item and leaves the rest unread",
            sign_data=tx_data, data_type=1, path_count=0)
    eth_row("a length head wider than canonical: sign-data of 1 as 0x18 0x01",
            cbor_head(5, 3) + cbor_uint(2) + cbor_head_wide(2, len(tx_data)) + tx_data
            + cbor_uint(3) + cbor_uint(1) + cbor_uint(5) + cbor_keypath([]), 0,
            "the build defines ZCBOR_CANONICAL")
    eth_row("an indefinite-length map",
            b"\xbf" + cbor_uint(2) + cbor_bytes(tx_data) + cbor_uint(3) + cbor_uint(1)
            + cbor_uint(5) + cbor_keypath([]) + b"\xff", 0,
            "the build defines ZCBOR_CANONICAL")
    eth_row("keys out of canonical order",
            cbor_head(5, 3) + cbor_uint(3) + cbor_uint(1) + cbor_uint(2) + cbor_bytes(tx_data)
            + cbor_uint(5) + cbor_keypath([]), 0, "canonical CBOR orders map keys ascending")

    btc = []

    def btc_row(name, cbor, accept, constraint="", **expect):
        btc.append((name, cbor, accept, constraint, expect))

    btc_row("minimal btc-sign-request",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([cbor_keypath(path_m)]))]), 1,
            request_id=uid, sign_data=tx_data, data_type=1, path_index=[44, 60, 0, 0, 0],
            path_hardened=[1, 1, 1, 0, 0])
    btc_row("with an address and an origin",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(b"message")), (3, cbor_uint(1)),
                      (4, cbor_array([cbor_keypath([(0, False)])])),
                      (5, cbor_array([cbor_text("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")])),
                      (6, cbor_text("Sparrow"))]), 1,
            request_id=uid, sign_data=b"message", data_type=1, path_index=[0], path_hardened=[0],
            origin="Sparrow", btc_address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    btc_row("no derivation paths at all is within [0*1]",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([]))]), 1,
            request_id=uid, sign_data=tx_data, data_type=1, path_count=0)
    btc_row("data-type 2 is not a btc-data-type, and nothing stores the field to check later",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(2)),
                      (4, cbor_array([cbor_keypath([])]))]), 0, "btc-data-type = btc-message = 1")
    btc_row("two derivation paths is past [0*1]",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([cbor_keypath([]), cbor_keypath([])]))]), 0,
            "btc-derivation-paths: [0*1 #6.304(crypto-keypath)]")
    btc_row("two addresses is past [0*1]",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([cbor_keypath([])])),
                      (5, cbor_array([cbor_text("a"), cbor_text("b")]))]), 0,
            "btc-addresses: [0*1 btc-address]")
    btc_row("no request-id",
            cbor_map([(2, cbor_bytes(tx_data)), (3, cbor_uint(1)), (4, cbor_array([]))]), 0,
            "request-id is required")
    btc_row("request-id without its tag",
            cbor_map([(1, cbor_bytes(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([]))]), 0, "uuid = #6.37(bstr)")
    btc_row("origin as a bstr rather than text",
            cbor_map([(1, cbor_uuid(uid)), (2, cbor_bytes(tx_data)), (3, cbor_uint(1)),
                      (4, cbor_array([])), (6, cbor_bytes(b"Sparrow"))]), 0, "btc-origin: text")

    psbt = []

    def psbt_row(name, cbor, accept, tagged, constraint="", payload=None):
        psbt.append((name, cbor, accept, tagged, constraint, payload))

    one = b"\x70\x73\x62\x74\xff\x01" + bytes(40)
    psbt_row("a plain bstr, which is what psbt = bstr says", cbor_bytes(one), 1, 0, payload=one)
    psbt_row("an empty bstr", cbor_bytes(b""), 1, 0, payload=b"")
    psbt_row("tag 310 around a bstr", cbor_tag(310, cbor_bytes(one)), 1, 1, payload=one)
    psbt_row("tag 310 is not accepted by the untagged decoder", cbor_tag(310, cbor_bytes(one)), 0, 0,
             "psbt = bstr")
    psbt_row("a plain bstr is not accepted by the tagged decoder", cbor_bytes(one), 0, 1,
             "tagged-psbt = #6.310(psbt)")
    psbt_row("tag 311 is not the psbt tag", cbor_tag(311, cbor_bytes(one)), 0, 1,
             "tagged-psbt = #6.310(psbt)")
    psbt_row("text rather than bstr", cbor_text("psbt"), 0, 0, "psbt = bstr")
    psbt_row("an array of bstrs", cbor_array([cbor_bytes(one)]), 0, 0, "psbt = bstr")
    psbt_row("tag 310 around text", cbor_tag(310, cbor_text("psbt")), 0, 1, "psbt = bstr")
    psbt_row("trailing bytes after the bstr: the decoder stops at the first whole item",
             cbor_bytes(one) + b"\xf6", 1, 0, "the rest of the payload is left unread", payload=one)
    psbt_row("empty payload", b"", 0, 0, "there is nothing to decode")

    dev = []

    def dev_row(name, cbor, accept, constraint="", **expect):
        dev.append((name, cbor, accept, constraint, expect))

    dev_row("init step alone", cbor_map([(1, cbor_uint(1))]), 1, step=1)
    dev_row("server step, all fields present",
            cbor_map([(1, cbor_uint(3)), (2, cbor_uuid(uid)), (3, cbor_uint(1700000000)),
                      (4, cbor_uint(1700000600)), (5, cbor_uint(7)),
                      (6, cbor_bytes(bytes(32))), (7, cbor_bytes(bytes(64)))]), 1,
            step=3, dev_id=uid, first_auth=1700000000, auth_time=1700000600, auth_count=7,
            challenge=bytes(32), auth_sig=bytes(64))
    dev_row("device step with a challenge only",
            cbor_map([(1, cbor_uint(2)), (6, cbor_bytes(bytes(range(32))))]), 1,
            step=2, challenge=bytes(range(32)))
    dev_row("step 0 is not one of the three", cbor_map([(1, cbor_uint(0))]), 0,
            "dev-auth-step-type = 1 / 2 / 3")
    dev_row("step 4 is not one of the three", cbor_map([(1, cbor_uint(4))]), 0,
            "dev-auth-step-type = 1 / 2 / 3")
    dev_row("no step", cbor_map([(2, cbor_uuid(uid))]), 0, "dev-auth-step is required")
    dev_row("challenge of 31 bytes",
            cbor_map([(1, cbor_uint(2)), (6, cbor_bytes(bytes(31)))]), 0, "challenge: bstr .size 32")
    dev_row("challenge of 33 bytes",
            cbor_map([(1, cbor_uint(2)), (6, cbor_bytes(bytes(33)))]), 0, "challenge: bstr .size 32")
    dev_row("auth-sig of 63 bytes",
            cbor_map([(1, cbor_uint(2)), (7, cbor_bytes(bytes(63)))]), 0, "auth-sig: bstr .size 64")
    dev_row("auth-count past uint32",
            cbor_map([(1, cbor_uint(2)), (5, cbor_uint(2**32))]), 0, "auth-count: uint32")
    dev_row("a negative timestamp",
            cbor_map([(1, cbor_uint(2)), (3, cbor_int(-1))]), 0, "timestamp = uint .size 4")
    dev_row("dev-id as a bare bstr",
            cbor_map([(1, cbor_uint(2)), (2, cbor_bytes(uid))]), 0, "dev-id: uuid = #6.37(bstr)")

    # --- emission ---------------------------------------------------------------------------
    blobs: list[tuple[str, bytes]] = []
    tables: list[tuple[str, list[int], str]] = []

    def blob(prefix: str, data: bytes) -> str:
        name = f"{prefix}_{len(blobs)}"
        blobs.append((name, data))
        return name

    def uint_table(values: list[int]) -> str:
        name = f"path_{len(tables)}"
        tables.append((name, values, "uint32_t"))
        return name

    def bool_table(values: list[int]) -> str:
        name = f"hard_{len(tables)}"
        tables.append((name, values, "uint8_t"))
        return name

    def opt_bytes_expr(value) -> str:
        if value is None:
            return "0, 0"
        return f"{blob('b', value)}, {len(value)}"

    eth_rows = []
    for name, cbor, accept, constraint, ex in eth:
        fields = [f'"{name}"', blob('eth', cbor), str(len(cbor)), str(accept), f'"{constraint}"']
        fields += [opt_bytes_expr(ex.get("sign_data")), str(ex.get("data_type", 0))]
        fields += [str(ex.get("chain_id", 0)), str(ex.get("has_chain_id", 0))]
        idx = ex.get("path_index")
        hard = ex.get("path_hardened")
        if idx:
            fields += [uint_table([NO_INDEX if v is None else v for v in idx]),
                       bool_table(hard), str(len(idx))]
        else:
            fields += ["0", "0", str(ex.get("path_count", 0))]
        fields += [opt_bytes_expr(ex.get("address")), opt_bytes_expr(ex.get("request_id"))]
        fields += [str(ex.get("source_fingerprint", 0)), str(ex.get("depth", 0)),
                   str(1 if "source_fingerprint" in ex else 0), str(1 if "depth" in ex else 0)]
        fields += [f'"{ex.get("origin")}"' if ex.get("origin") is not None else "0"]
        eth_rows.append("  {" + ", ".join(fields) + "},")

    btc_rows = []
    for name, cbor, accept, constraint, ex in btc:
        fields = [f'"{name}"', blob('btc', cbor), str(len(cbor)), str(accept), f'"{constraint}"']
        fields += [opt_bytes_expr(ex.get("sign_data")), str(ex.get("data_type", 0))]
        idx = ex.get("path_index")
        if idx:
            fields += [uint_table(idx), bool_table(ex.get("path_hardened", [])), str(len(idx))]
        else:
            fields += ["0", "0", str(ex.get("path_count", 0))]
        fields += [opt_bytes_expr(ex.get("request_id"))]
        fields += [f'"{ex.get("origin")}"' if ex.get("origin") is not None else "0"]
        fields += [f'"{ex.get("btc_address")}"' if ex.get("btc_address") else "0"]
        btc_rows.append("  {" + ", ".join(fields) + "},")

    psbt_rows = []
    for name, cbor, accept, tagged, constraint, payload in psbt:
        psbt_rows.append("  {" + ", ".join(
            [f'"{name}"', blob('ps', cbor), str(len(cbor)), str(accept), f'"{constraint}"',
             str(tagged), opt_bytes_expr(payload)]) + "},")

    dev_rows = []
    for name, cbor, accept, constraint, ex in dev:
        fields = [f'"{name}"', blob('dv', cbor), str(len(cbor)), str(accept), f'"{constraint}"',
                  str(ex.get("step", 0)), opt_bytes_expr(ex.get("dev_id")),
                  str(ex.get("first_auth", 0)), str(ex.get("auth_time", 0)),
                  str(ex.get("auth_count", 0)),
                  str(1 if "first_auth" in ex else 0), str(1 if "auth_time" in ex else 0),
                  str(1 if "auth_count" in ex else 0),
                  opt_bytes_expr(ex.get("challenge")), opt_bytes_expr(ex.get("auth_sig"))]
        dev_rows.append("  {" + ", ".join(fields) + "},")

    blob_defs = []
    for name, data in blobs:
        if data:
            blob_defs.append(f"static const uint8_t {name}[] = {{\n{c_array(data, 16)}\n}};\n")
        else:
            blob_defs.append(f"static const uint8_t {name}[] = {{0}};\n")
    for name, values, ctype in tables:
        blob_defs.append(f"static const {ctype} {name}[] = {{{', '.join(str(v) for v in values)}}};\n")

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    head = f"""#ifndef VECTORS_UR_DECODE_H
#define VECTORS_UR_DECODE_H

/* spec: https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-4527.md
 * sha256 {digest(erc)}
 *     https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
 * sha256 {digest(iana)}
 *     cddl/ur.cddl in this repository
 * sha256 {digest(cddl)}
 *
 * What the CBOR decoders that scanned URs reach are required to accept and to refuse. Those four
 * entry points -- eth-sign-request, psbt and tagged-psbt, btc-sign-request and dev-auth -- are the
 * ones app/qrcode/qrscan.c hands camera bytes to, so every payload here is something a QR code in
 * front of the lens can carry.
 *
 * The bytes are built by generate.py's own encoders, which share nothing with the decoders under
 * test, from the field numbers and constraints the documents above state -- the generator refuses to
 * write this header unless ERC-4527 still labels the request fields 1..6, still tags the derivation
 * path 304, still fixes an address at 20 bytes and still restricts data-type to 1..4, and unless the
 * IANA registry still gives tag 37 to a byte string holding a Binary UUID. No expectation is a round
 * trip through the code under test.
 *
 * btc-sign-request and dev-auth have no document outside this repository, so their rows are read
 * from cddl/ur.cddl, whose sha256 is above: for those two families a schema change moves the
 * vectors, and the constraint column says which clause of the CDDL each refusal comes from. Two rows
 * A handful of rows record behaviour rather than a defect, so that a change to it shows up as a
 * failing test. The schema puts no size on a uuid, so a tag 37 around three bytes is accepted as a
 * three byte request id. `child-index = uint31 = uint32 .lt 2^31` is not enforced by the generated
 * decoder, and core.c's core_set_derivation_path() ORs the hardened bit in without bounding the
 * index, so an index of 2^31 spells the same BIP32 path as 0'. Neither is a zcbor quirk to argue
 * with: the generated decoders do enforce .size (a uint32 field checks <= UINT32_MAX, a challenge
 * checks .len <= 32) but emit a plain zcbor_uint32_decode for .gt and .lt, so every bound written
 * that way in cddl/ur.cddl is documentation only, while the bounds written with .size are checked:
 * the row asking for depth 256 is refused, the two above are not. And zcbor reports success once one
 * whole item has been read, so a psbt with a byte appended decodes and reports the shorter count;
 * for the same reason a btc-sign-request truncated inside its optional tail decodes with those
 * fields absent, which is why core_btc.c requires the derivation paths rather than relying on the
 * decode to fail.
 *
 * One disagreement with the document is deliberate. ERC-4527 writes the derivation path as
 * `#5.304(crypto-keypath)`, and 304 is a CBOR tag, which belongs to major type 6; cddl/ur.cddl and
 * every decoder in the field tag it with #6.304, so that is what the rows here build. The generator
 * accepts either digit so this note, not a green build, is what tells the next reader about it.
 *
 * The same document models data-type as `#3.401(sign-data-type)` over `type: int .default 1`, a
 * defaulted integer inside a tagged map, while cddl/ur.cddl spells it as the plain choice of
 * eth-transaction-data / eth-typed-data / eth-raw-bytes / eth-typed-transaction that the document
 * also lists. So a sender that encoded the map form would be refused here, and none of the rows
 * below establishes which form a real wallet sends. That question belongs to whoever next wires a
 * wallet to this scanner; the rows test the choice the shell declared.
 *
 * A path index of UR_DECODE_PATH_NO_INDEX means the component carried no child index at all, which
 * the CDDL allows: path-component = (? child-index, is-hardened).
 */
#define UR_DECODE_PATH_NO_INDEX 0xffffffffu

enum {{
  UR_DECODE_PSBT_UNTAGGED = 0,
  UR_DECODE_PSBT_TAGGED = 1,
}};

typedef struct {{
  const char* name;
  const uint8_t* cbor;
  uint16_t cbor_len;
  int accept;
  const char* constraint;
  const uint8_t* sign_data;
  uint16_t sign_data_len;
  uint8_t data_type;
  int32_t chain_id;
  uint8_t has_chain_id;
  const uint32_t* path_index;
  const uint8_t* path_hardened;
  uint8_t path_count;
  const uint8_t* address;
  uint16_t address_len;
  const uint8_t* request_id;
  uint16_t request_id_len;
  uint32_t source_fingerprint;
  uint32_t depth;
  uint8_t has_fingerprint;
  uint8_t has_depth;
  const char* origin;
}} ur_decode_eth_case_t;

typedef struct {{
  const char* name;
  const uint8_t* cbor;
  uint16_t cbor_len;
  int accept;
  const char* constraint;
  const uint8_t* sign_data;
  uint16_t sign_data_len;
  uint8_t data_type;
  const uint32_t* path_index;
  const uint8_t* path_hardened;
  uint8_t path_count;
  const uint8_t* request_id;
  uint16_t request_id_len;
  const char* origin;
  const char* btc_address;
}} ur_decode_btc_case_t;

typedef struct {{
  const char* name;
  const uint8_t* cbor;
  uint16_t cbor_len;
  int accept;
  const char* constraint;
  int tagged;
  const uint8_t* payload;
  uint16_t payload_len;
}} ur_decode_psbt_case_t;

typedef struct {{
  const char* name;
  const uint8_t* cbor;
  uint16_t cbor_len;
  int accept;
  const char* constraint;
  uint8_t step;
  const uint8_t* dev_id;
  uint16_t dev_id_len;
  uint32_t first_auth;
  uint32_t auth_time;
  uint32_t auth_count;
  uint8_t has_first_auth;
  uint8_t has_auth_time;
  uint8_t has_auth_count;
  const uint8_t* challenge;
  uint16_t challenge_len;
  const uint8_t* auth_sig;
  uint16_t auth_sig_len;
}} ur_decode_dev_case_t;

{(chr(10).join(blob_defs))}
static const ur_decode_eth_case_t UR_DECODE_ETH_CASES[] = {{
{chr(10).join(eth_rows)}
}};

static const ur_decode_btc_case_t UR_DECODE_BTC_CASES[] = {{
{chr(10).join(btc_rows)}
}};

static const ur_decode_psbt_case_t UR_DECODE_PSBT_CASES[] = {{
{chr(10).join(psbt_rows)}
}};

static const ur_decode_dev_case_t UR_DECODE_DEV_CASES[] = {{
{chr(10).join(dev_rows)}
}};

#endif /* VECTORS_UR_DECODE_H */
"""
    return head


def ur_vectors() -> str:
    paper = fetch("bc_multipart_ur.md")

    cddl = paper[paper.index("part = ["):paper.index("]", paper.index("part = ["))]
    for field in ("seqNum", "seqLen", "messageLen", "checksum", "data"):
        assert field in cddl, f"the part CDDL no longer carries {field}"
    assert (cddl.index("seqNum") < cddl.index("seqLen") < cddl.index("messageLen")
            < cddl.index("checksum") < cddl.index("data")), "the part fields changed order"
    assert "MUST be rejected" in paper, \
        "a part that disagrees with the first received one is no longer required to be rejected"
    assert "(seqNum || checksum) -> SHA256 -> Xoshiro256" in paper, "the rateless seed rule changed"
    assert "padded with zeroes" in paper, "the last fragment is no longer zero padded"
    assert "MAY be chosen by the implementer" in paper, "the fragment size is no longer a choice"

    rng_stream = parse_mur_rng_stream(paper)
    seeded = Xoshiro256(b"Wolf")
    assert [seeded.next() % 100 for _ in rng_stream] == rng_stream, \
        "this xoshiro256** model does not reproduce the document's own stream"

    parts = parse_mur_parts(paper)
    assert len(parts) == 20, f"expected 20 encoder parts, parsed {len(parts)}"
    assert [p[0] for p in parts] == list(range(1, 21)), "the published parts are out of order"
    message = mur_message(256)
    checksum = zlib.crc32(message) & 0xffffffff
    assert {p[1] for p in parts} == {9}, "the parts are no longer a sequence of nine"
    assert {p[2] for p in parts} == {256}, "the message length the parts carry changed"
    assert {p[3] for p in parts} == {checksum}, \
        "the checksum the parts carry is not crc32 of the message rebuilt from the document"
    assert {len(p[4]) for p in parts} == {29}, "the fragments are no longer 29 bytes each"

    fragment_len = 29
    fragments = [message[i:i + fragment_len] for i in range(0, 256, fragment_len)]
    fragments[-1] += bytes(fragment_len - len(fragments[-1]))
    assert parts[0][4] == fragments[0], "the first published part is not the first fragment"
    assert parts[8][4] == fragments[-1], "the last simple part is not the padded last fragment"

    choices = parse_mur_fragment_choices(paper)
    assert len(choices) == 50, f"expected 50 fragment choices, parsed {len(choices)}"
    assert choices[:11] == [[i] for i in range(11)], "the first seqLen choices are not the fragments"
    fragment_checksum = zlib.crc32(mur_message(1024)) & 0xffffffff

    (part_fields, part_cbor) = parse_mur_part_cbor(paper)
    assert cbor_part(*part_fields) == part_cbor, \
        "the document's part fields no longer serialize to the document's own CBOR"

    published = []
    for source in ("bc_hdkey.md", "bc_output_desc.md", "bc_account.md"):
        found = parse_published_pairs(source)
        assert found, f"{source} no longer publishes an example as CBOR hex and as UR text together"
        published += found
    assert all(len(cbor) <= 1024 for _, _, cbor in published), "a published example outgrew the row"

    registry = parse_registry_labels()

    rows = []
    for label, ur, cbor in published:
        rows.append(f'  {{"{label}",\n   "{ur}",\n   {{ {c_array(cbor, 16, "   ")} }},\n'
                    f'   {len(cbor)}}},')

    head = """#ifndef VECTORS_UR_H
#define VECTORS_UR_H

/* What the UR framing and the fountain codes of app/ur are required to produce, by Blockchain
 * Commons' BCR-2024-001 (multipart UR) and by the type papers that publish an example twice, once
 * as CBOR hex and once as UR text.
 *
 * No expectation here is a round trip through the code under test. The 20 parts, the 50 fragment
 * choices and the CBOR of one part are copied out of the document's own test vectors. The message
 * they were computed over is rebuilt from the generator the document names, and generate.py refuses
 * to emit anything unless that rebuild reproduces the document's published RNG stream, its published
 * checksum and its published first and last fragments.
 *
 * Left out, and why:
 *   - the fragment size a sender uses. The document leaves it to the implementer, so the device's
 *     choice is not a conformance question; what has to conform is that every part of one sequence
 *     carries fragments of a single length, the last zero padded.
 *   - URs whose label the device does not register. The registry was renamed once: `psbt`, `hdkey`,
 *     `output-descriptor` and `account-descriptor` now list ~~crypto-psbt~~, ~~crypto-hdkey~~,
 *     ~~crypto-output~~ and ~~crypto-account~~ as the old spellings, and the device registers only
 *     the crypto-* generation. UR_REGISTRY_LABELS carries both generations; which one the device
 *     answers to is a product decision, not a fact from this document.
 */

#include <stdbool.h>
#include <stdint.h>

#define UR_SPEC_SEQ_LEN 9
#define UR_SPEC_FRAGMENT_LEN 29
#define UR_SPEC_MESSAGE_LEN 256
#define UR_SPEC_CHECKSUM @@CHECKSUM@@

/* makeMessage(len: 256) of the document's vectors: the message all 20 parts are generated from. */
static const uint8_t UR_SPEC_MESSAGE[UR_SPEC_MESSAGE_LEN] = {
@@MESSAGE@@
};

typedef struct {
  uint32_t seq_num;
  uint32_t seq_len;
  uint32_t message_len;
  uint32_t checksum;
  uint8_t data[UR_SPEC_FRAGMENT_LEN];
} ur_spec_part_t;

/* testEncoder, run in order without skipping a part: the first nine parts are the fragments
 * themselves, the eleven after them are mixtures. */
static const ur_spec_part_t UR_SPEC_PARTS[] = {
@@PARTS@@
};

#define UR_SPEC_PARTS_COUNT (sizeof(UR_SPEC_PARTS) / sizeof(UR_SPEC_PARTS[0]))

#define UR_FRAGMENT_SEQ_LEN 11
#define UR_FRAGMENT_CHECKSUM @@FRAGMENT_CHECKSUM@@

typedef struct {
  uint32_t seq_num;
  uint16_t fragments;   /* bit i set is fragment i: the set the sender mixed into this part */
} ur_fragment_choice_t;

/* testFragmentChooser, rateless parts only: seqNum 12 through 50 of a sequence of eleven. */
static const ur_fragment_choice_t UR_FRAGMENT_CHOICES[] = {
@@CHOICES@@
};

#define UR_FRAGMENT_CHOICES_COUNT (sizeof(UR_FRAGMENT_CHOICES) / sizeof(UR_FRAGMENT_CHOICES[0]))

/* One part as its fields and as its bytes, from the document that states both. */
typedef struct {
  uint32_t seq_num;
  uint32_t seq_len;
  uint32_t message_len;
  uint32_t checksum;
  uint8_t data[5];
  uint8_t cbor[32];
  size_t cbor_len;
} ur_part_cbor_t;

static const ur_part_cbor_t UR_PART_CBOR = {
@@PART_FIELDS@@
  { @@PART_DATA@@ },
  { @@PART_CBOR@@ },
  @@PART_CBOR_LEN@@
};

typedef struct {
  const char* label;    /* as published, which is not always the spelling the device registers */
  const char* ur;       /* the published text in full */
  uint8_t cbor[1024];   /* the CBOR the same document prints for the same example */
  size_t cbor_len;
} ur_published_t;

static const ur_published_t UR_PUBLISHED[] = {
@@PUBLISHED@@
};

#define UR_PUBLISHED_COUNT (sizeof(UR_PUBLISHED) / sizeof(UR_PUBLISHED[0]))

/* The four of these types the device implements, and every spelling the registry lists for each:
 * the current one first, the struck-out ones after, then an empty string. Only the registry's own
 * types are here -- the device's other labels (eth-sign-request, btc-sign-request, btc-signature,
 * eth-signature, bytes, fs-data, fw-update, dev-auth, crypto-multi-accounts) are Keycard's and the
 * registry has never carried them. */
static const char* const UR_REGISTRY_LABELS[][3] = {
@@REGISTRY@@
};

#define UR_REGISTRY_COUNT (sizeof(UR_REGISTRY_LABELS) / sizeof(UR_REGISTRY_LABELS[0]))

#endif\t/* VECTORS_UR_H */
"""

    seq_num, seq_len, message_len, part_checksum, data = part_fields
    for token, value in (
        ("@@CHECKSUM@@", f"{checksum}u"),
        ("@@MESSAGE@@", c_array(message, 12, "  ")),
        ("@@PARTS@@", "\n".join(ur_part_row(part) for part in parts)),
        ("@@FRAGMENT_CHECKSUM@@", f"{fragment_checksum}u"),
        ("@@CHOICES@@", "\n".join(ur_choice_row(12 + i, choice)
                                  for i, choice in enumerate(choices[11:]))),
        ("@@PART_FIELDS@@", f"  {seq_num}, {seq_len}, {message_len}, {part_checksum}u,"),
        ("@@PART_DATA@@", c_array(data, 5, "   ")),
        ("@@PART_CBOR@@", c_array(part_cbor, 8, "   ")),
        ("@@PART_CBOR_LEN@@", str(len(part_cbor))),
        ("@@PUBLISHED@@", "\n".join(rows)),
        ("@@REGISTRY@@", ur_registry_rows(registry)),
    ):
        assert token in head, f"the vectors template lost {token}"
        head = head.replace(token, value)
    assert "@@" not in head, "a vectors template placeholder survived"
    return head


# ------------------------------------------------------- OpenPGP (app/openpgp)

OPENPGP_SECP256K1_OID = bytes.fromhex("2b8104000a")
OPENPGP_UID_MAX_LEN = 255
OPENPGP_MESSAGE_MAX_LEN = 255


def openpgp_packets(data: bytes) -> list:
    """(tag, header, body) per RFC 4880 4.2, both header formats. A body whose length is not in its
    own header -- a partial body length, an indeterminate old-format length -- is an error here,
    because these vectors only ever walk a complete packet stream."""
    out, offset = [], 0
    while offset < len(data):
        ctb = data[offset]
        if not ctb & 0x80:
            raise AssertionError(f"{ctb:#04x} at {offset} is not a packet header")
        if ctb & 0x40:
            tag, pos = ctb & 0x3F, offset + 1
            first = data[pos]
            if first < 192:
                body_len, pos = first, pos + 1
            elif first < 224:
                body_len, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
            elif first == 255:
                body_len, pos = int.from_bytes(data[pos + 1:pos + 5], "big"), pos + 5
            else:
                raise AssertionError(f"partial body length {first:#04x} at {offset}")
        else:
            tag, length_type, pos = (ctb >> 2) & 0x0F, ctb & 0x03, offset + 1
            if length_type == 0:
                body_len, pos = data[pos], pos + 1
            elif length_type == 1:
                body_len, pos = int.from_bytes(data[pos:pos + 2], "big"), pos + 2
            elif length_type == 2:
                body_len, pos = int.from_bytes(data[pos:pos + 4], "big"), pos + 4
            else:
                raise AssertionError(f"indeterminate length at {offset}")
        assert pos + body_len <= len(data), "a packet runs past the end of the stream"
        out.append((tag, data[offset:pos], data[pos:pos + body_len]))
        offset = pos + body_len
    return out


def openpgp_wrap(tag: int, body: bytes, form: str) -> bytes:
    """A packet header in the requested format.

    "old" and "new" are the shortest header of that format, which is what GnuPG writes. The numbered
    forms force one of the definite-length headers RFC 4880 4.2.1 and 4.2.2 define, including the
    longer ones no implementation writes for a body this small: old format counts length types
    0, 1 and 2 as one, two and four octets, new format counts one, two and five octets, and new
    format's two-octet form only exists for bodies of 192 to 8383 octets.
    """
    old_length_types = {"old1": 0, "old2": 1, "old4": 2}
    if form in old_length_types:
        length_type = old_length_types[form]
        octets = 1 << length_type
        assert len(body) < (1 << (8 * octets)), f"{len(body)} octets in a {octets}-octet length"
        return (bytes([0x80 | (tag << 2) | length_type]) + len(body).to_bytes(octets, "big") + body)
    if form == "new1":
        assert len(body) < 192, f"{len(body)} octets is not a one-octet new-format length"
        return bytes([0xC0 | tag, len(body)]) + body
    if form == "new2":
        assert 192 <= len(body) < 8384, f"{len(body)} octets is not a two-octet new-format length"
        return bytes([0xC0 | tag, 192 + ((len(body) - 192) >> 8), (len(body) - 192) & 0xFF]) + body
    if form == "new5":
        assert len(body) < (1 << 32)
        return bytes([0xC0 | tag, 255]) + len(body).to_bytes(4, "big") + body
    if form == "old":
        return openpgp_wrap(tag, body, "old1" if len(body) < 256 else ("old2" if len(body) < 65536 else "old4"))
    return openpgp_wrap(tag, body, "new1" if len(body) < 192 else ("new2" if len(body) < 8384 else "new5"))


def openpgp_header_forms(data: bytes) -> list:
    """(tag, octets of the length field) for every packet in a stream, shortest form assumed."""
    out = []
    for tag, header, body in openpgp_packets(data):
        out.append((tag, len(header) - 1))
    return out


def openpgp_sig_areas(body: bytes):
    """(hash material, unhashed area with its length, left 16 bits, MPIs) of a v4 signature body."""
    hashed_len = int.from_bytes(body[4:6], "big")
    pos = 6 + hashed_len
    unhashed_len = int.from_bytes(body[pos:pos + 2], "big")
    tail_start = pos
    pos += 2 + unhashed_len
    values, end = [], pos + 2
    while end < len(body):
        bits = int.from_bytes(body[end:end + 2], "big")
        count = (bits + 7) // 8
        plain = int.from_bytes(body[end + 2:end + 2 + count], "big")
        assert plain.bit_length() == bits, "an MPI whose bit count is not its significant bits"
        values.append(body[end:end + 2 + count])
        end += 2 + count
    assert end == len(body), "a signature body does not end with its MPIs"
    return (body[:6 + hashed_len], body[tail_start:tail_start + 2 + unhashed_len],
            body[pos:pos + 2], values)


def openpgp_digest(signed_data: bytes, material: bytes) -> bytes:
    """RFC 4880 5.2.4: the signed data, the signature header and its hashed subpackets, then a
    trailer of the version, 0xFF, and a count that covers the hash material and not the trailer."""
    return hashlib.sha256(signed_data + material
                          + b"\x04\xff" + len(material).to_bytes(4, "big")).digest()


def openpgp_certification_data(key_body: bytes, uid: bytes) -> bytes:
    """RFC 4880 5.2.4: 0x99 and a two-octet length before the key, 0xB4 and a four-octet length
    before the user ID."""
    return (b"\x99" + len(key_body).to_bytes(2, "big") + key_body
            + b"\xb4" + len(uid).to_bytes(4, "big") + uid)


OPENPGP_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def openpgp_der(mpi_r: bytes, mpi_s: bytes) -> bytes:
    """An (r, s) pair as an ECDSA-Signature ASN.1 value, S normalized to the low half of the order.

    GnuPG emits high-S signatures; libsecp256k1 refuses them. Normalizing before the independent
    check is what a verifier that accepts both forms does -- it is ECDSA's malleability, not a
    difference in the digest -- and the vectors keep the MPIs exactly as GnuPG wrote them.
    """
    def integer(mpi: bytes) -> bytes:
        raw = mpi[2:].lstrip(b"\x00") or b"\x00"
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    r, s = (int.from_bytes(mpi[2:], "big") for mpi in (mpi_r, mpi_s))
    if s > OPENPGP_CURVE_N // 2:
        s = OPENPGP_CURVE_N - s
    s_mpi = s.to_bytes(len(mpi_s) - 2, "big")
    body = integer(mpi_r) + integer(b"\0\0" + s_mpi)
    return b"\x30" + bytes([len(body)]) + body


def openpgp_verify(point: bytes, mpi_r: bytes, mpi_s: bytes, digest: bytes) -> bool:
    from coincurve import PublicKey

    try:
        return PublicKey(point).verify(openpgp_der(mpi_r, mpi_s), digest, hasher=None)
    except Exception:
        return False


def openpgp_fixture(name: str) -> bytes:
    path = Path(__file__).with_name("openpgp_fixture") / name
    assert path.exists(), f"{path} is missing; run tests/vectors/oracle/openpgp.sh"
    return path.read_bytes()


def openpgp_canonicalize(text: bytes) -> bytes | None:
    """What openpgp_v4_canonicalize_text does: LF becomes CRLF, an existing CRLF stays, and a CR
    that does not begin a CRLF is refused rather than guessed at."""
    out, i = bytearray(), 0
    while i < len(text):
        c = text[i:i + 1]
        if c == b"\r":
            if text[i + 1:i + 2] != b"\n":
                return None
            out += b"\r\n"
            i += 2
        elif c == b"\n":
            out += b"\r\n"
            i += 1
        else:
            out += c
            i += 1
    return bytes(out)


def openpgp_vectors() -> str:
    rfc = fetch("rfc4880.txt")
    for sentence in (
        "A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99",
        "canonicalized by converting line endings to <CR><LF>",
        "note that this number does not include these final\n   six octets",
        "A certification signature (type 0x10 through 0x13) hashes the User",
        "the constant 0xB4 for User ID certifications",
        "Two-octet field holding left 16 bits of signed hash value",
        "a two-octet scalar that is the length\n   of the MPI in bits",
        "greater than or equal to 224, and less than 255",
        "A one-octet Body Length header encodes a length of 0 to 191 octets",
        "bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192",
        "The packet has a two-octet length.  The header is 3 octets long.",
        "The packet has a four-octet length.  The header is 5 octets long.",
        "the value 255, followed by a four-octet scalar",
    ):
        assert sentence in rfc, f"RFC 4880 no longer says {sentence!r}"

    exported = openpgp_packets(openpgp_fixture("key-minimal.gpg"))
    assert [t for t, _, _ in exported] == [6, 13, 2], \
        f"the minimal export is {[t for t, _, _ in exported]}, not key, user ID, certification"
    key_body, uid, cert_body = (b for _, _, b in exported)

    assert key_body[0] == 4 and key_body[5] == 19, "the fixture key is not a v4 ECDSA key"
    assert key_body[6] == 5 and key_body[7:12] == OPENPGP_SECP256K1_OID, \
        f"the fixture key names OID {key_body[7:12].hex()}, not 1.3.132.0.10"
    creation_time = int.from_bytes(key_body[1:5], "big")
    point = key_body[14:]
    assert len(point) == 65 and point[0] == 0x04, "the fixture point is not a 65-octet SEC1 point"
    assert int.from_bytes(key_body[12:14], "big") == 515, \
        "the point MPI is not 515 bits: 64 octets plus the three significant bits of 0x04"
    assert len(key_body) == 79, "a secp256k1 v4 public key body is not 79 octets"

    assert len(uid) >= 192, (
        f"the fixture user ID is {len(uid)} octets, too short for a new-format two-octet length to "
        "exist; make the fixture key's comment longer"
    )

    published = [l.split(":")[9] for l in openpgp_fixture("report.txt").decode().splitlines()
                 if l.startswith("fpr")][0]
    fingerprint = hashlib.sha1(b"\x99" + len(key_body).to_bytes(2, "big") + key_body).digest()
    assert fingerprint.hex().upper() == published, \
        "SHA1(0x99||len||body) is not the fingerprint GnuPG publishes for this key"

    material, unhashed, left16, mpis = openpgp_sig_areas(cert_body)
    sig_type = cert_body[1]
    assert 0x10 <= sig_type <= 0x13, "the fixture signature is not a certification"
    assert cert_body[2] == 19 and cert_body[3] == 8, "the certification is not ECDSA/SHA-256"
    assert unhashed[:2] == b"\x00\x0a" and unhashed[3] == 0x10, \
        "GnuPG's unhashed area is not a 10-octet issuer-key-id block"
    assert len(mpis) == 2, "the certification does not carry exactly two MPIs"
    cert_data = openpgp_certification_data(key_body, uid)
    cert_digest = openpgp_digest(cert_data, material)
    assert cert_digest[:2] == left16, "our digest is not the one GnuPG recorded in its signature"
    assert openpgp_verify(point, mpis[0], mpis[1], cert_digest), \
        "coincurve does not accept our digest as what GnuPG signed"
    issuer_key_id = unhashed[4:12]
    cert_tail = cert_body[6 + int.from_bytes(cert_body[4:6], "big"):]
    hashed_area = material[6:]

    def subpacket(area: bytes, kind: int) -> bytes:
        """One hashed subpacket as GnuPG wrote it, length octet and all."""
        pos = 0
        while pos < len(area):
            length = area[pos]
            assert length, "a zero-length subpacket needs the two-octet length form"
            if area[pos + 1] == kind:
                return area[pos:pos + 1 + length]
            pos += 1 + length
        raise AssertionError(f"the fixture certification has no hashed subpacket {kind:#04x}")

    creation_subpacket = subpacket(hashed_area, 0x02)
    fingerprint_subpacket = subpacket(hashed_area, 0x21)
    assert len(creation_subpacket) == 6, "GnuPG's creation-time subpacket is not 05 02 <time>"
    assert int.from_bytes(creation_subpacket[2:6], "big") == creation_time, \
        "the certification was made in a different second than the key was born"
    assert fingerprint_subpacket[:3] == bytes([0x16, 0x21, 0x04]) and \
        fingerprint_subpacket[3:] == fingerprint, \
        "GnuPG's issuer-fingerprint subpacket is not 16 21 04 <the v4 fingerprint>"
    raw_sig = mpis[0][2:].rjust(32, b"\x00") + mpis[1][2:].rjust(32, b"\x00")

    text_rows, refused = [], []
    for index in range(1, 40):
        try:
            message = openpgp_fixture(f"text-{index}.msg")
            signature = openpgp_fixture(f"text-{index}.sig")
        except AssertionError:
            break
        own_material, _, want, own_mpis = openpgp_sig_areas(openpgp_packets(signature)[0][2])
        assert own_material[:4] == bytes([4, 1, 19, 8]), \
            f"text-{index} is not a v4 canonical-text ECDSA/SHA-256 signature"
        canonical = openpgp_canonicalize(message)
        if canonical is None:
            refused.append(message)
            continue
        digest = openpgp_digest(canonical, own_material)
        assert digest[:2] == want and openpgp_verify(point, own_mpis[0], own_mpis[1], digest), \
            f"text-{index}: GnuPG did not sign what our canonicalization produces"
        text_rows.append((message, own_material, digest))
    assert text_rows and len(refused) == 1, \
        f"{len(text_rows)} canonical texts and {len(refused)} refused"

    binary_body = openpgp_packets(openpgp_fixture("binary.sig"))[0][2]
    binary_material, _, binary_left16, binary_mpis = openpgp_sig_areas(binary_body)
    assert binary_body[1] == 0x00, "the binary signature is not a binary document signature"
    binary_msg = openpgp_fixture("binary.msg")
    binary_digest = openpgp_digest(binary_msg, binary_material)
    assert binary_digest[:2] == binary_left16 and \
        openpgp_verify(point, binary_mpis[0], binary_mpis[1], binary_digest), \
        "GnuPG did not sign the binary message as it came"

    def bundle(key_form, uid_form, cert_form, key=key_body, idn=uid, cert=cert_body):
        return (openpgp_wrap(6, key, key_form) + openpgp_wrap(13, idn, uid_form)
                + openpgp_wrap(2, cert, cert_form))

    def only(*packets):
        return b"".join(packets)

    key_p, uid_p, cert_p = (openpgp_wrap(6, key_body, "old"), openpgp_wrap(13, uid, "old"),
                            openpgp_wrap(2, cert_body, "old"))

    def sig_of_type(kind: int) -> bytes:
        return openpgp_wrap(2, cert_body[:1] + bytes([kind]) + cert_body[2:], "old")

    bundles = [
        ("GnuPG's own export, old-format headers", bundle("old", "old", "old"), True),
        ("the same three packets under new-format headers", bundle("new", "new", "new"), True),
        ("one header of each format", bundle("new", "old", "new"), True),
        ("the key packet missing", only(uid_p, cert_p), False),
        ("the user ID missing", only(key_p, cert_p), False),
        ("the certification missing", only(key_p, uid_p), False),
        ("a fourth packet after the certification", only(key_p, uid_p, cert_p, key_p), False),
        ("user ID and certification the other way round", only(key_p, cert_p, uid_p), False),
        ("a subkey packet where the primary key is",
         only(openpgp_wrap(14, key_body, "old"), uid_p, cert_p), False),
        ("a key packet holding a user ID body",
         only(openpgp_wrap(6, uid, "old"), uid_p, cert_p), False),
        ("an empty user ID", only(key_p, openpgp_wrap(13, b"", "old"), cert_p), False),
        ("a version 3 key body",
         only(openpgp_wrap(6, b"\x03" + key_body[1:], "old"), uid_p, cert_p), False),
        ("a version 3 certification",
         only(key_p, uid_p, openpgp_wrap(2, b"\x03" + cert_body[1:], "old")), False),
        ("a subkey binding signature where the certification is",
         only(key_p, uid_p, sig_of_type(0x18)), False),
        ("a key revocation where the certification is",
         only(key_p, uid_p, sig_of_type(0x20)), False),
        ("a certification body too short for a signature header",
         only(key_p, uid_p, openpgp_wrap(2, cert_body[:5], "old")), False),
        ("a body that stops short of the last octet the header promised",
         only(key_p, uid_p, cert_p[:-1]), False),
        ("a stream cut in the middle of the key packet", bundle("old", "old", "old")[:20], False),
        ("an old-format indeterminate length",
         only(key_p, bytes([0x80 | (13 << 2) | 3]) + uid, cert_p), False),
        ("a new-format partial body length",
         only(key_p, bytes([0xC0 | 13, 224]) + uid, cert_p), False),
        ("the three packets with an old-format two-octet length each",
         bundle("old2", "old2", "old2"), True),
        ("the user ID under a two-octet new-format length",
         only(key_p, openpgp_wrap(13, uid, "new2"), cert_p), True),
        ("a key packet under a new-format five-octet length, the others short",
         only(openpgp_wrap(6, key_body, "new5"), uid_p, cert_p), True),
        ("a five-octet length that promises more than the stream holds",
         only(key_p, bytes([0xC0 | 13, 255, 0, 0, 1, 0]) + uid, cert_p), False),
        ("the three packets with an old-format four-octet length each",
         bundle("old4", "old4", "old4"), True),
        ("the three packets with a new-format five-octet length each",
         bundle("new5", "new5", "new5"), True),
        ("a new-format two-octet length over a body of 192 octets or more",
         only(key_p, openpgp_wrap(13, uid, "new2"), cert_p), len(uid) >= 192),
        ("a two-octet new-format length that stops after its first octet",
         only(key_p, bytes([0xC0 | 13, 192]), cert_p), False),
        ("a five-octet new-format length with three of its four octets",
         only(key_p, bytes([0xC0 | 13, 255, 0, 0, 0]), cert_p), False),
        ("an old-format two-octet length with one octet after it",
         only(key_p, bytes([0x80 | (13 << 2) | 1, 0x00]), cert_p), False),
        ("an old-format four-octet length with two octets after it",
         only(key_p, bytes([0x80 | (13 << 2) | 2, 0x00, 0x01]), cert_p), False),
        ("a new-format length octet with nothing after it",
         only(key_p, bytes([0xC0 | 13]), cert_p), False),
        ("a packet header that is not a packet header at all",
         only(key_p, bytes([0x00, 0x01]) + uid, cert_p), False),
        ("a one-octet length one short of the user ID it carries",
         only(key_p, bytes([0x80 | (13 << 2), len(uid) - 1]) + uid, cert_p), False),
        ("a two-octet old-format length one short of the user ID it carries",
         only(key_p, bytes([0x80 | (13 << 2) | 1]) + (len(uid) - 1).to_bytes(2, "big") + uid,
              cert_p), False),
        ("a four-octet old-format length one short of the user ID it carries",
         only(key_p, bytes([0x80 | (13 << 2) | 2]) + (len(uid) - 1).to_bytes(4, "big") + uid,
              cert_p), False),
        # A length field that is cut short in the middle is its own failure, distinct from a body
        # that is short: RFC 4880 4.2.1 and 4.2.2 give each form a fixed header size.
        ("an old-format one-octet length with no length", bytes([0x80 | (6 << 2)]), False),
        ("an old-format two-octet length with one of its two octets",
         bytes([0x80 | (6 << 2) | 1, 0x00]), False),
        ("an old-format four-octet length with three of its four octets",
         bytes([0x80 | (6 << 2) | 2, 0x00, 0x01, 0x00]), False),
        ("a new-format header with no length octet at all", bytes([0xC0 | 6]), False),
        ("a new-format two-octet length with one of its two octets", bytes([0xC0 | 6, 192]), False),
        ("a new-format five-octet length with three of its four octets",
         bytes([0xC0 | 6, 255, 0x00, 0x00, 0x00]), False),
        ("no packets at all", b"", False),
        ("one octet", bytes([0x88]), False),
    ]

    def cbor_map(entries: list[tuple[int, bytes]]) -> bytes:
        return (cbor_head(5, len(entries))
                + b"".join(cbor_uint(k) + v for k, v in entries))

    def bstr(data: bytes) -> bytes:
        return cbor_head(2, len(data)) + data

    create = [(1, cbor_uint(1)), (2, cbor_uint(1)), (3, bstr(uid)), (4, cbor_uint(creation_time))]
    sign = [(1, cbor_uint(1)), (2, cbor_uint(2)), (3, bstr(b"hello\n")),
            (4, cbor_uint(creation_time)), (5, cbor_uint(creation_time + 60))]

    def create_expect(payload=uid, at=creation_time):
        return dict(operation=1, payload=payload, creation_time=at, key_creation_time=0,
                    signature_creation_time=0)

    def sign_expect(payload=b"hello\n", key_at=creation_time, sig_at=creation_time + 60):
        return dict(operation=2, payload=payload, creation_time=key_at, key_creation_time=key_at,
                    signature_creation_time=sig_at)

    requests = [
        ("CREATE_IDENTITY as the protocol defines it", cbor_map(create), create_expect()),
        ("SIGN_MESSAGE as the protocol defines it", cbor_map(sign), sign_expect()),
        ("an unknown protocol version", cbor_map([(1, cbor_uint(2))] + create[1:]), None),
        ("protocol version zero", cbor_map([(1, cbor_uint(0))] + create[1:]), None),
        ("an unknown operation", cbor_map([create[0], (2, cbor_uint(3))] + create[2:]), None),
        ("operation zero", cbor_map([create[0], (2, cbor_uint(0))] + create[2:]), None),
        ("no payload", cbor_map(create[:2] + create[3:]), None),
        ("no creation time", cbor_map(create[:3]), None),
        ("an empty user ID", cbor_map(create[:2] + [(3, bstr(b""))] + create[3:]), None),
        (f"a user ID of {OPENPGP_UID_MAX_LEN} octets",
         cbor_map(create[:2] + [(3, bstr(b"u" * OPENPGP_UID_MAX_LEN))] + create[3:]),
         create_expect(b"u" * OPENPGP_UID_MAX_LEN)),
        (f"a user ID of {OPENPGP_UID_MAX_LEN + 1} octets",
         cbor_map(create[:2] + [(3, bstr(b"u" * (OPENPGP_UID_MAX_LEN + 1)))] + create[3:]), None),
        ("a creation time of zero", cbor_map(create[:3] + [(4, cbor_uint(0))]), None),
        ("a payload given as a text string, not a byte string",
         cbor_map(create[:2] + [(3, cbor_head(3, len(uid)) + uid)] + create[3:]), None),
        ("keys out of canonical order",
         cbor_map([(2, cbor_uint(1)), (1, cbor_uint(1))] + create[2:]), None),
        ("a repeated key", cbor_map(create + [(4, cbor_uint(creation_time))]), None),
        ("bytes after the map", cbor_map(create) + b"\xf6", None),
        ("an indefinite-length map",
         b"\xbf" + b"".join(cbor_uint(k) + v for k, v in create) + b"\xff", None),
        ("a map of two items", cbor_map(create[:2]), None),
        ("an empty map", cbor_map([]), None),
        ("a key creation time of zero on SIGN_MESSAGE",
         cbor_map(sign[:3] + [(4, cbor_uint(0)), sign[4]]), None),
        ("a signature created before the key",
         cbor_map(sign[:3] + [(4, cbor_uint(creation_time)),
                              (5, cbor_uint(creation_time - 1))]), None),
        ("a signature creation time of zero",
         cbor_map(sign[:3] + [(4, cbor_uint(creation_time))]), None),
        ("a signature creation time given twice",
         cbor_map(sign + [(5, cbor_uint(creation_time + 60))]), None),
        (f"a message of {OPENPGP_MESSAGE_MAX_LEN} octets",
         cbor_map(sign[:2] + [(3, bstr(b"m" * OPENPGP_MESSAGE_MAX_LEN))] + sign[3:]),
         sign_expect(b"m" * OPENPGP_MESSAGE_MAX_LEN)),
        (f"a message of {OPENPGP_MESSAGE_MAX_LEN + 1} octets",
         cbor_map(sign[:2] + [(3, bstr(b"m" * (OPENPGP_MESSAGE_MAX_LEN + 1)))] + sign[3:]), None),
        ("an empty message", cbor_map(sign[:2] + [(3, bstr(b""))] + sign[3:]), None),
        ("SIGN_MESSAGE with no signature creation time", cbor_map(sign[:4]), None),
        ("SIGN_MESSAGE in the same second the key was made",
         cbor_map(sign[:4] + [(5, cbor_uint(creation_time))]), sign_expect(sig_at=creation_time)),
        ("not a map", bstr(b"\x01\x02"), None),
        ("one octet", b"\x00", None),
        ("nothing at all", b"", None),
    ]

    def request_row(what, data, expect):
        fields = [f' .what = "{what}"',
                  f' .cbor = {{ {c_array(data, 12, "      ")} }}',
                  f' .len = {len(data)}',
                  f' .accepted = {"true" if expect is not None else "false"}']
        if expect is not None:
            fields += [f' .operation = {expect["operation"]}',
                       f' .payload = {{ {c_array(expect["payload"], 12, "      ")} }}',
                       f' .payload_len = {len(expect["payload"])}',
                       f' .creation_time = {expect["creation_time"]}u',
                       f' .key_creation_time = {expect["key_creation_time"]}u',
                       f' .signature_creation_time = {expect["signature_creation_time"]}u']
        return "  { " + ",\n    ".join(fields) + " },"

    def text_row(message, own_material, digest):
        return ('  {\n'
                f'    .message = {{ {c_array(message, 10, "    ")} }},\n'
                f'    .message_len = {len(message)},\n'
                f'    .material = {{ {c_array(own_material, 10, "    ")} }},\n'
                f'    .material_len = {len(own_material)},\n'
                f'    .digest = {{ {c_array(digest, 10, "    ")} }},\n'
                '  },')

    out = f"""#ifndef VECTORS_OPENPGP_H
#define VECTORS_OPENPGP_H

/* app/openpgp against GnuPG and RFC 4880.
 *
 * The key material was made by GnuPG 2.4 on secp256k1 -- the curve this device implements -- and is
 * kept verbatim in tests/vectors/openpgp_fixture; regenerate with tests/vectors/oracle/openpgp.sh,
 * which replaces the key and every signature with it. Expectations are GnuPG's own bytes (a public
 * key packet body, the fingerprint it publishes, the octet string its signature covers) or rules
 * quoted from RFC 4880, and generate.py emits nothing until coincurve has verified that the digest
 * we compute is the digest GnuPG signed. So the certification rows are pinned by a signature an
 * independent ECDSA implementation accepts, not by agreement with this firmware.
 *
 * What GnuPG settled here, each a fact about the wire:
 *   - a v4 fingerprint is SHA1(0x99 || uint16 length || key body) -- RFC 4880 12.1, and it is
 *     exactly the fingerprint GnuPG publishes for this key;
 *   - a v4 user ID certification hashes 0x99||len||key then 0xB4||uint32 len||user ID, then the
 *     signature header and hashed subpackets, then a trailer whose four-octet count covers the hash
 *     material and not the trailer's own six octets -- RFC 4880 5.2.4;
 *   - a canonical text signature hashes the text with LF mapped to CRLF and nothing else removed:
 *     RFC 4880 5.2.4 asks only for "canonicalized by converting line endings to <CR><LF>", and
 *     GnuPG signs trailing spaces, trailing tabs and a "From " line through unchanged, so there is
 *     no trailing-whitespace stripping and no dash-escaping to implement;
 *   - an MPI is a bit count followed by exactly that many significant bits -- RFC 4880 3.2 -- so a
 *     65-octet uncompressed point is 515 bits, not 520;
 *   - the unhashed area of a signature GnuPG actually produces is a 10-octet issuer-key-id block,
 *     00 0a 09 10 followed by the key id, which is what our signature packet ends with.
 *
 * Left to the device, and pinned as its own choice rather than as RFC 4880:
 *   - a certification bundle is exactly three packets: a version 4 public key, a non-empty user ID,
 *     and a version 4 certification of type 0x10 through 0x13. RFC 4880 allows streams of many
 *     packets and many signature types; this operation reviews one identity at a time, so a subkey
 *     binding (0x18) or a revocation (0x20) is refused -- those rows are GnuPG's own signature body
 *     with its type octet replaced by what RFC 4880 5.2.1 says each type is;
 *   - a new-format partial body length (224 to 254) and an old-format indeterminate length are
 *     refused although RFC 4880 4.2.2.4 and 4.2.1 define them: the bundle arrives complete in one
 *     buffer, so a length that is not in the header has no honest reading;
 *   - text containing a CR that does not begin a CRLF is refused by
 *     openpgp_v4_canonicalize_text, while GnuPG signs a bare CR through as an ordinary octet. The
 *     fixture has such a message, so the divergence is measured rather than assumed;
 *   - the request map, its bounds and the canonical CBOR ordering are the Shell's protocol, stated
 *     in app/openpgp/openpgp_protocol.h.
 *
 * Not covered: openpgp_v4_verify_uid_self_cert beyond the point where it hands the digest and the
 * point to ecdsa_verify_raw_pub, which needs the public-key accelerator and aborts in a host build.
 * Its refusals before that call are covered, as is everything up to it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The primary key GnuPG generated. Packet body: version, creation time, algorithm 19, OID length
 * and OID 1.3.132.0.10, then the point as an MPI. */
#define OPENPGP_CREATION_TIME {creation_time}u
#define OPENPGP_KEY_BODY_LEN {len(key_body)}
static const uint8_t OPENPGP_KEY_POINT[65] = {{
  {c_array(point, 12, "  ")}
}};

static const uint8_t OPENPGP_KEY_BODY[OPENPGP_KEY_BODY_LEN] = {{
  {c_array(key_body, 12, "  ")}
}};

/* The fingerprint GnuPG publishes for that key, taken from its keyring listing. */
static const uint8_t OPENPGP_FINGERPRINT[20] = {{
  {c_array(fingerprint, 12, "  ")}
}};

static const uint8_t OPENPGP_UID[] = {{
  {c_array(uid, 12, "  ")}
}};
#define OPENPGP_UID_LEN {len(uid)}

/* GnuPG's self-certification of that key and user ID, and the pieces of it the digest needs. */
#define OPENPGP_SIG_TYPE {sig_type}
#define OPENPGP_CERT_BODY_LEN {len(cert_body)}
static const uint8_t OPENPGP_CERT_BODY[] = {{
  {c_array(cert_body, 12, "  ")}
}};

static const uint8_t OPENPGP_CERT_MATERIAL[] = {{
  {c_array(material, 12, "  ")}
}};
#define OPENPGP_CERT_MATERIAL_LEN {len(material)}

static const uint8_t OPENPGP_CERT_DATA[] = {{
  {c_array(cert_data, 12, "  ")}
}};
#define OPENPGP_CERT_DATA_LEN {len(cert_data)}

static const uint8_t OPENPGP_CERT_DIGEST[32] = {{
  {c_array(cert_digest, 12, "  ")}
}};

/* What follows the hashed area: the unhashed subpackets with their length, the two octets of the
 * signed hash GnuPG recorded, and the two MPIs. */
static const uint8_t OPENPGP_CERT_TAIL[] = {{
  {c_array(cert_tail, 12, "  ")}
}};
#define OPENPGP_CERT_TAIL_LEN {len(cert_tail)}

static const uint8_t OPENPGP_ISSUER_KEY_ID[8] = {{
  {c_array(issuer_key_id, 12, "  ")}
}};

/* Two hashed subpackets as GnuPG wrote them into its own certification: the creation time, and the
 * issuer fingerprint whose bytes are the fingerprint above. RFC 4880 5.2.3.1 gives the
 * length-and-type framing; these are what a real certification carries inside it. */
static const uint8_t OPENPGP_CREATION_SUBPACKET[] = {{
  {c_array(creation_subpacket, 12, "  ")}
}};
#define OPENPGP_CREATION_SUBPACKET_LEN {len(creation_subpacket)}

static const uint8_t OPENPGP_FINGERPRINT_SUBPACKET[] = {{
  {c_array(fingerprint_subpacket, 12, "  ")}
}};
#define OPENPGP_FINGERPRINT_SUBPACKET_LEN {len(fingerprint_subpacket)}

/* The certification's signature the way the secure element hands one over: r then s, 32 octets
 * each, without the MPI framing. */
static const uint8_t OPENPGP_CERT_RAW_SIG[64] = {{
  {c_array(raw_sig, 12, "  ")}
}};

/* The same key's signature over a binary document: the octets as they came, no canonicalization. */
static const uint8_t OPENPGP_BINARY_MESSAGE[] = {{
  {c_array(binary_msg, 12, "  ")}
}};
#define OPENPGP_BINARY_MESSAGE_LEN {len(binary_msg)}

static const uint8_t OPENPGP_BINARY_MATERIAL[] = {{
  {c_array(binary_material, 12, "  ")}
}};
#define OPENPGP_BINARY_MATERIAL_LEN {len(binary_material)}

static const uint8_t OPENPGP_BINARY_DIGEST[32] = {{
  {c_array(binary_digest, 12, "  ")}
}};

typedef struct {{
  uint8_t message[64];
  size_t message_len;
  uint8_t material[128];   /* GnuPG's own hash material for this signature */
  size_t material_len;
  uint8_t digest[32];      /* what its signature covers, after canonicalization */
}} openpgp_text_t;

/* One canonical text signature per row: canonicalize the message, hash that followed by this row's
 * material, and the result is what GnuPG signed. */
static const openpgp_text_t OPENPGP_TEXTS[] = {{
{chr(10).join(text_row(m, mat, dig) for m, mat, dig in text_rows)}
}};

#define OPENPGP_TEXTS_COUNT (sizeof(OPENPGP_TEXTS) / sizeof(OPENPGP_TEXTS[0]))

/* The message GnuPG signed with its own idea of canonicalization and this device refuses: a bare
 * CR, kept by GnuPG as an ordinary octet. */
static const uint8_t OPENPGP_CANONICAL_REFUSALS[][32] = {{
{chr(10).join(f'  {{ {c_array(m, 10, "    ")} }},' for m in refused)}
}};
static const size_t OPENPGP_CANONICAL_REFUSAL_LENS[] = {{
{chr(10).join(f'  {len(m)},' for m in refused)}
}};
#define OPENPGP_CANONICAL_REFUSALS_COUNT (sizeof(OPENPGP_CANONICAL_REFUSALS) / sizeof(OPENPGP_CANONICAL_REFUSALS[0]))

typedef struct {{
  const char* what;
  uint8_t packets[1024];
  size_t len;
  bool accepted;
}} openpgp_bundle_t;

/* Inputs to openpgp_parse_cert_target. The bodies are GnuPG's; the headers and the mutations are
 * built here, and each row says what it is about. */
static const openpgp_bundle_t OPENPGP_BUNDLES[] = {{
{chr(10).join(f'  {{ .what = "{what}",\n    .packets = {{ {c_array(data, 12, "      ")} }},\n    .len = {len(data)},\n    .accepted = {"true" if ok else "false"} }},' for what, data, ok in bundles)}
}};

#define OPENPGP_BUNDLES_COUNT (sizeof(OPENPGP_BUNDLES) / sizeof(OPENPGP_BUNDLES[0]))

#define OPENPGP_PAYLOAD_MAX 255

typedef struct {{
  const char* what;
  uint8_t cbor[512];
  size_t len;
  bool accepted;
  uint8_t operation;
  uint8_t payload[OPENPGP_PAYLOAD_MAX];
  size_t payload_len;
  uint32_t creation_time;
  uint32_t key_creation_time;
  uint32_t signature_creation_time;
}} openpgp_request_row_t;

/* Inputs to openpgp_protocol_parse_request: the request map as app/openpgp/openpgp_protocol.h
 * defines it, and every way a host could send something else. The map is parsed under
 * ZCBOR_CANONICAL, so keys arrive in increasing order and no key arrives twice. */
static const openpgp_request_row_t OPENPGP_REQUESTS[] = {{
{chr(10).join(request_row(what, data, expect) for what, data, expect in requests)}
}};

#define OPENPGP_REQUESTS_COUNT (sizeof(OPENPGP_REQUESTS) / sizeof(OPENPGP_REQUESTS[0]))

#endif\t/* VECTORS_OPENPGP_H */
"""
    return out


MULTISIG_HEADER = """\
#ifndef VECTORS_MULTISIG_H
#define VECTORS_MULTISIG_H

/* spec: {provenance}
 *
 * Multisig setup files, in the format COLDCARD exports and Sparrow reads: a Name, a "M of N"
 * Policy, an address Format, Derivation lines that apply to every key below them, and one line per
 * cosigner of eight hex digits of master fingerprint, a colon, and an extended public key. The
 * accepted files here are the one printed on the format page and the exports another wallet keeps as
 * its own parser's test fixtures, so "what this file means" is somebody else\u2019s answer.
 *
 * Refusals are pinned too, and several of them are places where this parser is stricter than the
 * format page suggests: it takes no M/N policy spelling, no lowercase labels or formats, no default
 * Policy when one is missing, and no CRLF line endings anywhere in the file. Stricter is the right
 * direction for bytes that arrive from a camera, but the rows are the place to notice if that ever
 * needs to change.
 *
 * Paths are stored as the firmware stores them, with the hardening bit set, flattened six keys of
 * six components; fingerprints and xpubs are hex per key in the order the file lists them. The
 * serialized and re-exported forms are our own layout rather than anything published, so they are
 * pinned for two rows only and the rest are checked by round trip.
 */
#include <stdbool.h>
#include <stdint.h>

#include "error.h"

typedef struct {{
  const char* label;
  const char* text;
  uint32_t text_len;
  app_err_t err;
  const char* name;
  uint8_t m;
  uint8_t n;
  uint8_t format;
  uint8_t key_count;
  uint32_t path[6][6];
  uint8_t path_len[6];
  const char* fingerprints;
  const char* xpubs;
  const char* serialized;
  const char* reexport;
}} multisig_case_t;

static const multisig_case_t MULTISIG_CASES[] = {{
{rows}
}};

#define MULTISIG_CASE_COUNT (sizeof(MULTISIG_CASES) / sizeof(MULTISIG_CASES[0]))

#endif /* VECTORS_MULTISIG_H */
"""


HARDENED = 0x80000000
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58_decode(text: str) -> bytes:
    """Base58Check, decoded and checked here rather than trusted: the vectors carry the 78 bytes the
    firmware must end up with, so a parser that decoded the wrong payload would differ from them."""
    value = 0
    for char in text:
        digit = B58.index(char)
        value = value * 58 + digit
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    pad = len(text) - len(text.lstrip('1'))
    data = b'\x00' * pad + raw
    body, checksum = data[:-4], data[-4:]
    assert hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum, text
    return body


def b58_encode(data: bytes) -> str:
    """Base58Check, for the text the device writes back out."""
    raw = data + hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    value = int.from_bytes(raw, 'big')
    out = ''
    while value:
        value, rest = divmod(value, 58)
        out = B58[rest] + out
    return '1' * (len(raw) - len(raw.lstrip(b'\x00'))) + out


def cc_path(text: str) -> list[int]:
    """A Coldcard derivation path as the firmware stores it: ' or h hardens, and the leading m is
    not a component. Per the format page: 'Must use single quote or h for hardened keys, and start
    with m/ (master).'"""
    parts = text.split('/')[1:]
    out = []
    for part in parts:
        hardened = part.endswith(("'", 'h'))
        digits = part[:-1] if hardened else part
        index = int(digits)
        assert index <= 0xffffffff, text
        out.append(index | (HARDENED if hardened else 0))
    return out


def cc_keys(text: str, default_path: list[int] | None = None) -> list[tuple[str, list[int], bytes]]:
    """The key lines of a setup file, each with the derivation path in force above it."""
    keys, current = [], default_path
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or ':' not in line:
            continue
        key, value = line.split(':', 1)
        key, value = key.strip(), value.strip()
        if key == 'Derivation':
            current = cc_path(value)
            continue
        if len(key) != 8:
            continue
        keys.append((key, list(current or []), b58_decode(value)))
    return keys


def cc_serialize(name: str, m: int, n: int, fmt: int,
                 keys: list[tuple[str, list[int], bytes]]) -> bytes:
    """The storage form: our own layout, pinned so that a change to it shows up as a migration
    problem rather than a passing test."""
    out = bytearray([fmt, m, n, len(keys), len(name)])
    out += name.encode()
    for fingerprint, path, xpub in keys:
        out.append(len(path))
        for index in path:
            out += index.to_bytes(4, 'little')
        out += bytes.fromhex(fingerprint)
        out += xpub
    return bytes(out)


def cc_to_text(name: str, m: int, n: int, fmt: int,
               keys: list[tuple[str, list[int], bytes]]) -> str:
    """What the device writes back out for a QR export."""
    formats = ['P2SH', 'P2SH-P2WSH', 'P2WSH']
    out = f'Name: {name}\nPolicy: {m} of {n}\nFormat: {formats[fmt]}\n\n'
    for fingerprint, path, xpub in keys:
        derived = 'm' + ''.join(f"/{index & ~HARDENED}{'\'' if index & HARDENED else ''}"
                                for index in path)
        out += f'Derivation: {derived}\n{fingerprint.lower()}: {b58_encode(xpub)}\n\n'
    return out


def multisig_case(label: str, text: str, *, name: str = '', m: int = 0, n: int = 0, fmt: int = 2,
                  keys: list[tuple[str, list[int], bytes]] | None = None,
                  err: str = 'ERR_OK', pinned: bool = False) -> str:
    keys = keys or []
    flat, lens, fps, xpubs = [], [], '', ''
    for fingerprint, path, xpub in keys:
        lens.append(len(path))
        flat.append(list(path) + [0] * (6 - len(path)))
        fps += fingerprint.lower()
        xpubs += xpub.hex()
    while len(lens) < 6:
        lens.append(0)
        flat.append([0] * 6)
    serialized = (f'"{hexs(cc_serialize(name, m, n, fmt, keys))}"'
                  if pinned and err == 'ERR_OK' else 'NULL')
    reexport = cstr(cc_to_text(name, m, n, fmt, keys)) if pinned and err == 'ERR_OK' else 'NULL'
    paths = ', '.join('{' + ', '.join(f'0x{index:08x}' for index in row) + '}' for row in flat)
    return (f'  {{{cstr(label)}, {cstr(text)}, {len(text)}, {err}, {cstr(name)}, {m}, {n}, {fmt}, '
            f'{len(keys)}, {{{paths}}}, {{{", ".join(str(x) for x in lens)}}}, '
            f'{cstr(fps)}, {cstr(xpubs)}, {serialized}, {reexport}}}')


def xpub_rekey(key: str, key33: bytes) -> str:
    """An extended public key with its 33 byte key field replaced and the checksum recomputed, so that a
    refusal is about the key and not about the base58 around it."""
    payload = bytearray(b58_decode(key))
    assert len(payload) == 78, key
    payload[45:78] = key33
    return b58check_encode(bytes(payload))


def xpub_without_point() -> bytes:
    """A compressed key with no point above its x: x^3 + 7 is a quadratic non-residue, which
    ec_uncompress_point answers with a y anyway."""
    x = 1
    while pow((x ** 3 + 7) % SECP256K1_P, (SECP256K1_P - 1) // 2, SECP256K1_P) != SECP256K1_P - 1:
        x += 1
    return b'\x02' + x.to_bytes(32, 'big')


def multisig_vectors() -> str:
    raw = fetch('coldcard_multisig.html')
    doc = re.sub(r'<[^>]+>', '', raw).replace('&quot;', '"').replace('&amp;', '&')
    doc = doc.replace('&#39;', "'").replace('&gt;', '>')
    flattened = re.sub(r'\s+', ' ', doc)  # the page wraps mid-sentence

    for sentence in (
        'Comments start with # and go the end of the line. Blank lines are okay.',
        'Values and labels are case insensitive.',
        'Can be written "M of N", or just "M/N".',
        'Must use single quote or h for hardened keys, and start with m/ (master).',
        'Applies to all subsequent XPUBs and may be repeated',
        'Policy Default is M==N.',
        'The rest of the line, after the colon is the XPUB for that signer',
    ):
        assert sentence in flattened, sentence

    example = re.search(r'(# Coldcard Multisig setup file.*?)</code>', raw, re.S)
    assert example, 'the format page no longer carries an example setup file'
    coldcard = re.sub(r'<[^>]+>', '', example.group(1)).replace('&#39;', "'")
    assert coldcard.startswith('# Coldcard Multisig setup file (exported from 0F056943)')

    export1, export2 = fetch('cc_export_1.txt'), fetch('cc_export_2.txt')
    missing, multi, nopolicy = (fetch('cc_export_missingkey.txt'),
                                fetch('cc_export_multideriv.txt'), fetch('cc_export_nopolicy.txt'))
    assert 'Policy: 2 of 4' in export1 and 'Format: P2WSH-P2SH' in export2
    assert 'Policy' not in nopolicy

    xpub = export1.split('0F056943: xpub')[1].split('\n')[0]
    tpub = export2.split('0F056943: tpub')[1].split('\n')[0]

    path_48_0_0_2 = cc_path("m/48'/0'/0'/2'")
    rows = [
        multisig_case('the example on the format page', coldcard, name='MeMyself', m=2, n=4, fmt=2,
                      keys=cc_keys(coldcard), pinned=True),
        multisig_case('a Coldcard export, apostrophe hardening', export1, name='CC-2-of-4', m=2,
                      n=4, fmt=2, keys=cc_keys(export1)),
        # The wrapped format, spelled the way Coldcard spells it when exporting a nested script, and
        # testnet keys: the version bytes are part of the 78, so they are part of the expectation.
        multisig_case('P2WSH-P2SH over tpubs', export2, name='CC-2-of-4', m=2, n=4, fmt=1,
                      keys=cc_keys(export2)),
        # One Derivation line per key, and the last key at a different path: the path in force is
        # the nearest one above, not the first one seen.
        multisig_case('a per-key derivation, Electrum export', multi, name='el-CC-3-of-3-sb-2',
                      m=3, n=3, fmt=2, keys=cc_keys(multi)),
        multisig_case('a comment between keys, and blank lines', multi.replace(
            'Derivation: m/47', '# a comment\nDerivation: m/47'), name='el-CC-3-of-3-sb-2', m=3,
            n=3, fmt=2, keys=cc_keys(multi.replace('Derivation: m/47',
                                                   '# a comment\nDerivation: m/47'))),
        multisig_case('indented labels and trailing blanks',
                      '\t \n   Name: Indented\t\n  Policy: 1 of 1  \n  Format: P2WSH  \n\n'
                      + '  0F056943: xpub' + xpub + '\n', name='Indented', m=1, n=1, fmt=2,
                      keys=[('0F056943', [], b58_decode('xpub' + xpub))]),
        # The default format is P2SH, which is the value a zeroed descriptor already has; a file
        # without a Format line is accepted and means P2SH.
        multisig_case('no Format line at all', 'Name: Default\nPolicy: 1 of 1\n\n0F056943: '
                      + export1.split('0F056943: ')[1].split('\n')[0] + '\n',
                      name='Default', m=1, n=1, fmt=0,
                      keys=cc_keys('0F056943: ' + export1.split('0F056943: ')[1].split('\n')[0])),
    ]

    def single(**changes) -> str:
        """One key, with the parts a hostile or broken QR can get wrong changed one at a time."""
        fields = {'name': 'One', 'policy': 'Policy: 1 of 1', 'format': 'Format: P2WSH',
                  'derivation': "Derivation: m/48'/0'/0'/2'", 'fp': '0F056943', 'xpub': 'xpub' + xpub}
        fields.update(changes)
        lines = [f"Name: {fields['name']}", fields['policy'], fields['format'], '',
                 fields['derivation'], '', f"{fields['fp']}: {fields['xpub']}", '']
        return '\n'.join(lines)

    second = '6BA6CFD0: xpub' + export1.split('6BA6CFD0: xpub')[1].split('\n')[0]

    pool = list(dict.fromkeys(re.findall(r'xpub[1-9A-HJ-NP-Za-km-z]{100,120}', export1 + coldcard)))
    assert len(pool) >= 6, 'the fixtures no longer offer six distinct cosigner keys'

    def six(bad_last: str | None = None) -> str:
        """Six cosigners, the last line replaceable. Derivation walks every key in the file, because the
        script lists all of them, so the sixth is the last one in keys[]."""
        lines = ['Name: Six', 'Policy: 6 of 6', 'Format: P2WSH', '', "Derivation: m/48'/0'/0'/2'", '']
        for i, key in enumerate(pool[:5] + [bad_last or pool[5]]):
            lines.append(f'{0x0F056943 + i:08X}: {key}')
        return '\n'.join(lines) + '\n'

    rows += [
        # Refusals, each one a file another tool might hand over.
        multisig_case('no Policy line (Coldcard would default M=N)', nopolicy, err='ERR_DATA'),
        multisig_case('one key missing from a 2 of 4', missing, err='ERR_DATA'),
        multisig_case('policy in the M/N spelling the format page allows',
                      export1.replace('Policy: 2 of 4', 'Policy: 2/4'), err='ERR_DATA'),
        multisig_case('a lowercase format, as the format page spells it',
                      single(format='Format: p2wsh'), name='One', m=1, n=1, fmt=2,
                      keys=cc_keys(single(format='Format: p2wsh'))),
        # Electrum writes P2SH-P2WPKH for a single-address segwit wallet. The multisig module has
        # no such format, and the line is what a wrong file looks like rather than a typo.
        multisig_case('a format the module does not have', single(format='Format: P2SH-P2WPKH'),
                      err='ERR_DATA'),
        multisig_case('an unknown label, which becomes a key line',
                      single(name='One', policy='Wallet: 1 of 1'), err='ERR_DATA'),
        # The key field is where a hostile or merely truncated QR reaches the derivation, and the base58
        # check and the 78 byte length let both of these through. A 0x04 prefix is the one that reads
        # memory: ec_uncompress_key answers it with a pointer into a 33 byte field that _derive_key_pub
        # then reads ECC256_POINT_SIZE bytes of.
        multisig_case('an uncompressed cosigner key',
                      single(xpub=xpub_rekey('xpub' + xpub,
                                             b'\x04' + b58_decode('xpub' + xpub)[46:78])),
                      err='ERR_DATA'),
        multisig_case('a cosigner key with no point above its x',
                      single(xpub=xpub_rekey('xpub' + xpub, xpub_without_point())), err='ERR_DATA'),
        multisig_case('six cosigners, all keys points', six(), name='Six', m=6, n=6, fmt=2,
                      keys=cc_keys(six())),
        multisig_case('six cosigners, the last key uncompressed',
                      six(bad_last=xpub_rekey(pool[5], b'\x04' + b58_decode(pool[5])[46:78])),
                      err='ERR_DATA'),
        multisig_case('a label with no colon at all', single().replace('Format: P2WSH', 'P2WSH'),
                      err='ERR_DATA'),
        multisig_case('a lowercase label', single().replace('Name:', 'name:'), name='One', m=1,
                      n=1, fmt=2, keys=cc_keys(single())),
        # "Values and labels are case insensitive" on the format page, which covers the keywords and
        # not the base58: an xpub in another case is a different string and fails its own checksum.
        multisig_case('every label uppercase, the policy spelled OF, hardening by H',
                      'NAME: Shouted\nPOLICY: 1 OF 1\nFORMAT: P2WSH\n\n'
                      'Derivation: M/48H/0H/0H/2H\n\n0F056943: xpub' + xpub + '\n', name='Shouted',
                      m=1, n=1, fmt=2, keys=cc_keys(single())),
        multisig_case('the nested format in lower case, reversed spelling',
                      single(format='format: p2wsh-p2sh'), name='One', m=1, n=1, fmt=1,
                      keys=cc_keys(single())),
        multisig_case('a fingerprint in lower case', single(fp='0f056943'), name='One', m=1, n=1,
                      fmt=2, keys=cc_keys(single())),
        multisig_case('a hardening mark in the middle of a path, uppercase',
                      single(derivation='Derivation: m/48h/0H/0/2'), name='One', m=1, n=1, fmt=2,
                      keys=cc_keys(single(derivation="Derivation: m/48'/0'/0/2"))),
        multisig_case('a name of 33 characters', single(name='x' * 33), err='ERR_DATA'),
        multisig_case('a name of 32 characters', single(name='x' * 32), name='x' * 32, m=1, n=1,
                      fmt=2, keys=cc_keys(single())),
        multisig_case('a name containing a colon', single(name='CC: 1 of 1'), name='CC: 1 of 1',
                      m=1, n=1, fmt=2, keys=cc_keys(single(name='CC: 1 of 1'))),
        multisig_case('M greater than N', single(policy='Policy: 2 of 1'), err='ERR_DATA'),
        multisig_case('M of zero keys', single(policy='Policy: 1 of 0'), err='ERR_DATA'),
        multisig_case('zero of zero', single(policy='Policy: 0 of 0'), err='ERR_DATA'),
        multisig_case('a key line before any policy',
                      single().replace('Policy: 1 of 1\n', ''), err='ERR_DATA'),
        multisig_case('a fingerprint that is not hex', single(fp='ZZZZZZZZ'), err='ERR_DATA'),
        multisig_case('a fingerprint of seven digits', single(fp='0F05694'), err='ERR_DATA'),
        multisig_case('a fingerprint of nine digits', single(fp='0F056943A'), err='ERR_DATA'),
        multisig_case('an xpub with a broken checksum',
                      single(xpub='xpub' + xpub[:-1] + ('A' if xpub[-1] != 'A' else 'B')),
                      err='ERR_DATA'),
        multisig_case('an xpub one character short', single(xpub='xpub' + xpub[:-1]),
                      err='ERR_DATA'),
        multisig_case('an xpub one character too long', single(xpub='xpub' + xpub + 'A'),
                      err='ERR_DATA'),
        multisig_case('a key with no value after the colon', single(xpub=''), err='ERR_DATA'),
        # tpub is a different version prefix with the same length; the 78 octets are what is stored,
        # so a testnet descriptor parses exactly like a mainnet one.
        multisig_case('testnet keys', single(xpub='tpub' + tpub), name='One', m=1, n=1, fmt=2,
                      keys=cc_keys(single(xpub='tpub' + tpub))),
        multisig_case('a path with no components', single(derivation='Derivation: m'),
                      err='ERR_DATA'),
        # The scan for the path begins at the first slash, so a path written without its m/ prefix
        # loses its first component instead of being refused. The wallet that comes out is a
        # different one and nothing says so.
        # A path is a position under the master key. Reading from the first slash instead of
        # insisting on it turns "48'/0'/0'/2'" into m/0'/0'/2' -- a different wallet, accepted
        # without a word -- so the prefix is required.
        multisig_case('a path with no master prefix',
                      single(derivation="Derivation: 48'/0'/0'/2'"), err='ERR_DATA'),
        multisig_case('a path that starts with a slash',
                      single(derivation="Derivation: /48'/0'/0'/2'"), err='ERR_DATA'),
        multisig_case('a path that starts with the master key but no slash',
                      single(derivation="Derivation: m48'/0'/0'/2'"), err='ERR_DATA'),
        multisig_case('a path component that is not a number',
                      single(derivation="Derivation: m/48'/x'/0'/2'"), err='ERR_DATA'),
        multisig_case('a path with an empty component',
                      single(derivation="Derivation: m/48'//0'/2'"), err='ERR_DATA'),
        multisig_case('a path of seven components',
                      single(derivation="Derivation: m/1'/2'/3'/4'/5'/6'/7'"), err='ERR_DATA'),
        multisig_case('a path of six components, which is the most there is room for',
                      single(derivation="Derivation: m/1'/2'/3'/4'/5'/6'"), name='One', m=1, n=1,
                      fmt=2, keys=cc_keys(single(derivation="Derivation: m/1'/2'/3'/4'/5'/6'"))),
        # The hardening mark is the top bit of the stored component, so 2^31 is not an index this
        # format can hold -- read as-is it would reach the card as m/2147483648h. Ten digits is also
        # fewer than a uint32 holds, so 4294967296 is refused by the conversion rather than wrapping
        # to m/0.
        multisig_case('an index of 2^31 is not an index',
                      single(derivation='Derivation: m/2147483648/1'), err='ERR_DATA'),
        multisig_case('an index of 2^31 - 1 is the largest there is room for',
                      single(derivation='Derivation: m/2147483647/1'), name='One', m=1, n=1, fmt=2,
                      keys=cc_keys(single(derivation='Derivation: m/2147483647/1'))),
        multisig_case('an index of 2^32 would wrap to the master key itself',
                      single(derivation='Derivation: m/4294967296'), err='ERR_DATA'),
        multisig_case('an index of twenty digits', single(derivation='Derivation: m/1' + '0' * 19),
                      err='ERR_DATA'),
        multisig_case('a line of 256 octets', single() + 'a' * 256 + '\n', err='ERR_DATA'),
        multisig_case('a comment line of 255 octets, which is a comment, not a key',
                      single() + '#' * 255 + '\n', name='One', m=1, n=1, fmt=2,
                      keys=cc_keys(single())),
        # A file saved with CRLF endings is refused rather than half-parsed: the carriage return
        # would otherwise end up inside the name and behind the xpub.
        multisig_case('CRLF line endings', single().replace('\n', '\r\n'), err='ERR_DATA'),
        multisig_case('empty text', '', err='ERR_DATA'),
        multisig_case('comments only', '# nothing here\n#\n', err='ERR_DATA'),
        multisig_case('a space where the colon should be', single().replace('Name: One', 'Name One'),
                      err='ERR_DATA'),
        # Six keys is MULTISIG_MAX_KEYS; seven does not fit, and the refusal is ERR_FULL rather than
        # ERR_DATA because the descriptor was fine and the room was not.
    ]

    # The key count bound, with the key lines spelled out.
    keyless = single().rsplit('\n', 3)[0] + '\n'
    fingerprints = ['0F056943', '6BA6CFD0', '747B698E', '7BB026BE', 'AAAAAAAA', 'BBBBBBBB']
    path = cc_keys(single())[0][1]
    rows.append(multisig_case(
        'six keys, which is the most that fits',
        keyless.replace('Policy: 1 of 1', 'Policy: 6 of 6')
        + '\n'.join(f'{fp}: xpub{xpub}' for fp in fingerprints) + '\n',
        name='One', m=6, n=6, fmt=2,
        keys=[(fp, path, b58_decode('xpub' + xpub)) for fp in fingerprints]))
    rows.append(multisig_case(
        'seven keys: the descriptor does not fit',
        keyless.replace('Policy: 1 of 1', 'Policy: 7 of 7')
        + '\n'.join(f'{fp}: xpub{xpub}' for fp in fingerprints + ['CCCCCCCC']) + '\n',
        err='ERR_FULL'))
    # Nothing compares the cosigners with one another, so the same key twice is a wallet that has
    # the same signer in it twice.
    rows.append(multisig_case(
        'the same cosigner twice',
        keyless.replace('Policy: 1 of 1', 'Policy: 2 of 2')
        + '\n'.join([f'0F056943: xpub{xpub}'] * 2) + '\n', name='One', m=2, n=2, fmt=2,
        keys=[('0F056943', path, b58_decode('xpub' + xpub))] * 2))

    # A single key at a path with both hardened and plain components, whose storage bytes and
    # re-exported text are pinned in full.
    canonical = single(derivation="Derivation: m/48'/1/2'/3")
    rows.append(multisig_case('canonical: one key, mixed hardening', canonical, name='One', m=1,
                              n=1, fmt=2,
                              keys=[('0F056943', [48 | HARDENED, 1, 2 | HARDENED, 3],
                                     b58_decode('xpub' + xpub))], pinned=True))

    return MULTISIG_HEADER.format(rows=',\n'.join(rows),
                                  provenance=provenance('coldcard_multisig.html'))


# ----------------------------------------------------------------- pka stand-in


# secp256k1 as SEC 2 states it, and NIST P-256 as RFC 6979 states it. Both are checked before use:
# the secp256k1 numbers against the table in app/crypto/secp256k1.c, the P-256 ones against the
# document that the deterministic-k model is validated with below.
PKA_CURVE = {
    "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    "a": 0,
    "b": 7,
    "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
}

PKA_P256 = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
}


def pka_curve_table(name: str) -> dict:
    """The curve constants as the firmware holds them, read out of its own table so that a vector
    computed against PKA_CURVE below is known to describe the curve the stand-in is handed."""
    text = (HERE.parents[1] / "app" / "crypto" / f"{name}.c").read_text()
    body = text.split("const ecdsa_curve " + name + " = {", 1)[1].split("\n};", 1)[0]
    fields = {}
    for field in ("prime", "G", "order", "a", "b", "sqrt_exp"):
        octets = re.findall(r"0x([0-9a-fA-F]{2})", body.split("." + field + " = {", 1)[1].split("},", 1)[0])
        fields[field] = bytes(int(o, 16) for o in octets)
    for field in ("prime", "order", "a", "b", "sqrt_exp"):
        assert len(fields[field]) == 32, (field, len(fields[field]))
    assert len(fields["G"]) == 64, len(fields["G"])
    sign = re.search(r"\.a_sign = (A_SIGN_\w+)", body)
    assert sign, "no a_sign in the table"
    return fields, sign.group(1)


def pka_check_curve_table() -> None:
    fields, a_sign = pka_curve_table("secp256k1")
    c = PKA_CURVE
    assert fields["prime"].hex() == "%064x" % c["p"], "prime moved"
    assert fields["order"].hex() == "%064x" % c["n"], "order moved"
    assert fields["G"][:32].hex() == "%064x" % c["gx"], "G.x moved"
    assert fields["G"][32:].hex() == "%064x" % c["gy"], "G.y moved"
    assert fields["a"].hex() == "%064x" % c["a"] and a_sign == "A_SIGN_ZERO"
    assert fields["b"].hex() == "%064x" % c["b"]
    # The table's sqrt exponent is (p + 1) // 4, which is what a square root is raised to.
    assert int(fields["sqrt_exp"].hex(), 16) == (c["p"] + 1) // 4, "sqrt_exp is not (p+1)//4"


def pka_ec_add(p1, p2, P: int, A: int):
    """Chord-and-tangent on y^2 = x^3 + A*x + B, with None as the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return (x3, (slope * (x1 - x3) - y1) % P)


def pka_ec_mul(k: int, point, P: int, A: int):
    acc = None
    for bit in range(255, -1, -1):
        acc = pka_ec_add(acc, acc, P, A)
        if (k >> bit) & 1:
            acc = pka_ec_add(acc, point, P, A)
    return acc


def pka_bits2int(block: bytes, q: int) -> int:
    """RFC 6979 section 2.3.2: the leftmost bits of a block, at the width the group order needs.
    A digest longer than the order loses its tail and a shorter one is taken whole, which is why
    `e` in the signature equation is not the hash modulo the order."""
    qlen = q.bit_length()
    value = int.from_bytes(block, "big")
    extra = len(block) * 8 - qlen
    return value >> extra if extra > 0 else value


def pka_rfc6979_k(q: int, priv: bytes, digest: bytes, hash_name: str) -> int:
    """RFC 6979 section 3.2, the deterministic nonce. Validated against the appendix of the same
    document before it is used for secp256k1, which that appendix does not cover."""
    hlen = hashlib.new(hash_name).digest_size
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8

    def bits2octets(block: bytes) -> bytes:
        return (pka_bits2int(block, q) % q).to_bytes(rlen, "big")

    seed = priv + bits2octets(digest)
    v = b"\x01" * hlen
    key = b"\x00" * hlen
    key = hmac.new(key, v + b"\x00" + seed, hash_name).digest()
    v = hmac.new(key, v, hash_name).digest()
    key = hmac.new(key, v + b"\x01" + seed, hash_name).digest()
    v = hmac.new(key, v, hash_name).digest()
    while True:
        taken = b""
        while len(taken) * 8 < qlen:
            v = hmac.new(key, v, hash_name).digest()
            taken += v
        k = pka_bits2int(taken, q)
        if 1 <= k < q:
            return k
        key = hmac.new(key, v + b"\x00", hash_name).digest()
        v = hmac.new(key, v, hash_name).digest()


def pka_parse_rfc6979() -> tuple[int, int, list[dict]]:
    """Appendix A.2.5, the only 256-bit prime-field case the RFC publishes. It is P-256, not
    secp256k1, so what it can pin is the model rather than the curve the firmware uses."""
    text = fetch("rfc6979.txt")
    head = "A.2.5.  ECDSA, 256 Bits (Prime Field)"
    assert head in text, "rfc6979: appendix A.2.5 missing"
    # rsplit, because the same heading is in the table of contents and the table of contents
    # carries an A.2.6 line a few lines later.
    section = text.rsplit(head, 1)[1]
    for marker in ("\nA.2.6.", "\nA.3."):
        if marker in section:
            section = section.split(marker, 1)[0]

    # "curve: NIST P-256" and the published q are what the section's triples are stated over.
    assert "curve: NIST P-256" in section, "A.2.5 is not stated over NIST P-256"
    q = int(re.search(r"\n\s+q = ([0-9A-F]+)", section).group(1), 16)
    priv = int(re.search(r"\n\s+x = ([0-9A-F]+)", section).group(1), 16)
    assert q == PKA_P256["n"], "A.2.5's q is not the P-256 order used here"

    cases = []
    for block in re.finditer(
        r'With (SHA-\d+), message = "([A-Za-z]+)":\s*\n\s*k = ([0-9A-F]+)\s*\n\s*r = ([0-9A-F]+)\s*\n\s*s = ([0-9A-F]+)',
        section,
    ):
        cases.append(
            {
                "hash": block.group(1).lower().replace("-", ""),
                "message": block.group(2).encode(),
                "k": int(block.group(3), 16),
                "r": int(block.group(4), 16),
                "s": int(block.group(5), 16),
            }
        )
    return q, priv, cases


def pka_validate_k_model() -> int:
    """Every published triple of A.2.5 has to come out of the model, including its k. Returns the
    number of triples checked, which the emitted header records."""
    q, priv, cases = pka_parse_rfc6979()
    if len(cases) != 10:
        sys.exit(f"rfc6979 A.2.5: parsed {len(cases)} triples, expected 10")
    if {c["hash"] for c in cases} != {"sha1", "sha224", "sha256", "sha384", "sha512"}:
        sys.exit(f"rfc6979 A.2.5: hashes parsed were {sorted({c['hash'] for c in cases})}")

    for case in cases:
        digest = hashlib.new(case["hash"], case["message"]).digest()
        k = pka_rfc6979_k(q, priv.to_bytes(32, "big"), digest, case["hash"])
        assert k == case["k"], (case["hash"], case["message"], "%x" % k, "%x" % case["k"])
        point = pka_ec_mul(k, (PKA_P256["gx"], PKA_P256["gy"]), PKA_P256["p"], PKA_P256["a"])
        r = point[0] % q
        s = pow(k, -1, q) * (pka_bits2int(digest, q) % q + r * priv) % q
        assert (r, s) == (case["r"], case["s"]), case["hash"]
    return len(cases)


def pka_secp_sign(priv: int, digest: bytes) -> tuple[int, int, int]:
    """(k, r, s) for secp256k1, the equation as RFC 6979 states it and as the stand-in computes
    it. The caller proves each row against coincurve's independent signature of the same digest."""
    c = PKA_CURVE
    k = pka_rfc6979_k(c["n"], priv.to_bytes(32, "big"), digest, "sha256")
    point = pka_ec_mul(k, (c["gx"], c["gy"]), c["p"], c["a"])
    r = point[0] % c["n"]
    s = pow(k, -1, c["n"]) * (pka_bits2int(digest, c["n"]) % c["n"] + r * priv) % c["n"]
    assert r and s
    return k, r, s


def pka_coincurve_signature(priv: int, digest: bytes) -> tuple[int, int]:
    """The same digest signed by libsecp256k1, whose default nonce is RFC 6979 without additional
    data. A row whose (r, s) matches this is a row whose k matches what libsecp256k1 picked."""
    import coincurve

    key = coincurve.PrivateKey(priv.to_bytes(32, "big"))
    # The digest is handed over as the hash of anything, because these rows are about the
    # equation over a given digest rather than about a message.
    der = key.sign(digest, hasher=lambda message: digest)
    compact = coincurve.ecdsa.serialize_compact(coincurve.ecdsa.der_to_cdata(der))
    public = coincurve.PublicKey.from_secret(priv.to_bytes(32, "big"))
    assert public.verify(der, digest, hasher=lambda message: digest), "coincurve does not accept its own signature"
    return int.from_bytes(compact[:32], "big"), int.from_bytes(compact[32:], "big")


def pka_bip32_keys() -> list[tuple[int, bytes]]:
    """(private key, published public key) for every level of BIP-32's test vector 1, pairing the
    xprv and xpub of the same level. The document states K = point(k), and asserts it below."""
    text = fetch("bip32.mediawiki")
    assert "the secp256k1 base point with the integer p" in text, "BIP-32 no longer states point(p)"
    section = text.split("===Test vector 1===", 1)[1].split("===Test vector 2", 1)[0]
    assert "Seed (hex): 000102030405060708090a0b0c0d0e0f" in section, "test vector 1 is not the seed it was"
    levels = re.findall(
        r"\* Chain m[^\n]*\n\*\* ext pub: (xpub[0-9A-HJ-NP-Za-km-z]+)\n\*\* ext prv: (xprv[0-9A-HJ-NP-Za-km-z]+)",
        section,
    )
    if len(levels) < 5:
        sys.exit(f"bip32: paired {len(levels)} levels of test vector 1, expected at least 5")

    pairs = []
    for xpub, xprv in levels:
        private = b58decode(xprv)[:-4][46:78]
        public = b58decode(xpub)[:-4][45:78]
        assert public[0] in (0x02, 0x03), public
        pairs.append((int.from_bytes(private, "big"), public))
    return pairs


def pka_decompress(compressed: bytes) -> tuple[int, int]:
    """A compressed key expanded by coincurve, which does its own square root."""
    import coincurve

    uncompressed = coincurve.PublicKey(compressed).format(compressed=False)
    assert uncompressed[0] == 0x04, "coincurve did not expand the key"
    return int.from_bytes(uncompressed[1:33], "big"), int.from_bytes(uncompressed[33:65], "big")


def pka_point_hex(point) -> str:
    return "" if point is None else "%064x%064x" % point


def pka_bn_rows() -> dict[str, list[tuple[str, str, str, str, str, int]]]:
    """The bignum helpers, against CPython. mod empty means the width-fixed add, sub and cmp."""
    p, n = PKA_CURVE["p"], PKA_CURVE["n"]
    W = 1 << 256
    top = W - 1
    rows: dict[str, list] = {key: [] for key in ("add", "sub", "cmp", "add_mod", "sub_mod", "mul_mod", "exp_mod", "inv_mod")}

    for a, b in ((0, 0), (1, 2), (p - 1, 1), (top, 1), (top, top), (n - 1, n), (n, n), (2**128, 2**128 - 1)):
        rows["add"].append(("", "%064x" % a, "%064x" % b, "", "%064x" % ((a + b) % W), 0))
    for a, b in ((1, 1), (1, 2), (0, 1), (p, 1), (n, top), (0, top), (2**128, 2**128 + 1)):
        rows["sub"].append(("", "%064x" % a, "%064x" % b, "", "%064x" % ((a - b) % W), 0))
    for a, b, want in ((0, 0, 0), (0, 1, -1), (1, 0, 1), (top - 1, top, -1), (top, top, 0), (n, p, -1), (p, n, 1)):
        rows["cmp"].append(("", "%064x" % a, "%064x" % b, "", "", want))
    for modulus, label in ((p, "p"), (n, "n")):
        for a, b in ((0, 0), (1, 1), (modulus - 1, 1), (modulus, 0), (modulus + 5, modulus - 6), (top, top)):
            rows["add_mod"].append((label, "%064x" % a, "%064x" % b, "%064x" % modulus, "%064x" % ((a + b) % modulus), 0))
            rows["sub_mod"].append((label, "%064x" % a, "%064x" % b, "%064x" % modulus, "%064x" % ((a - b) % modulus), 0))
            rows["mul_mod"].append((label, "%064x" % a, "%064x" % b, "%064x" % modulus, "%064x" % (a * b % modulus), 0))
        for exponent, answer in ((0, 1), (1, 2), (2, 4), (255, pow(2, 255, modulus))):
            rows["exp_mod"].append((label, "%064x" % 2, "%064x" % exponent, "%064x" % modulus, "%064x" % answer, 0))
        rows["exp_mod"].append((label, "%064x" % top, "%064x" % (modulus - 1), "%064x" % modulus, "%064x" % pow(top, modulus - 1, modulus), 0))
        for a in (1, 2, modulus - 1, modulus + 1, (modulus >> 1) + 1):
            rows["inv_mod"].append((label, "%064x" % a, "", "%064x" % modulus, "%064x" % pow(a, -1, modulus), 0))
    # Fermat reaches zero the same way as any other input, and answers zero. Nothing in app/ asks.
    for modulus, label in ((p, "p"), (n, "n")):
        rows["inv_mod"].append((label, "%064x" % 0, "", "%064x" % modulus, "%064x" % 0, 0))
    # The square root exponent the curve table carries, applied to a residue.
    rows["exp_mod"].append(("sqrt", "%064x" % 4, "%064x" % ((p + 1) // 4), "%064x" % p, "%064x" % 2, 0))
    return rows


def bip32_public_levels() -> list[dict]:
    """Every xpub BIP-32's test vectors publish, in document order, with the derivation path
    rebuilt from the depth and child-number fields of the serialisation itself."""
    text = fetch("bip32.mediawiki")
    levels, stack = [], []
    for kind, key in re.findall(r"\*\* ext (pub|prv): (x(?:pub|prv)[0-9A-HJ-NP-Za-km-z]+)", text):
        if kind != "pub":
            continue
        raw = b58decode(key)[:-4]
        version, depth, child = raw[:4], raw[4], int.from_bytes(raw[9:13], "big")
        assert version == bytes.fromhex("0488b21e"), version.hex()
        while len(stack) > depth:
            stack.pop()
        assert len(stack) == depth, (depth, stack)
        stack.append(child)
        levels.append(
            {
                "path": "m"
                + "".join(
                    "/%d%s" % (c & 0x7FFFFFFF, "H" if c & 0x80000000 else "") for c in stack[1:]
                ),
                "depth": depth,
                "index": child,
                "chain": raw[13:45],
                "pub": raw[45:78],
                "raw": raw,
            }
        )
    assert len(levels) >= 12, len(levels)
    return levels


def bip32_vectors() -> str:
    levels = bip32_public_levels()

    def uncompressed(level) -> str:
        x, y = pka_decompress(level["pub"])
        return "04%064x%064x" % (x, y)

    def derives(parent, child) -> bool:
        return child["depth"] == parent["depth"] + 1

    def public_step(parent, child) -> bool:
        return derives(parent, child) and not child["index"] & 0x80000000

    ckd = []
    for parent, child in zip(levels, levels[1:]):
        if not public_step(parent, child):
            continue
        ckd.append(
            (
                child["path"],
                uncompressed(parent),
                hexs(parent["chain"]),
                child["index"],
                uncompressed(child),
                hexs(child["chain"]),
                1,
            )
        )
    for parent, child in zip(levels, levels[1:]):
        if derives(parent, child) and child["index"] & 0x80000000:
            ckd.append(
                (
                    "%s, asked for with the hardened bit set" % parent["path"],
                    uncompressed(parent),
                    hexs(parent["chain"]),
                    child["index"],
                    "",
                    "",
                    0,
                )
            )

    walk = []
    for account, change, leaf in zip(levels, levels[1:], levels[2:]):
        if public_step(account, change) and public_step(change, leaf):
            walk.append(
                (
                    account["path"],
                    uncompressed(account),
                    hexs(account["chain"]),
                    change["index"],
                    leaf["index"],
                    uncompressed(change),
                    hexs(change["chain"]),
                    hexs(leaf["pub"]),
                )
            )
    if not walk:
        sys.exit("bip32: no account/change/leaf triple of published public keys")

    def ckd_row(r):
        return (cstr(r[0]), cstr(r[1]), cstr(r[2]), "%dU" % r[3], cstr(r[4]), cstr(r[5]), "%d" % r[6])

    def walk_row(r):
        return (
            cstr(r[0]),
            cstr(r[1]),
            cstr(r[2]),
            "%dU" % r[3],
            "%dU" % r[4],
            cstr(r[5]),
            cstr(r[6]),
            cstr(r[7]),
        )

    ckd_body = ",\n".join("  {%s}" % ", ".join(ckd_row(r)) for r in ckd)
    walk_body = ",\n".join("  {%s}" % ", ".join(walk_row(r)) for r in walk)

    return f"""#ifndef VECTORS_BIP32_H
#define VECTORS_BIP32_H

/* spec: {provenance('bip32.mediawiki')}
 * reference: coincurve expands each published key to the uncompressed form the code works in
 *
 * Two consecutive xpubs of one test chain, where the child's number has the hardened bit clear,
 * are a public derivation the standard defines: parent key, parent chain code, index, child key
 * and child chain code all come out of the document. The hardened rows are the same parents asked
 * for with the hardened bit set, which is the one input the code is told to refuse; BIP-32
 * publishes nothing to compare against there, so those rows claim only that no key comes out.
 */
typedef struct {{
  const char* path;
  const char* parent_pub;
  const char* parent_chain;
  unsigned index;
  const char* child_pub; /* empty when ok is 0 */
  const char* child_chain;
  int ok;
}} bip32_ckd_t;

static const bip32_ckd_t BIP32_CKD[] = {{
{ckd_body}
}};

#define BIP32_CKD_COUNT (sizeof(BIP32_CKD) / sizeof(BIP32_CKD[0]))

/* The same published chain walked through the account context: setup at the account level, then
 * the change level, then a leaf. The leaf is compared as the document writes it, compressed,
 * because that is the form the context hands to the address encoders. */
typedef struct {{
  const char* account_path;
  const char* account_pub;
  const char* account_chain;
  unsigned change;
  unsigned leaf;
  const char* change_pub;
  const char* change_chain;
  const char* leaf_pub;
}} bip32_walk_t;

static const bip32_walk_t BIP32_WALK[] = {{
{walk_body}
}};

#define BIP32_WALK_COUNT (sizeof(BIP32_WALK) / sizeof(BIP32_WALK[0]))

#endif /* VECTORS_BIP32_H */
"""


def taproot_vectors() -> str:
    """BIP-86 publishes, for each of three leaves, the leaf's xprv, the x-only internal key and the
    taproot output key, together with the account xpub the same leaves are derived from
    publicly. All of it is used: the private key proves the internal key, the internal key and its
    TapTweak prove the output key, and only then is a row emitted."""
    text = fetch("bip86.mediawiki")
    c = PKA_CURVE
    g = (c["gx"], c["gy"])

    account = None
    rows = []
    for chunk in text.split("// Account 0,")[1:]:
        path = re.search(r"= (m(?:/[0-9]+'?)+)", chunk)
        xpub = re.search(r"xpub\s*= (xpub[0-9A-HJ-NP-Za-km-z]+)", chunk)
        assert path and xpub, chunk[:60]
        if not re.search(r"internal_key = [0-9a-f]{64}", chunk):
            account = xpub.group(1)
            continue
        internal = re.search(r"internal_key = ([0-9a-f]{64})", chunk).group(1)
        output = re.search(r"output_key\s*= ([0-9a-f]{64})", chunk).group(1)
        xprv = re.search(r"xprv\s*= (xprv[0-9A-HJ-NP-Za-km-z]+)", chunk)
        assert xprv, path.group(1)
        private = int.from_bytes(b58decode(xprv.group(1))[:-4][46:78], "big")
        x, y = pka_ec_mul(private, g, c["p"], c["a"])
        assert "%064x" % x == internal, path.group(1)
        assert b58decode(xpub.group(1))[:-4][45:78] == bytes.fromhex("%02x%064x" % (0x02 | (y & 1), x))

        # BIP-341 tweaks the even-y internal point, which is what the caller's prefix byte records.
        even = (x, y) if y % 2 == 0 else (x, c["p"] - y)
        tweak = int.from_bytes(tagged_hash("TapTweak", bytes.fromhex(internal)), "big")
        q = pka_ec_add(even, pka_ec_mul(tweak, g, c["p"], c["a"]), c["p"], c["a"])
        assert "%064x" % q[0] == output, path.group(1)

        steps = [int(part.rstrip("'")) for part in path.group(1).split("/")[1:]]
        assert not steps[-1] & 0x80000000 and not steps[-2] & 0x80000000, path.group(1)
        assert account, "a leaf appeared before its account xpub"
        body = b58decode(account)[:-4]
        assert body[:4] == bytes.fromhex("0488b21e"), body[:4].hex()
        ax, ay = pka_decompress(body[45:78])
        rows.append(
            (
                path.group(1).replace("'", "H"),
                "04%064x%064x" % (ax, ay),
                hexs(body[13:45]),
                steps[-2],
                steps[-1],
                "%02x%064x%064x" % (0x02 | (y & 1), x, y),
                output,
                y & 1,
            )
        )
    if len(rows) < 3:
        sys.exit(f"bip86: parsed {len(rows)} output keys, expected at least 3")
    if not (any(row[7] for row in rows) and any(not row[7] for row in rows)):
        sys.exit("bip86: the published internal keys are all of one parity")

    body = ",\n".join(
        "  {%s, %s, %s, %dU, %dU, %s, %s}"
        % (cstr(r[0]), cstr(r[1]), cstr(r[2]), r[3], r[4], cstr(r[5]), cstr(r[6]))
        for r in rows
    )
    even, odd = (sum(1 for r in rows if not r[7]), sum(1 for r in rows if r[7]))

    return f"""#ifndef VECTORS_TAPROOT_H
#define VECTORS_TAPROOT_H

/* spec: {provenance('bip86.mediawiki')}
 *
 * Three leaves of the BIP-86 test vector. The document publishes the account xpub they derive
 * from publicly, each leaf's own xprv, the x-only internal key and the output key. The generator
 * first recomputes the internal key from the private key and then the output key from the internal
 * key and its TapTweak, so the published quadruple is consistent with the standard before any of
 * it reaches a test.
 *
 * {even} of these internal keys have an even y and {odd} an odd one, which is the difference
 * between handing the point to the tweak as it stands and negating it first. The internal buffer
 * is the layout bip32_ctx_t.leaf_pub holds: a SEC1 compression prefix, then x || y.
 */
typedef struct {{
  const char* path;
  const char* account_pub; /* the account xpub, 0x04 || x || y */
  const char* account_chain;
  unsigned change;
  unsigned index;
  const char* internal; /* 0x02|parity || x || y */
  const char* witprog;
}} taproot_t;

static const taproot_t TAPROOT_OUTPUT_KEY[] = {{
{body}
}};

#define TAPROOT_OUTPUT_KEY_COUNT (sizeof(TAPROOT_OUTPUT_KEY) / sizeof(TAPROOT_OUTPUT_KEY[0]))

#endif /* VECTORS_TAPROOT_H */
"""


def ecdsa_curve_vectors() -> str:
    """The curve side of app/crypto/ecdsa.c: public keys, ECDH, and signature recovery."""
    c = PKA_CURVE
    g = (c["gx"], c["gy"])
    p, n = c["p"], c["n"]

    def point_hex(point) -> str:
        return "04%064x%064x" % point

    keys = pka_bip32_keys()

    pubkey = []
    for priv, compressed in keys:
        x, y = pka_decompress(compressed)
        assert (x, y) == pka_ec_mul(priv, g, p, c["a"]), "the published key is not the private key's"
        pubkey.append(("%064x" % priv, point_hex((x, y)), "%02x%064x" % (0x02 | (y & 1), x)))

    ecdh = []
    for first, second in zip(keys, keys[1:]):
        priv_a, compressed_a = first
        priv_b, compressed_b = second
        a, b = pka_decompress(compressed_a), pka_decompress(compressed_b)
        shared = pka_ec_mul(priv_a, b, p, c["a"])
        assert shared == pka_ec_mul(priv_b, a, p, c["a"]), "ECDH is not symmetric"
        ecdh.append(("%064x" % priv_a, point_hex(b), point_hex(shared)))
        ecdh.append(("%064x" % priv_b, point_hex(a), point_hex(shared)))

    def point_over(x: int, parity: int) -> tuple[int, int]:
        """The point whose x is x and whose y has the parity named; no such point exists when
        x^3 + 7 is not a square, which is what the curve test in the code under test catches."""
        return pka_decompress(bytes([0x02 | parity]) + x.to_bytes(32, "big"))

    def recovered(r: int, s: int, digest: bytes, point) -> tuple[int, int]:
        """The recovery the code does: r^-1 (s P + (order - digest) G). The digest is taken off the
        order with an ordinary 256-bit subtraction, as the code does, before it is a scalar."""
        z = ((n - int.from_bytes(digest, "big")) % (1 << 256)) % n
        both = pka_ec_add(pka_ec_mul(s, point, p, c["a"]), pka_ec_mul(z, g, p, c["a"]), p, c["a"])
        return pka_ec_mul(pow(r, -1, n), both, p, c["a"])

    recover = []
    for priv, digest, k, r, s in pka_signature_rows():
        if int.from_bytes(digest, "big") > n:
            continue  # below the order, or the subtraction the code does goes negative
        own_point = pka_ec_mul(priv, g, p, c["a"])
        parity = pka_ec_mul(k, g, p, c["a"])[1] & 1
        signature = "%064x%064x" % (r, s)
        assert recovered(r, s, digest, point_over(r, parity)) == own_point, \
            "the recovery formula does not return the signer"
        recover.append(("the signer's own key", point_hex(own_point), signature, hexs(digest), parity))

        other = recovered(r, s, digest, point_over(r, parity ^ 1))
        assert other != own_point
        recover.append(("the other point over the same x", point_hex(other), signature, hexs(digest), parity ^ 1))


    def pubkey_row(r):
        return (cstr(r[0]), cstr(r[1]), cstr(r[2]))

    def ecdh_row(r):
        return (cstr(r[0]), cstr(r[1]), cstr(r[2]))

    # A signature is two elements of the order, and the recovery entry point is the one place in
    # ecdsa.c that says so out loud. The first real signature provides the half that is fine.
    first_priv, first_digest, _k, first_r, first_s = pka_signature_rows()[0]
    reject = [
        ("r of 0", "%064x%064x" % (0, first_s), hexs(first_digest)),
        ("r of the order", "%064x%064x" % (n, first_s), hexs(first_digest)),
        ("r above the order", "%064x%064x" % (n + 1, first_s), hexs(first_digest)),
        ("s of 0", "%064x%064x" % (first_r, 0), hexs(first_digest)),
        ("s of the order", "%064x%064x" % (first_r, n), hexs(first_digest)),
        ("s above the order", "%064x%064x" % (first_r, n + 1), hexs(first_digest)),
    ]

    def reject_row(r):
        return (cstr(r[0]), cstr(r[1]), cstr(r[2]))

    def recover_row(r):
        return (cstr(r[0]), cstr(r[1]), cstr(r[2]), cstr(r[3]), "%dU" % r[4])

    def body(rows, fields):
        return ",\n".join("  {%s}" % ", ".join(fields(r)) for r in rows)

    return f"""#ifndef VECTORS_ECDSA_CURVE_H
#define VECTORS_ECDSA_CURVE_H

/* spec: {provenance('bip32.mediawiki')}
 * reference: CPython integers, with coincurve expanding each published key and signing the
 * digests the recovery rows run over
 *
 * The public keys are the levels of BIP-32 test vector 1, whose xprv and xpub are published
 * together, so the point of a private key is a published value rather than a computed one; the
 * generator recomputes each one and asserts it before emitting.
 *
 * The ECDH rows are pairs of those same published keys, each shared secret stated from both ends,
 * which is the property the exchange is defined by.
 *
 * The recovery rows are signatures from vectors_pka.h over a digest below the order, and a
 * signature is recovered twice: once with the id the generator derives from the nonce, for which
 * the standard's own recovery formula is asserted to return the published key of the signer, and
 * once with the id naming the other y over the same x, for which it states what that formula
 * yields. An x taken from a real point is a coordinate of points whatever parity is read from it,
 * so neither row asks for a refusal.
 *
 * The other bit of a recovery id, which claims an x of r plus the order, is not here. On this
 * curve that sum is past the width of a scalar unless r is under prime - order, a window of 2**32
 * values out of the order, so what the bit does is a consequence of how the addition overflows
 * rather than of the standard; the test covers it with the property that holds either way.
 */
typedef struct {{
  const char* priv;
  const char* pub; /* 0x04 || x || y */
  const char* compressed; /* 0x02|parity || x */
}} ecdsa_pubkey_t;

static const ecdsa_pubkey_t ECDSA_PUBKEY[] = {{
{body(pubkey, pubkey_row)}
}};

#define ECDSA_PUBKEY_COUNT (sizeof(ECDSA_PUBKEY) / sizeof(ECDSA_PUBKEY[0]))

typedef struct {{
  const char* priv;
  const char* peer; /* 0x04 || x || y */
  const char* shared; /* 0x04 || x || y */
}} ecdsa_ecdh_t;

static const ecdsa_ecdh_t ECDSA_ECDH[] = {{
{body(ecdh, ecdh_row)}
}};

#define ECDSA_ECDH_COUNT (sizeof(ECDSA_ECDH) / sizeof(ECDSA_ECDH[0]))

typedef struct {{
  const char* name;
  const char* pub; /* 0x04 || x || y */
  const char* sig; /* r || s */
  const char* digest;
  unsigned recid; /* the id handed to the call, which returns the key above */
}} ecdsa_recover_t;

static const ecdsa_recover_t ECDSA_RECOVER[] = {{
{body(recover, recover_row)}
}};

#define ECDSA_RECOVER_COUNT (sizeof(ECDSA_RECOVER) / sizeof(ECDSA_RECOVER[0]))

/* Two numbers that are not a signature, because an element is in [1, order-1]. The recovery entry
 * point is the one that checks, and the digest it then hashes is a valid one, so what a row tests
 * is the check rather than anything behind it. */
typedef struct {{
  const char* name;
  const char* sig; /* r || s */
  const char* digest;
}} ecdsa_reject_t;

static const ecdsa_reject_t ECDSA_RECOVER_REJECTED[] = {{
{body(reject, reject_row)}
}};

#define ECDSA_RECOVER_REJECTED_COUNT (sizeof(ECDSA_RECOVER_REJECTED) / sizeof(ECDSA_RECOVER_REJECTED[0]))

#endif /* VECTORS_ECDSA_CURVE_H */
"""


def pka_signature_rows() -> list[tuple[int, bytes, int, int, int]]:
    """(private key, digest, k, r, s), one row per (private key, digest). The k is what the
    deterministic-k model picks; every row is then compared with a signature libsecp256k1 made
    over the same private key and digest, since libsecp256k1's own nonce is RFC 6979 without
    additional data."""
    c = PKA_CURVE
    n = c["n"]
    pka_validate_k_model()

    digests = [hashlib.sha256(b"keycard-shell pka %d" % i).digest() for i in range(6)]
    digests.append(bytes(32))
    digests.append(bytes([0xFF] * 32))

    rows = []
    privates = [priv for priv, _ in pka_bip32_keys()] + [1, n - 1, 0x1234567890ABCDEF]
    for priv in privates:
        for digest in digests:
            k, r, s = pka_secp_sign(priv, digest)
            signed = pka_coincurve_signature(priv, digest)
            # libsecp256k1 hands back the lower of the two s when it signs, so the comparison is
            # against either root; which one a row carries is the point of the s-above-n/2 check.
            assert (r, s) == signed or (r, (n - s) % n) == signed, "model and libsecp256k1 disagree"
            rows.append((priv, digest, k, r, s))
    return rows


def pka_vectors() -> str:
    pka_check_curve_table()
    checked = pka_validate_k_model()

    c = PKA_CURVE
    g = (c["gx"], c["gy"])
    p, n = c["p"], c["n"]
    neg_g = (g[0], (p - g[1]) % p)

    sign_rows = pka_signature_rows()
    high = [row for row in sign_rows if row[4] * 2 > n]
    if not high:
        sys.exit("no row had s above n/2, so the other root would go uncovered")

    # --- verification: each signature accepts, and each way of perturbing it does not.
    verify_rows = []
    for index, (priv, digest, _k, r, s) in enumerate(sign_rows):
        public = pka_ec_mul(priv, g, p, c["a"])
        verify_rows.append(("as signed", "%064x%064x" % (r, s), hexs(digest), pka_point_hex(public), 1))
        if index >= 8:
            continue  # one accept per row, and the perturbations of the first eight
        flipped = bytearray(digest)
        flipped[0] ^= 1
        verify_rows.append(("digest bit flipped", "%064x%064x" % (r, s), hexs(bytes(flipped)), pka_point_hex(public), 0))
        verify_rows.append(("digest one higher", "%064x%064x" % (r, s), "%064x" % ((int.from_bytes(digest, "big") + 1) % (1 << 256)), pka_point_hex(public), 0))
        verify_rows.append(("r one higher", "%064x%064x" % (r + 1, s), hexs(digest), pka_point_hex(public), 0))
        verify_rows.append(("s one higher", "%064x%064x" % (r, s + 1), hexs(digest), pka_point_hex(public), 0))
        verify_rows.append(("wrong key", "%064x%064x" % (r, s), hexs(digest), pka_point_hex(g), 0))
        if index == 0:
            # The all-zero digest is a real digest, so this row is about the equation rather than
            # about a message; it is kept because it is the one digest a test reaches by accident.
            verify_rows.append(("empty digest", "%064x%064x" % (r, s), hexs(bytes(32)), pka_point_hex(public), 0))
    # Both roots of s satisfy the equation: negating s negates the scalar of the point it recovers,
    # and negating a point leaves its x coordinate alone.
    first = sign_rows[0]
    public_first = pka_ec_mul(first[0], g, p, c["a"])
    verify_rows.append(("s replaced by n - s", "%064x%064x" % (first[3], (n - first[4]) % n), hexs(first[1]), pka_point_hex(public_first), 1))
    for zero in (0, n, n + 1, 1 << 255):
        verify_rows.append(("r of %s" % hex(zero), "%064x%064x" % (zero, first[4]), hexs(first[1]), pka_point_hex(public_first), 0))
        verify_rows.append(("s of %s" % hex(zero), "%064x%064x" % (first[3], zero), hexs(first[1]), pka_point_hex(public_first), 0))

    # --- multiplication against the published keys of BIP-32's test vector 1, then the degenerate
    # scalars, with the answers from CPython.
    mul_rows = []
    for priv, compressed in pka_bip32_keys():
        x, y = pka_decompress(compressed)
        assert (x, y) == pka_ec_mul(priv, g, p, c["a"]), "BIP-32's published key is not priv*G"
        mul_rows.append(("%064x" % priv, pka_point_hex(g), "%064x%064x" % (x, y), 1))
    for scalar, point, want in (
        (2, g, pka_ec_mul(2, g, p, c["a"])),
        (n - 1, g, pka_ec_mul(n - 1, g, p, c["a"])),
        (n + 1, g, g),
        (n - 2, neg_g, pka_ec_mul(n - 2, neg_g, p, c["a"])),
        (1, neg_g, neg_g),
        (0, g, None),
        (n, g, None),
        (n + (1 << 127), neg_g, pka_ec_mul(1 << 127, neg_g, p, c["a"])),
        (n + 3, neg_g, pka_ec_mul(n + 3, neg_g, p, c["a"])),
    ):
        mul_rows.append(("%064x" % scalar, pka_point_hex(point), pka_point_hex(want), 0 if want is None else 1))

    # --- the double ladder, which is how BIP-32's public child derivation and the taproot tweak
    # reach the accelerator: s1*p1 + s2*p2.
    ladder_rows = []
    priv, compressed = pka_bip32_keys()[0]
    parent = pka_decompress(compressed)
    for tweak in (1, 2, int(hashlib.sha256(b"I").hexdigest(), 16), n - 1):
        want = pka_ec_add(pka_ec_mul(1, parent, p, c["a"]), pka_ec_mul(tweak, g, p, c["a"]), p, c["a"])
        ladder_rows.append(("%064x" % 1, pka_point_hex(parent), "%064x" % tweak, pka_point_hex(g), pka_point_hex(want), 1))
    ladder_rows.append(("%064x" % 1, pka_point_hex(g), "%064x" % 2, pka_point_hex(g), pka_point_hex(pka_ec_mul(3, g, p, c["a"])), 1))
    ladder_rows.append(("%064x" % 5, pka_point_hex(g), "%064x" % 3, pka_point_hex(neg_g), pka_point_hex(pka_ec_mul(2, g, p, c["a"])), 1))
    ladder_rows.append(("%064x" % 1, pka_point_hex(g), "%064x" % (n - 1), pka_point_hex(g), "", 0))
    ladder_rows.append(("%064x" % 0, pka_point_hex(g), "%064x" % (n - 2), pka_point_hex(neg_g), pka_point_hex(pka_ec_mul(2, g, p, c["a"])), 1))

    # --- the curve test itself. A coordinate of p + x names the same field element, so it is the
    # same point to arithmetic modulo p; the rest are not on the curve.
    x0, y0 = pka_ec_mul(0x1000, g, p, c["a"])
    check_rows = [(pka_point_hex(g), 1), (pka_point_hex(neg_g), 1), (pka_point_hex((x0, y0)), 1)]
    for priv, compressed in pka_bip32_keys():
        check_rows.append((pka_point_hex(pka_decompress(compressed)), 1))
    # A point whose x is small enough that x + p still fits in 32 bytes, for the one non-canonical
    # encoding this curve can express at all: p is within 2**32 of 2**256, so there is barely any
    # room above it, and y + p does not fit for a point that exists.
    head = lambda x: (x * x * x + c["a"] * x + c["b"]) % p
    x_small = next(value for value in range(2, 500) if pow(head(value), (p - 1) // 2, p) == 1)
    y_small = pow(head(x_small), (p + 1) // 4, p)
    assert y_small * y_small % p == head(x_small)

    check_rows += [
        ("%064x%064x" % (x0, y0 + 1), 0),
        ("%064x%064x" % (x0 + 1, y0), 0),
        ("%064x%064x" % (x0, (p - y0 + 1) % p), 0),
        ("0" * 128, 0),
        ("%064x%064x" % (p - 1, 1), 0),
        ("%064x%064x" % (p, 0), 0),
        ("%064x%064x" % (1, 1), 0),
        ("%064x%064x" % (x_small, y_small), 1),
        ("%064x%064x" % (p + x_small, y_small), 1),
    ]
    # Each row against the curve equation, arithmetic modulo p, so an off-curve row is off it for
    # the reason the stand-in will give, and every point is a coordinate pair the encoder can hold.
    for point, claims in check_rows:
        assert len(point) == 128 and all(ch in "0123456789abcdef" for ch in point), point
        x = int(point[:64], 16) % p
        y = int(point[64:], 16) % p
        on = (y * y - (x * x * x + c["a"] * x + c["b"])) % p == 0
        assert on == bool(claims), point

    bn = pka_bn_rows()

    def table(name: str, type_name: str, rows, fields) -> str:
        body = ",\n".join("  {%s}" % ", ".join(f for f in fields(row)) for row in rows)
        # Every literal that is made of hex digits is a byte string, so an odd length would be a
        # value the test's reader has to guess at. A name column always has a space or a
        # non-hex letter in it, which is what keeps this check from tripping on those.
        for literal in re.findall(r'"([0-9a-f]*)"', body):
            assert len(literal) % 2 == 0, (name, literal)

        return f"""static const {type_name} {name}[] = {{
{body}
}};

#define {name}_COUNT (sizeof({name}) / sizeof({name}[0]))
"""

    def sign_row(row):
        priv, digest, k, r, s = row
        return (cstr("%064x" % priv), cstr(hexs(digest)), cstr("%064x" % k), cstr("%064x" % r), cstr("%064x" % s))

    def verify_row(row):
        name, sig, digest, pub, verdict = row
        return (cstr(name), cstr(sig), cstr(digest), cstr(pub), str(verdict))

    def mul_row(row):
        scalar, point, out, verdict = row
        return (cstr(scalar), cstr(point), cstr(out), str(verdict))

    def ladder_row(row):
        s1, p1, s2, p2, out, verdict = row
        return (cstr(s1), cstr(p1), cstr(s2), cstr(p2), cstr(out), str(verdict))

    def check_row(row):
        point, verdict = row
        return (cstr(point), str(verdict))

    def bn_row(row):
        label, a, b, modulus, out, want = row
        return (cstr(label), cstr(a), cstr(b), cstr(modulus), cstr(out), str(want))

    return f"""#ifndef VECTORS_PKA_H
#define VECTORS_PKA_H

/* spec: {provenance('rfc6979.txt')}
 * reference: CPython integers, and coincurve/libsecp256k1 for every signature row
 * {provenance('bip32.mediawiki')}
 *
 * {checked} triples of RFC 6979 appendix A.2.5 were reproduced by the same deterministic-k model
 * that produced the k of every row below, k, r and s all matching. A.2.5 is NIST P-256, and
 * secp256k1 is the only curve this firmware builds, so what the appendix pins is the model; each
 * row below is then checked against a signature libsecp256k1 made for the same private key and
 * the same digest, which is where the secp256k1 answer comes from.
 *
 * The curve constants are compared against app/crypto/secp256k1.c before a row is emitted, and
 * its sqrt_exp against (p+1)//4. The keys of BIP-32 test vector 1 are published as both an xprv
 * and an xpub of the same level, which is what makes priv*G a published value rather than a
 * computed one; the decompression of each published key is done by coincurve.
 */
typedef struct {{
  const char* priv;
  const char* digest;
  const char* k;
  const char* r;
  const char* s;
}} pka_sign_t;

typedef struct {{
  const char* name;
  const char* sig;      /* r then s, 64 bytes */
  const char* digest;
  const char* point;    /* x then y, no prefix */
  int accept;           /* 0 means the equation must not hold */
}} pka_verify_t;

typedef struct {{
  const char* scalar;
  const char* point;
  const char* out;
  int ok;               /* 0 where the answer is the point at infinity, which has no encoding */
}} pka_mul_t;

typedef struct {{
  const char* s1;
  const char* p1;
  const char* s2;
  const char* p2;
  const char* out;
  int ok;
}} pka_ladder_t;

typedef struct {{
  const char* point;
  int on_curve;
}} pka_check_t;

typedef struct {{
  const char* label;    /* which modulus the row was computed over, empty for the fixed-width ops */
  const char* a;
  const char* b;        /* the exponent of exp_mod; empty where unused */
  const char* mod;      /* empty for add, sub and cmp, which are not reduced */
  const char* out;      /* empty for cmp */
  int cmp;              /* the answer for cmp, -1, 0 or 1; unused otherwise */
}} pka_bn_t;

{table("PKA_SIGN", "pka_sign_t", sign_rows, sign_row)}

{table("PKA_VERIFY", "pka_verify_t", verify_rows, verify_row)}

{table("PKA_MUL", "pka_mul_t", mul_rows, mul_row)}

{table("PKA_LADDER", "pka_ladder_t", ladder_rows, ladder_row)}

{table("PKA_CHECK", "pka_check_t", check_rows, check_row)}

{table("PKA_BN_ADD", "pka_bn_t", bn['add'], bn_row)}

{table("PKA_BN_SUB", "pka_bn_t", bn['sub'], bn_row)}

{table("PKA_BN_CMP", "pka_bn_t", bn['cmp'], bn_row)}

{table("PKA_BN_ADD_MOD", "pka_bn_t", bn['add_mod'], bn_row)}

{table("PKA_BN_SUB_MOD", "pka_bn_t", bn['sub_mod'], bn_row)}

{table("PKA_BN_MUL_MOD", "pka_bn_t", bn['mul_mod'], bn_row)}

{table("PKA_BN_EXP_MOD", "pka_bn_t", bn['exp_mod'], bn_row)}

{table("PKA_BN_INV_MOD", "pka_bn_t", bn['inv_mod'], bn_row)}

#endif
"""

# --------------------------------------------- multisig public derivation

# A wallet is cosigner xpubs plus (change, index). Both halves of the answer are anchored outside
# this file: the xpubs and the transitions between published levels come from BIP-32's test vector
# 1, and the redeem script and its P2SH address come from BIP-67's test vectors. Each is proven
# below before a single row is emitted, so what reaches a test is a composition of two documents.

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def ms_bech32(hrp: str, witver: int, program: bytes) -> str:
    """BIP-173's encoding of a witness program. ms_check_bech32() proves it against the addresses
    BIP-173 publishes; secp256k1 and the script rules are somebody else's problem elsewhere."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

    def polymod(values):
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ value
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= gen[i]
        return chk

    data = [witver]
    acc = bits = 0
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)

    chk = polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(
        BECH32_CHARSET[d] for d in data + [(chk >> (5 * (5 - i))) & 31 for i in range(6)])


def ms_check_bech32() -> int:
    """Every version 0 address BIP-173 publishes, re-encoded from the witness program beside it."""
    rows, _ = parse_segwit_vectors("bip173.mediawiki")
    proven = 0
    for row in rows:
        if row["witver"] != 0:
            continue
        got = ms_bech32(row["hrp"], 0, bytes.fromhex(row["program"]))
        if got != row["address"].lower():
            sys.exit(f"bech32: {row['program']} encodes to {got}, BIP-173 says {row['address']}")
        proven += 1
    if proven < 3:
        sys.exit(f"BIP-173 published {proven} version 0 addresses, expected at least 3")
    return proven


def ms_script(m: int, n: int, keys: list[bytes]) -> bytes:
    """BIP-67: the compressed keys sorted as bytes, inside OP_M ... OP_N OP_CHECKMULTISIG."""
    out = bytes([0x50 + m])
    for key in sorted(keys):
        out += bytes([33]) + key
    return out + bytes([0x50 + n, 0xAE])


def ms_p2sh_of(redeem: bytes, prefix: int = 5) -> str:
    """The BIP-16 address of a redeem script. ms_check_nesting_against_bip49 proves it against the
    chain BIP-49 publishes -- key hash, wrap, HASH160 of the wrap, base58check -- before use."""
    return b58check_encode(bytes([prefix]) + hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest())


def ms_p2sh_address(script: bytes) -> str:
    return ms_p2sh_of(script)


def ms_p2wsh_address(script: bytes) -> str:
    return ms_bech32("bc", 0, hashlib.sha256(script).digest())


def ms_p2sh_p2wsh_address(script: bytes) -> str:
    """BIP-141: the redeem script of a P2WSH nested in P2SH is OP_0 followed by the 32-byte
    sha256 of the witness script, and it is that wrap -- 34 bytes -- which BIP-16 hashes. Not the
    hash on its own."""
    return ms_p2sh_of(bytes([0x00, 0x20]) + hashlib.sha256(script).digest())


def ms_check_nesting_against_bip49() -> None:
    """BIP-49's test vector states the nesting chain end to end. The wrap it publishes is for
    P2WPKH (OP_0 <20-byte key hash>); BIP-141 says the same with a 32-byte script hash, which is
    what ms_p2sh_p2wsh_address above produces."""
    text = fetch("bip49.mediawiki")
    keyhash = bytes.fromhex(re.search(r"keyhash = HASH160\(account0recvPublicKeyHex\) = 0x([0-9a-f]{40})", text).group(1))
    wrap = bytes.fromhex(re.search(r"scriptSig = <0 <keyhash>> = (0x0014[0-9a-f]{40})", text).group(1)[2:])
    inner = bytes.fromhex(re.search(r"addressBytes = HASH160\(scriptSig\) = 0x([0-9a-f]{40})", text).group(1))
    address = re.search(r"address = base58check\(prefix \| addressBytes\) = ([mn2][a-km-zA-HJ-NP-Z1-9]{25,34})", text).group(1)

    assert wrap == bytes([0x00, 0x14]) + keyhash, "BIP-49's wrap is not OP_0 <keyhash>"
    if hashlib.new("ripemd160", hashlib.sha256(wrap).digest()).digest() != inner:
        sys.exit("BIP-49: HASH160 of the published wrap is not the published addressBytes")
    # The vector is testnet, and BIP-49 addresses carry the 0xC4 prefix that SLIP-0132 registers
    # for them; 0x6F, the ordinary testnet P2KH byte, produces a different string.
    if ms_p2sh_of(wrap, prefix=0xC4) != address:
        sys.exit(f"BIP-49: the published wrap pays to {ms_p2sh_of(wrap, prefix=0xC4)}, not {address}")


def ms_bip67_vectors() -> list[dict]:
    """BIP-67's test vectors: the list as given, the same list sorted, the redeem script and the
    P2SH address. The document states that two signatures are required in each of them."""
    text = fetch("bip67.mediawiki")
    assert "Two signatures are required in each of these test vectors." in text
    section = text.split("==Test vectors==", 1)[1]

    vectors, current, field = [], None, None
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("Vector"):
            current = {"list": [], "sorted": [], "script": "", "address": ""}
            vectors.append(current)
            field = None
            continue
        if current is None:
            continue
        named = re.match(r"\*\*?\s*(List|Sorted|Script|Address)", line)
        if named:
            field = named.group(1).lower()
            inline = line[named.end():].strip(" :")
            if field in ("list", "sorted") and re.fullmatch(r"[0-9a-fA-F]{66}", inline):
                current[field].append(inline)
            continue
        if not line.startswith("**") or field is None:
            continue
        value = line[2:].strip()
        if field in ("list", "sorted"):
            current[field].append(value)
        elif field == "script":
            current[field] = value.lower()
        else:
            current[field] = value

    vectors = [v for v in vectors if v["list"] and v["sorted"] and v["script"] and v["address"]]
    if len(vectors) < 3:
        sys.exit(f"BIP-67 published {len(vectors)} test vectors, expected at least 3")
    return vectors


def ms_check_script_against_bip67() -> int:
    """The sorting, the script layout and the P2SH address, against what BIP-67 says they are."""
    proven = 0
    for vector in ms_bip67_vectors():
        keys = [bytes.fromhex(k) for k in vector["list"]]
        if sorted(keys) != [bytes.fromhex(k) for k in vector["sorted"]]:
            sys.exit("BIP-67: the document's own sort is not a byte sort")
        script = ms_script(2, len(keys), keys)
        if hexs(script) != vector["script"]:
            sys.exit(f"BIP-67: script {hexs(script)} is not the published {vector['script']}")
        if ms_p2sh_address(script) != vector["address"]:
            sys.exit(f"BIP-67: {hexs(script)} pays to {ms_p2sh_address(script)}, not {vector['address']}")
        proven += 1
    return proven


def ms_ckd_pub(code: bytes, key: bytes, index: int) -> tuple[bytes, bytes]:
    """BIP-32 public derivation: I = HMAC-SHA512(chain code, serP(K) || ser32(i)), the child point
    is point(I_L) + K and the child chain code is I_R. The parent is expanded by coincurve and the
    arithmetic is CPython's; ms_ckd_pub_matches_published proves both against BIP-32's own
    published children before this file writes anything."""
    i = hmac.new(code, key + index.to_bytes(4, "big"), hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    assert 0 < il < PKA_CURVE["n"], "I_L is not a valid scalar"
    base = (PKA_CURVE["gx"], PKA_CURVE["gy"])
    parent = pka_decompress(key)
    child = pka_ec_add(pka_ec_mul(il, base, PKA_CURVE["p"], PKA_CURVE["a"]), parent,
                       PKA_CURVE["p"], PKA_CURVE["a"])
    assert child is not None, "the child is the point at infinity"
    x, y = child
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big"), i[32:]


def ms_ckd_pub_matches_published() -> int:
    """Every plain one-level step BIP-32 publishes from one xpub to the next, checked on both the
    child key and the child chain code. The published xpubs are the same list the bip32 vectors
    are built from."""
    proven = 0
    levels = bip32_public_levels()
    for parent, child in zip(levels, levels[1:]):
        if child["depth"] != parent["depth"] + 1 or child["index"] & 0x80000000:
            continue
        got_key, got_code = ms_ckd_pub(parent["chain"], parent["pub"], child["index"])
        if (got_key, got_code) != (child["pub"], child["chain"]):
            sys.exit(f"CKDpub {child['path']}: {hexs(got_key)}/{hexs(got_code)} is not "
                     f"{hexs(child['pub'])}/{hexs(child['chain'])}")
        proven += 1
    if proven < 4:
        sys.exit(f"BIP-32 published {proven} plain public steps, expected at least 4")
    return proven


def ms_derive(levels: list[dict], picks: list[int], change: int, index: int) -> list[bytes]:
    keys = []
    for pick in picks:
        level = levels[pick]
        key, code = ms_ckd_pub(level["chain"], level["pub"], change)
        key, _ = ms_ckd_pub(code, key, index)
        keys.append(key)
    return keys


def ms_address(fmt: int, keys: list[bytes], m: int, n: int) -> str:
    script = ms_script(m, n, keys)
    return {0: ms_p2sh_address, 1: ms_p2sh_p2wsh_address, 2: ms_p2wsh_address}[fmt](script)


MULTISIG_DERIVE_HEADER = """/* Generated by tests/vectors/generate.py -- do not edit by hand.
 *
 * Addresses of multisig descriptors, for bitcoin/multisig.c's multisig_derive_address.
 *
 * A row is a wallet (m of n, the format, the cosigner xpubs in the order the setup file lists
 * them) and one (change, index) step, with the address that step is supposed to produce.
 *
 * Each cosigner xpub is an extended public key one of BIP-32's test vectors publishes, so the
 * input of every row is somebody else's number. The address is composed by generate.py out of three documents:
 * the plain public derivation of BIP-32, the sorted redeem script and its P2SH address of BIP-67,
 * and the bech32 encoding of BIP-173. Before writing this file generate.py proves each of those
 * against the published data it names -- the derivation against BIP-32's own published children
 * (both key and chain code), the script and the P2SH address against every BIP-67 vector, the
 * encoding against every version 0 address BIP-173 publishes -- and exits rather than emit if any
 * of them disagrees. Nothing in between the published xpub and the published address is believed
 * because it is convenient.
 *
 * The order of the xpubs is part of the input on purpose: BIP-67 sorts the derived keys, so a
 * wallet listed in another order must give the same address.
 *
 * %s
 * %s
 */

#ifndef VECTORS_MULTISIG_DERIVE_H
#define VECTORS_MULTISIG_DERIVE_H

#include <stdint.h>

typedef struct {
  const char* label;
  uint8_t m;
  uint8_t n;
  int format;    /* multisig_format_t: 0 P2SH, 1 P2WSH-P2SH, 2 P2WSH */
  uint32_t change;
  uint32_t index;
  const char* xpubs[6]; /* the cosigners' serialized xpubs, 156 hex chars each, no checksum, in
                           the order the setup file lists them */
  const char* addr;
} multisig_derive_t;

static const multisig_derive_t MULTISIG_DERIVE[] = {
%s
};

#define MULTISIG_DERIVE_COUNT (sizeof(MULTISIG_DERIVE) / sizeof(MULTISIG_DERIVE[0]))

#endif
"""


def multisig_derive_vectors() -> str:
    steps = ms_ckd_pub_matches_published()
    bip67 = ms_check_script_against_bip67()
    bech32 = ms_check_bech32()
    ms_check_nesting_against_bip49()
    levels = bip32_public_levels()

    # Three master xpubs from three different published chains, so no cosigner is a descendant of
    # another. The deeper positions add cosigners for the larger wallets; two of them are in a
    # chain with one of the masters, which is of no consequence because each cosigner is derived
    # from on its own.
    trio, five, six = [0, 6, 14], [0, 6, 12, 14, 4], [0, 2, 6, 9, 12, 15]

    rows = []

    def row(label, picks, m, fmt, change, index):
        keys = ms_derive(levels, picks, change, index)
        rows.append(
            "  {%s, %d, %d, %d, %du, %du, {%s}, %s}"
            % (cstr(label), m, len(picks), fmt, change, index,
               ", ".join(cstr(hexs(levels[p]["raw"])) for p in picks),
               cstr(ms_address(fmt, keys, m, len(picks))))
        )

    for fmt, format_name in ((2, "P2WSH"), (1, "P2WSH-P2SH"), (0, "P2SH")):
        row(f"2 of 3 {format_name}, first receive address", trio, 2, fmt, 0, 0)
        row(f"2 of 3 {format_name}, first change address", trio, 2, fmt, 1, 0)
        row(f"2 of 3 {format_name}, seventh change address", trio, 2, fmt, 1, 7)
    row("3 of 5 P2WSH, first receive address", five, 3, 2, 0, 0)
    row("3 of 5 P2WSH, seventh change address", five, 3, 2, 1, 7)
    row("6 of 6 P2WSH, third receive address", six, 6, 2, 0, 2)
    row("2 of 6 P2WSH, third receive address", six, 2, 2, 0, 2)

    print(f"multisig: {steps} published public steps, {bip67} BIP-67 vectors, {bech32} BIP-173 addresses")
    return MULTISIG_DERIVE_HEADER % (
        provenance("bip32.mediawiki"),
        provenance("bip67.mediawiki") + "\n * " + provenance("bip49.mediawiki"),
        ",\n".join(rows))


# ----------------------------------------------------------------- shell token db
#
# The published Shell database is the only corpus with the shape eth_db.c really parses: one long chain
# of mixed entries handed to a single fs_write(), spanning many flash blocks. Each release publishes the
# upstream lists the blob was generated from (chain.json, erc20.json, abi.json) alongside it, and every
# row below is confirmed against them, so a lookup is pinned to what chainid.network and tokens.uniswap.org
# say rather than to what the C parser read back.

SHELL_DB = "shell_db_20261111.zip"
SHELL_DB_SIGNED = "shell_db_20261111.bin"
SHELL_DB_VERSION = 20261111
DB_SIG_LEN = 64
DB_NET_LEN = 24
DB_MAGICS = {0x4532: "version", 0x4348: "chain", 0x3020: "erc20", 0x4142: "abi"}


def db_read_zip(name: str) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(fetch_bytes(name))) as z:
        return {n: z.read(n) for n in z.namelist()}


def db_addr(text: str) -> bytes | None:
    """Addresses in the upstream list are hex with an 0x prefix; some releases carry other shapes."""
    body = text[2:] if text[:2].lower() == "0x" else text
    if len(body) != 40 or any(c not in "0123456789abcdefABCDEF" for c in body):
        return None
    return bytes.fromhex(body)


def db_parse(blob: bytes):
    """Walk the published blob as the tight entry chain the updater receives, signature excluded."""
    body = blob[: len(blob) - DB_SIG_LEN]
    off, version, chains, tokens, abis = 0, None, [], [], []
    while off < len(body):
        magic, ln = struct.unpack_from("<HH", body, off)
        kind = DB_MAGICS.get(magic)
        if kind is None:
            raise ValueError(f"unknown magic 0x{magic:04x} at {off}")
        end = off + 4 + ln
        if end > len(body):
            raise ValueError(f"{kind} entry at {off} runs past the blob")
        if kind == "version":
            version = struct.unpack_from("<I", body, off + 4)[0]
        elif kind == "chain":
            chain_id = struct.unpack_from("<I", body, off + 4)[0]
            fields = body[off + 8 : end].split(b"\0")
            if len(fields) != 4 or fields[3]:
                raise ValueError(f"chain {chain_id} is not ticker/name/short_name/NUL")
            chains.append({"id": chain_id, "ticker": fields[0].decode(), "name": fields[1].decode(),
                           "short": fields[2].decode()})
        elif kind == "erc20":
            count = body[off + 4]
            nets = [struct.unpack_from("<I20s", body, off + 5 + i * DB_NET_LEN) for i in range(count)]
            rest = body[off + 5 + count * DB_NET_LEN : end]
            decimals, ticker = rest[0], rest[1:].split(b"\0")[0].decode()
            if len(rest) != 1 + len(ticker) + 1:
                raise ValueError(f"token {ticker} tail is not decimals/ticker/NUL")
            tokens.append({"nets": [(c, a) for c, a in nets], "decimals": decimals, "ticker": ticker})
        else:
            abis.append(struct.unpack_from("<Q", body, off + 4)[0])
        off = end
    if off != len(body):
        raise AssertionError("the walk did not end on the signature")
    return version, chains, tokens, abis, len(body)


def db_row(row: dict, chain_id: int, addr: bytes) -> str:
    return (f'{{ 0x{chain_id:08x}, {{ {", ".join(f"0x{b:02x}" for b in addr)} }}, '
            f'{row["decimals"]}, "{row["ticker"]}" }}')


def eth_db_vectors() -> str:
    files = db_read_zip(SHELL_DB)
    blob = files["db.bin"]
    chain_json = json.loads(files["chain.json"])
    erc20_json = json.loads(files["erc20.json"])

    version, chains, tokens, abis, body_len = db_parse(blob)
    assert version == SHELL_DB_VERSION, f"blob version {version} is not the release {SHELL_DB_VERSION}"

    for chain in chains:
        upstream = [c for c in chain_json if c.get("chainId") == chain["id"]]
        if not [c for c in upstream
                if c["name"] == chain["name"] and c["shortName"] == chain["short"]
                and c["nativeCurrency"]["symbol"] == chain["ticker"]]:
            raise AssertionError(f"chain {chain['id']} is not what chainlist says")

    for token in tokens:
        addr = token["nets"][0][1]
        upstream = [t for t in erc20_json["tokens"] if db_addr(t["address"]) == addr]
        if not [t for t in upstream if t["decimals"] == token["decimals"] and t["symbol"] == token["ticker"]]:
            raise AssertionError(f"token {token['ticker']} {addr.hex()} is not what the token list says")

    present_addrs = {a for t in tokens for _, a in t["nets"]}
    present_ids = {c["id"] for c in chains}

    # chains and tokens the upstream lists carry and this release does not: real negatives, chosen
    # where the upstream source still confirms them
    missing_chains = [c["chainId"] for c in chain_json if c["chainId"] not in present_ids][:3]
    missing_tokens = []
    for t in erc20_json["tokens"]:
        addr = db_addr(t["address"])
        if addr is None or addr in present_addrs or t["decimals"] > 255 or not t["symbol"].isascii():
            continue
        missing_tokens.append({"decimals": t["decimals"], "ticker": t["symbol"],
                               "nets": [(t["chainId"], addr)]})
        if len(missing_tokens) == 3:
            break

    multi = [t for t in tokens if len(t["nets"]) > 1]
    sample = {0, len(tokens) - 1, *(range(0, len(tokens), max(1, len(tokens) // 40)))}
    token_rows = [tokens[i] for i in sorted(sample)] + multi[:3]

    prologue = f"""#ifndef VECTORS_ETH_DB_H
#define VECTORS_ETH_DB_H

/* What app/ethereum/eth_db.c and the storage log have to do with the database the Shell actually
 * ships, taken from the published release {SHELL_DB} and from the upstream lists it was generated
 * from.
 *
 * The blob is the artifact itself with its signature stripped, which is the shape updater.c hands
 * over. No expectation here is read back through the C parser: each chain row is confirmed against
 * chainlist (name, shortName, nativeCurrency.symbol) and each token row against the Uniswap list
 * (decimals, symbol), both carried in the same zip, and generate.py refuses to emit a row those
 * sources do not confirm. The missing rows are chains and tokens the upstream lists carry and this
 * release does not.
 *
 * Left out, and why:
 *   - the signature. updater.c checks it against the pinned DB key, which is not in this repository,
 *     and eth_db.c never sees the bytes.
 *   - ABI entries one by one. To eth_db.c they are selector blobs classified by magic when erasing;
 *     what the store has to carry is their count.
 *   - delta updates. No published release is one, and eth_db_update() answers ERR_UNSUPPORTED to
 *     anything that is not a full database.
 */

#include <stdint.h>

#define ETH_DB_BODY {body_len} /* the release blob without its {DB_SIG_LEN}-byte signature */
#define ETH_DB_VERSION {version}u
#define ETH_DB_ENTRIES {1 + len(chains) + len(tokens) + len(abis)} /* version, {len(chains)} chains, {len(tokens)} tokens, {len(abis)} abis */

static const uint8_t ETH_DB[] = {{
{c_array(blob[:body_len])}
}};

typedef struct {{
  uint32_t chain_id;
  const char *ticker, *name, *short_name;
}} eth_db_chain_t;

/* Every chain of the release, as chainlist describes it. */
static const eth_db_chain_t ETH_DB_CHAINS[] = {{
{',\n'.join(f'{{ 0x{c["id"]:08x}, "{c["ticker"]}", "{c["name"]}", "{c["short"]}" }}' for c in chains)}
}};

typedef struct {{
  uint32_t chain_id;
  uint8_t addr[20];
  uint8_t decimals;
  const char *ticker;
}} eth_db_token_t;

/* A sample in blob order across the token range, plus the first multi-net entries. */
static const eth_db_token_t ETH_DB_TOKENS[] = {{
{',\n'.join(db_row(t, *t["nets"][0]) for t in token_rows)}
}};

/* One entry lists every (chain, address) pair it is good on, so an address has to answer under a
 * net other than the first as well. */
static const eth_db_token_t ETH_DB_OTHER_NETS[] = {{
{',\n'.join(db_row(t, chain_id, addr) for t in multi[:3] for chain_id, addr in t["nets"])}
}};

static const uint32_t ETH_DB_MISSING_CHAINS[] = {{
{',\n'.join(f"0x{c:08x}" for c in missing_chains)}
}};

static const eth_db_token_t ETH_DB_MISSING_TOKENS[] = {{
{',\n'.join(db_row(t, *t["nets"][0]) for t in missing_tokens)}
}};

#endif\t/* VECTORS_ETH_DB_H */
"""

    return prologue



# ------------------------------------------------------------------------- AES


def ccm_spec(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes, tag_len: int) -> tuple[bytes, bytes]:
    from Crypto.Cipher import AES
    """AES-CCM as SP 800-38C 5.2 and Appendix A specify it, composed from the AES block cipher alone.

    Written from the document rather than from how app/crypto/aes_ccm.c drives the peripheral -- the whole
    point of modelling the peripheral is that nothing in the model comes from its caller."""
    ecb = AES.new(key, AES.MODE_ECB)

    len_field = 15 - len(nonce)
    if not 2 <= len_field <= 8:
        sys.exit(f"ccm: a nonce of {len(nonce)} bytes is outside what CCM's length field carries")

    flags = ((tag_len // 2) - 1) << 3
    if aad:
        flags |= 0x40

    # B0, then the length-prefixed associated data, then the payload: one byte string, zero padded once
    # at the end rather than per field (A.2.1/A.2.2).
    formatted = bytes([flags | (len_field - 1)]) + nonce + len(plaintext).to_bytes(len_field, "big")
    # Each string is zero padded to a block on its own -- see B in Appendix C, where a 20-byte associated
    # data field occupies two blocks and the payload starts on a fresh one -- and an empty one contributes
    # no block at all.
    if aad:
        if len(aad) < 0xFF00:
            formatted += len(aad).to_bytes(2, "big") + aad
        else:
            formatted += b"\xff\xfe" + len(aad).to_bytes(4, "big") + aad
        formatted += b"\x00" * (-len(formatted) % 16)
    if plaintext:
        formatted += plaintext + b"\x00" * (-len(plaintext) % 16)

    mac = bytes(16)
    for i in range(0, len(formatted), 16):
        mac = ecb.encrypt(bytes(a ^ b for a, b in zip(mac, formatted[i : i + 16])))

    # CTR* blocks carry neither the M bits nor the Adata bit -- see Ctr0 in Appendix C, which is L-1 alone
    # for an example whose B0 announces associated data. Counter 0 is reserved for masking the tag, so the
    # payload starts at 1.
    counter_flags = bytes([len_field - 1])
    mask = ecb.encrypt(counter_flags + nonce + bytes(len_field))
    tag = bytes(a ^ b for a, b in zip(mac, mask))[:tag_len]

    keystream = b""
    for i in range(1, len(plaintext) // 16 + 2):
        keystream += ecb.encrypt(counter_flags + nonce + i.to_bytes(len_field, "big"))

    return bytes(a ^ b for a, b in zip(plaintext, keystream))[: len(plaintext)], tag


def ccm_reference(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes, tag_len: int) -> tuple[bytes, bytes]:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=tag_len)
    if aad:
        cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


# SP 800-38C Appendix C, transcribed from the PDF. Nothing here is trusted: the run aborts unless the
# model above reproduces all four, which is what catches a mistyped digit. Example 4 is the erratum-
# corrected one (its formatted string B ends with two appended hex values) and exercises the long
# associated-data length encoding.
SP800_38C_CCM = [
    {
        "tag_len": 4,
        "key": "404142434445464748494a4b4c4d4e4f",
        "nonce": "10111213141516",
        "aad": "0001020304050607",
        "pt": "20212223",
        "ct": "7162015b",
        "tag": "4dac255d",
    },
    {
        "tag_len": 6,
        "key": "404142434445464748494a4b4c4d4e4f",
        "nonce": "1011121314151617",
        "aad": "000102030405060708090a0b0c0d0e0f",
        "pt": "202122232425262728292a2b2c2d2e2f",
        "ct": "d2a1f0e051ea5f62081a7792073d593d",
        "tag": "1fc64fbfaccd",
    },
    {
        "tag_len": 8,
        "key": "404142434445464748494a4b4c4d4e4f",
        "nonce": "101112131415161718191a1b",
        "aad": "000102030405060708090a0b0c0d0e0f10111213",
        "pt": "202122232425262728292a2b2c2d2e2f3031323334353637",
        "ct": "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
        "tag": "484392fbc1b09951",
    },
    # Appendix C Example 4 is deliberately absent: its published C and T do not reproduce under this model
    # or under pycryptodome, and the PDF carries a marginal correction note against the 2004 text ("the
    # value of parameter B has been corrected by adding the final two hexadecimal values") that cannot be
    # applied from the associated-data string the document prints -- it says only "the first sixteen blocks
    # ... concatenated with itself repeatedly". A vector nobody can reproduce is not an anchor.
]

# What the device actually asks for: app/crypto/aes.h fixes the nonce at 13 bytes and the tag at 8, and
# _ccm_build_b0() never sets the associated-data bit. No published vector has that shape -- SP 800-38C's
# own examples all carry associated data, and RFC 3610's are all 8-byte nonces with associated data -- so
# these are emitted only where the model written from the specification and pycryptodome agree.
CCM_DEVICE_CASES = [
    (0, "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c"),
    (1, "404142434445464748494a4b4c4d4e4f", "101112131415161718191a1b1c"),
    (7, "000102030405060708090a0b0c0d0e0f", "f0e1d2c3b4a5968778695a4b3c"),
    (15, "6c79b4d5a342ae0f8c38f73f44e52b7e", "11223344556677889900aabbcc"),
    (16, "00000000000000000000000000000000", "00000000000000000000000000"),
    (17, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "0123456789abcdeffedcba9876"),
    (31, "9e88e9f2d9e0b5dac1d2e3f4a5b6c7d8", "0a0b0c0d0e0f10111213141516"),
    (32, "0123456789abcdeffedcba9876543210", "1d4e7a2b3c5d6e7f8091a2b3c4"),
    (33, "11111111111111111111111111111111", "ffffffffffffffffffffffffff"),
    (47, "5b6c7d8e9f001122334455667788990a", "7a6b5c4d3e2f1001a2b3c4d5e6"),
    (64, "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", "0f1e2d3c4b5a69788796a5b4c3"),
    (1000, "3c4d5e6f708192a3b4c5d6e7f8091a2b", "5a4b3c2d1e0f00112233445566"),
]


def aes_vectors() -> str:
    from Crypto.Cipher import AES
    for index, case in enumerate(SP800_38C_CCM, start=1):
        key = bytes.fromhex(case["key"])
        nonce = bytes.fromhex(case["nonce"])
        aad = bytes.fromhex(case["aad"])
        pt = bytes.fromhex(case["pt"])
        expected = (bytes.fromhex(case["ct"]), bytes.fromhex(case["tag"]))

        if ccm_spec(key, nonce, aad, pt, case["tag_len"]) != expected:
            sys.exit(f"sp800-38c: example {index} does not reproduce -- the transcription or the model is wrong")
        if ccm_reference(key, nonce, aad, pt, case["tag_len"]) != expected:
            sys.exit(f"sp800-38c: example {index} disagrees with pycryptodome")

    device = []
    for length, key_hex, nonce_hex in CCM_DEVICE_CASES:
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        pt = bytes((i * 7 + 3) & 0xFF for i in range(length))

        spec = ccm_spec(key, nonce, b"", pt, 8)
        reference = ccm_reference(key, nonce, b"", pt, 8)
        if spec != reference:
            sys.exit(f"ccm at device parameters ({length} bytes): the spec model and pycryptodome disagree")

        device.append((key_hex, nonce_hex, pt.hex(), (spec[0] + spec[1]).hex()))

    # AES-256-CBC has no published vector set at 256 bits -- SP 800-38A's examples are all 128-bit and
    # RFC 3602 stops at 128 too -- so the chaining is pinned to pycryptodome, and the block itself to
    # FIPS-197 C.3 below.
    cbc = []
    for length, key_hex, iv_hex in [
        (16, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f"),
        (32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "ffffffffffffffffffffffffffffffff"),
        (48, "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", "101112131415161718191a1b1c1d1e1f"),
        (64, "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000"),
    ]:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        data = bytes((i * 13 + 5) & 0xFF for i in range(length))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        cbc.append((key_hex, iv_hex, data.hex(), cipher.encrypt(data).hex()))

    cbc_mac = []
    for length, key_hex in [
        (16, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        (32, "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0"),
        (64, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ]:
        key = bytes.fromhex(key_hex)
        data = bytes((i * 29 + 11) & 0xFF for i in range(length))
        mac = AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(data)[-16:]
        cbc_mac.append((key_hex, data.hex(), mac.hex()))

    spec_rows = ",\n".join(
        "  {.key = %s, .nonce = %s, .aad = %s, .plaintext = %s, .out = %s}"
        % (cstr(c["key"]), cstr(c["nonce"]), cstr(c["aad"]), cstr(c["pt"]), cstr(c["ct"] + c["tag"]))
        for c in [SP800_38C_CCM[2]]
    )
    device_rows = ",\n".join(
        "  {.key = %s, .nonce = %s, .aad = \"\", .plaintext = %s, .out = %s}"
        % (cstr(k), cstr(n), cstr(p), cstr(ct))
        for k, n, p, ct in device
    )
    cbc_rows = ",\n".join(
        "  {.key = %s, .iv = %s, .data = %s, .out = %s}" % (cstr(k), cstr(iv), cstr(d), cstr(o)) for k, iv, d, o in cbc
    )
    mac_rows = ",\n".join(
        "  {.key = %s, .iv = \"\", .data = %s, .out = %s}" % (cstr(k), cstr(d), cstr(m)) for k, d, m in cbc_mac
    )

    return f"""#ifndef VECTORS_HAL_AES_H
#define VECTORS_HAL_AES_H

/* spec: {{fips197}}
 * spec: {{sp80038c}}
 *
 * The block vector is FIPS-197 Appendix C.3, the AES-256 known-answer pair.
 *
 * The CCM cases below are the device's shape -- 13-byte nonce, 8-byte tag, no associated data -- and no
 * published vector has it: SP 800-38C's examples all carry associated data, and RFC 3610's are all
 * 8-byte nonces with associated data too. So they are emitted only where ccm_spec(), composed from
 * SP 800-38C 5.2 and Appendix A rather than from aes_ccm.c, and pycryptodome's own CCM agree; the
 * generator aborts otherwise. Appendix C Examples 1, 2 and 3 are checked the same way before anything is
 * written, which is what keeps that model honest at the points that are published. Example 4 is not
 * checked, because neither implementation reproduces the C and T the document prints. Example 3 is the
 * one published case an 8-byte tag can express, so it is carried through below as a vector of its own.
 */

/* FIPS-197 C.3 */
#define AES256_BLOCK_KEY "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define AES256_BLOCK_PLAINTEXT "00112233445566778899aabbccddeeff"
#define AES256_BLOCK_CIPHERTEXT "8ea2b7ca516745bfeafc49904b496089"

typedef struct {{
  const char* key;
  const char* nonce;
  const char* aad;
  const char* plaintext;
  const char* out; /* ciphertext then tag, as aes128_ccm_encrypt() lays them down */
}} aes_ccm_kat_t;

/* SP 800-38C Appendix C Example 3. The only published CCM vector with an 8-byte tag, and it carries
 * associated data, which the peripheral's streaming API has no way to accept: a test reaches it through
 * hal_host_aes_ccm_aad(). */
static const aes_ccm_kat_t AES_CCM_SPEC[] = {{
{spec_rows}
}};

#define AES_CCM_SPEC_COUNT (sizeof(AES_CCM_SPEC) / sizeof(AES_CCM_SPEC[0]))

/* What the device asks for: no associated data, nonce 13, tag 8. */
static const aes_ccm_kat_t AES_CCM_DEVICE[] = {{
{device_rows}
}};

#define AES_CCM_DEVICE_COUNT (sizeof(AES_CCM_DEVICE) / sizeof(AES_CCM_DEVICE[0]))

typedef struct {{
  const char* key;
  const char* iv;
  const char* data;
  const char* out;
}} aes_cbc_kat_t;

/* reference: pycryptodome's AES-256-CBC, independent of the model in host/hal_aes_host.c. There is no
 * published AES-256 CBC vector set: SP 800-38A's examples and RFC 3602 are both 128-bit only. */
static const aes_cbc_kat_t AES_CBC_KAT[] = {{
{cbc_rows}
}};

#define AES_CBC_KAT_COUNT (sizeof(AES_CBC_KAT) / sizeof(AES_CBC_KAT[0]))

/* aes_cbc_mac() is CBC with a zero IV, read back as the last block. Lengths are multiples of the block:
 * the function rounds up, so anything else would drag in whatever follows the message. */
static const aes_cbc_kat_t AES_CBC_MAC_KAT[] = {{
{mac_rows}
}};

#define AES_CBC_MAC_KAT_COUNT (sizeof(AES_CBC_MAC_KAT) / sizeof(AES_CBC_MAC_KAT[0]))

#endif
""".replace("{fips197}", provenance("fips-197.pdf")).replace("{sp80038c}", provenance("sp800-38c.pdf"))


# ------------------------------------------------------------------- key store


def keys_vectors() -> str:
    """The one trust anchor in keys.c that an outside artifact can settle: the database verification
    key must be the key the released database was signed with."""
    blob = fetch_bytes(SHELL_DB_SIGNED)
    _, _, _, _, body_len = db_parse(blob)

    body, signature = blob[:body_len], blob[body_len:]
    if len(signature) != 64:
        sys.exit(f"{SHELL_DB_SIGNED}: expected a 64-byte signature after the body, found {len(signature)}")

    if db_read_zip(SHELL_DB)["db.bin"][:body_len] != body:
        sys.exit(f"{SHELL_DB}: the reproduction db.bin is not the body the production key signed")

    return f"""#ifndef VECTORS_KEYS_H
#define VECTORS_KEYS_H

/* reference: {{shelldb}}
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

#define DB_RELEASE_BODY_SHA256 "{hexs(hashlib.sha256(body).digest())}"
#define DB_RELEASE_SIGNATURE "{hexs(signature)}"

#endif
""".replace("{shelldb}", provenance(SHELL_DB_SIGNED))


# ------------------------------------------------------------------- multisig


def multisig_crypto_vectors() -> str:
    """enc_key and blob, computed from the definitions in multisig_crypto.h by RFC 5869 and FIPS 198-1
    rather than by the C code: HKDF-SHA256 over the EIP-1581 root with no salt -- so zeros, per the RFC --
    and the first four bytes of HMAC-SHA256(fp_key, fingerprint little-endian)."""
    cases = [
        (bytes(range(32)), 0x00000000),
        (bytes((i * 7 + 1) & 0xFF for i in range(32)), 0xDEADBEEF),
        (bytes(32), 0x12345678),
        (hashlib.sha256(b"eip-1581 root").digest(), 0xAABBCCDD),
    ]

    rows = []
    for root, fingerprint in cases:
        fp_key = hkdf_reference(bytes(32), root, b"multisig-fp", 32)[1]
        enc_key = hkdf_reference(bytes(32), root, b"multisig-enc", 16)[1]
        blob = hmac.new(fp_key, fingerprint.to_bytes(4, "little"), hashlib.sha256).digest()[:4]
        rows.append((root.hex(), fingerprint, enc_key.hex(), blob.hex()))

    body = ",\n".join(
        "  {.root = %s, .master_fingerprint = 0x%08X, .enc_key = %s, .blob = %s}"
        % (cstr(root), fp, cstr(enc), cstr(blob))
        for root, fp, enc, blob in rows
    )

    return f"""#ifndef VECTORS_MULTISIG_CRYPTO_H
#define VECTORS_MULTISIG_CRYPTO_H

/* spec: {provenance('rfc5869.txt')}
 *
 * The labels, the truncation to AES-128 and the little-endian fingerprint are the module's own definitions
 * -- they are what the header documents -- but the bytes below come from RFC 5869 extract-and-expand and
 * FIPS 198-1 HMAC, computed here rather than read back from aes_ccm/hkdf's C. enc_key is the key that
 * keeps a stored descriptor private; blob is the searchable index the store matches on, so it must be the
 * same for every session with the same card and different for every card.
 */

typedef struct {{
  const char* root;
  uint32_t master_fingerprint;
  const char* enc_key;
  const char* blob;
}} multisig_crypto_kat_t;

static const multisig_crypto_kat_t MULTISIG_CRYPTO_KAT[] = {{
{body}
}};

#define MULTISIG_CRYPTO_KAT_COUNT (sizeof(MULTISIG_CRYPTO_KAT) / sizeof(MULTISIG_CRYPTO_KAT[0]))

#endif
"""


def pbkdf2_vectors() -> str:
    """PBKDF2-HMAC-SHA256, computed by pycryptodome's PBKDF2 -- a released implementation, not this
    tree's. The cases are the shapes the callers use plus the ones they will use next time: the
    exact call keycard.c makes for a pairing password, key lengths that are not a multiple of the
    digest, iteration counts around the loop's arms, and salt lengths across the SHA-256 block."""
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    pairing_salt = b"Keycard Pairing Password Salt"
    if len(pairing_salt) != 29:
        raise ValueError("keycard.c passes 29 as this salt's length")

    rows = []

    def add(name: str, password: bytes, salt: bytes, iterations: int, dk_len: int):
        dk = PBKDF2(password, salt, dkLen=dk_len, count=iterations, hmac_hash_module=SHA256)
        rows.append((name, password, salt, iterations, dk))

    for pw in (b"", b"1234", b"password", b"p" * 63, b"p" * 64, b"p" * 65, "pässwörd".encode()):
        add(f"pairing password, {len(pw)}B", pw, pairing_salt, 50000, 32)

    for dk_len in (8, 16, 31, 32, 33, 40, 64, 72):
        add(f"derived key of {dk_len} bytes", b"password", b"salt", 4096, dk_len)

    for it in (1, 2, 3, 1000, 4096):
        add(f"{it} iterations", b"password", b"salt", it, 32)

    for n in (0, 1, 15, 63, 64, 65, 200):
        add(f"salt of {n} bytes", b"password", b"S" * n, 1000, 32)

    body = "\n".join(
        f'    {{ "{name}", "{hexs(passw)}", "{hexs(salt)}", {it}, "{hexs(dk)}" }},'
        for name, passw, salt, it, dk in rows
    )

    return f"""#ifndef VECTORS_PBKDF2_H
#define VECTORS_PBKDF2_H

/* reference: pycryptodome {PBKDF2.__module__} PBKDF2, HMAC-SHA256.
 *
 * The first group is the call keycard.c:722 makes -- password, the literal salt
 * "Keycard Pairing Password Salt" with its length passed as 29, 50000 iterations, 32 bytes -- which is
 * how a pairing password becomes the key that seals the session, so the two implementations have to
 * agree byte for byte or the card rejects every pairing. The rest is the surrounding shape: a derived
 * key shorter or longer than one digest (slip39.c derives 8 and 16), the iteration loop entered once
 * or many times, and salt lengths on both sides of the SHA-256 block.
 *
 * Password and salt are hex rather than string literals so that a UTF-8 password and an empty salt
 * are both expressible; the derived key's length is half the hex string's.
 */

typedef struct {{
  const char* name;
  const char* pass_hex;
  const char* salt_hex;
  uint32_t iterations;
  const char* dk_hex;
}} pbkdf2_kat_t;

static const pbkdf2_kat_t PBKDF2_KAT[] = {{
{body}
}};

#define PBKDF2_KAT_COUNT (sizeof(PBKDF2_KAT) / sizeof(PBKDF2_KAT[0]))

#endif
"""


def util_vectors() -> str:
    """crypto/util.c -- the parsers that sit between a string someone typed and the bytes that get
    hashed, plus the ISO 7816-4 padding the secure channel uses.

    The arithmetic is Python's: a decimal or hex string through Python's big integers and to_bytes(32).
    That is the point -- decimal_to_256 is a hand-rolled 256-bit accumulator (limbs * 8 plus a carry),
    and an error in it changes the number being signed without changing its shape. The accept/reject
    lines are not Python's: they are the contract str_to_int256 implements, written out here so that a
    change to it -- what gets trimmed, whether a bare sign or a negative hex literal is accepted, where
    a hex string stops fitting -- has to be changed in two places on purpose.
    """
    WS = " \t\n\v\f\r"
    DIGITS = set("0123456789")
    HEX = DIGITS | set("abcdefABCDEF")

    def parse(text: str):
        """The contract, as the module documents it: surrounding whitespace trimmed, one optional sign,
        0x/0X introducing up to 64 hex digits and no sign, otherwise decimal up to 2**256 - 1. Returns
        (magnitude, negative) or None for a rejection."""
        i, j = 0, len(text)
        while i < j and text[i] in WS:
            i += 1
        while j > i and text[j - 1] in WS:
            j -= 1
        neg = False
        if i < j and text[i] in "+-":
            neg = text[i] == "-"
            i += 1
            if i == j:
                return None
        if i == j:
            return (0, False)
        body = text[i:j]
        if len(body) >= 2 and body[0] == "0" and body[1] in "xX":
            if neg:
                return None
            digits = body[2:]
            if len(digits) == 0 or len(digits) > 64 or any(c not in HEX for c in digits):
                return None
            return (int(digits, 16), False)
        if any(c not in DIGITS for c in body):
            return None
        value = int(body)
        if value >= 1 << 256:
            return None
        return (value, neg)

    inputs = [
        ("empty string", ""),
        ("whitespace only", "   \t\n "),
        ("zero", "0"),
        ("one", "1"),
        ("single digit with spaces", "\t 7 \n"),
        ("carriage return and vertical tab", "\r\v42\f\v"),
        ("leading zeros", "000000000000000000000016"),
        ("plus sign", "+1234"),
        ("negative one", "-1"),
        ("negative zero", "-0"),
        ("space after the sign", "- 7"),
        ("bare sign", "-"),
        ("bare sign with space", "+ "),
        ("ten", "10"),
        ("uint64 max", str(2**64 - 1)),
        ("uint128 boundary", "340282366920938463463374607431768211455"),
        ("uint256 max", str(2**256 - 1)),
        ("uint256 overflow", str(2**256)),
        ("seventy nine digits", "9" * 79),
        ("negative uint256 max", "-" + str(2**256 - 1)),
        ("two to the 255", str(2**255)),
        ("negative two to the 255", "-" + str(2**255)),
        ("hex zero", "0x0"),
        ("hex lowercase", "0xdeadbeef"),
        ("hex uppercase prefix", "0XFF"),
        ("hex odd digits", "0xabc"),
        ("hex one digit", "0xf"),
        ("hex uint256 max", "0x" + "f" * 64),
        ("hex one digit too many", "0x" + "f" * 65),
        ("hex no digits", "0x"),
        ("hex with a space inside", "0x1 f"),
        ("negative hex", "-0x10"),
        ("not a number", "12a3"),
        ("space inside a decimal", "1 2"),
        ("leading zero then letters", "0abc"),
        ("hex letters out of range", "0xg"),
    ]

    int256_rows = []
    for name, text in inputs:
        got = parse(text)
        if got is None:
            int256_rows.append(f'    {{ "{name}", "{hexs(text.encode())}", NULL, false, NULL, 0 }},')
            continue
        mag, neg = got
        value = (-mag) & ((1 << 256) - 1) if neg else mag
        sig = 32 - ((mag.bit_length() + 7 + 7) // 8) if mag == 0 else (mag.bit_length() + 7) // 8
        sig = 0 if mag == 0 else sig
        int256_rows.append(
            f'    {{ "{name}", "{hexs(text.encode())}", '
            f'"{mag.to_bytes(32, "big").hex()}", {"true" if neg else "false"}, '
            f'"{value.to_bytes(32, "big").hex()}", {sig} }},'
        )

    pad_rows = []
    for plen in (16, 8):
        for size in (0, 1, 7, 8, 15, 16, 17, 31, 32):
            payload = bytes((0xa0 + i) & 0xff for i in range(size))
            padding = plen - (size % plen)
            padded = payload + b"\x80" + b"\x00" * (padding - 1)
            pad_rows.append(
                f'    {{ {plen}, "{hexs(payload)}", "{hexs(padded)}", {size + padding}, {size + plen} }},'
            )

    u64_rows = []
    for value in (0, 1, 9, 10, 99, 100, 2**31 - 1, 2**32 - 1, 2**32, 2**53, 10**18, 2**64 - 1):
        text = str(value)
        u64_rows.append(f'    {{ {value}ULL, "{text}", {len(text) + 1} }},')

    return f"""#ifndef VECTORS_UTIL_H
#define VECTORS_UTIL_H

/* The values are Python's -- big integers, to_bytes(32, "big"), str(). decimal_to_256 is a hand-rolled
 * 256-bit accumulator and u64toa a hand-rolled decimal conversion, so the arithmetic here belongs to
 * nobody who shipped this firmware. Which strings are accepted is this module's own contract, restated
 * below and asserted verbatim: it is not pinned by any standard, and eip712.c reads whatever it returns
 * into the struct hash of a message the user is being asked to approve.
 */

typedef struct {{
  const char* name;
  const char* text_hex;
  const char* mag_hex;
  bool negative;
  const char* value_hex;
  size_t significant;
}} int256_kat_t;

static const int256_kat_t INT256_KAT[] = {{
{chr(10).join(int256_rows)}
}};

#define INT256_KAT_COUNT (sizeof(INT256_KAT) / sizeof(INT256_KAT[0]))

/* ISO 7816-4 padding: 0x80 then zeros up to the next block. room is what the caller has to leave
 * past the payload, because pad_iso9797_m1 always writes a whole block's worth. */
typedef struct {{
  uint8_t block;
  const char* data_hex;
  const char* padded_hex;
  uint32_t padded_len;
  uint32_t room;
}} pad_kat_t;

static const pad_kat_t PAD_KAT[] = {{
{chr(10).join(pad_rows)}
}};

#define PAD_KAT_COUNT (sizeof(PAD_KAT) / sizeof(PAD_KAT[0]))

typedef struct {{
  uint64_t value;
  const char* text;
  uint32_t room;
}} u64toa_kat_t;

static const u64toa_kat_t U64TOA_KAT[] = {{
{chr(10).join(u64_rows)}
}};

#define U64TOA_KAT_COUNT (sizeof(U64TOA_KAT) / sizeof(U64TOA_KAT[0]))

#endif
"""


# ATRs to parse. Two sources, both stated in the emitted comment.
#
# - pcsc: captured from real cards, copied from pcsc-tools' smartcard_list.txt (Ludovic Rousseau's
#   collection of ATRs reported by people running pcsc_scan), with the card that list names.
# - own: captured on the bench with tools/capture-atr.py, from the stack of cards at hand. Every one
#   of them is in pcsc-tools' collection too, which is where the row names come from.
# - spec: built byte by byte from ISO/IEC 7816-3:2006 for a shape the collection does not contain,
#   so that a clause the wild cards never exercise is still pinned.
#
# Expectations come from the standard, never from iso7816/atr.c: see iso_expect().
CAPTURED_ATRS = [
    # (name, atr, source, what the structure is)
    ("timing only", "3B 90 95 80 11 FE 6A", "pcsc",
     "T=0 offered first; TD2 then offers T=1, whose first triple is a lone TA = IFSC 254"),
    ("staros s21", "3B BF 18 00 80 31 70 35 53 54 41 52 43 4F 53 20 53 32 31 20 43 90 00 9B", "pcsc",
     "STARCOS S21 C: T=0 then T=1 with IFSC 112 and BWI 3 CWI 5, 15 historical bytes"),
    ("three protocols",
     "3B 9F 97 C0 0A B1 FE 45 3F C6 82 80 31 E0 73 FE 21 1B 65 D0 02 3A 14 C9 81 0F 8B", "pcsc",
     "T=0, then T=1, then T=15, whose first TA is classes A+B+C with clock stop both states"),
    ("second group TC", "3B 97 11 C0 FF B1 FE 35 1F 83 A5 05 01 01 02 A3 01 5F", "pcsc",
     "TC2 = FF is T=0's WI; the T=1 triple is split across TA3 (IFSC) and TB3 (BWI 3 CWI 5)"),
    ("t1 tb only", "3B 85 C0 FA 21 63 80 63 01 01 05 1B", "pcsc",
     "the T=1 triple offers only TB, so IFSC keeps its default while CWI 3 and BWI 6 are read"),
    ("t0 only", "3B 15 11 12 CA 07 00 DB", "pcsc",
     "nothing offered but T=0, so 8.2.5 says there is no check byte and the last byte is historical"),
    ("t1 no interface", "3B 80 01 81", "pcsc",
     "TD1 = 01 offers T=1 and nothing else: no interface byte at all, check byte still required"),
    ("sse piv", "3B 9C 95 81 01 50 53 43 50 2D 53 43 53 56 31 2E 30 8E", "pcsc",
     "TD1 offers T=1, TD2 = 01 repeats it with no bytes; the T=1 triple never arrives"),
    ("didem v1.7", "3B 97 18 11 81 44 49 44 45 4D 01 07 58", "pcsc",
     "Didem Card V1.7: TD1 offers T=1 and TA2, which 8.3 makes the global specific mode byte, not IFSC"),
    ("t15 in td1", "3B 81 1F 00 CC 52", "pcsc",
     "the one card in that list that puts T=15 in TD1, which 8.2.3 declares invalid"),
    # Built from the standard: shapes the collection above does not exercise.
    ("t1 crc", "3B 80 81 71 81 59 01 A9", "spec",
     "8.2.3 puts the first T=1 triple after a TD2 indicating T=1: IFSC 129, BWI 5 CWI 9, and bit 1 of "
     "the first TC asks for CRC per 11.4.4"),
    ("t1 lrc", "3B 80 81 71 81 59 00 A8", "spec",
     "the same triple with bit 1 of the first TC clear, which 11.4.4 makes LRC -- the default when "
     "that byte is absent anyway"),
    ("t1 first triple wins", "3B 80 81 B1 21 44 31 62 66 E0", "spec",
     "two triples qualified for T=1: 8.2.3 numbers them by occurrence and 11.4.1 lets only the first "
     "set IFSC, BWI and CWI, so IFSC is 33 and not 98"),
    ("t0 and t15", "3B 80 80 1F 47 58", "spec",
     "T=0 then T=15, whose first TA is classes A+B+C with clock stop preferred in state L. 8.2.3 says "
     "T=15 is not a protocol, so T=1 stays unoffered -- yet 8.2.5 still requires the check byte"),
    ("no interface byte", "3B 02 14 1C", "pcsc",
     "T0 sets no Y1 bit and offers no TD, so 8.2.3 leaves only T=0 by default: 8.3 and 10.2 give every "
     "parameter and 8.2.5 wants no check byte. 93 of the list's ATRs are shaped like this"),
    ("comsign eid", "3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 10 0A", "own",
     "TD1 offers T=1 and TD2 repeats it with a lone TA3 = IFSC 254, so 11.4.3 and 11.4.4 leave BWI at "
     "4, CWI at 13 and the code at LRC; TD3 then brings T=15 last, classes A+C"),
    ("renap guatemala", "3B D5 18 FF 81 B1 FE 45 1F C3 80 73 C8 21 10 6F", "own",
     "the chain of comsign eid with a TB3 added to TD2's third group, and 11.4.3 takes BWI 4 and CWI 5 "
     "out of it: the only difference between the two rows is which byte TD2 indicates"),
    ("jcop3 p60", "3B DC 18 FF 81 91 FE 1F C3 80 73 C8 21 13 66 05 03 63 51 00 02 50", "own",
     "JCOP3 SecID P60: comsign eid's chain with 12 historical bytes, which 8.2.5 folds into the check "
     "byte like any other count"),
    ("jcop 2.4.1r3", "3B EA 00 00 81 31 FE 45 00 31 C1 73 C8 40 00 00 90 00 7A", "own",
     "Y1 sets TB1, TC1 and TD1 and no TA1, so 8.3 gives Fi = 372 and Di = 1 even though a TB1 is there "
     "to be ignored, and TC1 = 00 is N = 0 rather than a missing byte"),
    ("cryptnox fido2", "3B FA 13 00 FF 91 01 31 FE 00 00 31 C1 73 C8 40 00 00 90 00 D2", "own",
     "VPP not connected, TC1 = FF, T=1 offered by TD1 and again by TD2, whose triple is IFSC 254 "
     "with TB3 = 00, asking for CWI 0 and BWI 0"),
    ("acosj 40k", "3B 69 00 02 41 43 4F 53 4A 76 31 30 31", "own",
     "TB1 and TC1 and no TD anywhere, so 8.2.3 leaves only T=0 by default and 8.2.5 wants no check "
     "byte: the ATR ends with the nine historical bytes spelling ACOSJv101"),
    ("t0 not first", "3B 80 81 00 01", "spec",
     "TD1 offers T=1 and TD2 then offers T=0, which 8.2.3 forbids: if T=0 is present it shall be first"),
    ("t15 not last", "3B 80 80 9F 11 01 8F", "spec",
     "TD2 brings T=15 and TD3 repeats T=1 after it; 8.2.3 puts T=15 last, so the offer is refused "
     "rather than handed to pps_negotiate as a protocol of 15"),
    ("t0 offered, no t15", "3B 80 40 0B", "spec",
     "TD1 offers T=0 and TC2 = 0B is its WI. With no T=15, 8.3 gives class A and clock stop not "
     "supported; with nothing but T=0 indicated, 8.2.5 gives no check byte"),
    ("specific t0", "3B F0 11 00 FF 91 00 01 8E", "spec",
     "TD1 offers T=1, but TA2 = 00 is specific mode with type 0, so 6.3.1 runs T=0 and bit 5 clear "
     "keeps TA1's Fi = 372 and Di = 1"),
    ("specific unsupported type", "3B F0 11 00 FF 91 8F 01 01", "spec",
     "8.3's NOTE: a type the interface device cannot run is a warm reset or a deactivation, so TA2 = 8F "
     "of specific mode and type 15 is refused"),
]


def atr_walk(atr: str):
    """The structure per ISO/IEC 7816-3:2006:8.2.3. T0 conveys Y1 and K; every TD conveys the
    indicator Yi+1 -- which of TA, TB, TC, TD follow -- and the type T, which qualifies those bytes.
    If a TD is absent, the group after it is absent too.

    Returns the groups as (qualifying type, bytes) in order -- the first group is qualified by no
    type, being the timing group -- together with the bytes after the interface bytes. Only the two
    bytes a reader needs at the top of the walk are checked here: TS's convention and T0."""
    b = bytes.fromhex(atr.replace(" ", ""))
    if len(b) < 2 or (b[0] != 0x3B and b[0] != 0x3F):
        raise ValueError(f"not an ATR: {atr}")
    pos = 2
    groups = []
    presence, proto = (b[1] >> 4) & 0xF, None
    while presence:
        g, td = {}, None
        for bit, name in ((1, "TA"), (2, "TB"), (4, "TC"), (8, "TD")):
            if presence & bit:
                if pos >= len(b):
                    raise ValueError(f"ATR ends inside a group: {atr}")
                g[name] = b[pos]
                pos += 1
                if name == "TD":
                    td = g["TD"]
        groups.append((proto, g))
        if td is None:
            break
        presence, proto = (td >> 4) & 0xF, td & 0xF

    hist_len = b[1] & 0x0F
    if pos + hist_len > len(b):
        raise ValueError(f"ATR is shorter than T0 promises: {atr}")
    return b, groups, b[pos:pos + hist_len], b[pos + hist_len:]


def iso_expect(atr: str) -> dict:
    """What ISO/IEC 7816-3:2006 says a reader must take from an ATR, clause by clause. This is the
    specification the test asserts; atr.c is what it checks."""
    b, groups, hist, rest = atr_walk(atr)
    types = [g["TD"] & 0xF for _, g in groups if "TD" in g]

    e = {
        # 8.3: Fi = 372, Di = 1, which atr.c carries as the byte 0x11; N = 0; TA2 absent.
        "fi_di": 0x11, "n": 0, "ta2": 0xFF,
        # 10.2: WI = 10 unless TC2 says otherwise.
        "t0_wi": 10,
        # 8.2.3: without a TD1 the only offer is T=0, and 11.4.2/11.4.3/11.4.4 give the T=1 defaults.
        "default_protocol": 0, "protocols": 1,
        "t1_ifsc": 32, "t1_cwi": 13, "t1_bwi": 4, "t1_rc": 0,
        # 8.3: clock stop not supported, only class A.
        "t15_present": 0, "classes": 1, "clockstop": 0,
        "hist_len": len(hist), "hist": hist.hex(), "result": "ERR_OK",
    }

    # An empty group means T0 set no Y1 bit at all, so every byte here is a default of 8.3 and 10.2.
    if groups:
        if groups[0][1].get("TA") is not None:
            e["fi_di"] = groups[0][1]["TA"]
        if groups[0][1].get("TC") is not None:
            e["n"] = groups[0][1]["TC"]

    if types:
        # 8.2.3: TD1 encodes the first offered protocol.
        e["default_protocol"] = types[0]
        e["protocols"] = 0
        for t in types:
            if t == 0:
                e["protocols"] |= 1
            elif t == 1:
                e["protocols"] |= 2
        if types[0] == 15:
            e["result"] = "ERR_DATA"
        if 0 in types and types[0] != 0:
            e["result"] = "ERR_DATA"
        if 15 in types and types[-1] != 15:
            e["result"] = "ERR_DATA"

    # 8.2.3: TA1, TB1, TC1, TA2 and TB2 are global and TC2 is specific to T=0, whatever TD1 said.
    # TB1 and TB2 are deprecated and the reader shall ignore them.
    if len(groups) > 1:
        g2 = groups[1][1]
        if g2.get("TA") is not None:
            e["ta2"] = g2["TA"]
        if g2.get("TC") is not None:
            e["t0_wi"] = g2["TC"]

    if e["ta2"] != 0xFF:
        # 6.3.1 with 8.3: in specific mode the protocol is the type TA2 encodes. A type the reader
        # cannot run is the deactivation 8.3's NOTE asks for.
        specific = e["ta2"] & 0x0F
        if specific in (0, 1):
            e["default_protocol"] = specific
        else:
            e["result"] = "ERR_DATA"

    # 8.2.3: from the third group on, the type in the TD before it decides what TAi TBi TCi mean.
    # 11.4.1 and 8.3 then take only the first of each kind for their type.
    seen = 0
    for proto, g in groups[2:]:
        if proto == 1:
            if g.get("TA") is not None and not seen & 1:
                seen |= 1
                e["t1_ifsc"] = g["TA"]
            if g.get("TB") is not None and not seen & 2:
                seen |= 2
                e["t1_cwi"] = g["TB"] & 0xF
                e["t1_bwi"] = (g["TB"] >> 4) & 0xF
            if g.get("TC") is not None and not seen & 4:
                seen |= 4
                e["t1_rc"] = 1 if g["TC"] & 1 else 0
        elif proto == 15:
            e["t15_present"] = 1
            if g.get("TA") is not None and not seen & 8:
                seen |= 8
                e["classes"] = g["TA"] & 0x7
                e["clockstop"] = g["TA"] & 0xC0

    # 8.2.5: the check byte is absent if only T=0 is indicated, possibly by default, and present in
    # every other case. When it is present, T0 to TCK inclusive exclusive-or to 00.
    only_t0 = not types or set(types) == {0}
    e["tck"] = 0 if only_t0 else 1

    covered = b[1:2] + b[2:2 + (len(b) - 2 - len(rest))] + hist
    if e["tck"]:
        if len(rest) < 1:
            raise ValueError(f"8.2.5 requires a check byte, none present: {atr}")
        parity = 0
        for byte in b[1:2] + b[2:len(b) - 1]:
            parity ^= byte
        if parity ^ rest[0] != 0:
            raise ValueError(f"check byte does not cover T0 to historical inclusive: {atr}")
        if len(rest) != 1:
            raise ValueError(f"bytes after the check byte: {atr}")
    elif len(rest) != 0:
        raise ValueError(f"T=0 only, so bytes after the historical ones are unexplained: {atr}")

    return e


def atr_vectors() -> str:
    rows = []
    for name, atr, source, note in CAPTURED_ATRS:
        try:
            e = iso_expect(atr)
        except ValueError as exc:
            print(f"  skipping {name}: {exc}")
            continue
        rows.append((name, atr, source, note, e))

    def comment(name, source, note, e):
        origin = f"Synthetic: {name}" if source == "spec" else f"Card: {name}"
        lines = textwrap.wrap(f"{origin}. {note}", width=94)
        out = [f"    /* {lines[0]}"] + [f"     * {line}" for line in lines[1:]]
        out[-1] += " */"
        return "\n".join(out)

    body = "\n".join(
        f'{comment(name, source, note, e)}\n'
        f'    {{\n'
        f'        "{name}", "{atr.replace(" ", "")}", {e["result"]}, {e["tck"]},\n'
        f'        0x{e["fi_di"]:02X}, 0x{e["n"]:02X}, 0x{e["ta2"]:02X}, {e["t0_wi"]}, '
        f'{e["default_protocol"]}, {e["protocols"]},\n'
        f'        0x{e["t1_ifsc"]:02X}, {e["t1_bwi"]}, {e["t1_cwi"]}, {e["t1_rc"]}, '
        f'{e["t15_present"]}, 0x{e["classes"]:02X}, 0x{e["clockstop"]:02X},\n'
        f'        {e["hist_len"]}, "{e["hist"]}",\n'
        f'    }},'
        for name, atr, source, note, e in rows
    )

    return f"""#ifndef VECTORS_ATR_H
#define VECTORS_ATR_H

/* What ISO/IEC 7816-3:2006 requires of a reader facing an ATR, row by row. Each row is one ATR --
 * captured from a real card, from pcsc-tools' smartcard_list.txt or from the cards at hand, or built
 * from the standard's own tables for a shape those collections do not contain -- and the fields are
 * the
 * answer in iso7816/atr.c's terms, derived from the text by tests/vectors/generate.py rather than
 * from that file.
 *
 * The clauses:
 *  - 8.2.3 structure. T0 conveys Y1 and K; each TD conveys which of TA, TB, TC, TD follow it and the
 *    type T that qualifies those bytes; an absent TD means the whole group after it is absent. TA1,
 *    TB1, TC1, TA2 and TB2 are global and TC2 is specific to T=0, so from the third group on the
 *    bytes mean what the preceding TD's T says they mean, and the k-th triple for a type follows the
 *    k-th occurrence of that type. T=0 first if offered, T=15 last and invalid in TD1.
 *  - 8.2.5 check byte. Absent if only T=0 is indicated, possibly by default; present otherwise.
 *    Exclusive-oring T0 to TCK inclusive gives 00, TS excluded.
 *  - 8.3 global bytes. TA1 is Fi, Di and f(max), default Fi = 372, Di = 1; TB1 and TB2 are
 *    deprecated and the reader shall ignore them; TC1 is N, default 0; TA2 is the specific mode byte
 *    and says nothing about IFSC. The first TA for T=15 is the clock stop indicator X in bits 8-7 and
 *    the classes in bits 6-1, default clock stop not supported and class A only.
 *  - 10.2 T=0. TC2 is WI over eight bits except 00, default 10, and WT = WI * 960 * Fi / f.
 *  - 11.4.2 to 11.4.4 T=1. The first TA for T=1 is IFSC, 01..FE encoding 1..254 with 00 and FF
 *    reserved, default 32. The first TB for T=1 is BWI in bits 8-5 (0..9, default 4) and CWI in bits
 *    4-1 (default 13). Bit 1 of the first TC for T=1 selects CRC, and clear selects LRC, which is
 *    also the default when the byte is absent.
 *
 * Two things the standard does not let this reader enforce, and the suite therefore does not claim.
 * The types in TD1, TD2 and so on "shall be in ascending numerical order", yet 1014 of the 2678
 * check-byte-valid ATRs in that collection repeat the first type, which is exactly how the clause
 * 8.2.3 note places the first T=1 triple after a TD2 indicating T=1 for a card that offers no T=0;
 * order is only checked where the text names a case invalid. And 11.4.2 reserves IFSC values 00 and
 * FF without saying what a reader does about them; 4 of those 2678 ATRs use one, so no row here asks
 * for a verdict.
 */

typedef struct {{
  const char* name;
  const char* atr_hex;
  app_err_t result;
  uint8_t tck;
  uint8_t fi_di;
  uint8_t n;
  uint8_t ta2;
  uint8_t t0_wi;
  uint8_t default_protocol;
  uint8_t protocols;
  uint8_t t1_ifsc;
  uint8_t t1_bwi;
  uint8_t t1_cwi;
  uint8_t t1_rc;
  uint8_t t15_present;
  uint8_t classes;
  uint8_t clockstop;
  size_t hist_len;
  const char* hist_hex;
}} atr_kat_t;

static const atr_kat_t ATR_KAT[] = {{
{body}
}};

#define ATR_KAT_COUNT (sizeof(ATR_KAT) / sizeof(ATR_KAT[0]))

#endif
"""



# What a reader must ask the peripheral for once the ATR has been read. Every number is derived from
# ISO/IEC 7816-3:2006, none from iso7816/pps.c:
#
#  - 7.1: 1 etu = F / (D * f) seconds, with F the clock rate conversion integer, D the baud rate
#    adjustment integer and f the frequency supplied on CLK. Fd = 372 and Dd = 1 are the defaults of
#    6.3.1, which is also what "implicit values" means in TA2.
#  - 8.3 Table 7: bits 8 to 5 of TA1 give Fi and f(max) together, Table 8: bits 4 to 1 give Di. The
#    two nibbles are independent, so Fi does not come from the same nibble as Di.
#  - 8.3: GT = 12 etu + R * N / f, with R = F / D when T=15 is absent and R = Fi / Di when it is
#    present. The character frame already spans twelve etu, so the peripheral is asked for the
#    excess over that -- which is nothing for N = 0, and nothing for N = 255, where 11.2 fixes the
#    guard at 11 etu for T=1 whatever TA1 says.
#  - 9.1: the interface device starts the PPS exchange, the card answers a correct request or WT
#    (9600 etu) elapses, and 9.2 puts the proposed Fi/Di in PPS1 -- present only when bit 5 of PPS0
#    says so, encoded as in TA1, from Fd up and Dd up. A device that omits PPS1 proposes Fd and Dd.
#  - 9.3: the exchange succeeds when bits 4 to 1 of the answer match, bits 5 to 7 are the same or 0,
#    and an answer whose bit 5 is 0 means Fd and Dd are in force -- so the answer need not echo the
#    request, and it is one byte shorter when it does not.
#  - 10.2: WT = WI * 960 * Fi / f, which is WI * 960 * Fi * D / (F * f) in etu, and 11.4.3:
#    CWT = (11 + 2^CWI) etu and BWT = 11 etu + 2^BWI * 960 * Fd / f, Fd being 372 whatever Fi is.
#
# The frequency fed to CLK is the hardware's choice and is only bounded by the text: it shall not
# exceed f(max). This device divides the kernel clock by 2 * Prescaler (see
# hal_smartcard_pps in stm32/Core/Src/stm32_smartcard.c), so the expectation is the fastest such
# frequency the card allows -- derived from Table 7 and SMARTCARD_CLOCK, not from pps.c's table.

FI_FMAX = {
    0x0: (372, 4000000), 0x1: (372, 5000000), 0x2: (558, 6000000), 0x3: (744, 8000000),
    0x4: (1116, 12000000), 0x5: (1488, 16000000), 0x6: (1860, 20000000),
    0x9: (512, 5000000), 0xA: (768, 7500000), 0xB: (1024, 10000000),
    0xC: (1536, 15000000), 0xD: (2048, 20000000),
}
DI_CODE = {0x1: 1, 0x2: 2, 0x3: 4, 0x4: 8, 0x5: 16, 0x6: 32, 0x7: 64, 0x8: 12, 0x9: 20}
DEFAULT_FMAX = 5000000  # 8.3: "f (max.) = 5 MHz" when TA1 is absent
FD, DD = 372, 1         # 6.3.1
GUARD_MAX = 255         # GTPR.GT is 8 bits of etu (baud clock periods)
PPS_WT = 9600           # 9.1


def kernel_clock() -> int:
    """SMARTCARD_CLOCK, from the build rather than from a copy of it."""
    found = set()
    for cmake in (HERE / "../../CMakeLists.txt", HERE / "../../tests/CMakeLists.txt"):
        m = re.search(r"SMARTCARD_CLOCK=(\d+)", cmake.read_text())
        if m:
            found.add(int(m.group(1)))
    assert len(found) == 1, f"SMARTCARD_CLOCK disagrees between builds: {found}"
    return found.pop()


def card_clock(fmax: int) -> int:
    """The fastest f = kernel / (2 * Prescaler) that a card allowing f(max) will accept."""
    kernel = kernel_clock()
    return max(kernel // (2 * p) for p in range(1, 512) if kernel // (2 * p) <= fmax)


def mk_atr(groups: list, hist: bytes = b"", ts: int = 0x3B) -> str:
    """Assemble an ATR from its groups: the timing group as a dict of TA1/TB1/TC1, then one
    (type, dict of TA/TB/TC) per further group. TD bytes and their indicator nibbles follow from
    which groups and slots exist, per 8.2.3; the check byte follows from 8.2.5."""
    g1 = groups[0]
    y1 = 0
    body = []
    for name, bit in (("TA1", 1), ("TB1", 2), ("TC1", 4)):
        if name in g1:
            y1 |= bit
            body.append(g1[name])
    if len(groups) > 1:
        y1 |= 8
    out = [ts, (y1 << 4) | (len(hist) & 0xF)] + body

    rest = groups[1:]
    for i, (t, slots) in enumerate(rest):
        y = 0
        tail = []
        for name, bit in (("TA", 1), ("TB", 2), ("TC", 4)):
            if name in slots:
                y |= bit
                tail.append(slots[name])
        if i + 1 < len(rest):
            y |= 8
        out.append((y << 4) | t)
        out.extend(tail)
    out.extend(hist)

    types = [g[0] for g in groups[1:]]
    if types and set(types) != {0}:
        parity = 0
        for byte in out[1:]:
            parity ^= byte
        out.append(parity)
    return " ".join(f"{b:02X}" for b in out)


def pps_answer(t: int, fi_di: int | None, spu: bool = False, bad_pck: bool = False) -> str:
    """A card's PPS response: an echo of a request carrying type t and, if fi_di is not None, a
    PPS1 with those values. spu sets bit 6, and bad_pck corrupts the check byte."""
    pps0 = t
    if fi_di is not None:
        pps0 |= 0x10
    if spu:
        pps0 |= 0x20
    seq = [0xFF, pps0] + ([fi_di] if fi_di is not None else [])
    pck = 0
    for byte in seq:
        pck ^= byte
    seq.append(pck if not bad_pck else pck ^ 0xFF)
    return " ".join(f"{b:02X}" for b in seq)


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


# (name, atr, answer, note). `answer` names a card reply built by pps_answer(); None is a card that
# never answers, which 9.1 settles by WT. The ATRs of the bench cards are their real bytes; the
# others are assembled around the shape being pinned, and each offers T=1 through a TD2 with no
# interface bytes of its own so that the triple after it is TA3, TB3 and TC3 rather than the global
# TA2 of 8.3.
PPS_CASES = [
    ("comsign eid", mk_atr([{"TA1": 0x18, "TC1": 0xFF}, (1, {}), (1, {"TA": 0xFE}),
                            (15, {"TA": 0xC3})], bytes.fromhex("8073C82110")),
     "echo",
     "Fi = 372 comes from the upper nibble of TA1 and Di = 12 from the lower, so the proposal carries "
     "them, the bit rate is twelve per etu, and N = 255 asks for no extra guard"),
    ("cryptnox fido2", "3B FA 13 00 FF 91 01 31 FE 00 00 31 C1 73 C8 40 00 00 90 00 D2", "echo",
     "TB3 = 00: CWI = 0 is legal, 11.4.3 says so, and puts CWT at its minimum of 12 etu -- one etu "
     "above the eleven this reader's character spans -- while BWI = 0 puts BWT at 960 Fd/f plus the "
     "11 etu. The card that lights only the backlight"),
    ("specific t0", "3B F0 11 00 FF 91 00 01 8E", None,
     "6.3.1 applies the specific values at once, so T=0 is programmed with 10.2's waiting time and no "
     "request goes out"),
    ("comsign declined", mk_atr([{"TA1": 0x18, "TC1": 0xFF}, (1, {}), (1, {"TA": 0xFE}),
                                 (15, {"TA": 0xC3})], bytes.fromhex("8073C82110")),
     "decline",
     "9.3: an answer with bit 5 clear is a successful exchange, and Fd = 372 with Dn = 1 are then in "
     "force even though TA1 indicated 372 over 12 -- the etu grows twelvefold, and so does CWT"),
    ("jcop 2.4.1r3", mk_atr([{"TB1": 0x00, "TC1": 0x00}, (1, {}),
                             (1, {"TA": 0xFE, "TB": 0x45})],
                            bytes.fromhex("0031C173C840000090007A")),
     "echo_default",
     "no TA1 at all, so Fi = 372 and Di = 1 by default and there is nothing to propose in PPS1, yet "
     "9.1 still requires the request: PPS0's type nibble is how the card is told to run T=1"),
    ("di 64", mk_atr([{"TA1": 0x17}, (1, {}), (1, {"TA": 0xFE})]), "echo",
     "Table 8 gives Di = 64 for bits 4 to 1 equal to 0111, a valid value the reader may not refuse"),
    ("fi rfu", mk_atr([{"TA1": 0x71}, (1, {}), (1, {"TA": 0xFE})]), None,
     "Table 7 leaves bits 8 to 5 = 0111 without an Fi, so there is no rate to run and no exchange to "
     "start"),
    ("ta2 implicit", mk_atr([{"TA1": 0x77}, (1, {"TA": 0x11}), (1, {"TA": 0xFE})]), "decline",
     "TA2 = 11 has bit 5 set, so 8.3 takes the implicit Fd and Dd, and the RFU nibble of TA1 is none "
     "of the reader's business because nothing reads it"),
    ("ta2 indicated", mk_atr([{"TA1": 0x95}, (1, {"TA": 0x01}), (1, {"TA": 0xFE})]), "echo",
     "TA2 = 01 leaves bit 5 clear, so the Fi = 512 and Di = 1 of TA1 apply and are what gets proposed"),
    ("cwt zero", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TB": 0x00})]), "echo_default",
     "11.4.3 with CWI = 0 gives CWT = 11 + 1 = 12 etu, the minimum the text states"),
    ("cwt five", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TB": 0x45})]), "echo_default",
     "CWI = 5 and BWI = 4: CWT = 11 + 32 etu and BWT = 11 + 16 * 960 etu at Fd and Dd"),
    ("bwt nine", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TB": 0x90})]), "echo",
     "BWI = 9 is the largest 11.4.3 defines, and Fd over f grows with Di = 12"),
    ("guard n three", mk_atr([{"TA1": 0x11, "TC1": 0x03}, (1, {}), (1, {"TA": 0x20})]), "echo_default",
     "N = 3 with no T=15 in the ATR, so R = F / D and the extra guard comes out as exactly N etu"),
    ("guard n three t15", mk_atr([{"TA1": 0x91, "TC1": 0x03}, (1, {}), (1, {"TA": 0x20}),
                                  (15, {"TA": 0x03})]),
     "decline",
     "with T=15 present 8.3 takes R from Fi / Di instead of from what is in force, which does not "
     "divide: 512 * 3 over 372 is 4.13 etu and the card must not be shortchanged, so 5"),
    ("guard clamped", mk_atr([{"TA1": 0xD1, "TC1": 0xFE}, (1, {}), (1, {"TA": 0x20}),
                              (15, {"TA": 0x03})]),
     "decline",
     "Fi = 2048 over the Fd = 372 that is in force would ask for 1400 etu of guard and the peripheral "
     "holds 255: the card wanted more than the reader can give, so it gets the maximum, no error"),
    ("n 255", mk_atr([{"TA1": 0x11, "TC1": 0xFF}, (1, {}), (1, {"TA": 0x20})]), "echo_default",
     "8.3 defers N = 255 to the protocol and 11.2 answers 11 etu, which the character frame spans by "
     "itself: no extra guard either way"),
    ("etu not divisible", mk_atr([{"TA1": 0x26}, (1, {}), (1, {"TA": 0xFE})]), "echo",
     "Fi = 558 with Di = 32: the etu is 558 over 32 times f, so dividing F by D before multiplying by "
     "the clock loses a sixth of it"),
    ("answer wrong type", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TA": 0x20})]), "wrong_type",
     "9.3: bits 4 to 1 of the answer shall be identical to those of the request"),
    ("answer bad pck", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TA": 0x20})]), "bad_pck",
     "9.2: exclusive-oring PPSS to PCK inclusive shall give 00, and 9.1 hands a device whose answer "
     "does not check to a deactivation"),
    ("answer asks spu", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TA": 0x20})]), "spu",
     "9.3 lets bit 6 of the answer be what the request made it or 0, and the request made it 0, so a "
     "card offering the SPU of 5.2.4 here is answering a different request from the one it got"),
    ("no answer", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TA": 0x20})]), None,
     "9.1: a card that stays silent after a correct request leaves the reader to wait out WT and stop"),
    ("answer truncated", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TA": 0x20})]), "FF11",
     "the answer promises a PPS1 and then stops: two bytes are not an exchange, and 9.1 leaves the "
     "reader with a waiting time rather than with what it half heard"),
    ("answer without pck", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TA": 0x20})]), "FF1118",
     "9.2 puts PCK last, so an answer that ends before it says nothing whatever it carried"),
    ("answer unasked pps1", mk_atr([{"TA1": 0x11}, (1, {}), (1, {"TA": 0x20})]), "FF1118F6",
     "the request asked for no PPS1, so 9.3 lets bit 5 of the answer read only 0: a card that insists "
     "on proposing rates to a reader that did not ask is not answering this request"),
    ("answer one byte", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TA": 0x20})]), "FF",
     "one byte is not the start of an answer either: 9.1 gives the reader a waiting time and a "
     "deactivation, and nothing here reads meaning into a PPSS on its own"),
    ("decline with a fourth byte", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TA": 0x20})]), "FF01FE00",
     "9.3: with bit 5 clear PPS1 of the answer shall be absent, so the three bytes that do check are "
     "the whole answer and whatever followed it is not part of this exchange"),
    ("answer other rates", mk_atr([{"TA1": 0x18}, (1, {}), (1, {"TA": 0x20})]), "FF1112ED",
     "9.3: PPS1 of the answer shall be identical to the request's, so a card that agrees to T=1 while "
     "putting other integers in their place is refused rather than run at a rate neither asked for"),
    ("t0 card", mk_atr([{"TB1": 0x00, "TC1": 0x02}], b"ACOSJv101"), None,
     "no TD anywhere, so the only offer is T=0, which the shell refuses at the APDU layer; 10.2 still "
     "gives the waiting time to program, and N = 2 the guard"),
]


def pps_expect(atr: str, answer: str | None) -> dict:
    a = iso_expect(atr)
    b = bytes.fromhex(atr.replace(" ", ""))
    t = a["default_protocol"]

    e = {"atr": atr, "result": "ERR_OK", "pps_called": 0, "request": "", "protocol": t,
         "freq": 0, "baud": 0, "etu_10ns": 9300, "guard": 0, "cwt": 0, "bwt": 0, "timeout": 0,
         # t1.c scales the block waiting time by this, so a card in T=1 must find 1 in it.
         "bwt_factor": 1}

    fi_code, di_code = a["fi_di"] >> 4, a["fi_di"] & 0xF
    fi, fmax = FI_FMAX.get(fi_code, (None, DEFAULT_FMAX))
    ta2_implicit = a["ta2"] != 0xFF and (a["ta2"] & 0x10)
    if ta2_implicit:
        # 8.3: with bit 5 of TA2 set the implicit values apply, which are Fd and Dd -- and that
        # holds even when TA1 carries nibbles with no valid meaning, since nothing reads them.
        fi, di = FD, DD
    elif fi is None or di_code not in DI_CODE:
        e["result"] = "ERR_DATA"
        return e
    else:
        di = DI_CODE[di_code]

    e["freq"] = card_clock(fmax)
    e["etu_10ns"] = (100000000 * fi) // (di * e["freq"])
    e["baud"] = (e["freq"] * di) // fi

    def guard() -> int:
        # 8.3 and 11.2 less the frame this reader sends -- eleven etu in T=1 (STOP = 00), eleven and a
        # half otherwise, in half etu to keep that half exact. RM0481 programs GTPR.GT, in baud clock
        # periods of one etu each, as CGT minus the duration of one character, and takes twelve for a
        # frame with two stop bits. Both protocols take their CGT from 8.3, so this holds for the T=0
        # rows too.
        n = a["n"]
        if n == 255:
            return 0 if t == 1 else 1
        if a["t15_present"] and not ta2_implicit:
            r_num, r_den = FI_FMAX.get(fi_code, (FD, DD))[0], DI_CODE.get(di_code, DD)
        else:
            r_num, r_den = fi, di
        return min(GUARD_MAX, 1 + ceil_div(r_num * n * di, r_den * fi))

    if t != 1:
        e["guard"] = guard()

        # 10.2: WT = WI * 960 * Fi / f, in etu WI * 960 * Fi * D / F, and F is Fi until a PPS says
        # otherwise. The shell does not speak T=0, so it asks the peripheral for the waiting time
        # and leaves the exchange to fail later, where the reason is visible.
        e["timeout"] = a["t0_wi"] * 960 * di  # F is Fi until a PPS changes it, so 10.2 is WI*960*Di
        e["pps_called"] = 1  # the waiting time still reaches the peripheral; no exchange is made
        return e

    if a["ta2"] != 0xFF:
        # 6.3.1: specific mode applies the specific values at once, and the card need not support a PPS
        # exchange, so nothing goes on the wire.
        e["pps_called"] = 1
        e["guard"] = guard()
        e["cwt"] = 11 + (1 << a["t1_cwi"])
        e["bwt"] = 11 + (((1 << a["t1_bwi"]) * 960 * FD * di) // fi)
        return e

    # 9.1 and 9.2: the request goes out whatever the rates are, because PPS0's type nibble is what
    # puts the card into T=1. PPS1 is only there when there is something to propose.
    propose = (fi, di) != (FD, DD)
    pps0 = t | (0x10 if propose else 0)
    seq = [0xFF, pps0] + ([a["fi_di"]] if propose else [])
    pck = 0
    for byte in seq:
        pck ^= byte
    e["request"] = " ".join(f"{x:02X}" for x in seq + [pck])

    if answer is None:
        e["result"] = "ERR_TXRX"
        return e

    r = bytes.fromhex(answer.replace(" ", ""))
    # The reader takes the answer in one reception of four bytes, which is all of it it can see: an
    # answer longer than that arrives as one unread byte after the exchange, and one shorter ends
    # the reception by waiting time.
    r = r[:4]
    if len(r) < 2:
        e["result"] = "ERR_TXRX"
        return e
    req0 = (0x10 if propose else 0) | t
    if r[0] != 0xFF or (r[1] & 0x0F) != t or (r[1] & ~req0 & 0xF0):
        # 9.3: bits 4 to 1 identical, and each of bits 5, 6 and 7 as requested or 0, with bit 8
        # reserved. A bit the answer sets on its own claims a parameter byte the request never sent,
        # and is refused before any further byte is asked for.
        e["result"] = "ERR_DATA"
        return e

    checked = 3
    if r[1] & 0x10:
        if len(r) < 4:
            e["result"] = "ERR_TXRX"
            return e
        if r[2] != a["fi_di"]:
            e["result"] = "ERR_DATA"
            return e
        checked = 4
    else:
        # 9.3: clearing bit 5 is a success, and it puts Fd and Dd in force however TA1 read.
        fi, di = FD, DD
    if len(r) != checked:
        # A PPS1 where none was invited is as much a violation as a missing PCK: 9.3 makes the
        # answer's shape follow the request's, so the reader takes what it promised and nothing more.
        e["result"] = "ERR_TXRX"
        return e

    parity = 0
    for byte in r[:checked]:
        parity ^= byte
    if parity != 0:
        e["result"] = "ERR_DATA"
        return e

    # Nothing reaches the peripheral unless the exchange succeeded: 9.1 sends a device whose answer
    # does not check, or one that heard nothing at all, to a deactivation.
    e["pps_called"] = 1
    e["etu_10ns"] = (100000000 * fi) // (di * e["freq"])
    e["baud"] = (e["freq"] * di) // fi
    e["guard"] = guard()
    e["cwt"] = 11 + (1 << a["t1_cwi"])
    e["bwt"] = 11 + (((1 << a["t1_bwi"]) * 960 * FD * di) // fi)

    return e


def pps_vectors() -> str:
    rows = []
    for name, atr, answer, note in PPS_CASES:
        if iso_expect(atr)["ta2"] != 0xFF:
            answer = None  # 6.3.1: specific mode, the exchange never happens
        if answer is not None and re.fullmatch(r"[0-9A-F]+", answer):
            rows.append((name, atr, answer, note, pps_expect(atr, answer)))
            continue
        if answer == "echo":
            a = iso_expect(atr)
            answer = pps_answer(a["default_protocol"], None if a["fi_di"] == 0x11 else a["fi_di"])
        elif answer == "echo_default":
            answer = pps_answer(1, None)
        elif answer == "decline":
            answer = pps_answer(1, None)
        elif answer == "wrong_type":
            answer = pps_answer(0, None)
        elif answer == "bad_pck":
            answer = pps_answer(1, None, bad_pck=True)
        elif answer == "spu":
            answer = pps_answer(1, None, spu=True)
        rows.append((name, atr, answer, note, pps_expect(atr, answer)))

    def comment(name, atr, note, e):
        text = f"Card ATR {atr}. {note}"
        lines = textwrap.wrap(text, width=94)
        out = [f"    /* {lines[0]}"] + [f"     * {line}" for line in lines[1:]]
        out[-1] += " */"
        return "\n".join(out)

    body = "\n".join(
        f'{comment(name, atr, note, e)}\n'
        f'    {{\n'
        f'        "{name}", "{atr.replace(" ", "")}", '
        f'{"NULL" if answer is None else chr(34) + answer.replace(" ", "") + chr(34)}, '
        f'{e["result"]}, {e["pps_called"]},\n'
        f'        "{e["request"].replace(" ", "")}", {e["protocol"]}, '
        f'{e["freq"]}, {e["baud"]}, {e["etu_10ns"]},\n'
        f'        {e["guard"]}, {e["cwt"]}, {e["bwt"]}, {e["timeout"]}, {e["bwt_factor"]},\n'
        f'    }},'
        for name, atr, answer, note, e in rows
    )

    fmax_rows = "\n".join(
        f'    {{ 0x{code:X}, {fmax}, "TA1 {code:X}x" }},' for code, (_, fmax) in sorted(FI_FMAX.items())
    )

    return f"""#ifndef VECTORS_PPS_H
#define VECTORS_PPS_H

/* What ISO/IEC 7816-3:2006 requires of a reader once it has read an ATR: the protocol and parameter
 * selection of clause 9 and the rates, guard and waiting times that follow from clauses 7, 8, 10
 * and 11. One row is one ATR and one card answer, and the fields are what pps.c must hand to
 * hal_smartcard_pps and to smartcard_t, derived from the text by tests/vectors/generate.py.
 *
 * The derivation is in pps_vectors() above; the short version is that Table 7 of 8.3 pairs Fi with
 * f(max) in the upper nibble of TA1 and Table 8 puts Di in the lower one, so the two are read from
 * different nibbles; that the clock fed to CLK is whatever the device can produce under f(max) --
 * kernel / (2 * Prescaler) here -- and that everything else is arithmetic on 7.1's etu, 8.3's guard
 * with its R taken from F/D or from Fi/Di depending on whether T=15 is in the ATR, 10.2's waiting
 * time, and 11.4.3's CWT and BWT, both of which carry an 11 etu term. Clause 9 is structural: the
 * request is always sent, PPS1 only when there is something to propose and only with bit 5 of PPS0
 * set, and a card may answer shorter than it was asked, in which case Fd and Dd are in force.
 */

#include "error.h"
#include "iso7816/smartcard.h"

typedef struct {{
  const char* name;
  const char* atr_hex;
  const char* pps_answer_hex; /* NULL when the card never answers */
  app_err_t result;
  uint8_t pps_called;
  const char* pps_request_hex;
  uint8_t protocol;
  uint32_t freq;
  uint32_t baud;
  uint32_t etu_10ns;
  uint8_t guard;
  uint32_t t1_cwt;
  uint32_t t1_bwt;
  uint32_t t0_timeout;
  uint8_t t1_bwt_factor;
}} pps_kat_t;

/* Table 7 of 8.3, as a bound a test can check the device's own frequency table against. */
typedef struct {{
  uint8_t code;
  uint32_t fmax_hz;
  const char* name;
}} pps_fmax_t;

static const pps_fmax_t PPS_FMAX[] = {{
{fmax_rows}
}};

#define PPS_FMAX_COUNT (sizeof(PPS_FMAX) / sizeof(PPS_FMAX[0]))

static const pps_kat_t PPS_KAT[] = {{
{body}
}};

#define PPS_KAT_COUNT (sizeof(PPS_KAT) / sizeof(PPS_KAT[0]))

#endif
"""

# --- T=1 blocks: 11.3 framing, 11.4.2 field sizes, 11.4.4 epilogue, 11.6 blocks ---------------

T1_IFSD = 254          # t1.h offers this as IFSD in S(IFS request)
T1_BUF = 261           # smartcard.h's APDU_BUF_LEN
T1_BGT = 22            # 11.2, both directions
T1_BWT_WAIT = 2        # 11.4.3 bounds the card's reply; 32 bits leave room for two times the largest
T1_EDC_RETRIES = 3     # t1.c's T1_MAX_LRC_RETRIES: 7.4.1 allows two further attempts, so one spare
T1_TIMEOUTS_MAX = 24
T1_XMIT, T1_IFSD_ENTRY = 0, 1


def t1_lrc(body: bytes) -> int:
    """11.3.4: exclusive-oring the block from NAD to LRC inclusive shall give 00."""
    x = 0
    for byte in body:
        x ^= byte
    return x


def t1_block(pcb: int, inf: bytes = b"", bad_edc: bool = False) -> bytes:
    body = bytes([0x00, pcb, len(inf)]) + inf
    return body + bytes([t1_lrc(body) ^ (0xFF if bad_edc else 0)])


def t1_i(ns: int, inf: bytes = b"", more: bool = False, bad_edc: bool = False) -> bytes:
    return t1_block((ns << 6) | (0x20 if more else 0), inf, bad_edc)   # 11.3.2.2: bit 7 is N(S), bit 6 is M


def t1_r(nr: int, err: int = 0) -> bytes:
    return t1_block(0x80 | (nr << 5) | err)     # bits 8 and 7 are 10; N(R) is bit 6, the code bits 4 to 1


def t1_s(kind: int, inf: bytes = b"", resp: bool = False) -> bytes:
    return t1_block(0xC0 | (0x20 if resp else 0) | kind, inf)


def apdu_bytes(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None):
    """The command as the shell holds it, with the flags APDU_LEN counts."""
    body = bytes([cla, ins, p1, p2])
    has_lc = 1 if data else 0
    has_le = 0 if data else (1 if le is not None else 0)
    if data:
        body += bytes([len(data)]) + data
    if le is not None and not data:
        body += bytes([le])
    return body, has_lc, has_le


def t1_expect(atr: str, cmd: bytes, entry: int, card: bytes, retry: int = 0,
              refuse_sends: int = 0) -> dict:
    """The exchange 11.6 describes, from the script of blocks the card sends. Reader output is built
    from the clauses, not from t1.c: the point is that the two agree by different routes."""
    a = iso_expect(atr)
    # 6.3.1: specific mode, so no PPS answer precedes the blocks below.
    answer = None if a["ta2"] != 0xFF else pps_answer(
        a["default_protocol"], None if a["fi_di"] == 0x11 else a["fi_di"])
    p = pps_expect(atr, answer)

    ifsc = a["t1_ifsc"]
    bwt, cwt, etu = p["bwt"], p["cwt"], p["etu_10ns"]
    wire = bytearray()
    resp = bytearray()
    timeouts: list[int] = []
    state = {"ns": 0, "nr": 0, "factor": 1, "retries": 0, "pos": 0, "delay": 0, "ifsc": ifsc}

    def read(n: int) -> bytes | None:
        if state["pos"] + n > len(card):
            return None
        out = card[state["pos"]:state["pos"] + n]
        state["pos"] += n
        return out

    def receive_one(accept_i: bool, chain_open: bool = False) -> str:
        """One block from the card. 'again' keeps waiting for the next one, 'advance' ends the
        exchange or acknowledges a chunk, 'retry' retransmits it, 'fail' gives up."""
        timeouts.append(T1_BWT_WAIT * bwt * state["factor"])
        state["factor"] = 1                    # the extension the card granted is spent on this block
        head = read(3)
        if head is None:
            return "fail"
        _, pcb, ln = head
        is_i = (pcb & 0x80) == 0
        timeouts.append(cwt)
        if is_i:
            # 11.4.2: nothing lands outside the response buffer, and an I-block has no business in an
            # exchange that asked only to negotiate. Rule 2.2 adds that a card owing the
            # acknowledgment of a chained I-block owes an R-block, so an I-block in that window is
            # refused rather than written over command bytes still to go. The rest stays unread.
            if not accept_i or chain_open or len(resp) + ln > T1_BUF:
                return "fail"
        elif (pcb & 0xC0) == 0xC0 and ln > 1:
            return "fail"
        inf = read(ln) if ln else b""
        if inf is None:
            return "fail"
        edc = read(1)
        if edc is None:
            return "fail"
        state["delay"] += (etu * T1_BGT) // 100     # 11.2: BGT after each block received
        if t1_lrc(head + inf) != edc[0]:
            state["retries"] += 1
            if state["retries"] > T1_EDC_RETRIES:
                return "fail"
            wire.extend(t1_r(state["nr"], 0x01))    # rule 7.1: ask again for the expected I-block
            return "again"
        state["retries"] = 0
        if is_i:
            resp.extend(inf)
            if (pcb & 0x40) != (state["nr"] << 6):
                wire.extend(t1_r(state["nr"], 0x02))
                return "again"
            state["nr"] ^= 1
            if pcb & 0x20:
                # 11.6.2.2: a more-data I-block is answered by R(N(R)) naming the next one
                wire.extend(t1_r(state["nr"]))
                return "again"
            return "advance"
        if (pcb & 0xC0) == 0x80:
            # rule 5: the R-block acknowledging a chunk carries N(R) other than the N(S) just sent
            if (pcb & 0x0F) != 0 or (pcb & 0x20) != ((state["ns"] ^ 1) << 5):
                return "retry"
            return "advance"
        kind = pcb & 0x03
        is_resp = (pcb & 0x20) != 0
        if kind == 3:                                # rule 3
            if ln != 1:
                return "retry"                       # the multiplier is in INF: there is nothing to apply
            state["factor"] = inf[0]
            wire.extend(t1_s(3, inf, resp=True))
            return "again"
        if kind == 2:                                # rule 9
            wire.extend(t1_s(2, resp=True))
            return "fail"
        if kind == 1:                                # rule 4
            if ln != 1:
                return "retry"
            if is_resp:
                return "advance"
            if inf[0] != 0:                          # 11.4.2 reserves 00 and FF
                state["ifsc"] = min(inf[0], T1_IFSD)
            wire.extend(t1_s(1, inf, resp=True))     # the response echoes the byte, as rule 4 says
            return "again"
        kind = pcb & 0x1F
        if kind != 0:
            # Figure 20 reserves the other codings and 11.6.3.1 counts an unknown PCB as an invalid
            # block: nothing is acknowledged, least of all a resynchronization.
            return "retry"
        if not is_resp:
            wire.extend(t1_s(0, resp=True))          # rule 6.2 answers the request
        state["ns"] = 0
        state["nr"] = 0
        return "advance" if is_resp else "again"

    if refuse_sends:                                 # the peripheral will not write at all
        return {"result": "ERR_TXRX", "wire": "", "send_seq": 0, "recv_seq": 0, "ifsc": ifsc,
                "bwt_factor": 1, "unread": len(card), "delay_us": (etu * T1_BGT) // 100
                if entry == T1_IFSD_ENTRY else 0, "resp_len": 0, "timeouts": [],
                "pps_answer": answer}

    if a["t1_rc"]:                                   # 11.4.4 asked for a CRC: nothing goes out
        return {"result": "ERR_UNSUPPORTED", "wire": "", "send_seq": 0, "recv_seq": 0, "ifsc": ifsc,
                "bwt_factor": 1, "unread": len(card), "delay_us": 0, "resp_len": 0,
                "timeouts": [], "pps_answer": answer}

    if entry == T1_IFSD_ENTRY:
        result = "ERR_TXRX"
        for attempt in range(retry + 1):
            # A negotiation is opened with a BGT, and rule 6 restarts it from the beginning.
            state["delay"] += (etu * T1_BGT) // 100
            wire.extend(t1_s(1, bytes([T1_IFSD])))
            outcome = "again"
            while outcome == "again":
                outcome = receive_one(accept_i=False)
            if outcome == "advance":
                result = "ERR_OK"
                break
            if attempt == retry:
                break
            # rule 7.3 then rule 6: the request goes unanswered, so reach resynchronization first
            wire.extend(t1_s(0))
            outcome = "again"
            while outcome == "again":
                outcome = receive_one(accept_i=False)
            if outcome != "advance":
                break
    else:
        if ifsc == 0:
            return {"result": "ERR_TXRX", "wire": "", "send_seq": 0, "recv_seq": 0, "ifsc": 0,
                    "bwt_factor": 1, "unread": len(card), "delay_us": 0, "resp_len": 0,
                    "timeouts": [], "pps_answer": answer}
        to_send, off, resend = len(cmd), 0, 0
        while to_send > 0 and resend < 2:
            blen = min(to_send, state["ifsc"])
            # rule 1 wants N(S) = 0 first and it alternates after each I-block; the M-bit is rule 5
            wire.extend(t1_i(state["ns"], cmd[off:off + blen], more=to_send > state["ifsc"]))
            outcome = "again"
            while outcome == "again":
                outcome = receive_one(accept_i=True, chain_open=to_send > state["ifsc"])
            if outcome == "fail":
                break
            if outcome == "retry":
                resend += 1
                continue
            state["ns"] ^= 1
            off += blen
            to_send -= blen
            resend = 0
        result = "ERR_OK" if to_send == 0 and len(resp) >= 2 else "ERR_TXRX"

    return {"result": result, "wire": wire.hex(), "send_seq": state["ns"], "recv_seq": state["nr"],
            "ifsc": state["ifsc"], "bwt_factor": state["factor"], "unread": len(card) - state["pos"],
            "delay_us": state["delay"], "resp_len": len(resp), "timeouts": timeouts,
            "pps_answer": answer}


def t1_atr(ifsc: int = 0x20, tb: int = 0x45, tc: int = 0x00, ta1: int | None = 0x18) -> str:
    """An ATR offering T=1 with its triple: TA is IFSC, TB is BWI and CWI, TC is the redundancy code
    (11.4.1, 11.4.2 and 11.4.4). CWI = 5 and BWI = 4 are TB = 0x45; no TA1 leaves the global Fd and Dd."""
    first = {} if ta1 is None else {"TA1": ta1}
    return mk_atr([first, (1, {}), (1, {"TA": ifsc, "TB": tb, "TC": tc})])


C5 = apdu_bytes(0x00, 0xA4, 0x04, 0x00, le=0x00)     # case 2: header and Le, nothing else
SW_OK = bytes.fromhex("9000")
PAYLOAD = bytes(range(0x41, 0x41 + 40))

T1_CASES = [
    ("single response", t1_atr(), C5, T1_XMIT, t1_i(0, SW_OK),
     "the smallest exchange there is: one I-block out, one back carrying SW1 SW2, and the reader "
     "acknowledges it by its next command rather than by an R-block (rule 2.1)"),
    ("chained command", t1_atr(ifsc=0x20), apdu_bytes(0x80, 0xC0, 0x00, 0x00, PAYLOAD), T1_XMIT,
     t1_r(1) + t1_i(0, SW_OK),
     "figure 23: the command is longer than IFSC, so it is split with the M-bit set on all but the "
     "last block, and each piece is acknowledged by R(N(R)) naming the next one (rule 5)"),
    ("chained response", t1_atr(), C5, T1_XMIT,
     t1_i(0, bytes(range(20)), more=True) + t1_i(1, SW_OK),
     "11.6.2.2: a more-data I-block is answered by R(N(R)) with the sequence of the I-block expected "
     "next, and the last block of the chain is not answered at all"),
    ("wtx request", t1_atr(), C5, T1_XMIT,
     t1_s(3, bytes([0x05])) + t1_i(0, SW_OK),
     "rule 3: the multiplier is applied to the waiting time of the block being waited for, and the "
     "response carries the same INF"),
    ("wtx without inf", t1_atr(), C5, T1_XMIT,
     t1_s(3) + t1_i(0, SW_OK),
     "rule 3 puts the multiplier in INF, so a block that promises one without carrying it is not an "
     "extension to apply: the factor stays one and the chunk is retransmitted"),
    ("ifs request without inf", t1_atr(), C5, T1_XMIT,
     t1_s(1) + t1_i(0, SW_OK),
     "rule 4 puts the new IFSC in INF: a request carrying none is not a size to adopt, because "
     "IFSC 0 would leave nothing to send, and the chunk goes out again"),
    ("ifs request from card", t1_atr(), C5, T1_XMIT,
     t1_s(1, bytes([0x40])) + t1_i(0, SW_OK),
     "rule 4: the new IFSC is in force from the request, and the response echoes the byte"),
    ("ifs request zero reserved", t1_atr(), C5, T1_XMIT,
     t1_s(1, bytes([0x00])) + t1_i(0, SW_OK),
     "11.4.2 reserves 00, so what is kept is unchanged while rule 4 still gets its echo"),
    ("ifs request ff reserved", t1_atr(), C5, T1_XMIT,
     t1_s(1, bytes([0xFF])) + t1_i(0, SW_OK),
     "11.4.2 reserves FF too; the largest IFSD is what is kept, since a larger field than that "
     "cannot be received anyway"),
    ("ifs negotiate", t1_atr(), b"", T1_IFSD_ENTRY, t1_s(1, bytes([0xFE]), resp=True),
     "rule 4 the other way round: the reader offers its IFSD and the exchange is over when the "
     "response arrives, before any APDU is sent"),
    ("edc error then good block", t1_atr(), C5, T1_XMIT,
     t1_i(0, SW_OK, bad_edc=True) + t1_i(0, SW_OK),
     "11.3.4 with the LRC: a block whose epilogue does not check is refused by R(N(R)) with the "
     "redundancy-code error, and the block retransmitted is accepted with the same N(S)"),
    ("edc error exhausted", t1_atr(), C5, T1_XMIT,
     t1_i(0, SW_OK, bad_edc=True) * 4,
     "the reader asks a bounded number of times: rule 7.4.1 allows two further attempts, and t1.c "
     "grants three, so the fourth bad block is the last one it answers"),
    ("card repeats a sequence", t1_atr(), C5, T1_XMIT,
     t1_i(0, bytes(10), more=True) + t1_i(0, bytes(10), more=True) + t1_i(1, SW_OK),
     "the second block repeats the N(S) the reader has already accepted, so it is a retransmission of "
     "a piece already had: the reader says so with the other-error code, naming the I-block it wants"),
    ("r block wrong n(r)", t1_atr(), C5, T1_XMIT,
     t1_r(0) + t1_i(0, SW_OK),
     "rule 5: N(R) of the R-block acknowledging a chunk is not the N(S) that chunk carried, so an "
     "R(0) after I(0) acknowledges nothing and the chunk goes out again"),
    ("abort", t1_atr(), C5, T1_XMIT,
     t1_s(2) + t1_i(0, SW_OK),
     "rule 9: a chain is aborted by S(ABORT request), answered by S(ABORT response); nothing the "
     "card sends afterwards completes the exchange"),
    ("response over the buffer", t1_atr(), C5, T1_XMIT,
     b"".join(t1_i(i & 1, bytes(32), more=True) for i in range(9)),
     "the response is bounded by the buffer the reader holds, not by what the card decides to send: "
     "the block that would pass the end is refused and left unread"),
    ("crc requested", t1_atr(tc=0x01), C5, T1_XMIT, t1_i(0, SW_OK),
     "11.4.4: bit 1 of the first TC for T=1 asks for a CRC epilogue, which is not implemented, so "
     "the card is refused before a single byte goes out rather than answered with an LRC it rejects"),
    ("crc requested, negotiation", t1_atr(tc=0x01), b"", T1_IFSD_ENTRY, b"",
     "the IFSD negotiation is the first thing the protocol does after PPS, so it refuses a CRC card "
     "too, instead of talking at it with the wrong epilogue"),
    ("silent card", t1_atr(), C5, T1_XMIT, b"",
     "a card that answers nothing within BWT leaves the reader with the command it sent and a "
     "waiting time that expired (rule 7.6 leaves R(0) unattempted here)"),
    ("block without epilogue", t1_atr(), C5, T1_XMIT,
     bytes([0x00, 0x00, 0x02]),
     "11.3.1 makes the epilogue mandatory: a block that ends with its information field is not a "
     "block, and there is no code to check"),
    ("card asks to resynchronize", t1_atr(), C5, T1_XMIT,
     t1_s(0) + t1_i(0, SW_OK),
     "rule 6.2 acknowledged in the other direction: the answer to S(RESYNCH request) is S(RESYNCH "
     "response), and both sequence numbers start again at zero (11.6.2.1)"),
    dict(name="ifs request answered by resynchronization", atr=t1_atr(), cmd=C5, entry=T1_IFSD_ENTRY,
         card=t1_r(0) + t1_s(0, resp=True) + t1_s(1, bytes([0xFE]), resp=True), retry=1,
         note="rule 7.3: an S(request) that does not get its response is tried again, and rule 6 "
              "puts S(RESYNCH request) between the attempts, after which the negotiation starts over "
              "with the parameters at their initial values"),
    dict(name="s block of an undefined type", atr=t1_atr(), cmd=C5, entry=T1_XMIT,
         card=t1_s(4) + t1_i(0, SW_OK),
         note="Figure 20 leaves the coding 4 reserved and 11.6.3.1 calls an unknown PCB an invalid "
              "block: it is not a request, so nothing is acknowledged and the command goes out again"),
    dict(name="answer in the middle of a chain", atr=t1_atr(),
         cmd=apdu_bytes(0x80, 0xC0, 0x00, 0x00, PAYLOAD), entry=T1_XMIT, card=t1_i(0, SW_OK),
         note="rule 2.2: a chained I-block is acknowledged by R(N(R)), and the note to it allows "
              "chaining in one direction at a time. An I-block in that window is not an "
              "acknowledgment, and it would also be appended over command bytes that have not gone "
              "out, answer and command sharing apdu->data"),
    dict(name="wtx request in the middle of a chain", atr=t1_atr(),
         cmd=apdu_bytes(0x80, 0xC0, 0x00, 0x00, PAYLOAD), entry=T1_XMIT,
         card=t1_s(3, bytes([5])) + t1_r(1) + t1_i(0, SW_OK),
         note="S(…request) carries no acknowledgment (11.6.2.1), so the refusal above is about "
              "I-blocks only: the extension is applied, the chain goes on, and the R-block is what "
              "acknowledges the piece"),
    dict(name="command longer than a byte counts", atr=t1_atr(ifsc=0xFE),
         cmd=apdu_bytes(0x80, 0xC0, 0x00, 0x00, bytes([0x41 + (i % 26) for i in range(255)])),
         entry=T1_XMIT, card=t1_r(1) + t1_i(0, SW_OK),
         note="APDU_LEN is 4 + 1 + 255 for a full data field, which is why the count of bytes left "
              "to send is not a byte: 254 in the first chunk, 6 in the second"),
    dict(name="cryptnox single response", atr="3B FA 13 00 FF 91 01 31 FE 00 00 31 C1 73 C8 40 00 00 90 00 D2",
         cmd=apdu_bytes(0x00, 0xA4, 0x04, 0x00, bytes.fromhex("A0 00 00 08 04 00 01")),
         entry=T1_XMIT, card=t1_i(0, SW_OK),
         note="the card that lights only the backlight, at its own parameters: IFSC 254, CWI 0 so CWT is "
              "the 12 etu minimum of 11.4.3, BWI 0 so BWT is 960 Fd/f plus 11 etu, and no TC3 so the LRC"),
    dict(name="cryptnox silent card", atr="3B FA 13 00 FF 91 01 31 FE 00 00 31 C1 73 C8 40 00 00 90 00 D2",
         cmd=apdu_bytes(0x00, 0xA4, 0x04, 0x00, bytes.fromhex("A0 00 00 08 04 00 01")),
         entry=T1_XMIT, card=b"",
         note="the same card saying nothing: the block waiting time it asked for is the only thing that "
              "ends the exchange, and with BWI = 0 it is the shortest the text allows"),
    dict(name="peripheral refuses the write", atr=t1_atr(), cmd=C5, entry=T1_XMIT,
         card=t1_i(0, SW_OK), refuse_sends=1,
         note="a write the peripheral refuses is not a card error to retry: the exchange is over, "
              "with nothing claimed to have been sent"),
]


def t1_vectors() -> str:
    rows = []
    for case in T1_CASES:
        case = dict(zip(("name", "atr", "cmd", "entry", "card", "note"), case)) if isinstance(
            case, tuple) else dict(case)
        cmd, has_lc, has_le = case["cmd"] if isinstance(case["cmd"], tuple) else (case["cmd"], 0, 0)
        e = t1_expect(case["atr"], cmd, case["entry"], case["card"], case.get("retry", 0),
                      case.get("refuse_sends", 0))
        rows.append((case["name"], case["atr"], cmd, case["entry"], case["card"], case["note"], e,
                     has_lc, has_le, case.get("retry", 0), case.get("refuse_sends", 0)))

    def comment(name, atr, note):
        lines = textwrap.wrap(f"ATR {atr}. {note}", width=94)
        out = [f"    /* {lines[0]}"] + [f"     * {line}" for line in lines[1:]]
        out[-1] += " */"
        return "\n".join(out)

    body = "\n".join(
        f'{comment(name, atr, note)}\n'
        f'    {{\n'
        f'        "{name}", "{atr.replace(" ", "")}", '
        f'{"NULL" if e["pps_answer"] is None else chr(34) + e["pps_answer"].replace(" ", "") + chr(34)}, '
        f'"{cmd.hex().upper()}", '
        f'{has_lc}, {has_le}, {entry}, {retry}, {refuse},\n'
        f'        "{card.hex().upper()}", {e["result"]}, "{e["wire"].upper()}",\n'
        f'        {e["send_seq"]}, {e["recv_seq"]}, {e["ifsc"]}, {e["bwt_factor"]}, '
        f'{e["unread"]}, {e["delay_us"]}, {e["resp_len"]},\n'
        f'        {len(e["timeouts"])}, {{{", ".join(str(t) for t in e["timeouts"])}}},\n'
        f'    }},'
        for name, atr, cmd, entry, card, note, e, has_lc, has_le, retry, refuse in rows
    )

    return f"""#ifndef VECTORS_T1_H
#define VECTORS_T1_H

/* Generated by tests/vectors/generate.py: t1_vectors(). T=1 blocks, framed per 11.3 and exchanged
 * per 11.6, with the parameters of 11.4. Every expectation is derived from those clauses; see the
 * note above each row. */

#define T1_TIMEOUTS_MAX {T1_TIMEOUTS_MAX}

typedef struct {{
  const char* name;
  const char* atr_hex;
  const char* pps_answer_hex;
  const char* apdu_hex;
  uint8_t has_lc;
  uint8_t has_le;
  uint8_t entry;           /* T1_ENTRY_TRANSMIT or T1_ENTRY_NEGOTIATE */
  uint8_t retry;           /* the retries t1_negotiate_ifsd is granted */
  uint8_t refuse_sends;    /* writes the peripheral refuses, before anything else happens */
  const char* card_hex;    /* the blocks the card sends, in order */
  app_err_t result;
  const char* wire_hex;    /* every byte the reader transmits, in order */
  uint8_t send_seq;
  uint8_t recv_seq;
  uint8_t ifsc;
  uint8_t bwt_factor;
  uint32_t unread;         /* card bytes left unconsumed */
  uint32_t delay_us;       /* BGT delays, 11.2 */
  uint32_t resp_len;       /* apdu->lr when the exchange ended */
  unsigned timeout_count;
  uint32_t timeouts[T1_TIMEOUTS_MAX];   /* BWT then CWT, per block awaited */
}} t1_kat_t;

#define T1_ENTRY_TRANSMIT 0
#define T1_ENTRY_NEGOTIATE 1

static const t1_kat_t T1_KAT[] = {{
{body}
}};

#define T1_KAT_COUNT (sizeof(T1_KAT) / sizeof(T1_KAT[0]))

#endif
"""


def main() -> None:
    written = {
        "vectors_hash.h": hash_vectors(),
        "vectors_hmac.h": hmac_vectors(),
        "vectors_hkdf.h": hkdf_vectors(),
        "vectors_pbkdf2.h": pbkdf2_vectors(),
        "vectors_util.h": util_vectors(),
        "vectors_atr.h": atr_vectors(),
        "vectors_pps.h": pps_vectors(),
        "vectors_t1.h": t1_vectors(),
        "vectors_bip39.h": bip39_vectors(),
        "vectors_multisig.h": multisig_vectors(),
        "vectors_slip39.h": slip39_vectors(),
        "vectors_base58.h": base58_vectors(),
        "vectors_bech32.h": bech32_vectors(),
        "vectors_compactsize.h": compactsize_vectors(),
        "vectors_address.h": address_vectors(),
        "vectors_script.h": script_vectors(),
        "vectors_addr_uri.h": addr_uri_vectors(),
        "vectors_psbt.h": psbt_vectors(),
        "vectors_bytewords.h": bytewords_vectors(),
        "vectors_qrcode.h": qrcode_vectors(),
        "vectors_tx.h": tx_vectors(),
        "vectors_psbt_tx.h": psbt_tx_vectors(),
        "vectors_psbt_ctx.h": ctx_vectors(),
        "vectors_sighash.h": sighash_vectors(),
        "vectors_bignum.h": bignum_vectors(),
        "vectors_pka.h": pka_vectors(),
        "vectors_bip32.h": bip32_vectors(),
        "vectors_taproot.h": taproot_vectors(),
        "vectors_ecdsa_curve.h": ecdsa_curve_vectors(),
        "vectors_multisig_derive.h": multisig_derive_vectors(),
        "vectors_ethereum.h": ethereum_vectors(),
        "vectors_eth_db.h": eth_db_vectors(),
        "vectors_shamir.h": shamir_vectors(),
        "vectors_tlv.h": tlv_vectors(),
        "vectors_ecdsa_der.h": ecdsa_der_vectors(),
        "vectors_keycard_signature.h": sign_reply_vectors(),
        "vectors_eip712.h": eip712_vectors(),
        "vectors_ur.h": ur_vectors(),
        "vectors_ur_decode.h": ur_decode_vectors(),
    "vectors_openpgp.h": openpgp_vectors(),
        "vectors_hal_aes.h": aes_vectors(),
        "vectors_keys.h": keys_vectors(),
        "vectors_multisig_crypto.h": multisig_crypto_vectors(),
    }
    for name, content in written.items():
        (HERE / name).write_text(content)
        print(f"wrote {name} ({len(content)} bytes)")


if __name__ == "__main__":
    if "--eip712-documents" in sys.argv[1:]:
        documents = eip712_documents()
        (CACHE / "eip712_documents.json").write_text(json.dumps(documents, indent=1) + "\n")
        print(f"{len(documents)} documents -> {CACHE / 'eip712_documents.json'}")
    else:
        main()
