#!/usr/bin/env python3
"""Generate the known-answer vector headers consumed by the native tests.

Every value in the emitted headers comes from one of two places, and each header says which:

  spec      fetched from the upstream document or word list, hashed below so a regenerated
            header can be audited against the same source
  reference computed by an independent implementation (CPython hashlib/hmac/zlib,
            pycryptodome, or the BIP's own reference code)

Run from anywhere; requires network unless the sources are already in tests/vectors/.cache/.

    uv run python tests/vectors/generate.py
"""

import base64
import hashlib
import hmac
import json
import os
import re
import string
import sys
import unicodedata
import urllib.request
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"

SOURCES = {
    "bip39_wordlist.txt": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
    "bip39_vectors.json": "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json",
    "bip32.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki",
    "base58.cpp": "https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/base58.cpp",
    "bip173.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0173.mediawiki",
    "bip350.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0350.mediawiki",
    "slip39_wordlist.txt": "https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt",
    "slip39_vectors.json": "https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json",
    "rfc4231.txt": "https://www.rfc-editor.org/rfc/rfc4231.txt",
    "rfc5869.txt": "https://www.rfc-editor.org/rfc/rfc5869.txt",
    "bip174.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0174.mediawiki",
    "bip143.mediawiki": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0143.mediawiki",
    "bip341_wallet.json": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json",
    "bip340_vectors.csv": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv",
    "bc_bytewords.c": "https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/src/bc-bytewords.c",
    "bc_bytewords_test.c": "https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/test/test.c",
}


def fetch(name: str) -> str:
    path = CACHE / name
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        print(f"fetch {SOURCES[name]}")
        path.write_bytes(urllib.request.urlopen(SOURCES[name]).read())
    return path.read_text(encoding="utf-8", errors="replace")


def provenance(name: str) -> str:
    digest = hashlib.sha256((CACHE / name).read_bytes()).hexdigest()
    return f"{SOURCES[name]}\n * sha256 {digest}"


def hexs(data: bytes) -> str:
    return data.hex()


def cstr(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
                hexs(hashlib.new("ripemd160", msg).digest()),
                hexs(hashlib.sha3_256(msg).digest()),
                hexs(hashlib.sha3_512(msg).digest()),
                hexs(k.digest()),
                "%#010x" % zlib.crc32(msg),
            )
        )

    body = ",\n".join(
        "  {%s, %s, %s, %s, %s, %s, %s, %s}" % tuple(cstr(v) for v in row) for row in rows
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


# ---------------------------------------------------------------- address


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
        rows.append(
            "  {%s, %s, %s, %s}"
            % (
                cstr(hexs(compressed)),
                cstr(hexs(uncompressed)),
                cstr(lowercase),
                cstr(eth_utils.to_checksum_address("0x" + lowercase)[2:]),
            )
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
            f'    {{ "{name}", psbt_ctx_{i}, sizeof(psbt_ctx_{i}), {accept},\n'
            f'      {kind if kind else "-1"}, {amount}ULL, "{hexs(script)}" }},')

    return """/* Generated by tests/vectors/generate.py -- do not edit.
 *
 * PSBTs built from BIP-174's grammar to pin what the device takes an input to be. Where two utxo
 * fields describe one input, the prevtx is authoritative -- the answer a verifying node computes --
 * whichever record the wallet wrote last.
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

#endif
""" % ("\n\n".join(arrays), "\n".join(rows))

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
        # The historical SIGHASH_SINGLE answer is the digest 0x...01; the device reports the case
        # instead of signing it, so no vector here asks for it.
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
    outputs each get their own hash over the whole transaction."""
    prevouts = b"".join(entry["txid"] + entry["index"].to_bytes(4, "little") for entry in tx["inputs"])
    sequences = b"".join(entry["sequence"] for entry in tx["inputs"])
    outputs = b"".join(amount + csb(len(script)) + script for amount, script in tx["outputs"])
    stream = tx["version"]
    stream += dsha256(prevouts)
    stream += dsha256(sequences)
    stream += tx["inputs"][in_]["txid"] + tx["inputs"][in_]["index"].to_bytes(4, "little")
    stream += csb(len(script_code)) + script_code
    stream += amount
    stream += tx["inputs"][in_]["sequence"]
    stream += dsha256(outputs)
    stream += tx["locktime"]
    stream += (hash_type & 0xFFFFFFFF).to_bytes(4, "little")
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
            if (hash_type & 0x1F) == 0x03 and index >= n_outputs:
                continue
            raw = sweep_tx(n_inputs, n_outputs, bytes([0x00, 0x14]) + bytes(23), 0)
            tx = sighash_parse_tx(raw.hex())
            digest = legacy_digest(tx, script_code, index, hash_type)
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


def main() -> None:
    written = {
        "vectors_hash.h": hash_vectors(),
        "vectors_hmac.h": hmac_vectors(),
        "vectors_hkdf.h": hkdf_vectors(),
        "vectors_bip39.h": bip39_vectors(),
        "vectors_slip39.h": slip39_vectors(),
        "vectors_base58.h": base58_vectors(),
        "vectors_bech32.h": bech32_vectors(),
        "vectors_compactsize.h": compactsize_vectors(),
        "vectors_address.h": address_vectors(),
        "vectors_psbt.h": psbt_vectors(),
        "vectors_bytewords.h": bytewords_vectors(),
        "vectors_qrcode.h": qrcode_vectors(),
        "vectors_tx.h": tx_vectors(),
        "vectors_psbt_ctx.h": ctx_vectors(),
        "vectors_sighash.h": sighash_vectors(),
    }
    for name, content in written.items():
        (HERE / name).write_text(content)
        print(f"wrote {name} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
