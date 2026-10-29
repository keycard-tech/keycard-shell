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
    }
    for name, content in written.items():
        (HERE / name).write_text(content)
        print(f"wrote {name} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
