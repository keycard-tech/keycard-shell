"""Keccak-256, RLP, ECDSA and the recovery id, in pure Python.

generate.py uses this to build the ethereum scenarios in vectors_core_eth.h, so that a row's signing
hash comes from something other than the parser under test. The module checks itself against the
values the specifications publish -- see self_check() -- because a second implementation that is
merely different from the first proves nothing.

The nonce here is deterministic and the card's is not: a Keycard picks k at random, so the r and s in
these vectors are not bytes a device ever produced. Nothing depends on which valid pair is used -- the
shell verifies the signature against the key the reply carries, so any k passes the same rows -- but a
header that changed every time it was regenerated could not be reviewed. RFC 6979 is the way to be
deterministic that also reproduces the r and s EIP-155 publishes for its example, which is how this
module's Keccak, RLP and curve arithmetic get checked against a document rather than against
themselves.
"""
import hashlib
import hmac

MASK = (1 << 64) - 1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# rotation offsets, indexed [x][y]
_R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
      [27, 20, 39, 8, 14]]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK if n else x


def _permute(state: list[int]) -> None:
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]

        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _R[x][y])

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & MASK)
                                                   & b[((x + 2) % 5) + 5 * y])
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """The Keccak the blockchain uses -- padding 0x01 .. 0x80 -- not the SHA-3 FIPS padding."""
    rate = 136
    padded = bytearray(data) + b"\x01"
    while len(padded) % rate != 0:
        padded += b"\x00"
    padded[-1] |= 0x80

    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _permute(state)

    out = bytearray()
    for i in range(4):
        out += state[i].to_bytes(8, "little")
    return bytes(out)


def rlp(item) -> bytes:
    """One item: an int in minimal big-endian, bytes, or a list -- which is where an access list lands.
    An int of 0 and empty bytes are the same string, as RLP has no zero."""
    if isinstance(item, (list, tuple)):
        return rlp_list(item)
    if isinstance(item, int):
        item = b"" if item == 0 else item.to_bytes((item.bit_length() + 7) // 8, "big")
    if len(item) == 1 and item[0] < 0x80:
        return item
    if len(item) < 56:
        return bytes([0x80 + len(item)]) + item
    ln = len(item).to_bytes((len(item).bit_length() + 7) // 8, "big")
    return bytes([0xb7 + len(ln)]) + ln + item


def rlp_list(items) -> bytes:
    body = b"".join(rlp(i) for i in items)
    if len(body) < 56:
        return bytes([0xc0 + len(body)]) + body
    ln = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0xf7 + len(ln)]) + ln + body


def tlv(tag: int, value: bytes) -> bytes:
    """One BER tag and length, the form the applet builds its reply templates from: short form below
    128 bytes, otherwise the one-octet long form a card actually sends for a 65 byte key."""
    if len(value) < 128:
        return bytes([tag, len(value)]) + value
    assert len(value) < 256
    return bytes([tag, 0x81, len(value)]) + value


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        m = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (m * m - p[0] - q[0]) % P
    return (x, (m * (p[0] - x) - p[1]) % P)


def _mul(p, k: int):
    acc, q = None, p
    while k:
        if k & 1:
            acc = _add(acc, q)
        q = _add(q, q)
        k >>= 1
    return acc


def public_key(priv: int):
    return _mul(G, priv)


def compress(pub) -> bytes:
    return (b"\x02" if pub[1] % 2 == 0 else b"\x03") + pub[0].to_bytes(32, "big")


def uncompressed(pub) -> bytes:
    return b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")


def _der_int(v: int) -> bytes:
    b = v.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b


def der_signature(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return bytes([0x30, len(body)]) + body


def _nonce(priv: int, digest: bytes) -> int:
    """RFC 6979 with HMAC-SHA-256: a fixed k per (key, digest), chosen so that self_check() can
    reproduce the signature EIP-155 prints. Not how a card picks one."""
    x, h1 = priv.to_bytes(32, "big"), digest
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand


def sign(priv: int, digest: bytes) -> tuple[int, int, int]:
    """(r, s, recovery id), with s in the lower half as Ethereum requires -- negating s flips the id."""
    z = int.from_bytes(digest, "big")
    k = _nonce(priv, digest)
    r_point = _mul(G, k)
    r = r_point[0] % N
    s = pow(k, -1, N) * (z + r * priv) % N
    assert r and s, "a degenerate nonce; nothing here should ever produce one"

    rec = r_point[1] & 1
    if s > N // 2:
        s, rec = N - s, rec ^ 1
    return r, s, rec


def message_digest(msg: bytes) -> bytes:
    """The 0x45 form of ERC-191, which is what personal_sign and the shell prepend: the prefix, the
    length of the message in decimal, then the message. No document publishes the result for a given
    message, so generate.py asserts the prefix against the text instead."""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)


def self_check() -> None:
    """The values the specifications print, so a rotted helper fails here and not in a device."""
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == \
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

    # EIP-155's worked example, quoted from EIPS/EIPS/eip-155.md.
    unsigned = rlp_list([9, 20 * 10**9, 21000,
                         bytes.fromhex("3535353535353535353535353535353535353535"),
                         10**18, b"", 1, 0, 0])
    assert unsigned.hex() == ("ec098504a817c8008252089435353535353535353535353535353535"
                             "35353535880de0b6b3a764000080018080"), unsigned.hex()
    digest = keccak256(unsigned)
    assert digest.hex() == "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"

    r, s, rec = sign(int("46" * 32, 16), digest)
    assert r == 18515461264373351373200002665853028612451056578545711640558177340181847433846
    assert s == 46948507304638947509940763649030358759909902576025900602547168820602576006531
    assert rec == 0 and 1 * 2 + 35 + rec == 37, "EIP-155 says v = 37 for this example"


if __name__ == "__main__":
    self_check()
    print("eth_txn self-check ok")
