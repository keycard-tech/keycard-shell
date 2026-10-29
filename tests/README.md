# Host tests

Native unit tests for the parts of the firmware that do not need silicon. They compile the
real sources from `app/`; the only difference is the platform seam (`host/host_stm32.h` and
`host/hal_host.c` in place of the STM32 HAL).

This directory is a **separate CMake project**. Nothing here participates in the firmware
build, and the firmware build must stay buildable with no `tests/` at all.

## Running

```sh
cd tests
cmake --preset host-tests
cmake --build --preset host-tests
ctest --preset host-tests
```

Presets: `host-tests` (ASan + UBSan), `host-tests-nosan`, `host-tests-coverage` (gcov).
`.github/workflows/host-tests.yml` runs the first two on every push and pull request that
touches `app/` or `tests/`; it is independent of the firmware release workflow.

The sanitizers are on by default. Leak detection is off: the firmware has no heap to leak,
LeakSanitizer needs ptrace permissions that containers often deny, and the checks worth
having here are buffer overflows and undefined behaviour.

## Layout

| Path | Contents |
| --- | --- |
| `CMakeLists.txt` | One static library per app area (`app_crypto`, `app_bitcoin`) plus `shellos_test()` |
| `host/host_stm32.h` | Host platform definition: geometry and typedefs, no register access |
| `host/hal_host.c` | Deterministic `hal_rng_next()`; anything needing silicon is deliberately left undefined |
| `host/host_data.c` | Constants that live in `app/mem.c` on the target (section attributes the host assembler rejects) |
| `framework/` | `TEST_ASSERT_HEX` and hex helpers over Unity |
| `unity/` | Vendored Unity 2.6.1 (MIT, see `unity/LICENSE.txt`) |
| `vectors/` | Generated known-answer vectors and the generator that produces them |
| `test_*.c` | One test binary per module |

Adding a module means adding its `.c` files to a library in `CMakeLists.txt` and a
`shellos_test(...)` line. If the linker then asks for a `hal_*` symbol, that module reaches
hardware: stub it in `host/hal_host.c` only if a test can meaningfully drive it, otherwise
the test belongs on the device.

## Where the expected values come from

Tests compare against values the code did not produce. `vectors/generate.py` writes every
`vectors_*.h` and each header records its source:

* **spec** — fetched from the upstream document or word list (BIP-32/39/173/350, SLIP-39,
  RFC 4231, RFC 5869, Bitcoin Core's `base58.cpp`), pinned by SHA-256 in the header.
* **reference** — computed by an independent implementation (CPython `hashlib`/`hmac`/`zlib`,
  `pycryptodome`, `coincurve`, `eth_utils`).

The generator self-checks what it parses: the RFC 4231 and RFC 5869 cases are recomputed with
CPython `hmac`, the BIP-39 seeds with `hashlib.pbkdf2_hmac`, and each corrupted BIP-39
mnemonic is verified to fail the checksum before it is emitted. A malformed vector therefore
fails the generator, not the test.

```sh
uv run python tests/vectors/generate.py     # needs network; sources cached in vectors/.cache
```

Generated headers are committed, so building the tests needs no network.

## What these tests changed

* `slip39_combine_shards()` validates each shard against the ones before it, through
  `slip39_validate_shard_in_group()`, which existed but was never called. Share sets that
  disagreed on identifier, extendability, iteration exponent, group count, group index, member
  threshold or member index interpolated into a plausible master secret belonging to no one;
  every un-recoverable share set in the SLIP-39 vectors is now rejected. `app/ui/ui.c`
  re-implements the identifier and group-index check at share entry, so the shipped flow covered
  two of the six fields.
* `compactsize_read()` writes `*err` on every outcome, and a rejected read yields **0** instead
  of `-1`. Both callers that check the status happened to initialize it to `PSBT_OK`, and a
  caller that ignores it -- `compactsize_read(p, NULL)` in `core_btc.c` -- got a length of
  0xFFFFFFFFFFFFFFFF out of a failed read.
* `base58_encode_check()` returns the string length, not the length including the terminator
  `b58enc()` reports. No caller read the value, so this is a trap removed rather than a bug
  fixed.
* `btc_generate_txid()` (`core_btc.c`) walks the transaction with bounds and status checks and
  returns whether it could parse, instead of hashing bytes it never verified. The comment there
  claimed the transaction had been parsed already, which is an invariant nothing enforced: a
  failed `compactsize_read` was discarded through a `NULL` error argument, truncated from 64 to
  32 bits, and used as a loop bound and as a `sha256_Update` length. An unparseable prevtx is
  now `ERR_DATA` in `core_btc_validate()`, so the transaction is refused rather than signed over
  a txid computed from garbage.
* `slip39.h` declared `slip39_comebine_groups`. The typo is gone; nothing had ever called it,
  which is why it survived.

## Behaviour this test records

Whether the following is *correct* is open; the test pins what the code does today so changing it
is a decision rather than an accident.

* `compactsize_read()` rejects any decoded length above `MAX_SERIALIZE_SIZE` (0x02000000,
  Bitcoin Core's `MAX_SIZE`), so not every well-formed encoding round-trips. It is 256 times
  `MEM_HEAP_SIZE` and larger than the whole 640 KB of RAM, so it cannot be the bound that
  protects this device: both PSBT parsers already check every read length against
  `data + src_size`. See the discussion in the commit that introduced this section.

## What these tests deliberately do not cover

* **The hardware crypto paths.** The firmware uses the PKA for EC, the HASH peripheral for
  SHA-256 and the AES accelerator. The host build takes the `SOFT_SHA256`/`SOFT_CRC32`
  fallbacks, so those implementations are covered and the peripheral ones are not. A
  differential test between the two (same vectors, host and device) is the next layer.
* **Elliptic curve math at all.** `SOFT_ECDSA` is inert: `ecdsa.h` hides `ecdsa_curve` under
  it, `secp256k1.c` compiles its curve constants out, and `ecdsa_soft.c` is written against
  Trezor's older API including a `hasher.h` that is not vendored — it compiles to zero
  symbols. Anything needing point multiplication (`bip32.c`, `taproot.c`, signing, SCv2 ECDH)
  cannot run here yet.
* **Flash, USB, camera, smartcard, display, FreeRTOS scheduling.** All HAL.
* **`shellos-test.elf`.** The QA app in the top-level `test/` directory is a production
  artifact run by the factory on every unit; it is not a test harness and is not touched here.

