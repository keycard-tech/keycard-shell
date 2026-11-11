cmake_minimum_required(VERSION 3.20)

# Native test build. It is a separate CMake project on purpose: the firmware build is a
# cross compile with a linker script and -mcpu=cortex-m33, and nothing here must be able to
# reach it. The modules under test are compiled from their real sources in app/; only the
# platform seam (host/host_stm32.h, host/hal_host.c) differs.
#
#   cmake --preset host-tests && cmake --build --preset host-tests && ctest --output-on-failure

project(shellos_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

option(HOST_TESTS_SANITIZERS "Build the native tests with ASan and UBSan" ON)
option(HOST_TESTS_COVERAGE "Instrument the native tests for gcov" OFF)

set(SHELLOS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_compile_definitions(
    HOST_TEST
    # No SHA/CRC hardware off-target. These are the switches the application already carries
    # for its software fallbacks, so the host build picks the portable implementation.
    SOFT_SHA256
    SOFT_CRC32
    # Matches the firmware build so code keyed on the smartcard clock sees the real value.
    SMARTCARD_CLOCK=200000000
)

# -Wextra on the application sources is a build configuration the firmware does not use (it
# builds with -Wall only), so the noise it produces here is silenced rather than chased -- except
# -Wenum-conversion, the one class that turns a peripheral's two-value answer into a reason by
# accident: HAL_FAIL read back as ERR_TXRX, or an app error returned in a hal_err_t. Nothing in
# the tree trips it now, and the firmware build will never check it, so this is where it is refused.
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Werror=enum-conversion -g)

# Nothing in the application converts a pointer through a 32-bit integer: fs.c and updater.c go through
# uintptr_t, and the only place that reads a device address back out of a pointer is the flash model,
# which maps its own array at HAL_FLASH_ADDR to make that true. So the test binaries are position
# independent like any other host program, which is the state worth defending -- a truncation put back
# into code under test lands above 4 GB here and breaks, instead of working because the image happens to
# be loaded low.

if(HOST_TESTS_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                      -fsanitize-address-use-after-scope -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

if(HOST_TESTS_COVERAGE)
  add_compile_options(--coverage -O0)
  add_link_options(--coverage)
endif()

add_library(unity STATIC unity/unity.c)
target_include_directories(unity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/unity)

add_library(test_framework STATIC
    framework/test_util.c
    host/hal_aes_host.c
    host/hal_derive_host.c
    host/hal_flash_host.c
    host/hal_host.c
    host/hal_pka_host.c
    host/host_data.c
    host/keys_host.c
    host/sc_host.c
    host/usb_host.c
)
target_include_directories(test_framework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/host
    ${CMAKE_CURRENT_SOURCE_DIR}/host/freertos
    ${SHELLOS_ROOT}/app
    ${SHELLOS_ROOT}/zcbor
)
target_link_libraries(test_framework PUBLIC unity)

# The firmware forces app/variant.h onto every translation unit so that a TU which forgot to
# include it cannot silently compile the other variant. The host build mirrors that.
set(SHELLOS_COMMON_FLAGS -include ${SHELLOS_ROOT}/app/variant.h)

# The TLV reader crypto/ecdsa.c walks a DER signature with.
add_library(app_util STATIC
    ${SHELLOS_ROOT}/app/util/tlv.c
)
target_include_directories(app_util PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_util PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_crypto STATIC
    ${SHELLOS_ROOT}/app/crypto/address.c
    ${SHELLOS_ROOT}/app/crypto/addr_uri.c
    ${SHELLOS_ROOT}/app/crypto/base32.c
    ${SHELLOS_ROOT}/app/crypto/base58.c
    ${SHELLOS_ROOT}/app/crypto/bignum.c
    ${SHELLOS_ROOT}/app/crypto/script.c
    ${SHELLOS_ROOT}/app/crypto/bip39.c
    ${SHELLOS_ROOT}/app/crypto/bip39_english.c
    ${SHELLOS_ROOT}/app/crypto/crc32.c
    ${SHELLOS_ROOT}/app/crypto/ecdsa.c
    ${SHELLOS_ROOT}/app/crypto/rfc6979.c
    ${SHELLOS_ROOT}/app/crypto/hkdf.c
    ${SHELLOS_ROOT}/app/crypto/hmac.c
    ${SHELLOS_ROOT}/app/crypto/memzero.c
    ${SHELLOS_ROOT}/app/crypto/pbkdf2.c
    ${SHELLOS_ROOT}/app/crypto/rand.c
    ${SHELLOS_ROOT}/app/crypto/ripemd160.c
    ${SHELLOS_ROOT}/app/crypto/secp256k1.c
    # multisig.c derives a child key from each cosigner's xpub, so the public half of BIP-32 has to
    # be in the link. Its one foreign call is hal_ec_double_ladder, which the host seam aborts.
    ${SHELLOS_ROOT}/app/crypto/bip32.c
    ${SHELLOS_ROOT}/app/crypto/segwit_addr.c
    ${SHELLOS_ROOT}/app/crypto/shamir.c
    ${SHELLOS_ROOT}/app/crypto/sha2.c
    ${SHELLOS_ROOT}/app/crypto/sha3.c
    ${SHELLOS_ROOT}/app/crypto/slip39.c
    ${SHELLOS_ROOT}/app/crypto/slip39_english.c
    ${SHELLOS_ROOT}/app/crypto/util.c
    ${SHELLOS_ROOT}/app/crypto/xoshiro256.c
)
target_include_directories(app_crypto PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_crypto PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_crypto PUBLIC app_util)

add_library(app_bitcoin STATIC
    ${SHELLOS_ROOT}/app/bitcoin/compactsize.c
    # A setup file arrives from a camera and the descriptor then lives in the store, so its parser
    # and its storage form are host tests. The address side is here too now that the PKA has a
    # stand-in (host/hal_pka_host.c): taproot's output key is one point operation.
    ${SHELLOS_ROOT}/app/bitcoin/multisig.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt_tx.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt_ctx.c
    ${SHELLOS_ROOT}/app/bitcoin/sighash.c
    ${SHELLOS_ROOT}/app/bitcoin/taproot.c
    ${SHELLOS_ROOT}/app/bitcoin/tx.c
)
target_include_directories(app_bitcoin PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_bitcoin PRIVATE ${SHELLOS_COMMON_FLAGS})

# The Ethereum transaction parser is what turns the bytes arriving over USB or from the camera
# into the amount and destination the user approves, so it is compiled here unmodified.
add_library(app_ethereum STATIC
    ${SHELLOS_ROOT}/app/ethereum/ethUtils.c
    ${SHELLOS_ROOT}/app/ethereum/ethUstream.c
    # Typed data arrives as JSON and what it hashes to is what the card signs, so the module is
    # compiled here unmodified, jsmn and all.
    ${SHELLOS_ROOT}/app/ethereum/eip712.c
    ${SHELLOS_ROOT}/app/json/jsmn.c
    # The token database reader, which is the store's heaviest consumer: one blob of ~1650 entries
    # installed by a single fs_write().
    ${SHELLOS_ROOT}/app/ethereum/eth_db.c
)
target_include_directories(app_ethereum PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_ethereum PRIVATE ${SHELLOS_COMMON_FLAGS})

# The secure element's answer parsers. The bytes they are fed are the applet's own, which is the
# only way to know where "what a genuine card sends" ends and "what a hostile one can send" starts.
add_library(app_keycard STATIC
    ${SHELLOS_ROOT}/app/keycard/application_info.c
    ${SHELLOS_ROOT}/app/keycard/signature.c
    ${SHELLOS_ROOT}/app/keycard/scv2_whitelist.c
    # Activation is the card's state machine -- SELECT, pairing, channel, PIN -- and it needs no
    # hardware: every platform call is a smartcard one, plus the ui calls scripted in
    # host/ui_keycard_host.c. Its ui.h chain reaches the CBOR codec, hence zcbor here.
    ${SHELLOS_ROOT}/app/keycard/keycard.c
)
target_include_directories(app_keycard PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_keycard PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_keycard PUBLIC app_util)

# The commands the applet is spoken to, and the channel they are handed to. keycard_cmdset.c is the
# APDU builders and the status-word mapping; secure_channel*.c is what decides whether a command goes
# out at all, so the three are one link unit. keycard.c is not in it: it needs the ui, and the two
# statements of keycard_init are made by the test's own setUp.
add_library(app_keycard_cmdset STATIC
    ${SHELLOS_ROOT}/app/keycard/keycard_cmdset.c
    ${SHELLOS_ROOT}/app/keycard/secure_channel.c
    ${SHELLOS_ROOT}/app/keycard/secure_channel_v1.c
    ${SHELLOS_ROOT}/app/keycard/secure_channel_v2.c
)
target_include_directories(app_keycard_cmdset PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_keycard_cmdset PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_keycard_cmdset PUBLIC app_util app_aes)

# What a SIGN reply becomes once it is a PSBT input record: BIP-174's key and value, assembled from
# the reply that test_keycard_signature pins. Kept apart from core_btc.c, which cannot be linked
# here, so that a record built wrong is a failing test and not a device symptom.
add_library(app_btc_sig STATIC
    ${SHELLOS_ROOT}/app/core/core_btc_sig.c
)
target_include_directories(app_btc_sig PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_btc_sig PRIVATE ${SHELLOS_COMMON_FLAGS})

# zcbor is vendored in tree and part of the firmware build, so the CBOR codec is compiled once, the
# same way here. ZCBOR_CANONICAL is what the firmware passes and what the generated encoders in
# ur_encode.c are written against.
add_library(zcbor STATIC
    ${SHELLOS_ROOT}/zcbor/zcbor_common.c
    ${SHELLOS_ROOT}/zcbor/zcbor_decode.c
    ${SHELLOS_ROOT}/zcbor/zcbor_encode.c
)
target_include_directories(zcbor PUBLIC ${SHELLOS_ROOT}/zcbor)
target_compile_definitions(zcbor PUBLIC ZCBOR_CANONICAL)
target_compile_options(zcbor PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_ur STATIC
    ${SHELLOS_ROOT}/app/ur/bytewords.c
    ${SHELLOS_ROOT}/app/ur/sampler.c
    ${SHELLOS_ROOT}/app/ur/ur.c
    ${SHELLOS_ROOT}/app/ur/ur_decode.c
    ${SHELLOS_ROOT}/app/ur/ur_encode.c
)
target_include_directories(app_ur PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host
)
target_compile_options(app_ur PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_ur PUBLIC app_crypto zcbor)

# ISO 7816. smartcard.c belongs here rather than being stubbed out: its *_sync wrappers decide between
# ERR_OK, ERR_TXRX and ERR_HW from the peripheral notification, and sc_host.c scripts that notification
# instead of faking the layer. tests/host/freertos stands in for the kernel headers for this library.
add_library(app_iso7816 STATIC
    ${SHELLOS_ROOT}/app/iso7816/atr.c
    ${SHELLOS_ROOT}/app/iso7816/pps.c
    ${SHELLOS_ROOT}/app/iso7816/t1.c
    ${SHELLOS_ROOT}/app/iso7816/smartcard.c
)
target_include_directories(app_iso7816 PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host
    ${CMAKE_CURRENT_SOURCE_DIR}/host/freertos)
target_compile_options(app_iso7816 PRIVATE ${SHELLOS_COMMON_FLAGS})

# The store. fs.c is the log every persisted thing in the device sits on -- settings, pairing, the
# multisig entries, the token database -- and its six entry points are the whole API, so it is
# compiled here against the flash model in host/hal_flash_host.c. g_flash_swap, the block buffer it
# stages a rewrite in, comes from host_data.c.
# AES. Not in app_crypto: the firmware's branches of these two files are the point, and their only
# dependencies are memzero and the seam in host/hal_aes_host.c.
add_library(app_aes STATIC
    ${SHELLOS_ROOT}/app/crypto/aes.c
    ${SHELLOS_ROOT}/app/crypto/aes_ccm.c
    ${SHELLOS_ROOT}/app/crypto/memzero.c
)
target_include_directories(app_aes PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_aes PRIVATE ${SHELLOS_COMMON_FLAGS})

# The key store: embedded trust anchors, plus the two private halves that come out of the device secret.
add_library(app_keys STATIC
    ${SHELLOS_ROOT}/app/storage/keys.c
)
target_include_directories(app_keys PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_keys PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_pairing STATIC
    ${SHELLOS_ROOT}/app/keycard/pairing.c
)
target_include_directories(app_pairing PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_pairing PRIVATE ${SHELLOS_COMMON_FLAGS})

# The encrypted multisig descriptors: key derivation and blob index, then the store over flash.
add_library(app_multisig STATIC
    ${SHELLOS_ROOT}/app/bitcoin/multisig_crypto.c
    ${SHELLOS_ROOT}/app/storage/multisig_store.c
)
target_include_directories(app_multisig PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_multisig PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_storage STATIC
    ${SHELLOS_ROOT}/app/storage/fs.c
)
target_include_directories(app_storage PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
# fs.c converts between flash addresses and pointers through uintptr_t, so nothing narrows here even
# though an address is 32 bits on the target, and no warning needs silencing. What still depends on
# the word size is the flash model itself: it maps its array at the device's base address so that the
# address it reads back out of a pointer is the one it wrote.
target_compile_options(app_storage PRIVATE ${SHELLOS_COMMON_FLAGS})

# Settings: the store half is the point of the test, and the four menus it hangs off are scripted in
# host/ui_host.c and host/ui_keycard_host.c. i18n.c and english.c compile as they are, so the string table is the device's own --
# menu.c is the one that cannot, needing FreeRTOS for data the seam only takes the address of.
add_library(app_settings STATIC
    ${SHELLOS_ROOT}/app/core/settings.c
    ${SHELLOS_ROOT}/app/ui/i18n.c
    ${SHELLOS_ROOT}/app/ui/english.c
)
target_include_directories(app_settings PUBLIC ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_settings PRIVATE ${SHELLOS_COMMON_FLAGS})

# The dispatcher. A USB command arrives as an APDU header and a length and leaves as segments, and
# everything between is routing: which handler an instruction selects, what a refusal costs, how a reply
# longer than the wire is paged. That is worth compiling rather than stubbing, and command.c is what
# makes the framing concrete -- the two only mean anything together. core_btc.c and core_eth.c come along
# because the table names them, and updater.c because an upgrade is a command like any other.
add_library(app_core STATIC
    ${SHELLOS_ROOT}/app/core/core.c
    ${SHELLOS_ROOT}/app/core/core_btc.c
    ${SHELLOS_ROOT}/app/core/core_eth.c
    ${SHELLOS_ROOT}/app/core/updater.c
    ${SHELLOS_ROOT}/app/keycard/command.c
    ${SHELLOS_ROOT}/app/usb/usb.c
)
target_include_directories(app_core PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host
    ${CMAKE_CURRENT_SOURCE_DIR}/host/freertos)
target_compile_options(app_core PRIVATE ${SHELLOS_COMMON_FLAGS})
# core_eth.c tests a transaction type against MIN_TX_TYPE, which is 0, so -Wextra calls the half of the
# comparison always true -- true on the device too, where the flag is not used. Nothing here narrows a
# pointer any more: fs.c and updater.c convert through uintptr_t, so that warning is not silenced and
# has nothing to say.
target_compile_options(app_core PRIVATE -Wno-type-limits)
target_link_libraries(app_core PUBLIC app_btc_sig)

add_library(ui_seam STATIC
    host/ui_host.c
    # The notices and prompts keycard.c shows while it activates a card, recorded by name and answered
    # from a script. One library with the menus above, because host_ui_reset() resets both.
    host/ui_keycard_host.c
    # The screens and confirmations a USB command shows, same convention and same reset.
    host/ui_display_host.c
)
target_include_directories(ui_seam PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(ui_seam PRIVATE ${SHELLOS_COMMON_FLAGS})

# The OpenPGP card mode's packet and request parsers, which are every byte of this device that
# reads an OpenPGP stream. They need no hardware and no UI: the one function that touches the
# curve, openpgp_v4_verify_uid_self_cert, calls ecdsa_verify_raw_pub, which is real code here and
# aborts only when it reaches the public-key accelerator, so its refusals are testable and its
# verdict is not.
add_library(app_openpgp STATIC
    ${SHELLOS_ROOT}/app/openpgp/openpgp_packet.c
    ${SHELLOS_ROOT}/app/openpgp/openpgp_protocol.c
    ${SHELLOS_ROOT}/app/openpgp/openpgp_v4.c
)
target_include_directories(app_openpgp PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host
)
target_compile_options(app_openpgp PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_openpgp PUBLIC app_crypto zcbor)

# shellos_test(<name> LIBS <targets...>) builds tests/test_<name>.c and registers it with ctest.
# The vendored quirc (OpenMV fork) and our own encoder. The image is supplied by the caller, so
# nothing here reaches hardware; fmath.c is what qrcode.c's perspective maths calls.
add_library(app_qrcode STATIC
    ${SHELLOS_ROOT}/app/qrcode/qrcode.c
    ${SHELLOS_ROOT}/app/qrcode/qrcodegen.c
    ${SHELLOS_ROOT}/app/util/fmath.c
)
target_include_directories(app_qrcode PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/app/qrcode ${CMAKE_CURRENT_SOURCE_DIR}/host
)
target_compile_options(app_qrcode PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_qrcode PUBLIC m)

function(shellos_test name)
  cmake_parse_arguments(TEST "" "SRC" "LIBS" ${ARGN})
  if(NOT TEST_SRC)
    set(TEST_SRC test_${name}.c)
  endif()
  add_executable(test_${name} ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_SRC})
  target_compile_options(test_${name} PRIVATE ${SHELLOS_COMMON_FLAGS})
  # test_framework supplies the hal and data symbols the application objects reference, so it
  # has to come after them on the link line. The two also need each other in the other
  # direction -- hal_pka_host.c computes with bignum.c out of app_crypto, and app_crypto's curve
  # code calls back into it -- which a single left-to-right scan of static archives cannot
  # resolve, hence the group.
  target_link_libraries(test_${name} PRIVATE
      -Wl,--start-group ${TEST_LIBS} test_framework -Wl,--end-group)
  add_test(NAME ${name} COMMAND test_${name})
  # The exit code is the verdict, but a test whose main() forgets to return UNITY_END() exits 0
  # whatever it found, so the summary line is checked as well.
  set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "0 Failures 0 Ignored")
  if(HOST_TESTS_SANITIZERS)
    # Leak checking is off: this firmware has no heap to leak, LeakSanitizer needs ptrace
    # permissions containers often deny, and ASan's overflows and UBSan's traps are the point.
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
  endif()
endfunction()

enable_testing()

shellos_test(hash LIBS app_crypto)
shellos_test(hmac LIBS app_crypto)
shellos_test(rand LIBS app_crypto)
shellos_test(pbkdf2 LIBS app_crypto)
# crypto/util.c, named for the module rather than test_util, which is the framework helper.
shellos_test(crypto_util LIBS app_crypto)
shellos_test(hkdf LIBS app_crypto)
shellos_test(bip39 LIBS app_crypto)
shellos_test(slip39 LIBS app_crypto)
shellos_test(base58 LIBS app_crypto)
shellos_test(bech32 LIBS app_crypto)
shellos_test(address LIBS app_crypto)
shellos_test(addr_uri LIBS app_crypto)
shellos_test(script LIBS app_crypto)

# One binary for every parser that takes bytes from outside the device, because the point is to run
# each of them over corpora it was not written for.
shellos_test(fuzz LIBS app_btc_sig app_keycard app_bitcoin app_ethereum app_crypto)
# Deterministic and in milliseconds; the timeout is only so that a parser that ever loops on a
# mutated count fails the suite instead of the CI runner.
set_tests_properties(fuzz PROPERTIES TIMEOUT 120)
shellos_test(bignum LIBS app_crypto)
shellos_test(ethereum LIBS app_ethereum app_crypto)
shellos_test(eip712 LIBS app_ethereum app_crypto)
shellos_test(compactsize LIBS app_bitcoin)
shellos_test(psbt LIBS app_bitcoin app_crypto)
shellos_test(tx LIBS app_bitcoin app_crypto)
shellos_test(psbt_ctx LIBS app_bitcoin app_crypto)
shellos_test(psbt_tx LIBS app_bitcoin app_crypto)
shellos_test(sighash LIBS app_bitcoin app_crypto)
shellos_test(bytewords LIBS app_ur app_crypto)
shellos_test(ur LIBS app_ur app_crypto)
shellos_test(openpgp LIBS app_openpgp app_crypto)
shellos_test(multisig LIBS app_bitcoin app_crypto)
shellos_test(qrcode LIBS app_qrcode)
shellos_test(tlv LIBS app_keycard)
shellos_test(ecdsa_der LIBS app_crypto app_keycard)
shellos_test(ecdsa_curve LIBS app_crypto)
shellos_test(keycard_signature LIBS app_crypto app_keycard)
shellos_test(keycard_cmdset LIBS app_keycard_cmdset app_iso7816 app_aes app_crypto app_keys app_pairing app_storage)
shellos_test(secure_channel_v2 LIBS app_keycard_cmdset app_iso7816 app_aes app_crypto app_keys app_pairing app_storage)
shellos_test(secure_channel_v1 LIBS app_keycard_cmdset app_iso7816 app_aes app_crypto app_keys app_pairing app_storage)
shellos_test(keycard_activate LIBS app_keycard app_keycard_cmdset app_settings ui_seam app_iso7816 app_aes app_crypto app_keys app_pairing app_storage)
shellos_test(updater LIBS app_core app_keycard app_keycard_cmdset app_settings ui_seam app_iso7816 app_aes app_crypto app_util app_keys app_pairing app_storage app_multisig app_bitcoin app_ethereum app_ur zcbor)
shellos_test(core_export LIBS app_core app_keycard app_keycard_cmdset app_settings ui_seam app_iso7816 app_aes app_crypto app_util app_keys app_pairing app_storage app_multisig app_bitcoin app_ethereum app_ur zcbor)
shellos_test(core_usb LIBS app_core app_keycard app_keycard_cmdset app_settings ui_seam app_iso7816 app_aes app_crypto app_util app_keys app_pairing app_storage app_multisig app_bitcoin app_ethereum app_ur zcbor)
shellos_test(btc_sig LIBS app_btc_sig app_keycard)

shellos_test(shamir LIBS app_crypto)
shellos_test(storage_fs LIBS app_storage)
shellos_test(eth_db LIBS app_ethereum app_storage)
shellos_test(scv2_whitelist LIBS app_keycard app_storage)
shellos_test(settings LIBS app_settings ui_seam app_storage)
shellos_test(aes LIBS app_aes)
shellos_test(hal_aes)
shellos_test(keys LIBS app_keys app_crypto)
shellos_test(pairing LIBS app_pairing app_keys app_aes app_storage app_crypto)
shellos_test(multisig_crypto LIBS app_multisig app_aes app_crypto)
shellos_test(multisig_store LIBS app_multisig app_aes app_storage app_crypto)
shellos_test(hal_pka LIBS app_crypto)
shellos_test(bip32 LIBS app_crypto)
shellos_test(taproot LIBS app_bitcoin app_crypto)

shellos_test(smartcard LIBS app_iso7816)
shellos_test(atr LIBS app_iso7816)
shellos_test(pps LIBS app_iso7816)
shellos_test(t1 LIBS app_iso7816)
