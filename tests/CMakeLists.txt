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
# builds with -Wall only), so the noise it produces here is silenced rather than chased.
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -g)

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
    host/hal_host.c
    host/host_data.c
)
target_include_directories(test_framework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/host
    ${SHELLOS_ROOT}/app
)
target_link_libraries(test_framework PUBLIC unity)

# The firmware forces app/variant.h onto every translation unit so that a TU which forgot to
# include it cannot silently compile the other variant. The host build mirrors that.
set(SHELLOS_COMMON_FLAGS -include ${SHELLOS_ROOT}/app/variant.h)

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

add_library(app_bitcoin STATIC
    ${SHELLOS_ROOT}/app/bitcoin/compactsize.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt_tx.c
    ${SHELLOS_ROOT}/app/bitcoin/psbt_ctx.c
    ${SHELLOS_ROOT}/app/bitcoin/sighash.c
    ${SHELLOS_ROOT}/app/bitcoin/tx.c
)
target_include_directories(app_bitcoin PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_bitcoin PRIVATE ${SHELLOS_COMMON_FLAGS})

# zcbor is vendored in tree and part of the firmware build, so the UR framing is compiled the
# same way here. ZCBOR_CANONICAL is what the firmware passes and what the generated encoders in
# ur_encode.c are written against.
# The Ethereum transaction parser is what turns the bytes arriving over USB or from the camera
# into the amount and destination the user approves, so it is compiled here unmodified.
add_library(app_ethereum STATIC
    ${SHELLOS_ROOT}/app/ethereum/ethUtils.c
    ${SHELLOS_ROOT}/app/ethereum/ethUstream.c
)
target_include_directories(app_ethereum PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_ethereum PRIVATE ${SHELLOS_COMMON_FLAGS})

# The secure element's answer parsers. The bytes they are fed are the applet's own, which is the
# only way to know where "what a genuine card sends" ends and "what a hostile one can send" starts.
add_library(app_keycard STATIC
    ${SHELLOS_ROOT}/app/util/tlv.c
    ${SHELLOS_ROOT}/app/keycard/application_info.c
    ${SHELLOS_ROOT}/app/keycard/signature.c
)
target_include_directories(app_keycard PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_keycard PRIVATE ${SHELLOS_COMMON_FLAGS})

# What a SIGN reply becomes once it is a PSBT input record: BIP-174's key and value, assembled from
# the reply that test_keycard_signature pins. Kept apart from core_btc.c, which cannot be linked
# here, so that a record built wrong is a failing test and not a device symptom.
add_library(app_btc_sig STATIC
    ${SHELLOS_ROOT}/app/core/core_btc_sig.c
)
target_include_directories(app_btc_sig PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_btc_sig PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_ur STATIC
    ${SHELLOS_ROOT}/app/ur/bytewords.c
    ${SHELLOS_ROOT}/app/ur/sampler.c
    ${SHELLOS_ROOT}/app/ur/ur.c
    ${SHELLOS_ROOT}/app/ur/ur_decode.c
    ${SHELLOS_ROOT}/app/ur/ur_encode.c
    ${SHELLOS_ROOT}/zcbor/zcbor_common.c
    ${SHELLOS_ROOT}/zcbor/zcbor_decode.c
    ${SHELLOS_ROOT}/zcbor/zcbor_encode.c
)
target_include_directories(app_ur PUBLIC
    ${SHELLOS_ROOT}/app ${SHELLOS_ROOT}/zcbor ${CMAKE_CURRENT_SOURCE_DIR}/host
)
target_compile_definitions(app_ur PUBLIC ZCBOR_CANONICAL)
target_compile_options(app_ur PRIVATE ${SHELLOS_COMMON_FLAGS})
target_link_libraries(app_ur PUBLIC app_crypto)

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
  # has to come after them on the link line.
  target_link_libraries(test_${name} PRIVATE ${TEST_LIBS} test_framework)
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
shellos_test(hkdf LIBS app_crypto)
shellos_test(bip39 LIBS app_crypto)
shellos_test(slip39 LIBS app_crypto)
shellos_test(base58 LIBS app_crypto)
shellos_test(bech32 LIBS app_crypto)
shellos_test(address LIBS app_crypto)
shellos_test(addr_uri LIBS app_crypto)
shellos_test(script LIBS app_crypto)
shellos_test(bignum LIBS app_crypto)
shellos_test(ethereum LIBS app_ethereum app_crypto)
shellos_test(compactsize LIBS app_bitcoin)
shellos_test(psbt LIBS app_bitcoin app_crypto)
shellos_test(tx LIBS app_bitcoin app_crypto)
shellos_test(psbt_ctx LIBS app_bitcoin app_crypto)
shellos_test(sighash LIBS app_bitcoin app_crypto)
shellos_test(bytewords LIBS app_ur app_crypto)
shellos_test(ur LIBS app_ur app_crypto)
shellos_test(qrcode LIBS app_qrcode)
shellos_test(tlv LIBS app_keycard)
shellos_test(ecdsa_der LIBS app_crypto app_keycard)
shellos_test(keycard_signature LIBS app_crypto app_keycard)
shellos_test(btc_sig LIBS app_btc_sig app_keycard)

shellos_test(shamir LIBS app_crypto)
