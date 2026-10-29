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
    ${SHELLOS_ROOT}/app/crypto/base32.c
    ${SHELLOS_ROOT}/app/crypto/base58.c
    ${SHELLOS_ROOT}/app/crypto/bip39.c
    ${SHELLOS_ROOT}/app/crypto/bip39_english.c
    ${SHELLOS_ROOT}/app/crypto/crc32.c
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
)
target_include_directories(app_crypto PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_crypto PRIVATE ${SHELLOS_COMMON_FLAGS})

add_library(app_bitcoin STATIC
    ${SHELLOS_ROOT}/app/bitcoin/compactsize.c
)
target_include_directories(app_bitcoin PUBLIC ${SHELLOS_ROOT}/app ${CMAKE_CURRENT_SOURCE_DIR}/host)
target_compile_options(app_bitcoin PRIVATE ${SHELLOS_COMMON_FLAGS})

# shellos_test(<name> LIBS <targets...>) builds tests/test_<name>.c and registers it with ctest.
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
shellos_test(compactsize LIBS app_bitcoin)
