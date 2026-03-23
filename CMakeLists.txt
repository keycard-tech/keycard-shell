cmake_minimum_required(VERSION 3.20)

project(shellos C ASM)

# Set the default build type to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Set language standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS_DEBUG "-O0 -g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_ASM_FLAGS_RELEASE "-O2 -DNDEBUG")

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=cortex-m33")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=fpv5-sp-d16")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=hard")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mthumb")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --specs=nano.specs")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCM33")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DZCBOR_CANONICAL")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSMARTCARD_CLOCK=200000000")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSTM32_HAL")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_HAL_DRIVER")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSTM32H573xx")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffast-math")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-usage")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcyclomatic-complexity")

# Assembly flags
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} -x assembler-with-cpp")

# Include directories
set(INCLUDE_DIRS
    # stm32/Core includes
    ${CMAKE_SOURCE_DIR}/stm32/Core/Inc
    # STM32 HAL Driver includes
    ${CMAKE_SOURCE_DIR}/stm32/Drivers/STM32H5xx_HAL_Driver/Inc
    ${CMAKE_SOURCE_DIR}/stm32/Drivers/STM32H5xx_HAL_Driver/Inc/Legacy
    # CMSIS Device includes
    ${CMAKE_SOURCE_DIR}/stm32/Drivers/CMSIS/Device/ST/STM32H5xx/Include
    # CMSIS stm32/Core includes
    ${CMAKE_SOURCE_DIR}/stm32/Drivers/CMSIS/Include
    # FreeRTOS includes
    ${CMAKE_SOURCE_DIR}/freertos/freertos_kernel/include
    ${CMAKE_SOURCE_DIR}/freertos/freertos_kernel/portable/GCC/ARM_CM33_NTZ/non_secure
    # Application includes
    ${CMAKE_SOURCE_DIR}/app
    # ZCBOR includes
    ${CMAKE_SOURCE_DIR}/zcbor
)

# Add include directories
include_directories(${INCLUDE_DIRS})

# Source files - ZCBOR
set(ZCBOR_SOURCES
    zcbor/zcbor_common.c
    zcbor/zcbor_decode.c
    zcbor/zcbor_encode.c
)

# Source files - Test
set(TEST_SOURCES
    test/core_task.c
    test/ui_task.c
)

# Source files - FreeRTOS
set(FREERTOS_SOURCES
    freertos/freertos_kernel/portable/GCC/ARM_CM33_NTZ/non_secure/port.c
    freertos/freertos_kernel/portable/GCC/ARM_CM33_NTZ/non_secure/portasm.c
    freertos/freertos_kernel/croutine.c
    freertos/freertos_kernel/event_groups.c
    freertos/freertos_kernel/list.c
    freertos/freertos_kernel/queue.c
    freertos/freertos_kernel/stream_buffer.c
    freertos/freertos_kernel/tasks.c
    freertos/freertos_kernel/timers.c
)

# Source files - Bootloader
set(BOOTLOADER_SOURCES
    bootloader/bootloader.c
)

# Source files - App
set(APP_SOURCES
    app/util/fmath.c
    app/util/tlv.c
    app/usb/usb.c
    app/ur/bytewords.c
    app/ur/sampler.c
    app/ur/ur.c
    app/ur/ur_decode.c
    app/ur/ur_encode.c
    app/ui/dialog.c
    app/ui/english.c
    app/ui/i18n.c
    app/ui/icons.c
    app/ui/input.c
    app/ui/menu.c
    app/ui/settings_ui.c
    app/ui/ui.c
    app/tasks/core_task.c
    app/tasks/ui_task.c
    app/tasks/usb_task.c
    app/storage/fs.c
    app/storage/keys.c
    app/screen/screen.c
    app/screen/st7789.c
    app/qrcode/qrcode.c
    app/qrcode/qrcodegen.c
    app/qrcode/qrout.c
    app/qrcode/qrscan.c
    app/keypad/keypad.c
    app/keycard/application_info.c
    app/keycard/command.c
    app/keycard/keycard.c
    app/keycard/keycard_cmdset.c
    app/keycard/pairing.c
    app/keycard/secure_channel.c
    app/json/jsmn.c
    app/iso7816/atr.c
    app/iso7816/pps.c
    app/iso7816/smartcard.c
    app/iso7816/t1.c
    app/font/msg_40px.c
    app/font/navigation_24px.c
    app/font/shell_16px.c
    app/font/shell_18px.c
    app/ethereum/eip712.c
    app/ethereum/ethUstream.c
    app/ethereum/ethUtils.c
    app/ethereum/eth_data.c
    app/ethereum/eth_db.c
    app/crypto/aes/lookup_tables.c
    app/crypto/address.c
    app/crypto/aes.c
    app/crypto/base32.c
    app/crypto/base58.c
    app/crypto/bignum.c
    app/crypto/bip39.c
    app/crypto/bip39_english.c
    app/crypto/cash_addr.c
    app/crypto/crc32.c
    app/crypto/ecdsa.c
    app/crypto/ecdsa_soft.c
    app/crypto/hmac.c
    app/crypto/memzero.c
    app/crypto/nist256p1.c
    app/crypto/pbkdf2.c
    app/crypto/rand.c
    app/crypto/rfc6979.c
    app/crypto/ripemd160.c
    app/crypto/script.c
    app/crypto/secp256k1.c
    app/crypto/segwit_addr.c
    app/crypto/sha2.c
    app/crypto/sha3.c
    app/crypto/shamir.c
    app/crypto/slip39.c
    app/crypto/slip39_english.c
    app/crypto/util.c
    app/crypto/xoshiro256.c
    app/core/auth.c
    app/core/card.c
    app/core/core.c
    app/core/core_btc.c
    app/core/core_eth.c
    app/core/settings.c
    app/core/updater.c
    app/camera/camera.c
    app/bitcoin/compactsize.c
    app/bitcoin/psbt.c
    app/bitcoin/psbt_tx.c
    app/freertos_support.c
    app/main.c
    app/mem.c
    app/pwr.c
)

# Source files - STM32 HAL Driver
set(HAL_SOURCES
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_adc.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_adc_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_cortex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_crc.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_crc_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_dcmi.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_dma.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_dma_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_exti.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_flash.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_flash_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_gpio.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_hash.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_i2c.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_i2c_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_icache.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pcd.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pcd_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pka.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pwr.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_pwr_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rcc.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rcc_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rng.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_rng_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_smartcard.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_smartcard_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_spi.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_spi_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_tim.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_hal_tim_ex.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_ll_rng.c
    stm32/Drivers/STM32H5xx_HAL_Driver/Src/stm32h5xx_ll_usb.c
)

# Source files - stm32/Core
set(CORE_SOURCES
    stm32/Core/Startup/startup_stm32h573vitx.s
    stm32/Core/Src/linked_list.c
    stm32/Core/Src/main.c
    stm32/Core/Src/stm32.c
    stm32/Core/Src/stm32_camera.c
    stm32/Core/Src/stm32_crypto.c
    stm32/Core/Src/stm32_flash.c
    stm32/Core/Src/stm32_smartcard.c
    stm32/Core/Src/stm32_usb.c
    stm32/Core/Src/stm32h5xx_hal_msp.c
    stm32/Core/Src/stm32h5xx_it.c
    stm32/Core/Src/stubs.c
    stm32/Core/Src/system_stm32h5xx.c
)

# Source files - soft AES (unused)
set(AES_SOURCES
    app/crypto/aes/CM7_1T/CM7_1T_AES_128_keyschedule_enc.S
    app/crypto/aes/CM7_1T/CM7_1T_AES_192_keyschedule_enc.S
    app/crypto/aes/CM7_1T/CM7_1T_AES_256_keyschedule_enc.S
    app/crypto/aes/CM7_1T/CM7_1T_AES_decrypt.S
    app/crypto/aes/CM7_1T/CM7_1T_AES_encrypt.S
    app/crypto/aes/CM7_1T/CM7_1T_AES_keyschedule_dec.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_128_keyschedule_enc.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_192_keyschedule_enc.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_256_keyschedule_enc.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_decrypt.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_encrypt.S
    app/crypto/aes/CM3_1T/CM3_1T_AES_keyschedule_dec.S
)

# Linker script
set(LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/stm32/STM32H573VITX_FLASH.ld")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T${LINKER_SCRIPT}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-warn-rwx-segment")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--start-group")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lc -lm")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--end-group")

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Bootloader target
set(BOOTLOADER_C_FLAGS "-DBOOTLOADER")
set(BOOTLOADER_ASM_FLAGS "-DBOOTLOADER")

# Create bootloader executable
add_executable(shellos-bootloader.elf 
    ${BOOTLOADER_SOURCES}
    ${HAL_SOURCES}
    ${CORE_SOURCES}
    app/mem.c
    app/crypto/secp256k1.c
)

# Set bootloader-specific flags
set_target_properties(shellos-bootloader.elf PROPERTIES
    COMPILE_FLAGS "${BOOTLOADER_C_FLAGS}"
    ASM_FLAGS "${BOOTLOADER_ASM_FLAGS}"
)

# Custom command to convert bootloader ELF to binary (always runs after build)
add_custom_command(TARGET shellos-bootloader.elf POST_BUILD
    COMMAND uv run python ${CMAKE_SOURCE_DIR}/tools/bootloader-perso.py
        -p ${CMAKE_SOURCE_DIR}/deployment/bootloader-pubkey.txt
        -e shellos-bootloader.elf
        -o shellos-bootloader.bin
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Converting bootloader with bootloader-perso.py"
)

# Bootloader target
set(TESTAPP_C_FLAGS "-DTEST_APP")
set(TESTAPP_ASM_FLAGS "-DTEST_APP")

# Create testapp executable
add_executable(shellos-test.elf 
    ${ZCBOR_SOURCES}
    ${TEST_SOURCES}
    ${FREERTOS_SOURCES}
    ${APP_SOURCES}
    ${HAL_SOURCES}
    ${CORE_SOURCES}
)

# Set bootloader-specific flags
set_target_properties(shellos-test.elf PROPERTIES
    COMPILE_FLAGS "${TESTAPP_C_FLAGS}"
    ASM_FLAGS "${TESTAPP_ASM_FLAGS}"
)

# Custom command for testapp signing
add_custom_command(TARGET shellos-test.elf POST_BUILD
    COMMAND uv run python ${CMAKE_SOURCE_DIR}/tools/firmware-sign.py 
        -s ${CMAKE_SOURCE_DIR}/deployment/fw-test-key.txt 
        -e shellos-test.elf 
        -o shellos-test.bin
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Signing testapp with firmware-sign.py"
)

# Create main executable
add_executable(shellos.elf
    ${ZCBOR_SOURCES}
    ${TEST_SOURCES}
    ${FREERTOS_SOURCES}
    ${APP_SOURCES}
    ${HAL_SOURCES}
    ${CORE_SOURCES}
)

# Custom command for firmware signing
add_custom_command(TARGET shellos.elf POST_BUILD
    COMMAND uv run python ${CMAKE_SOURCE_DIR}/tools/firmware-sign.py 
        -s ${CMAKE_SOURCE_DIR}/deployment/fw-test-key.txt 
        -e shellos.elf 
        -o shellos.bin
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Signing firmware with firmware-sign.py"
)

# Print configuration summary
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "ASM Compiler: ${CMAKE_ASM_COMPILER}")
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "Linker script: ${LINKER_SCRIPT}")