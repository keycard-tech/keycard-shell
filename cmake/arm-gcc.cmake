# Toolchain file for the ARM GCC toolchain
# This file resolves the full paths to the compiler tools
#
# The toolchain is expected to be installed in the 'toolchain' directory
# relative to the project root. It can be downloaded using:
#   ./tools/download-toolchain.sh
#

# Target system
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Set the toolchain directory
set(ARM_TOOLCHAIN_VERSION 15.2.rel1)
set(ARM_TOOLCHAIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../toolchain/arm-gnu-toolchain-${ARM_TOOLCHAIN_VERSION}")

# Check if the toolchain exists
if(NOT EXISTS "${ARM_TOOLCHAIN_DIR}")
    message(FATAL_ERROR 
        "ARM GCC Toolchain not found at: ${ARM_TOOLCHAIN_DIR}\n"
        "Please download it using: ./tools/download-toolchain.sh")
endif()

# Find the ARM GCC toolchain executables
set(CMAKE_C_COMPILER "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc")
set(CMAKE_ASM_COMPILER "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc")
set(CMAKE_LINKER "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc")
set(CMAKE_OBJCOPY "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-objcopy")
set(CMAKE_AR "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-ar")
set(CMAKE_OBJDUMP "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-objdump")
set(CMAKE_SIZE_UTIL "${ARM_TOOLCHAIN_DIR}/bin/arm-none-eabi-size")

# Verify the compilers exist
if(NOT EXISTS "${CMAKE_C_COMPILER}")
    message(FATAL_ERROR "C compiler not found: ${CMAKE_C_COMPILER}")
endif()
if(NOT EXISTS "${CMAKE_ASM_COMPILER}")
    message(FATAL_ERROR "ASM compiler not found: ${CMAKE_ASM_COMPILER}")
endif()
if(NOT EXISTS "${CMAKE_LINKER}")
    message(FATAL_ERROR "Linker not found: ${CMAKE_LINKER}")
endif()

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
