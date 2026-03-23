# Toolchain file for STM32 ARM GCC toolchain
# This file resolves the full paths to the compiler tools

# Target system
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Find the ARM GCC toolchain executables
# These will be resolved from PATH
find_program(CMAKE_C_COMPILER arm-none-eabi-gcc)
find_program(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
find_program(CMAKE_LINKER arm-none-eabi-gcc)
find_program(CMAKE_OBJCOPY arm-none-eabi-objcopy)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
