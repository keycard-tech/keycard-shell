# Keycard Shell - Firmware Development Guide

## Project Overview

This is a firmware project for the STM32H573VITX microcontroller, designed as a secure keycard shell for cryptocurrency operations. The firmware implements QR code scanning, smartcard communication (ISO 7816), USB HID interface, and cryptographic operations.

## Hardware Platform

- **MCU**: STM32H573VITX (ARM Cortex-M33)
- **Memory**: 2MB Flash (2 banks of 1MB each), 640KB RAM
- **Peripherals**:
  - DCMI (Camera interface)
  - SMARTCARD (ISO 7816 smartcard)
  - USB FS (HID device)
  - SPI (LCD display)
  - I2C (Camera control)
  - PKA (Public Key Accelerator)
  - RNG (Random Number Generator)
  - HASH (SHA2/SHA3 hardware)

## Project Structure

```
keycard-shell/
├── app/                    # Application code
│   ├── core/              # Core business logic (keycard operations, signing)
│   ├── crypto/            # Cryptographic primitives (ECC, hashing, encoding)
│   ├── ethereum/          # Ethereum-specific operations
│   ├── iso7816/           # Smartcard protocol implementation
│   ├── qrcode/            # QR code generation and scanning
│   ├── screen/            # LCD display driver and rendering
│   ├── tasks/             # FreeRTOS task implementations
│   ├── ui/                # User interface components
│   ├── usb/               # USB HID implementation
│   ├── camera/            # Camera driver
│   ├── mem.c              # Memory area definitions
│   ├── mem.h              # Memory area declarations
│   ├── hal.h              # Hardware Abstraction Layer
│   ├── common.h           # Common macros and types
│   └── main.c             # Application entry point
├── bootloader/            # Bootloader code
├── stm32/                 # STM32 HAL and startup code
│   ├── Core/
│   │   ├── Inc/           # Header files
│   │   └── Src/           # Source files
│   └── Drivers/           # STM32 HAL drivers
├── freertos/              # FreeRTOS kernel
└── tools/                 # Build and utility scripts
```

## Memory Management

### No Dynamic Heap

**CRITICAL**: This firmware does **NOT** use dynamic heap allocation. The following functions are **FORBIDDEN**:
- `malloc()`
- `calloc()`
- `realloc()`
- `free()`

FreeRTOS is configured with `configSUPPORT_DYNAMIC_ALLOCATION = 0`, meaning the standard heap allocation functions are disabled.

### Static Memory Allocation

All memory must be allocated statically at compile time. The project uses several approaches:

1. **Global variables** for persistent data
2. **Stack allocation** for local variables (careful with stack depth)
3. **Custom memory pools** for temporary allocations

### Memory Areas

The file [`app/mem.h`](app/mem.h) defines the following memory areas:

- Main heap for dynamic-style allocation (static pool)
- Flash swap buffer for firmware updates
- Camera frame buffers (2 buffers)

When functions require temporary memory that exceeds stack capacity, they must coordinate with called functions to avoid overlapping allocations. Each function is responsible for its entire memory segment. Camera buffers can be used for very large allocations when the device is **NOT** scanning QR codes.

### Flash Layout

The project uses an A/B firmware scheme with a data partition that extends across the two memory banks. See [`docs/FLASHMAP.md`](docs/FLASHMAP.md) for detailed flash memory layout information.

## FreeRTOS Configuration

The project uses FreeRTOS with static allocation. See [`app/FreeRTOSConfig.h`](app/FreeRTOSConfig.h) for configuration details.

### Task Definition Pattern

Tasks are defined using macros in [`app/common.h`](app/common.h). See the task definition and creation macros for the complete pattern.

### Task Priorities

Task priorities are defined in [`app/main.c`](app/main.c):
- USB task: priority 1
- Core task: priority 2
- UI task: priority 3

## Code Style

### Naming Conventions

- **Functions**: `snake_case` (e.g., `hal_camera_init`, `core_export_key`)
- **Types**: `snake_case_t` (e.g., `hal_err_t`, `core_ctx_t`)
- **Constants**: `UPPER_CASE` (e.g., `CAMERA_FB_SIZE`, `FW_MAJOR`)
- **Globals**: `g_` prefix (e.g., `g_core`, `g_ui_cmd`)
- **Static variables**: No prefix (file-scope static)

### Macros and Attributes

Common macros and attributes are defined in [`app/common.h`](app/common.h). Refer to that file for alignment, section placement, inlining, and weak symbol macros.

### Error Handling

Functions return error codes:
- `HAL_SUCCESS` / `HAL_FAIL` for HAL functions
- `ERR_OK` / `ERR_XXX` for application functions
- `app_err_t` for application-level errors

### Inline Assembly

ARM inline assembly uses GCC syntax. See [`app/common.h`](app/common.h) for examples.

## Hardware Abstraction Layer (HAL)

The HAL is defined in [`app/hal.h`](app/hal.h) and provides:

- **Camera**: Initialization, start/stop, frame acquisition and submission
- **Screen**: Display initialization, pixel drawing, window management
- **SmartCard**: ISO 7816 communication (start/stop, send/recv, PPS)
- **USB**: HID communication (send, receive, stall control)
- **Crypto**: Hardware-accelerated operations (SHA256, CRC32, AES, ECDSA, bignum)
- **Flash**: Program, erase, and firmware switching
- **GPIO/I2C/SPI**: Peripheral control
- **Timer/ADC/PWM**: System utilities

## Camera Operation

The camera uses a double-buffered DMA approach. See [`stm32/Core/Src/stm32_camera.c`](stm32/Core/Src/stm32_camera.c) for the implementation details.

## QR Code Scanning

QR scanning uses the camera in a dedicated task:

1. Camera captures frames via DMA
2. QR scan task processes frames using `quirc` library
3. Decoded data is passed to UR decoder
4. CBOR data is deserialized for display/approval

Key files:
- [`app/qrcode/qrscan.c`](app/qrcode/qrscan.c) - QR scanning logic
- [`app/qrcode/qrcodegen.c`](app/qrcode/qrcodegen.c) - QR code generation

## Cryptographic Operations

The project uses hardware acceleration where available:

- **PKA**: ECC operations (secp256k1, NIST P-256)
- **HASH**: SHA2/SHA3 hardware accelerator
- **RNG**: Hardware random number generator
- **AES**: Hardware AES accelerator

Software fallbacks are available via `SOFT_` macros.

## Build System

The project uses CMake with custom presets in [`CMakePresets.json`](CMakePresets.json).

## Important Notes

1. **Never use malloc/free**: All memory must be statically allocated
2. **Stack depth**: Be careful with stack usage; use heap memory for large buffers
3. **Memory coordination**: When using `g_mem_heap`, coordinate with called functions
4. **Camera buffers**: Can be reused for large allocations when not scanning
5. **Nocache section**: Use `APP_NOCACHE` for DMA buffers (e.g., screen framebuffer)
6. **Aligned sections**: Use `APP_ALIGNED` for DMA and cache-line aligned data

## Task Communication

Tasks communicate via:
- **Task notifications**: Fast one-way signaling (used for camera, screen, smartcard)
- **Command queue**: UI commands from core to UI task
- **Global state**: `g_core`, `g_ui_cmd`, etc.

## Testing

The project supports test mode via `TEST_APP` macro:
- In test mode, certain functions are accessible for testing
- Use `TEST_APP_ACCESSIBLE` macro for test-accessible declarations