# Keycard Shell

Keycard Shell transforms any Keycard into a standalone, air-gapped hardware wallet with built-in keypad, display, camera, and USB (which can be turned off). Fully open-source and EAL6+ certified, it uses ERC-4527 QR codes for secure signing and supports infinite removable backups.

## Main features

### Modular & Open Source

All firmware, hardware designs, and toolchain scripts are fully open source under the MIT license.

### Air-gapped Operation

Scan and display QR codes (ERC-4527) to sign transactions without ever exposing your keys.

### High-Security Secure Element

EAL6+ certified secure element for key storage and signing.

### Removable Smartcards

Support for an infinite number of Keycard smartcards, each with its own key & PIN.

### Wide Compatibility

Works seamlessly with MetaMask, imToken, Rabby, BlueWallet, BlueWallet, Sparrow, Specter, and more.

### Built to Last

Powered by a replaceable Nokia BL-4C battery (25 + year expectancy), water & dust resistant.

### Duress PIN

A second PIN stops bad actors from stealing crypto by physical force

## About this repo

This repo contains everything needed to build a Keycard Shell.

### Repo structure

* `app`: the main firmware code. This is what makes everything happen.
* `bootloader`: the bootloader. Since it is non-upgradable we kept its complexity to a minimum.
* `cddl`: contains definitions for the various CBOR messages defined by the UR standard
* `deployment`: git-ignored folder containing the signing keys and build results
* `freertos`: we use FreeRTOS as our task scheduler.
* `hardware`: everything hardware related. From schematics up to case designs.
* `json`: example json files for abi, token and chain db. These files are unused.
* `stm32`: all platform-specific code for the STM32H5 MCU. It also contains the project file for STM32CubeIDE needed to build the firmware.
* `test`: the tests firmware we run in the factory on each unit to check it has been properly assembled.
* `tools`: some tools used during the build process or during development.
* `zcbor`: the library we use to parse CBOR messages.

### Building the firmware

The Keycard Shell firmware build system uses CMake for the main firmware compilation and Python tools for post-processing (signing, image creation, database generation).

#### Getting the Code

First, clone the repository and switch to the release tag you want to build:

```bash
git clone https://github.com/keycard-tech/keycard-shell.git
cd keycard-shell
git checkout v1.1.1   # use the tag matching the official release you want to verify
```

make sure you follow the build instructions directly for the tag you checked out since some steps and toolchain versions can differ.

#### Prerequisites

##### Install Build Tools

**CMake** (3.15 or later) and **Ninja** are required for building the firmware.

On Ubuntu/Debian:
```bash
sudo apt install cmake ninja-build
```

On macOS (with Homebrew):
```bash
brew install cmake ninja
```

On Windows (with Chocolatey):
```bash
choco install cmake ninja
```

Alternatively, download from [cmake.org](https://cmake.org/download/) and [ninja-build.org](https://ninja-build.org/).

##### Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

or follow your OS instructions for installing uv.

##### Install ARM GCC Toolchain

Required for compiling STM32 firmware. The toolchain is automatically downloaded by the build script:

```bash
./tools/download-toolchain.sh
```

The script supports:
- Linux x86_64
- Linux aarch64
- macOS (Apple Silicon / arm64)
- Windows x86_64

After downloading, the toolchain is installed in `toolchain/`.

#### Setup Signing Keys

Create a `deployment` directory with two files:

- `bootloader-pubkey.txt`: Contains the public key the bootloader will use to verify the firmware. The key must be hex-encoded, uncompressed, and without the leading `04` byte.
- `fw-test-key.txt`: Contains a hex-encoded private key (the private part of the key in `bootloader-pubkey.txt`) used to sign the firmware.

#### Setup Virtual Environment

```bash
uv venv
uv sync
```

#### Build Firmware

```bash
cmake --preset release
cmake --build --preset release
```

#### Verifying the Firmware

After building, run:

```bash
uv run python tools/firmware-hash.py -b build/shellos.bin
```

Download the official binary from the [GitHub releases page](https://github.com/keycard-tech/keycard-shell/releases) and hash it the same way:

```bash
uv run python tools/firmware-hash.py -b ~/Downloads/shellos-<date>-<version>.bin
```

The two hashes must match.

#### Creating a Full Firmware Image

If you want to generate a full image to load on a device you built yourself, take a look at the `tools/create-image.py` script.
