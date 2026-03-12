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

The build is fully reproducible, although not yet in an automated way.

---

#### Getting the Code

First, clone the repository and switch to the release tag you want to build:

```bash
git clone https://github.com/keycard-tech/keycard-shell.git
cd keycard-shell
git checkout v1.1.1   # use the tag matching the official release you want to verify
```

---

#### Prerequisites

**1. Install STM32CubeIDE**

Download and install [STM32CubeIDE](https://www.st.com/en/development-tools/stm32cubeide.html).

**2. Configure the Toolchain**

After importing the project, verify you are using `GNU Tools for STM32 (14.3.rel1)` by checking the Toolchain manager in the IDE settings:
- Go to `Window → Preferences → STM32CubeIDE → Build → Settings`
- Select `GNU Tools for STM32 (14.3.rel1)` as your toolchain

**3. Install Python Dependencies**

Install the required Python packages:

```bash
pip install -r tools/requirements.txt
```

> **Note:** Depending on your platform, you may need additional steps to get Python set up correctly.

**4. Set up Signing Keys**

In your `deployment` directory, you need two files:

- `bootloader-pubkey.txt`: Contains the public key the bootloader will use to verify the firmware. The key must be hex-encoded, uncompressed, and without the leading `04` byte.
- `fw-test-key.txt`: Contains a hex-encoded private key (the private part of the key in `bootloader-pubkey.txt`) used to sign the firmware.

> **Note:** We use this signing method in our internal development units. Shipped units will have different keys and the signing process is handled in a secure environment.

---

#### Build Steps

1. **Import the Project**
   - Open STM32CubeIDE
   - Go to `File → Import → Existing Projects into Workspace`
   - Select the `stm32` directory and import the project

2. **Build the Bootloader (BL)**
   - Select the **BL** build configuration
   - Right-click on the project → `Build Project`
   - The bootloader binary will be generated in `stm32/BL/`

3. **Build the Release Firmware**
   - Select the **Release** build configuration
   - Right-click on the project → `Build Project`
   - The firmware binary will be generated in `stm32/Release/`

4. **(Optional) Build the TestApp**
   - Select the **TestApp** build configuration
   - Right-click on the project → `Build Project`
   - The test application binary will be generated in `stm32/TestApp/`

---

#### Verifying the Firmware

Build the **Release** target in STM32CubeIDE, and run:

```bash
python3 tools/firmware-hash.py -b stm32/Release/stm32.bin
```

Download the official binary from the [GitHub releases page](https://github.com/keycard-tech/keycard-shell/releases) and hash it the same way:

```bash
python3 tools/firmware-hash.py -b ~/Downloads/shellos-<date>-<version>.bin
```

The two hashes must match.

> **Note:** Use `-b` before the file path — it is required by the script.

---

#### Creating a Full Firmware Image

If you want to generate a full image to load on a device you built yourself, take a look at the `tools/create-image.py` script.
