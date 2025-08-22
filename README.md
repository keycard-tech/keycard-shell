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

The build is fully reproducibile although not yet in an automated way. You just need to download STM32CubeIDE, import the project and make sure you use `GNU Tools for STM32 (13.3.rel1)` as your toolchain.

In your `deployment` directory you also need to have a `bootloader-pubkey.txt` file containing the public key the bootloader will use to verify the firmware. The key will be hex-encoded, uncompressed and without leading `04` byte. You also need a `fw-test-key.txt` containin a hex encoded private key (the private part of the key in `bootloader-pubkey.txt`) used to sign the firmware. We use this signing method in our internal development units. Shipped units will have different keys and the signing process is handled in a secure environment.

At this point you can build the BL (bootloader), Release and (optionally) TestApp target

Verifying the firmware is as easy as matching the hashes between the released firmware and the one you built yourself using the matching git tag. The hash must exclude the signature from the calculation, since that obviosly depends on the signing keys, and the firmware must be padded with 0xff bytes up to its maximum size. A script to get a valid hash is in `tools/firmware-hash.py`.

If you want to generate a full image to load on a device you built yourself, take a look at the `tools/create-image.py` script.
