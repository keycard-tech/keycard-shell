# Keycard Shell Dev Firmware

## 1.0.1 (2025-10-29)

* [ui] fix verify device URL
* [eip712] handle EIP712 messages omitting verifyingContract/chainId fields

## 1.0.0 (2025-10-14)

* [ui] fix QR overlapping title in some cases
* [misc] update database and site public keys

## 0.10.6 (2025-10-01)

* [ui] maximize screen space used for QR output

## 0.10.5 (2025-09-24)

* [ui] update menu structure
* [usb] remove outdated code in EIP712 message signing

## 0.10.4 (2025-09-17)

* [ui] add inline help to "Connect software wallet" flow
* [ui] add software update instructions in device settings
* [ui] move informations and regulatory label to a different submenu
* [prefs] add the ability to disable all inline help

## 0.10.3 (2025-08-29)

* [eth] fix hex string hashing in EIP712
* [eth] remove outdated code
* [ui] rename "Scan QR transaction" to "Scan QR"

## 0.10.2 (2025-08-22)

* [usb] replace GET_ADDRESS command with GET_PUBLIC
* [usb] changed USB PID
* [usb] various bugfixes

## 0.10.1 (2025-08-14)

* [btc] better change output detection
* [btc] handle transactions with marker/flag fields
* [ui] add regulatory label screen
* [usb] detect charging status from VUSB_OK signal

## 0.10.0 (2025-08-06)

* [slip39] add support for SLIP39 seed generation
* [slip39] add support for SLIP39 import
* [core] increase stack size
* [stm32] run the firmware in HDPL3

## 0.9.20 (2025-07-11)

* [db] remove QR-based database upgrade
* [db] recognize and extract SafeTx EIP712 messages
* [ui] custom presentation for SafeTx messages
* [ui] refactor pager code
* [stm32] more conservative SPI clock

## 0.9.19 (2025-06-30)

* [ui] add SeedQR import flow
* [ui] check that PIN and Duress PIN do not match during onboarding
* [ui] fix some copy

## 0.9.18 (2025-06-23)

* [ui] mnemonic entry keyboard now skips disabled letters
* [ui] can now enter mnemonic without using long presses
* [ui] keyboard color and labels aligned to figma design
* [qr] implement scanning of non-UR QR (no UI yet)
* [bip39] implement decoding of SeedQR

## 0.9.17 (2025-06-13)

* [qr] allow scanning QR with up to 64 segments
* [ui] add ability to enter BIP39 passphrase
* [ui] add multiple suggestions to BIP39 mnemonic entry
* [ui] in BIP39 mnemonic entry disable letters that do not bring to valid words

## 0.9.16 (2025-06-06)

* [btc] fix hashing of WSH
* [btc] fix validation of Witness Scripts
* [btc] add support for MultiSig wallets
* [ui] improved experience when a wrong mnemonic is entered
* [ui] fix navigation in update ERC20 dialogs

## 0.9.15 (2025-05-29)

* [usb] correctly handle command reception when busy
* [usb] do not reset mainmenu upon receiving a command
* [keypad] bump long press threshold from 100ms to 200ms
* [ui] change keyboard layout and navigation
* [ui] fix cursor positioning in text inputs
* [ui] add prompt to empty text inputs
* [ui] add cancel buttons to QR screens
* [ui] better error message for BTC tx that cannot be signed
* [ui] better error message when inserting a card in wrong orientation
* [ui] add step indication to mnemonic backup
* [ui] add feedback to factory reset flow
* [ui] align colors to Figma design
* [ui] use larger font size for titles

## 0.9.14 (2025-05-15)

* [eth] add ABI database
* [eth] add formatting of ABI calls in transactions
* [ui] disable auto turn-off during mnemonic backup
* [iso7816] reduce max timeout from 30s to 1s
* [tools] update DB generation tool to include ABI data

## 0.9.13 (2025-04-17)

* [ui] Align duress PIN flow design
* [usb] add SIGN PSBT command to support BTC over USB
* [usb] add GET RESPONSE command to handle replies larger than 255 bytes

## 0.9.12 (2025-04-11)

* Add duress PIN during card setup

## 0.9.11 (2025-04-04)

* Recognize "unlimited" amounts
* Round decimals when amount does not fit
* Fix minor issues

## 0.9.10 (2025-03-27)

* Implement new device info screen
* Implement new ERC-20 update flow
* Implement help screen
* Implement new device verification flow
* Implement pairing with non-default password
* Implement USB cable plug/unplug detection
* Add ticker to BTC
* Minor fixes

## 0.9.9 (2025-03-20)

* Replace battery icons
* Replace fonts
* Implement new info dialogs
* Add action bar to all flows
* Add BIP39 verification
* Add success/error messages to Keycard init/load
* Require long press to proceed with factory reset
* (Almost) match mnemonic generation flow to design
* Match PIN/PUK confirmation to design
* Add prompt before setting pairing password
* Minor fixes

## 0.9.8 (2025-03-13)

* Implement all keyboard layouts (lower, upper, digit, mnemonic)
* Implement new progress screen
* Implement new brightness settings screen
* Replace all icons
* Adjust some theme colors
* Align message signing screen to design
* Add icon sprite sheet for ui testing (accessed by pressing cancel on main menu)
* More compact SN display

## 0.9.7 (2025-03-05)

* Tweak QR output for better scanning performance
* Implement new QR scan progress indicator
* Start aligning keyboard to design

## 0.9.6 (2025-02-27)

* Overhaul icon handling code
* Optimized font drawing
* Partially matched action bar to design
* Match PIN/PUK screens to design
* Match ERC20 approve to design
* Match EIP712 message to design

## 0.9.5 (2025-02-20)

* Change font to Inter
* Match title and action bar size to design
* Match menu implementation to design
* Match address QR and wallet connection QR to design
* Match ETH, ERC20 and Message transactions to design
