# Keycard Shell Dev Firmware

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
