# Keycard Shell USB protocol

Keycard Shell presents itself to the USB host a HID device with VID 0x1209 and PID 0x21f7. The protocol has been inspired by the one by used by Ledger, being compatible at the transport layer but diverging at the command level.

## Command transport

Keycard Shell exchanges commands with the host following a format closely resembling ISO7816 APDUs. Communication is always started by the host by sending a C-APDU and will receive a single R-APDU in reply by Shell. Timeouts should be handled at USB host level but must account for the fact that many actions require user interaction before a R-APDU is generated.

### C-APDU format

* CLA: 1 byte, set to 0xe0
* INS: 1 byte, identifies the command to execute
* P1: 1 byte, first parameter of the command. Used mostly for command chaining
* P2: 1 byte, second parameter of the command
* Lc: 1 byte, 0-255, length of following Data field
* Data: additional data length. Absent if Lc = 0

### R-APDU format

* Data: 0-253 bytes, response data
* Status Words (SW): 2 bytes error code of the command.

### Command chaining

Since C-APDU are limited to 255 bytes for their data field, it is often necessary to split the payload across multiple APDUs. This is achieved the following way:

1. the host prepares the full payload and splits in chunks of maximum 255 bytes
2. the first chunk is sent with P1 = 0
3. Shell will respond with SW = 0x9000 and no other response data (unless this was the only chunk)
4. all other chunks are sent with P1 = 1
5. Shell will acknowledge each intermediate chunk with SW = 0x9000 while the response to the last chunk will contain the actual reponse.

For this chaining scheme to work Shell must be able to detect when data ends. The way this is handled depends on each command but it either involves including the total length in the first segment or by transmitting data that instrinsically allows detecting its end.

### Encoding conventions

1. All multibyte integers are encoded in big endian byte order
2. BIP32 paths are encoded by 1 byte representing the number of elements (max 10) followed by a sequence of 32-bit integers

### Status Words used by Shell:

* 0x9000: no error
* 0x61XX: more data available (XX is how much data will be in the next chunk)
* 0x6e00: invalid CLA
* 0x6d00: invalid INS (unknown command)
* 0x6982: operation denied (usually by the user)
* 0x6985: conditions not satified
* 0x6a80: invalid Data field
* 0x6501: feature not supported
* 0x6fXX: internal error

## Commands

### GET RESPONSE

* INS: 0xc0
* P1: 0x00
* P2: 0x00
* Data: None

This is a transport level command. In case the SW of the latest received R-APDU was 0x61XX send this command to receive the next chunk of the response. Repeat until you get a SW different from 0x61XX. 

If sent where not more data available, the command will respond with SW = 0x6985.

### GET DEVICE INFO

* INS: 0x06
* P1: 0x00
* P2: 0x00
* Data: None

Returns informations about the device. The format is as follow:

* Firmware version: 3 bytes, representing major, minor, patch revision version respectively.
* Database version: 4 bytes. It's integer value is a date in YYYYMMDD format.
* Device UID: 16 bytes. Unique identifier of this Shell unit.
* Public Key: 33 bytes. A public key that can be used for device verification purposes.

### GET PUBLIC

* INS: 0x02
* P1: 0x00
* P2: 0x00 for normal public key, 0x01 for extended public key
* Data: BIP32 path

Exports the public key of the given BIP32 derivation path. This operation requires user approval. The output format is as follows:

* Length of fingerprint: 1 byte
* Fingerprint: 4 bytes, the master key fingerprint. Useful to identify the wallet.
* Length of public key: 1 byte
* Public key: the public key either in compressed (33-bytes) or uncompressed (65 bytes).
* Length of chain code: 1 byte. If P2 = 0, the value is always 0.
* Chain code: extension to the public key, allowing the client to derive deeper level of public keys

### SIGN ETH TX

* INS: 0x04
* P1: used for command chaining
* P2: 0x00
* Data: BIP32 path, unsigned Ethereum transaction

Signs the given Ethereum transaction. This operation requires user approval. Returns a 65-bytes signature in (v, r, s) format.

### SIGN ETH MSG

* INS: 0x08
* P1: used for command chaining
* P2: 0x00
* Data: BIP32 path, message length on 4 bytes, message to sign

Signs the given message in a way compatible with Ethereum's `personal_sign` function. This operation requires user approval. Returns a 65-bytes signature in (v, r, s) format.

### SIGN EIP712

* INS: 0x0c
* P1: used for command chaining
* P2: 0x00
* Data: BIP32 path, message length on 4 bytes, EIP712 message to sign

Signs the given EIP712 message. This operation requires user approval. Returns a 65-bytes signature in (v, r, s) format.

### SIGN PSBT

* INS: 0x0e
* P1: used for command chaining
* P2: 0x00
* Data: PSBT length on 4 bytes, PSBT to sign

Signs the given PSBT. This operation requires user approval. Returns the entire PSBT with added signatures. Retrieving the full response is likely to require the usage of the `GET RESPONSE` command.

### FW UPGRADE

* INS: 0xf2
* P1: used for command chaining
* P2: 0x00
* Data: firmware length on 4 bytes, firmware to load

Performs a firmware upgrade. This operation requires user approval and the firmware's signature will be verified. The length fo each data chunk must be a multiple of 16 bytes, meaning that the maximum chunk length is 240 bytes. Shell will reply with SW = 0x9000 on success and reboot, which will interrupt the USB connection.

### DB UPGRADE

* INS: 0xf4
* P1: used for command chaining
* P2: 0x00
* Data: databse length on 4 bytes, database to load

Performs a database upgrade. This operation requires user approval and the database's signature will be verified.

## HID framing

Since we are using the USB HID profile, the APDUs will need to be packed into HID frames, which have a length of 64 bytes and thus will require further segmentation/reassembly.

Each frame has the following format

Channel ID: 2 bytes, arbitrarely chosen by the host and repeated by Shell
Frame type: 1 byte. Set to 0x05 for APDU and 0x02 for PING
Segment number: 2 bytes indicating the current segment number (starting from 0)
Total data length: 2 bytes, only present if the segment number = 0 and is the total length of the APDU being transmitted
Data: the chunk of the APDU being transmitted, filling the remaining bytes of the HID frame

If frame type is PING, the Shell will answer with the exact same data received. This is ony useful for link diagnostic.

The APDU frame type is used for both C-APDU and R-APDU and the segmentation/reassembly procedure are exactly the same for both.

### Segmentation

1. Split the data to send into chunks of (64 - 5) bytes, with the first chunk being (64 - 7) bytes.
2. Send the first chunk with segment number = 0 and total data length set to the APDU size.
3. If there is more data to send, increment segment number by 1 and send the next chunk.
4. Repeat until no more chunks. Signal the upper layer that transmission succeded.

### Reassembly

1. If segment number == 0 reset the receiving buffer and set it's final length to the to value of the total data length field.
2. Append the data chunk to the receiving buffer. Increment the expected segment number by 1.
3. Upon receiving the next chunk (if any) check the segment number to matches the expected segment number and append its data to the receiving buffer.
4. When received data matches the total data length, signal the upper layer that reception succeded. Note that the last chunk might contain extra bytes since HID frames are always 64 bytes long. These bytes must be ignored and not added to the receiving buffer.