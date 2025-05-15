# Keycard Shell Flash Map

Total flash 2mb in 2 banks with 8kb pages and 128-bit writes.

each contiguous segment dedicated to data is called an area. Area addresses are remapped depending on bank swaps. Areas are transparent to higher layers and boundaries are handled internally.

fs entries are written sequentially, without a specific order. Entries are erased by rewriting the page they belong to, with the entries to delete omitted. Finding an entry has linear complexity and so does finding the next empty spot. Erasing is a slow operation and should be avoided whenever possible.

entries cannot spawn across pages. entries cannot spawn across areas.

if a write does not end at a 128-bit boundary and there is no other queued write padding is added to fill the word. The pattern for padding is 0b10XXXXXX where XXXXXX encode the length of the padding. This means that magic number of regular entries cannot have this bit sequence in its least significant byte. Padding is written in each remaining byte, for example if we need to add 3 bytes of padding it would be encoded as `0x83, 0x82, 0x81`

## Area map

Bank 1:

- 32kb bootloader (write protected)
- 608kb fw
- 384kb data

Bank 2:

- 32kb bootloader (write protected)
- 608kb fw
- 384kb data

## Data FS

magic: 2 bytes
len in bytes: 2 bytes (max len == page size)

### Magics

- 0xffff: empty (size 0)
- 0x4348: chain
- 0x3020: erc-20
- 0x5041: pairing
- 0x4f50: options
- 0x4142: ETH ABI

## Chain

- id: 4 bytes
- ticker: null-terminated ASCII
- network name: null-terminated ASCII
- short name: null-terminated ASCII

## ERC-20

- addr count: 1 byte
- sequence of:
  - chain id: 4 bytes
  - address : 20 bytes
- decimals: 1 byte
- ticker: null-terminated ASCII

## ABI

is composed of a function struct containing a linked list of argument structs. Internal pointers set to 0 are equivalent to NULL. Because of its nature length is very variable across entries

### Function struct

- func selector: 4 bytes
- func ext_selector: 4 bytes
- internal pointer to name: 2 bytes
- internal pointer to first argument: 2 bytes
- func attr: 1 byte
- name: null terminated string
- first argument: argument struct

### Argument struct

- argument type: 2 bytes
- internal pointer to next argument: 2 bytes
- internal pointer to child type (for composite types): 2 bytes
- next argument: argument struct
- child type: argument struct

## Pairing

- uid: 16 bytes
- key: 32 bytes
- index: 1 byte
