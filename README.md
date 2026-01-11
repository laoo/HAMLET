# HAMLET
Humble Another Minimal Lynx Encryption Tool

## Compilation

Use CMake. Requires C++20

## Usage
```
HAMLET input.bin
```

`HAMLET` does different things depending of the content of the input file.

### Simple loader

If the input file is raw binary block with size not greater than 250 bytes it is encrypted as is and the output file has extension `.bin` (unless it's already `.bin` then the extension is `.loader`).

### Atari XEX object

If the input file is in Atari XEX format generated for example my [MADS](https://mads.atari8.info/) assembler, there are few options.

#### Optional header

If the first load block is assembled at address 0 and it has 64 bytes it's treated as LNX header and prepended to the output. In such case the extension is replaced to `.lnx`, `.lyx` otherwise

The header should be of form (mads syntax):
```
    org 0
    .by 'LYNX'                              //magic
    .wo $0400                               //page size bank 0
    .wo $0000                               //page size bank 1
    .wo $0001                               //version
    //   12345678901234567890123456789012
    .by '                                '  //cart name (32 chars)
    .by '                '                  //manufacturer (16 chars)
    .by 0                                   //rotation
    .by 0                                   //audBits
    .by 0                                   //eeprom bits
    .by 0,0,0                               //spare
    ert * != 64
```

#### Loader as block at 0x200

If (after optional header block) there is a block starting at 0x200 and not greater than 250 bytes - it's encrypted as a loader. It's a mandatory block.

#### The rest of the file

If there is some file content after loader block - it's appended as is.

### Output file padding

If there is a header present, the first half word after magic string `LYNX` is treated as a block (page) size (actually only high byte of that word is processed, i.e. a byte at offset 5). In such case the cartridge image (without header) is padded to the multiple of page size.

In the case of absence of a header the resultant `.lyx` file is padded to 256 kB (to be easily used with AgaCart).

