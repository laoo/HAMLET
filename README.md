# HAMLET
Humble Another Minimal Lynx Encryption Tool

## Compilation

Use CMake. Requires some recent [boost](https://www.boost.org/) and C++20

## Usage
```
HAMLET input.bin output.[bin|lyx]
```
If input file is Atari XEX binary format assembled at address $200 ( header $FF $FF $00 $02 ) only the first block is encrypted. The rest is pasted to output file. Otherwise whole file is encrypter.
If output file extension is .lyx, the image is padded to 256 kB (to be easily used with AgaCart).
