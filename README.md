PS4 PKG/PFS tool (c) 2017-2021 by flatz

Dependencies:
* mbedtls
* uthash
* zlib

For ubuntu-ish:
```bash
sudo apt install libmbedtls-dev uthash-dev zlib
```

To produce windows executable from ubuntu-ish via mingw:
```bash
sudo apt install mingw-w64 libz-mingw-w64-dev
```
Then pass e.g. `-DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake` to cmake.

P.S. In memory of Maxton Garrett (maxton), this release is dedicated to you.
