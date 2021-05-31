# pico-littlefs

A small C/C++ Posix like journaling file system for the Raspberry Pico using a size configurable
portion of its SPI flash. Adapted from the [little-fs ARM project](https://github.com/littlefs-project/littlefs.git).

Building
```
git clone https://github.com/lurk101/pico-littlefs.git
cd pico-littlefs.git
mkdir b
cd b
cmake ..
make
```
