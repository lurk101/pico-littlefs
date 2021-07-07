cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(example C CXX ASM)

pico_sdk_init()

add_subdirectory(lfs)

add_executable(example example.c)
add_executable(test1 test1.c)
add_executable(test2 test2.c)

pico_enable_stdio_uart(example 1)
pico_enable_stdio_usb(example 0)

target_link_libraries(example PUBLIC lfs pico_stdlib)
target_include_directories(example PUBLIC lfs)

target_link_libraries(test1 PUBLIC lfs pico_stdlib)
target_include_directories(test1 PUBLIC lfs)

target_link_libraries(test2 PUBLIC lfs pico_stdlib)
target_include_directories(test2 PUBLIC lfs)

pico_add_extra_outputs(example)
pico_add_extra_outputs(test1)
pico_add_extra_outputs(test2)
