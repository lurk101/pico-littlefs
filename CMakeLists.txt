cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(test C CXX ASM)

pico_sdk_init()

add_subdirectory(lfs)

macro(addtarget name)
    add_executable(${name} ${name}.c)
    pico_enable_stdio_uart(${name} 1)
    pico_enable_stdio_usb(${name} 0)
    target_link_libraries(${name} PUBLIC pico_stdlib lfs)
    pico_add_extra_outputs(${name})
endmacro()

addtarget(test0)
addtarget(test1)
addtarget(test2)
