cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include(pico_sdk_import.cmake)

project(littlefs C CXX ASM)

pico_sdk_init()

add_subdirectory(lfs)

add_executable(littlefs littlefs.c hal.c)
add_executable(test1 test1.c hal.c)
add_executable(test2 test2.c hal.c)

pico_enable_stdio_uart(littlefs 1)
pico_enable_stdio_usb(littlefs 0)

target_link_libraries(littlefs PUBLIC lfs pico_stdlib hardware_flash)
target_include_directories(littlefs PUBLIC lfs/include)

target_link_libraries(test1 PUBLIC lfs pico_stdlib hardware_flash)
target_include_directories(test1 PUBLIC lfs/include)

target_link_libraries(test2 PUBLIC lfs pico_stdlib hardware_flash)
target_include_directories(test2 PUBLIC lfs/include)

pico_add_extra_outputs(littlefs)
pico_add_extra_outputs(test1)
pico_add_extra_outputs(test2)

if ("${CMAKE_BUILD_TYPE}" MATCHES "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,–gc-sections -O3")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

message(STATUS "Build type ${CMAKE_BUILD_TYPE}")
message(STATUS "CFlags ${CMAKE_C_FLAGS}")
message(STATUS "${PICO_COMPILER_DIR}")
message(STATUS "${PICO_COMPILER_CC}")

