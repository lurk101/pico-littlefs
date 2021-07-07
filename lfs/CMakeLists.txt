add_library(lfs STATIC lfs.c lfs_util.c pico_hal.c pico_hal.h)

target_include_directories(lfs PRIVATE include)

target_link_libraries(lfs PRIVATE pico_stdlib hardware_flash)
