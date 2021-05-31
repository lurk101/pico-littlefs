add_library(lfs STATIC lfs.c lfs_util.c)

target_include_directories(lfs PRIVATE include)

target_link_libraries(lfs PRIVATE pico_stdlib)

target_compile_definitions(lfs INTERFACE NO_MENUCONFIG)

