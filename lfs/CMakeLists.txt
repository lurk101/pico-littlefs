add_library(lfs INTERFACE)
target_include_directories(lfs INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(lfs INTERFACE hardware_flash)
target_sources(lfs INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/lfs.c
    ${CMAKE_CURRENT_LIST_DIR}/lfs_util.c
    ${CMAKE_CURRENT_LIST_DIR}/pico_hal.c
    ${CMAKE_CURRENT_LIST_DIR}/lfs/lfs.h
    ${CMAKE_CURRENT_LIST_DIR}/lfs/lfs_util.h
    ${CMAKE_CURRENT_LIST_DIR}/lfs/pico_hal.h)

