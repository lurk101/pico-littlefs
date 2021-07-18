file(GLOB LFS_SRCS ${PROJECT_SOURCE_DIR}/lfs/*.c ${PROJECT_SOURCE_DIR}/lfs/*.h)

add_library(lfs INTERFACE)
target_include_directories(lfs INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(lfs INTERFACE hardware_flash)
target_sources(lfs INTERFACE ${LFS_SRCS})

