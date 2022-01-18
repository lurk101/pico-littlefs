add_library(stdio_init INTERFACE)
target_include_directories(stdio_init INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(stdio_init INTERFACE pico_stdlib)
target_sources(stdio_init INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/stdio_init.c
    ${CMAKE_CURRENT_LIST_DIR}/stdio_init.h)

