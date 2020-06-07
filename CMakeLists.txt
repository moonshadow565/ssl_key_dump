cmake_minimum_required(VERSION 3.5)

project(ssl_key_dump LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ssl_key_dump SHARED 
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde32.c
    minhook/src/hde/hde64.c
    main.cpp
    )
target_include_directories(ssl_key_dump PRIVATE minhook/include)
target_link_libraries(ssl_key_dump User32)

add_executable(print_ssl_offsets print_ssl_offsets.cpp)
