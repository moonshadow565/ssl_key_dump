cmake_minimum_required(VERSION 3.20)

project(ssl_key_dump LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ssl_key_dump SHARED src/main.cpp src/ppp.hpp)
if (MSVC)
    #target_compile_definitions(ssl_key_dump PUBLIC -D_HAS_EXCEPTIONS=0)
    #target_compile_options(ssl_key_dump PUBLIC "-GR-" "-GS-" "-EHs-c-")
    target_compile_definitions(ssl_key_dump PUBLIC -D_CRT_SECURE_NO_WARNINGS)
endif()
target_link_libraries(ssl_key_dump kernel32 user32)
