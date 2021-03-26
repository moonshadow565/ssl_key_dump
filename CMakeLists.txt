cmake_minimum_required(VERSION 3.19)

project(ssl_key_dump LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(NOSTDLIB "Resolve imports manually" ON)
option(NODLLMAIN "Do not run from dllmain" OFF)

add_library(ssl_key_dump SHARED
    src/config.hpp
    src/common.hpp
    src/main.cpp
    src/ppp.hpp
    src/resolve_imports.hpp)
target_compile_definitions(ssl_key_dump PUBLIC -D_HAS_EXCEPTIONS=0)
target_compile_definitions(ssl_key_dump PUBLIC -D_CRT_SECURE_NO_WARNINGS)
target_compile_options(ssl_key_dump PUBLIC "-GR-" "-GS-" "-EHs-c-")


if (NOSTDLIB)
    target_compile_definitions(ssl_key_dump PUBLIC -DNOSTDLIB=1)
    target_link_options(ssl_key_dump PUBLIC "-nodefaultlib" "-safeseh:no" "-entry:DllMain")
    if (NODLLMAN)
        target_link_options(ssl_key_dump PUBLIC  "-noentry")
    else()
        target_link_options(ssl_key_dump PUBLIC  "-entry:DllMain")
    endif()
else()
    target_link_libraries(ssl_key_dump User32)
endif()

if (NODLLMAN)
    target_compile_definitions(ssl_key_dump PUBLIC -DNODLLMAIN=1)
endif()

