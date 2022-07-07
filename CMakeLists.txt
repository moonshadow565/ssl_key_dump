cmake_minimum_required(VERSION 3.20)

project(ssl_key_dump LANGUAGES CXX C)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        4a455528f61b5a375b1f9d44e7d296d47f18bb18
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
)
FetchContent_GetProperties(minhook)
if(NOT minhook_POPULATED)
    FetchContent_Populate(minhook)
    file(GLOB minhook_SRCS ${minhook_SOURCE_DIR}/src/*.c ${minhook_SOURCE_DIR}/src/hde/*.c)
    add_library(minhook STATIC ${minhook_SRCS})
    target_include_directories(minhook PUBLIC ${minhook_SOURCE_DIR}/include)
endif()

add_library(ssl_key_dump SHARED src/main.cpp src/ppp.hpp)
if (MSVC)
    #target_compile_definitions(ssl_key_dump PUBLIC -D_HAS_EXCEPTIONS=0)
    #target_compile_options(ssl_key_dump PUBLIC "-GR-" "-GS-" "-EHs-c-")
    target_compile_definitions(ssl_key_dump PUBLIC -D_CRT_SECURE_NO_WARNINGS)
endif()
target_link_libraries(ssl_key_dump kernel32 user32 minhook)
