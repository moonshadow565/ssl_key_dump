cmake_minimum_required(VERSION 3.5)

project(ssl_key_dump LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_library(ssl_key_dump SHARED main.cpp)
target_link_libraries(ssl_key_dump user32)
