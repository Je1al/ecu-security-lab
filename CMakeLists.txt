cmake_minimum_required(VERSION 3.16)
project(ecu_security_lab C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Strict ISO C (CMAKE_C_EXTENSIONS OFF) hides POSIX/glibc symbols such as
# clock_gettime and the SocketCAN headers; ask for them explicitly on Linux.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions(_GNU_SOURCE)
endif()

include(CTest)  # defines BUILD_TESTING (default ON) and enables ctest

add_subdirectory(ecu)
