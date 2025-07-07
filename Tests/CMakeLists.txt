cmake_minimum_required(VERSION 3.28)
project(runtests)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_VERBOSE_MAKEFILE OFF)
option(DEBUG_MESSAGES "Debug messages" OFF)

include(FetchContent)
FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG        v2.4.12
)

FetchContent_MakeAvailable(doctest)
add_executable(runtests TestMurmur3.cpp)

if(DEBUG_MESSAGES)
  target_compile_definitions(runtests PRIVATE MURMUR3_TEST_DEBUG_)
endif()

target_link_libraries(runtests PRIVATE doctest)

# Enable CTest
enable_testing()
add_test(NAME runtests COMMAND runtests)
