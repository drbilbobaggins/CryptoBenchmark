cmake_minimum_required(VERSION 3.24)

project(CryptoBenchmark VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

if(NOT WIN32)
    message(FATAL_ERROR "CryptoBenchmark is currently intended for the documented Windows/MSYS2 UCRT64 development environment.")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Network Widgets)
find_package(OpenSSL 3.6 REQUIRED COMPONENTS Crypto)

add_subdirectory(src/core)
add_subdirectory(src/crypto)
add_subdirectory(src/ipc)
add_subdirectory(src/platform/windows)
add_subdirectory(src/application)
add_subdirectory(src/gui)
add_subdirectory(src/worker)
add_dependencies(CryptoBenchmark CryptoBenchmarkWorker)
enable_testing()
add_subdirectory(tests)
