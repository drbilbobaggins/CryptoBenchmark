add_library(cryptobench_platform_windows STATIC
    WindowsProcessCpuTimeSource.cpp
)

target_include_directories(cryptobench_platform_windows
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cryptobench_platform_windows
    PUBLIC
        cryptobench_core
)
