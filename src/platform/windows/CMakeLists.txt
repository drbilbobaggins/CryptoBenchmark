add_library(cryptobench_platform_windows STATIC
    platform_windows.cpp
)

target_link_libraries(cryptobench_platform_windows
    PUBLIC
        cryptobench_core
)
