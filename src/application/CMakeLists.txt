add_library(cryptobench_application STATIC
    application.cpp
)

target_link_libraries(cryptobench_application
    PUBLIC
        cryptobench_core
        cryptobench_ipc
        cryptobench_platform_windows
        Qt6::Core
)
