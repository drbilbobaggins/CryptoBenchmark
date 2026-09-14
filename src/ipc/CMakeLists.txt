add_library(cryptobench_ipc STATIC
    ipc.cpp
)

target_link_libraries(cryptobench_ipc
    PUBLIC
        cryptobench_core
        Qt6::Core
        Qt6::Network
)
