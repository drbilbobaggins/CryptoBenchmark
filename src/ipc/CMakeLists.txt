add_library(cryptobench_ipc STATIC
    FrameCodec.cpp
    JsonCodec.cpp
    WorkerIpcChannel.cpp
)

target_include_directories(cryptobench_ipc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cryptobench_ipc
    PUBLIC
        cryptobench_core
        Qt6::Core
        Qt6::Network
)
