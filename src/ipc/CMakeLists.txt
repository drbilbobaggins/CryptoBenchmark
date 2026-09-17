add_library(cryptobench_ipc STATIC
    FrameCodec.cpp
    JsonCodec.cpp
    ParentIpcChannel.cpp
    include/cryptobench/ipc/ParentIpcChannel.h
    WorkerIpcChannel.cpp
)

set_target_properties(cryptobench_ipc PROPERTIES AUTOMOC ON)

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
