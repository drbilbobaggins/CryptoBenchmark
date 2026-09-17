add_executable(CryptoBenchmarkWorker
    WorkerSession.cpp
    WorkerSession.h
    worker_main.cpp
)

target_link_libraries(CryptoBenchmarkWorker
    PRIVATE
        cryptobench_core
        cryptobench_crypto
        cryptobench_ipc
        cryptobench_platform_windows
        Qt6::Core
        Qt6::Network
)
