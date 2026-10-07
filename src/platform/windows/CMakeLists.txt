add_library(cryptobench_platform_windows STATIC
    WindowsWorkerProcess.cpp
    WindowsProcessCpuTimeSource.cpp
    WorkerMemorySampler.cpp
    include/cryptobench/platform/windows/WindowsWorkerProcess.h
    include/cryptobench/platform/windows/WorkerMemorySampler.h
    WorkerMemorySamplerAccounting.h
)

set_target_properties(cryptobench_platform_windows PROPERTIES AUTOMOC ON)

target_include_directories(cryptobench_platform_windows
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cryptobench_platform_windows
    PUBLIC
        cryptobench_core
    Qt6::Core
)

target_link_libraries(cryptobench_platform_windows
    PRIVATE
        Psapi
)
