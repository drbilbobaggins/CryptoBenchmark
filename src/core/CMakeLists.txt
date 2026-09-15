add_library(cryptobench_core STATIC
    core.cpp
    AlgorithmProfileId.cpp
    AlgorithmRegistry.cpp
    ConfigValidator.cpp
    BenchmarkTask.cpp
    StatisticsCalculator.cpp
)

target_include_directories(cryptobench_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
