find_package(Git QUIET)

set(CRYPTOBENCH_BUILD_INFO_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${CRYPTOBENCH_BUILD_INFO_INCLUDE_DIR}/cryptobench/application")

set(CRYPTOBENCH_GIT_COMMIT "unknown")
if(GIT_FOUND)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_SOURCE_DIR}" rev-parse HEAD
        RESULT_VARIABLE CRYPTOBENCH_GIT_RESULT
        OUTPUT_VARIABLE CRYPTOBENCH_GIT_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(CRYPTOBENCH_GIT_RESULT EQUAL 0 AND NOT CRYPTOBENCH_GIT_OUTPUT STREQUAL "")
        set(CRYPTOBENCH_GIT_COMMIT "${CRYPTOBENCH_GIT_OUTPUT}")
    endif()
endif()

set(CRYPTOBENCH_APPLICATION_VERSION "${PROJECT_VERSION}")
set(CRYPTOBENCH_OPENSSL_VERSION "${OpenSSL_VERSION}")
if(CRYPTOBENCH_OPENSSL_VERSION STREQUAL "")
    message(FATAL_ERROR "OpenSSL_VERSION was not provided by find_package(OpenSSL)")
endif()

set(CRYPTOBENCH_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
if(CRYPTOBENCH_BUILD_TYPE STREQUAL "")
    set(CRYPTOBENCH_BUILD_TYPE "Unknown")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/BuildInfo.h.in"
    "${CRYPTOBENCH_BUILD_INFO_INCLUDE_DIR}/cryptobench/application/BuildInfo.h"
    @ONLY
)

add_library(cryptobench_application STATIC
    application.cpp
    BatchController.cpp
    include/cryptobench/application/BatchController.h
    BatchResultDocumentService.cpp
    include/cryptobench/application/BatchResultDocumentService.h
    BenchmarkController.cpp
    include/cryptobench/application/BenchmarkSessionExecutor.h
    include/cryptobench/application/BenchmarkController.h
    WorkerRunSession.cpp
    include/cryptobench/application/WorkerRunSession.h
    BenchmarkConfigJson.cpp
    include/cryptobench/application/BenchmarkConfigJson.h
    BatchTypes.cpp
    include/cryptobench/application/BatchTypes.h
    BatchInputFile.cpp
    include/cryptobench/application/BatchInputFile.h
    BatchInputParser.cpp
    include/cryptobench/application/BatchInputParser.h
    StrictJsonPreflight.cpp
    include/cryptobench/application/StrictJsonPreflight.h
    BatchInputSchema.cpp
    include/cryptobench/application/BatchInputSchema.h
    BatchPrimitiveParameters.cpp
    include/cryptobench/application/BatchPrimitiveParameters.h
    BatchJsonInteger.cpp
    BatchJsonInteger.h
    EnvironmentInfoProvider.cpp
    ResultJsonMapping.cpp
    include/cryptobench/application/ResultJsonMapping.h
    ResultDocument.cpp
    include/cryptobench/application/ResultDocument.h
    JsonResultExportService.cpp
    include/cryptobench/application/JsonResultExportService.h
    SingleResultDocumentService.cpp
    include/cryptobench/application/SingleResultDocumentService.h
    AtomicFileWriter.cpp
    include/cryptobench/application/AtomicFileWriter.h
)

set_target_properties(cryptobench_application PROPERTIES AUTOMOC ON)

target_include_directories(cryptobench_application
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CRYPTOBENCH_BUILD_INFO_INCLUDE_DIR}
)

target_link_libraries(cryptobench_application
    PUBLIC
        cryptobench_core
        cryptobench_ipc
        cryptobench_platform_windows
        Qt6::Core
)
