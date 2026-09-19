message(STATUS "Configuring tests")

add_executable(CryptoBenchmarkTests
	CoreExecutionContractTests.cpp
	CoreResultModelTests.cpp
	ResultAssemblerTests.cpp
	BenchmarkRunnerTests.cpp
	RegistryConsistencyTests.cpp
	RunnerErrorContextTests.cpp
	RunnerMeasurementContractTests.cpp
	StatisticsTests.cpp
	ValidatorTests.cpp
)

target_link_libraries(CryptoBenchmarkTests
	PRIVATE
		cryptobench_core
)

add_test(NAME CryptoBenchmarkTests COMMAND CryptoBenchmarkTests)

add_executable(CryptoBenchmarkEnvironmentInfoTests
	EnvironmentInfoProviderTests.cpp
)

target_link_libraries(CryptoBenchmarkEnvironmentInfoTests
	PRIVATE
		cryptobench_application
)

add_test(NAME CryptoBenchmarkEnvironmentInfoTests COMMAND CryptoBenchmarkEnvironmentInfoTests)

add_executable(CryptoBenchmarkBenchmarkControllerTests
	BenchmarkControllerTests.cpp
)

target_link_libraries(CryptoBenchmarkBenchmarkControllerTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBenchmarkControllerTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBenchmarkControllerTests COMMAND CryptoBenchmarkBenchmarkControllerTests)

add_executable(CryptoBenchmarkCancellationTests
	BenchmarkCancellationTests.cpp
)

set_target_properties(CryptoBenchmarkCancellationTests
	PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-runtime"
)

target_link_libraries(CryptoBenchmarkCancellationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkCancellationTests CryptoBenchmarkTestScriptedWorker)

add_test(NAME CryptoBenchmarkCancellationTests COMMAND CryptoBenchmarkCancellationTests)

add_executable(CryptoBenchmarkCryptoTests
	DigestAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkCryptoTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkCryptoTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkCryptoTests COMMAND CryptoBenchmarkCryptoTests)

add_executable(CryptoBenchmarkAeadTests
	AeadAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkAeadTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkAeadTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkAeadTests COMMAND CryptoBenchmarkAeadTests)

add_executable(CryptoBenchmarkEcdhXdhTests
	EcdhXdhAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkEcdhXdhTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkEcdhXdhTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkEcdhXdhTests COMMAND CryptoBenchmarkEcdhXdhTests)

add_executable(CryptoBenchmarkEcdsaTests
	EcdsaAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkEcdsaTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkEcdsaTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkEcdsaTests COMMAND CryptoBenchmarkEcdsaTests)

add_executable(CryptoBenchmarkEdDsaTests
	EdDsaAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkEdDsaTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkEdDsaTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkEdDsaTests COMMAND CryptoBenchmarkEdDsaTests)

add_executable(CryptoBenchmarkMlKemTests
	MlKemAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkMlKemTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkMlKemTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkMlKemTests COMMAND CryptoBenchmarkMlKemTests)

add_executable(CryptoBenchmarkRsaPssTests
	RsaPssAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkRsaPssTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkRsaPssTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkRsaPssTests COMMAND CryptoBenchmarkRsaPssTests)

add_executable(CryptoBenchmarkIpcTests
	IpcCodecTests.cpp
)

target_link_libraries(CryptoBenchmarkIpcTests
	PRIVATE
		cryptobench_ipc
)

add_test(NAME CryptoBenchmarkIpcTests COMMAND CryptoBenchmarkIpcTests)

add_executable(CryptoBenchmarkWorkerIpcTests
	WorkerIpcChannelTests.cpp
)

target_link_libraries(CryptoBenchmarkWorkerIpcTests
	PRIVATE
		cryptobench_ipc
)

add_test(NAME CryptoBenchmarkWorkerIpcTests COMMAND CryptoBenchmarkWorkerIpcTests)

add_executable(CryptoBenchmarkParentIpcTests
	ParentIpcChannelTests.cpp
)

target_link_libraries(CryptoBenchmarkParentIpcTests
	PRIVATE
		cryptobench_ipc
		Qt6::Core
		Qt6::Network
)

add_test(NAME CryptoBenchmarkParentIpcTests COMMAND CryptoBenchmarkParentIpcTests)

add_executable(CryptoBenchmarkWorkerSessionTests
	WorkerSessionTests.cpp
	${CMAKE_SOURCE_DIR}/src/worker/WorkerSession.cpp
)

target_link_libraries(CryptoBenchmarkWorkerSessionTests
	PRIVATE
		cryptobench_core
		cryptobench_crypto
		cryptobench_ipc
		cryptobench_platform_windows
		Qt6::Core
		Qt6::Network
)

add_test(NAME CryptoBenchmarkWorkerSessionTests COMMAND CryptoBenchmarkWorkerSessionTests)

add_executable(CryptoBenchmarkWorkerProcessIntegrationTests
	WorkerProcessIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkWorkerProcessIntegrationTests
	PRIVATE
		cryptobench_core
		cryptobench_ipc
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkWorkerProcessIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkWorkerProcessIntegrationTests COMMAND CryptoBenchmarkWorkerProcessIntegrationTests)

add_executable(CryptoBenchmarkPlatformWindowsTests
	WindowsProcessCpuTimeSourceTests.cpp
)

target_link_libraries(CryptoBenchmarkPlatformWindowsTests
	PRIVATE
		cryptobench_platform_windows
)

add_test(NAME CryptoBenchmarkPlatformWindowsTests COMMAND CryptoBenchmarkPlatformWindowsTests)

add_executable(CryptoBenchmarkWorkerMemorySamplerTests
	WorkerMemorySamplerTests.cpp
)

target_link_libraries(CryptoBenchmarkWorkerMemorySamplerTests
	PRIVATE
		cryptobench_ipc
		cryptobench_platform_windows
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkWorkerMemorySamplerTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkWorkerMemorySamplerTests COMMAND CryptoBenchmarkWorkerMemorySamplerTests)

add_executable(CryptoBenchmarkWindowsWorkerProcessTests
	WindowsWorkerProcessTests.cpp
)

set_target_properties(CryptoBenchmarkWindowsWorkerProcessTests
	PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-runtime"
)

target_link_libraries(CryptoBenchmarkWindowsWorkerProcessTests
	PRIVATE
		cryptobench_ipc
		cryptobench_platform_windows
		Qt6::Core
		Qt6::Network
)

add_executable(CryptoBenchmarkTestScriptedWorker
	TestScriptedWorker.cpp
)

set_target_properties(CryptoBenchmarkTestScriptedWorker
	PROPERTIES
		OUTPUT_NAME CryptoBenchmarkWorker
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-runtime"
)

target_link_libraries(CryptoBenchmarkTestScriptedWorker
	PRIVATE
		cryptobench_ipc
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkWindowsWorkerProcessTests CryptoBenchmarkTestScriptedWorker)

add_test(NAME CryptoBenchmarkWindowsWorkerProcessTests COMMAND CryptoBenchmarkWindowsWorkerProcessTests)
