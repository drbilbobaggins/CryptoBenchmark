message(STATUS "Configuring tests")

add_executable(CryptoBenchmarkTests
	CoreExecutionContractTests.cpp
	CoreResultModelTests.cpp
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
