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
