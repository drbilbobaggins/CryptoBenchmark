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

add_executable(CryptoBenchmarkResultDocumentTests
	ResultDocumentTests.cpp
)

target_link_libraries(CryptoBenchmarkResultDocumentTests
	PRIVATE
		cryptobench_application
)

add_test(NAME CryptoBenchmarkResultDocumentTests COMMAND CryptoBenchmarkResultDocumentTests)

add_executable(CryptoBenchmarkBenchmarkConfigJsonTests
	BenchmarkConfigJsonTests.cpp
)

target_link_libraries(CryptoBenchmarkBenchmarkConfigJsonTests
	PRIVATE
		cryptobench_application
)

add_test(NAME CryptoBenchmarkBenchmarkConfigJsonTests COMMAND CryptoBenchmarkBenchmarkConfigJsonTests)

add_executable(CryptoBenchmarkResultJsonMappingTests
	ResultJsonMappingTests.cpp
)

target_link_libraries(CryptoBenchmarkResultJsonMappingTests
	PRIVATE
		cryptobench_application
)

add_test(NAME CryptoBenchmarkResultJsonMappingTests COMMAND CryptoBenchmarkResultJsonMappingTests)

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

add_executable(CryptoBenchmarkBackendHashXofIntegrationTests
	BackendHashXofIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendHashXofIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendHashXofIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendHashXofIntegrationTests
	COMMAND CryptoBenchmarkBackendHashXofIntegrationTests
)

add_executable(CryptoBenchmarkBackendAeadIntegrationTests
	BackendAeadIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendAeadIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendAeadIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendAeadIntegrationTests
	COMMAND CryptoBenchmarkBackendAeadIntegrationTests
)

add_executable(CryptoBenchmarkBackendLifecycleIntegrationTests
	BackendLifecycleIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendLifecycleIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendLifecycleIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendLifecycleIntegrationTests
	COMMAND CryptoBenchmarkBackendLifecycleIntegrationTests
)

add_executable(CryptoBenchmarkBackendKeyEstablishmentIntegrationTests
	BackendKeyEstablishmentIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendKeyEstablishmentIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendKeyEstablishmentIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendKeyEstablishmentIntegrationTests
	COMMAND CryptoBenchmarkBackendKeyEstablishmentIntegrationTests
)

add_executable(CryptoBenchmarkBackendClassicSignatureIntegrationTests
	BackendClassicSignatureIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendClassicSignatureIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendClassicSignatureIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendClassicSignatureIntegrationTests
	COMMAND CryptoBenchmarkBackendClassicSignatureIntegrationTests
)

add_executable(CryptoBenchmarkBackendModernSignatureIntegrationTests
	BackendModernSignatureIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendModernSignatureIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendModernSignatureIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendModernSignatureIntegrationTests
	COMMAND CryptoBenchmarkBackendModernSignatureIntegrationTests
)

add_executable(CryptoBenchmarkBackendSlhDsaIntegrationTests
	BackendSlhDsaIntegrationTests.cpp
)

target_link_libraries(CryptoBenchmarkBackendSlhDsaIntegrationTests
	PRIVATE
		cryptobench_application
		Qt6::Core
		Qt6::Network
)

add_dependencies(CryptoBenchmarkBackendSlhDsaIntegrationTests CryptoBenchmarkWorker)

add_test(NAME CryptoBenchmarkBackendSlhDsaFastIntegrationTests
	COMMAND CryptoBenchmarkBackendSlhDsaIntegrationTests --fast
)

set_tests_properties(CryptoBenchmarkBackendSlhDsaFastIntegrationTests
	PROPERTIES
		TIMEOUT 120
)

add_test(NAME CryptoBenchmarkBackendSlhDsaSlowIntegrationTests
	COMMAND CryptoBenchmarkBackendSlhDsaIntegrationTests --slow
)

set_tests_properties(CryptoBenchmarkBackendSlhDsaSlowIntegrationTests
	PROPERTIES
		LABELS slow
		TIMEOUT 150
)

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

add_executable(CryptoBenchmarkMlDsaTests
	MlDsaAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkMlDsaTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkMlDsaTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkMlDsaTests COMMAND CryptoBenchmarkMlDsaTests)

add_executable(CryptoBenchmarkSlhDsaTests
	SlhDsaAdapterTests.cpp
)

target_link_libraries(CryptoBenchmarkSlhDsaTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkSlhDsaTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkSlhDsaTests COMMAND CryptoBenchmarkSlhDsaTests)

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

add_executable(CryptoBenchmarkAdapterClosureTests
	AdapterClosureTests.cpp
)

target_link_libraries(CryptoBenchmarkAdapterClosureTests
	PRIVATE
		cryptobench_crypto
)

target_include_directories(CryptoBenchmarkAdapterClosureTests
	PRIVATE
		${CMAKE_SOURCE_DIR}/src/crypto
)

add_test(NAME CryptoBenchmarkAdapterClosureTests COMMAND CryptoBenchmarkAdapterClosureTests)

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

add_executable(CryptoBenchmarkGuiTests
	MainWindowGuiTests.cpp
	${CMAKE_SOURCE_DIR}/src/gui/MainWindow.cpp
	${CMAKE_SOURCE_DIR}/src/gui/MainWindow.h
	${CMAKE_SOURCE_DIR}/src/gui/MainWindow.ui
)

set_target_properties(CryptoBenchmarkGuiTests
	PROPERTIES
		AUTOMOC ON
		AUTOUIC ON
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-runtime"
)

target_link_libraries(CryptoBenchmarkGuiTests
	PRIVATE
		cryptobench_application
		Qt6::Widgets
)

add_dependencies(CryptoBenchmarkGuiTests CryptoBenchmarkTestScriptedWorker)

add_test(NAME CryptoBenchmarkGuiTests COMMAND CryptoBenchmarkGuiTests)

set_tests_properties(CryptoBenchmarkGuiTests
	PROPERTIES
	ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
	TIMEOUT 120
)
