message(STATUS "Configuring tests")

add_executable(CryptoBenchmarkTests
	CoreExecutionContractTests.cpp
	RegistryConsistencyTests.cpp
	RunnerMeasurementContractTests.cpp
	StatisticsTests.cpp
	ValidatorTests.cpp
)

target_link_libraries(CryptoBenchmarkTests
	PRIVATE
		cryptobench_core
)

add_test(NAME CryptoBenchmarkTests COMMAND CryptoBenchmarkTests)
