message(STATUS "Configuring tests")

add_executable(CryptoBenchmarkTests
	RegistryConsistencyTests.cpp
	ValidatorTests.cpp
)

target_link_libraries(CryptoBenchmarkTests
	PRIVATE
		cryptobench_core
)

add_test(NAME CryptoBenchmarkTests COMMAND CryptoBenchmarkTests)
