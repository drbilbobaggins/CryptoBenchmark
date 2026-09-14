add_executable(CryptoBenchmark
    main.cpp
)

target_link_libraries(CryptoBenchmark
    PRIVATE
        cryptobench_application
        Qt6::Widgets
)
