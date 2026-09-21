add_executable(CryptoBenchmark
    main.cpp
    MainWindow.cpp
    MainWindow.h
    MainWindow.ui
)

set_target_properties(CryptoBenchmark PROPERTIES
    AUTOUIC ON
    AUTOMOC ON
)

target_link_libraries(CryptoBenchmark
    PRIVATE
        cryptobench_application
        Qt6::Widgets
)
