add_executable(CryptoBenchmark
    main.cpp
    CanonicalBenchmarkSelection.cpp
    CanonicalBenchmarkSelection.h
    CreatorRowWidget.cpp
    CreatorRowWidget.h
    CreatorRowState.h
    BatchCreatorWidget.cpp
    BatchCreatorWidget.h
    BatchRuntimeEstimatePresentation.cpp
    BatchRuntimeEstimatePresentation.h
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
