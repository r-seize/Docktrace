add_executable(docktrace_tests
    main_test.cpp
    test_aggregator.cpp
    test_renderer.cpp
    test_policy.cpp
    test_diff.cpp
    test_io.cpp
    test_cgroup_filter.cpp
    test_proc_collector.cpp
)

target_link_libraries(docktrace_tests PRIVATE
    docktrace_lib
    Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(docktrace_tests)
