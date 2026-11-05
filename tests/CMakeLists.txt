add_executable(docktrace_tests
    main_test.cpp
    test_aggregator.cpp
    test_renderer.cpp
    test_policy.cpp
    test_diff.cpp
    test_io.cpp
    test_cgroup_filter.cpp
    test_proc_collector.cpp
    test_e2e.cpp
)

target_link_libraries(docktrace_tests PRIVATE
    docktrace_lib
    Catch2::Catch2WithMain
)

# test_e2e.cpp shells out to the real docktrace binary and the bundled
# sample report rather than re-implementing CLI parsing logic.
target_compile_definitions(docktrace_tests PRIVATE
    DOCKTRACE_BIN="$<TARGET_FILE:docktrace>"
    DOCKTRACE_EXAMPLES_DIR="${CMAKE_SOURCE_DIR}/examples"
)

include(CTest)
include(Catch)
catch_discover_tests(docktrace_tests)
