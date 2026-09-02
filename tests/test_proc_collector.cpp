#include <catch2/catch_all.hpp>
#include "docktrace/collector/proc_collector.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <vector>

using namespace docktrace;
using namespace docktrace::collector;

TEST_CASE("ProcCollector - scans own PID and emits ProcessExec", "[proc]") {
    ProcCollector collector;
    CollectorOptions opts;
    opts.target_pid = static_cast<uint32_t>(getpid());
    opts.duration   = std::chrono::seconds(1);

    std::vector<Event> events;
    collector.start(opts, [&](const Event& e) { events.push_back(e); });

    // Should emit at least one ProcessExec for our own process
    bool found_exec = false;
    for (auto& e : events)
        if (e.type == EventType::ProcessExec) { found_exec = true; break; }
    CHECK(found_exec);
}

TEST_CASE("ProcCollector - returns false for PID 0", "[proc]") {
    ProcCollector collector;
    CollectorOptions opts;
    opts.target_pid = 0;
    opts.duration   = std::chrono::seconds(0);

    bool result = collector.start(opts, [](const Event&){});
    CHECK(result == false);
}

TEST_CASE("ProcCollector - emits FileOpen for open file descriptors", "[proc]") {
    ProcCollector collector;
    CollectorOptions opts;
    opts.target_pid = static_cast<uint32_t>(getpid());
    opts.duration   = std::chrono::seconds(1);

    std::vector<Event> events;
    collector.start(opts, [&](const Event& e) { events.push_back(e); });

    bool found_file = false;
    for (auto& e : events)
        if (e.type == EventType::FileOpen) { found_file = true; break; }
    CHECK(found_file);
}
