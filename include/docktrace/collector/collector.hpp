#pragma once
#include <chrono>
#include <functional>
#include <vector>
#include "docktrace/model/event.hpp"

namespace docktrace::collector {

using EventCallback = std::function<void(const Event&)>;

struct CollectorOptions {
    uint32_t    target_pid{0};
    uint64_t    target_cgroup_id{0};
    std::chrono::seconds duration{30};
    bool        trace_process{true};
    bool        trace_file{true};
    bool        trace_network{true};
    bool        trace_syscall{false};
};

class ICollector {
public:
    virtual ~ICollector() = default;
    virtual bool start(const CollectorOptions& opts, EventCallback cb) = 0;
    virtual void stop() = 0;
};

} // namespace docktrace::collector
