#pragma once
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace docktrace::collector {

// Manages cgroup and PID-namespace based filtering for events.
struct CgroupFilter {
    uint64_t                       target_cgroup_id{0};   // 0 = accept all
    uint64_t                       target_pid_ns{0};       // 0 = accept all
    std::unordered_set<uint32_t>   known_pids;

    bool matches(uint64_t cgroup_id, uint32_t pid) const;
    void add_pid(uint32_t pid);
    void clear();

    // Build from a root PID: walks /proc to collect all children
    static CgroupFilter from_pid(uint32_t root_pid);
};

} // namespace docktrace::collector
