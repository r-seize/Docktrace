#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace docktrace {

struct ContainerInfo {
    std::string name;
    std::string id;
    std::string image;
    std::string runtime;
    uint32_t    root_pid{0};
    uint64_t    cgroup_id{0};
    std::string pid_namespace;
    std::string net_namespace;
    std::string rootfs;
    std::string user;
    bool        privileged{false};
    bool        readonly_rootfs{false};
    std::vector<std::string> capabilities_configured;
    std::vector<std::string> volumes;
    std::string seccomp_profile;
};

} // namespace docktrace
