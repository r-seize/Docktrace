#pragma once
#include <string>
#include "docktrace/model/report.hpp"

namespace docktrace::policy {

enum class ProfileFormat {
    Yaml,
    OciSeccomp,
    DockerCompose,
};

ProfileFormat parse_profile_format(const std::string& s);

struct SecurityProfile {
    // Capabilities
    std::vector<std::string> caps_drop;
    std::vector<std::string> caps_add;

    // Filesystem
    bool                     readonly_root{false};
    std::vector<std::string> writable_paths;

    // Network
    struct NetRule {
        std::string protocol;
        uint16_t    port{0};
        std::string destination;
    };
    std::vector<NetRule> network_allow;

    // Syscalls (observed, for informational use)
    std::vector<std::string> syscalls_observed;
    std::vector<std::string> syscalls_sensitive;

    std::vector<std::string> warnings;
};

SecurityProfile generate(const Report& report);

std::string to_yaml(const SecurityProfile& profile);
std::string to_oci_seccomp(const SecurityProfile& profile, const Report& report);

} // namespace docktrace::policy
