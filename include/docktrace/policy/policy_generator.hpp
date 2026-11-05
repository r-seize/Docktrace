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

// Controls how permissive a generated seccomp profile is relative to the
// observed syscalls. See docs/THREAT-MODEL.md for the rationale.
enum class Strictness {
    // docktrace's curated baseline (a representative subset of syscalls
    // generally considered safe for containerized workloads) filtered down
    // to syscalls that were actually observed or are vital for process
    // startup/exit. Recommended default: closer to "docker default minus
    // syscalls never observed" than to a hand-picked minimal list.
    Conservative,
    // Only syscalls observed during this run, plus the small set required
    // for a process to start and exit cleanly. Smallest attack surface, but
    // more likely to break on code paths not exercised during observation.
    Minimal,
    // Same allow-set as Conservative, but defaultAction is SCMP_ACT_LOG
    // instead of SCMP_ACT_ERRNO: nothing is blocked, everything outside the
    // allow-set is logged. Intended for a first production rollout.
    Audit,
};

Strictness parse_strictness(const std::string& s);

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

// `use_docker_default_base`: when true (default), the allow-set adds in
// docktrace's curated baseline syscalls that are either observed or vital
// for startup — it is a union with what was observed, not a cap on it:
// any syscall actually observed is always kept even if it falls outside
// the curated baseline. This is what keeps "minimal"-looking profiles
// from accidentally dropping syscalls needed by the dynamic linker,
// signal handling, etc. that just weren't exercised as directly observed
// events; it does not bound the final allow-set to the curated list.
std::string to_oci_seccomp(const SecurityProfile& profile, const Report& report,
                            Strictness strictness = Strictness::Conservative,
                            bool use_docker_default_base = true);

// Human-readable explanation of why each syscall/capability ended up in (or
// out of) the profile. Used by `docktrace profile --explain`.
std::string explain(const SecurityProfile& profile, const Report& report,
                     Strictness strictness, bool use_docker_default_base);

} // namespace docktrace::policy
