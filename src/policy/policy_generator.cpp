#include "docktrace/policy/policy_generator.hpp"
#include <algorithm>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <stdexcept>

namespace docktrace::policy {

namespace {
    const std::set<std::string> SENSITIVE_SYSCALLS = {
        "ptrace", "mount", "umount2", "bpf", "perf_event_open",
        "init_module", "delete_module", "setns", "unshare",
    };

    bool is_root_write(const FileObservation& f) {
        if (f.access != FileAccess::Write && f.access != FileAccess::Create) return false;
        // /tmp, /var/cache, /var/log are expected writable paths
        for (auto& prefix : {"/tmp", "/var/cache", "/var/log", "/run", "/dev"})
            if (f.path.rfind(prefix, 0) == 0) return false;
        return true;
    }
}

ProfileFormat parse_profile_format(const std::string& s) {
    if (s == "yaml")        return ProfileFormat::Yaml;
    if (s == "oci-seccomp") return ProfileFormat::OciSeccomp;
    if (s == "docker-compose") return ProfileFormat::DockerCompose;
    throw std::invalid_argument("Unknown profile format: " + s);
}

SecurityProfile generate(const Report& report) {
    SecurityProfile prof;

    // Capabilities
    prof.caps_drop = {"ALL"};
    for (auto& cap : report.capabilities.observed)
        prof.caps_add.push_back(cap);

    // Filesystem: detect any write to non-temporary location
    bool has_rootfs_write = false;
    std::set<std::string> writable;
    for (auto& f : report.files) {
        if (f.access == FileAccess::Write || f.access == FileAccess::Create) {
            if (is_root_write(f)) has_rootfs_write = true;
            // Collect writable directory
            auto dir = f.path.substr(0, f.path.rfind('/'));
            if (dir.empty()) dir = "/";
            writable.insert(dir);
        }
    }
    prof.readonly_root = !has_rootfs_write;
    prof.writable_paths = std::vector<std::string>(writable.begin(), writable.end());

    // Network
    std::set<std::pair<std::string,uint16_t>> seen_net;
    for (auto& n : report.network) {
        if (seen_net.insert({n.destination_address, n.destination_port}).second) {
            SecurityProfile::NetRule rule;
            rule.protocol    = n.protocol;
            rule.port        = n.destination_port;
            rule.destination = n.destination_address.empty() ? "any" : n.destination_address;
            prof.network_allow.push_back(rule);
        }
    }

    // Syscalls
    for (auto& [name, cnt] : report.syscalls) {
        prof.syscalls_observed.push_back(name);
        if (SENSITIVE_SYSCALLS.count(name))
            prof.syscalls_sensitive.push_back(name);
    }

    if (!report.capabilities.not_evidenced.empty()) {
        prof.warnings.push_back(
            "Some configured capabilities were not exercised during this observation run. "
            "They may still be required for error paths or startup.");
    }
    prof.warnings.push_back(
        "This profile is a suggestion based on observed behavior. Test thoroughly before enforcing.");

    return prof;
}

std::string to_yaml(const SecurityProfile& profile) {
    std::ostringstream ss;
    ss << "# Docktrace suggested security profile\n";
    ss << "# WARNING: test before enforcing\n\n";

    ss << "capabilities:\n";
    ss << "  drop:\n";
    for (auto& c : profile.caps_drop) ss << "    - " << c << "\n";
    ss << "  add:\n";
    if (profile.caps_add.empty()) ss << "    []\n";
    else for (auto& c : profile.caps_add) ss << "    - " << c << "\n";

    ss << "\nfilesystem:\n";
    ss << "  readonly_root: " << (profile.readonly_root ? "true" : "false") << "\n";
    ss << "  writable_paths:\n";
    for (auto& p : profile.writable_paths) ss << "    - " << p << "\n";

    ss << "\nnetwork:\n";
    ss << "  allow:\n";
    for (auto& r : profile.network_allow) {
        ss << "    - protocol: " << r.protocol << "\n";
        ss << "      port: " << r.port << "\n";
        ss << "      destination: " << r.destination << "\n";
    }

    ss << "\nsyscalls_observed:\n";
    for (auto& s : profile.syscalls_observed) ss << "  - " << s << "\n";

    if (!profile.syscalls_sensitive.empty()) {
        ss << "\nsyscalls_sensitive_detected:\n";
        for (auto& s : profile.syscalls_sensitive)
            ss << "  - " << s << "  # review required\n";
    }

    ss << "\nwarnings:\n";
    for (auto& w : profile.warnings) ss << "  - \"" << w << "\"\n";

    return ss.str();
}

std::string to_oci_seccomp(const SecurityProfile& profile, const Report& /*report*/) {
    using json = nlohmann::json;
    json j;
    j["defaultAction"]  = "SCMP_ACT_ERRNO";
    j["architectures"]  = {"SCMP_ARCH_X86_64"};

    json allowed = json::array();
    for (auto& s : profile.syscalls_observed)
        allowed.push_back(s);

    j["syscalls"] = json::array();
    if (!allowed.empty()) {
        j["syscalls"].push_back({
            {"names",  allowed},
            {"action", "SCMP_ACT_ALLOW"},
        });
    }
    j["_comment"] = "EXPERIMENTAL - generated by docktrace. Validate before use.";
    return j.dump(2);
}

} // namespace docktrace::policy
