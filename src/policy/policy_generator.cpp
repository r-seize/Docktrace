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

    // Syscalls required for a process to start, allocate memory, handle
    // signals, and exit cleanly — regardless of what the observation window
    // happened to exercise. Dropping any of these tends to produce profiles
    // that look minimal but break on the very first run under enforcement.
    const std::set<std::string> VITAL_SYSCALLS = {
        "exit", "exit_group", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
        "sigaltstack", "futex", "arch_prctl", "brk", "mmap", "munmap", "mprotect",
        "access", "openat", "open", "close", "read", "write", "fstat", "stat",
        "lseek", "prlimit64", "getrandom", "set_tid_address", "set_robust_list",
        "clone", "clone3", "execve", "wait4", "getpid", "gettid", "getuid",
        "geteuid", "getgid", "getegid", "rseq", "pread64", "pwrite64",
        "readlink", "readlinkat", "poll", "epoll_create1", "epoll_ctl",
        "epoll_wait", "epoll_pwait", "pipe2", "dup", "dup2", "dup3",
    };

    // A curated, representative subset of syscalls generally considered
    // safe for containerized userspace workloads (loosely modeled on
    // Docker's default seccomp profile, but intentionally not a byte-for-
    // byte copy of it — treat this as docktrace's own conservative
    // baseline, not as a certified equivalent of any specific runtime's
    // default profile).
    const std::set<std::string> DOCKER_DEFAULT_BASELINE = []{
        std::set<std::string> s = VITAL_SYSCALLS;
        for (auto name : {
            "accept", "accept4", "bind", "connect", "listen", "socket",
            "socketpair", "getsockname", "getpeername", "getsockopt",
            "setsockopt", "shutdown", "sendto", "recvfrom", "sendmsg",
            "recvmsg", "send", "recv",
            "chdir", "fchdir", "getcwd", "mkdir", "mkdirat", "rmdir",
            "unlink", "unlinkat", "rename", "renameat", "renameat2",
            "link", "linkat", "symlink", "symlinkat", "chmod", "fchmod",
            "fchmodat", "chown", "fchown", "fchownat", "lchown", "umask",
            "truncate", "ftruncate", "fallocate", "fsync", "fdatasync",
            "statfs", "fstatfs", "statx", "newfstatat", "getdents64",
            "ioctl", "fcntl", "flock",
            "sched_yield", "sched_getaffinity", "sched_setaffinity",
            "nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres",
            "gettimeofday", "time", "times", "sysinfo", "uname",
            "getrlimit", "setrlimit", "getpriority", "setpriority",
            "getgroups", "setgroups", "getresuid", "getresgid",
            "capget", "capset", "prctl", "madvise", "mremap", "mlock",
            "munlock", "membarrier", "eventfd2", "signalfd4", "pipe",
            "vfork", "fork", "wait3", "waitid", "kill", "tgkill", "tkill",
            "restart_syscall", "exit_group",
        }) s.insert(name);
        return s;
    }();

    bool is_root_write(const FileObservation& f) {
        if (f.access != FileAccess::Write && f.access != FileAccess::Create) return false;
        // /tmp, /var/cache, /var/log are expected writable paths
        for (auto& prefix : {"/tmp", "/var/cache", "/var/log", "/run", "/dev"})
            if (f.path.rfind(prefix, 0) == 0) return false;
        return true;
    }

    // Computes the final allow-set for a given strictness/base combination.
    std::set<std::string> compute_allowlist(const std::vector<std::string>& observed,
                                             Strictness strictness,
                                             bool use_docker_default_base)
    {
        std::set<std::string> observed_set(observed.begin(), observed.end());

        if (strictness == Strictness::Minimal || !use_docker_default_base) {
            // Smallest surface: only what was actually seen, plus the bare
            // minimum needed to start/exit a process.
            std::set<std::string> allow = observed_set;
            allow.insert(VITAL_SYSCALLS.begin(), VITAL_SYSCALLS.end());
            return allow;
        }

        // Conservative / Audit: "docker-default minus syscalls never
        // observed", but never below the vital set — i.e. keep a syscall
        // from the baseline if it was observed OR it's vital for startup.
        std::set<std::string> allow;
        for (auto& name : DOCKER_DEFAULT_BASELINE)
            if (observed_set.count(name) || VITAL_SYSCALLS.count(name))
                allow.insert(name);
        // Still allow anything observed that isn't in the curated baseline
        // (e.g. an uncommon syscall the workload genuinely needs) rather
        // than silently dropping it.
        allow.insert(observed_set.begin(), observed_set.end());
        return allow;
    }
}

ProfileFormat parse_profile_format(const std::string& s) {
    if (s == "yaml")        return ProfileFormat::Yaml;
    if (s == "oci-seccomp") return ProfileFormat::OciSeccomp;
    if (s == "docker-compose") return ProfileFormat::DockerCompose;
    throw std::invalid_argument("Unknown profile format: " + s);
}

Strictness parse_strictness(const std::string& s) {
    if (s == "conservative") return Strictness::Conservative;
    if (s == "minimal")      return Strictness::Minimal;
    if (s == "audit")        return Strictness::Audit;
    throw std::invalid_argument("Unknown strictness: " + s + " (expected conservative|minimal|audit)");
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

std::string to_oci_seccomp(const SecurityProfile& profile, const Report& /*report*/,
                            Strictness strictness, bool use_docker_default_base)
{
    using json = nlohmann::json;
    json j;
    j["defaultAction"]  = (strictness == Strictness::Audit) ? "SCMP_ACT_LOG" : "SCMP_ACT_ERRNO";
    j["architectures"]  = {"SCMP_ARCH_X86_64"};

    auto allow_set = compute_allowlist(profile.syscalls_observed, strictness, use_docker_default_base);

    json allowed = json::array();
    for (auto& s : allow_set)
        allowed.push_back(s);

    j["syscalls"] = json::array();
    if (!allowed.empty()) {
        j["syscalls"].push_back({
            {"names",  allowed},
            {"action", "SCMP_ACT_ALLOW"},
        });
    }

    const char* strictness_name =
        strictness == Strictness::Minimal ? "minimal" :
        strictness == Strictness::Audit   ? "audit"   : "conservative";
    j["_comment"] = fmt::format(
        "Generated by docktrace (strictness={}, base={}). EXPERIMENTAL — "
        "validate and test thoroughly before enforcing in production.",
        strictness_name, use_docker_default_base ? "docker-default" : "none");
    return j.dump(2);
}

std::string explain(const SecurityProfile& profile, const Report& report,
                     Strictness strictness, bool use_docker_default_base)
{
    std::ostringstream ss;
    auto allow_set = compute_allowlist(profile.syscalls_observed, strictness, use_docker_default_base);
    std::set<std::string> observed_set(profile.syscalls_observed.begin(), profile.syscalls_observed.end());

    ss << "Capabilities:\n";
    for (auto& c : profile.caps_add)
        ss << fmt::format("  + {:<24} observed in use during this run\n", c);
    for (auto& c : report.capabilities.not_evidenced)
        ss << fmt::format("  - {:<24} configured but never exercised — dropped\n", c);

    ss << "\nSyscalls kept (" << allow_set.size() << "):\n";
    for (auto& name : allow_set) {
        std::string reason;
        if (observed_set.count(name))                reason = "observed during this run";
        else if (VITAL_SYSCALLS.count(name))          reason = "vital for clean process startup/exit";
        else                                          reason = "part of docktrace's curated baseline";
        if (SENSITIVE_SYSCALLS.count(name))
            reason += " (sensitive — review before trusting this profile)";
        ss << fmt::format("  {:<20} {}\n", name, reason);
    }

    if (strictness == Strictness::Audit)
        ss << "\ndefaultAction is SCMP_ACT_LOG: nothing is blocked, deviations from the "
              "allow-set are logged for review before switching to enforcement.\n";

    return ss.str();
}

} // namespace docktrace::policy
