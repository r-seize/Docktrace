#include <CLI/CLI.hpp>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace docktrace::cli {

namespace {
    struct ValidationResult {
        bool ok{true};
        std::vector<std::string> errors;
        std::vector<std::string> warnings;

        void error(const std::string& msg) { errors.push_back(msg); ok = false; }
        void warn(const std::string& msg)  { warnings.push_back(msg); }
    };

    // Not an exhaustive syscall table — a curated list of common Linux
    // x86_64 syscalls used to flag obviously unknown/misspelled names.
    // Absence from this list is a warning, not an error: new or
    // architecture-specific syscalls legitimately won't be in it.
    const std::set<std::string>& known_syscalls() {
        static const std::set<std::string> s = {
            "read","write","open","openat","close","stat","fstat","lstat","newfstatat",
            "statx","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction",
            "rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev",
            "access","pipe","pipe2","select","sched_yield","mremap","msync","mincore",
            "madvise","shmget","shmat","shmctl","dup","dup2","dup3","pause","nanosleep",
            "clock_nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket",
            "connect","accept","accept4","sendto","recvfrom","sendmsg","recvmsg","shutdown",
            "bind","listen","getsockname","getpeername","socketpair","setsockopt",
            "getsockopt","clone","clone3","fork","vfork","execve","exit","wait4","waitid",
            "kill","tgkill","tkill","uname","semget","semop","semctl","shmdt","msgget",
            "msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate",
            "ftruncate","getdents64","getcwd","chdir","fchdir","rename","renameat",
            "renameat2","mkdir","mkdirat","rmdir","creat","link","linkat","unlink",
            "unlinkat","symlink","symlinkat","readlink","readlinkat","chmod","fchmod",
            "fchmodat","chown","fchown","lchown","fchownat","umask","gettimeofday",
            "getrlimit","setrlimit","getrusage","sysinfo","times","ptrace","getuid",
            "syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid",
            "getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid",
            "getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid",
            "capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo",
            "rt_sigsuspend","sigaltstack","utime","mknod","mknodat","personality",
            "ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam",
            "sched_getparam","sched_setscheduler","sched_getscheduler",
            "sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval",
            "mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root",
            "prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday",
            "mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname",
            "iopl","ioperm","init_module","delete_module","quotactl","gettid","readahead",
            "setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr",
            "listxattr","llistxattr","flistxattr","removexattr","lremovexattr",
            "fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity",
            "set_thread_area","io_setup","io_destroy","io_getevents","io_submit",
            "io_cancel","get_thread_area","lookup_dcookie","epoll_create","remap_file_pages",
            "getdents","set_tid_address","restart_syscall","semtimedop","fadvise64",
            "timer_create","timer_settime","timer_gettime","timer_getoverrun",
            "timer_delete","clock_settime","clock_gettime","clock_getres","exit_group",
            "epoll_wait","epoll_ctl","tgkill","utimes","mbind","set_mempolicy",
            "get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive",
            "mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key",
            "keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch",
            "inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat",
            "futimesat","unlinkat","renameat","linkat","symlinkat","readlinkat",
            "fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list",
            "get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages",
            "utimensat","epoll_pwait","signalfd","timerfd_create","eventfd",
            "fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4",
            "eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev",
            "rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init",
            "fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at",
            "clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv",
            "process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr",
            "renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf",
            "execveat","userfaultfd","membarrier","mlock2","copy_file_range",
            "preadv2","pwritev2","pkey_mprotect","pkey_alloc","pkey_free","statx",
            "io_pgetevents","rseq","pidfd_send_signal","io_uring_setup",
            "io_uring_enter","io_uring_register","pidfd_open","clone3","close_range",
            "openat2","pidfd_getfd","faccessat2","process_madvise","epoll_pwait2",
            "landlock_create_ruleset","landlock_add_rule","landlock_restrict_self",
            "process_mrelease",
        };
        return s;
    }

    // High-risk syscalls: usually unnecessary for ordinary application
    // workloads and frequently relevant to container escape techniques.
    const std::set<std::string>& high_risk_syscalls() {
        static const std::set<std::string> s = {
            "mount","umount2","bpf","ptrace","unshare","setns","init_module",
            "delete_module","keyctl","add_key","request_key","kexec_load",
            "kexec_file_load","perf_event_open","pivot_root","reboot","swapon",
            "swapoff","iopl","ioperm","acct","quotactl","personality","syslog",
        };
        return s;
    }

    static const std::vector<std::string> VALID_ARCHS = {
        "SCMP_ARCH_X86","SCMP_ARCH_X86_64","SCMP_ARCH_X32","SCMP_ARCH_ARM",
        "SCMP_ARCH_AARCH64","SCMP_ARCH_MIPS","SCMP_ARCH_MIPS64",
        "SCMP_ARCH_MIPSEL","SCMP_ARCH_MIPSEL64","SCMP_ARCH_PPC",
        "SCMP_ARCH_PPC64","SCMP_ARCH_PPC64LE","SCMP_ARCH_S390",
        "SCMP_ARCH_S390X","SCMP_ARCH_RISCV64",
    };

    ValidationResult validate_seccomp_json(const nlohmann::json& j) {
        ValidationResult r;
        if (!j.contains("defaultAction"))
            r.error("Missing 'defaultAction' field");
        if (!j.contains("syscalls"))
            r.error("Missing 'syscalls' array");
        else if (!j["syscalls"].is_array())
            r.error("'syscalls' must be an array");
        else {
            std::set<std::string> seen_high_risk;
            for (auto& sc : j["syscalls"]) {
                if (!sc.contains("names") || !sc.contains("action")) {
                    r.error("Each syscall entry needs 'names' and 'action'");
                    continue;
                }
                if (!sc["action"].is_string()) {
                    r.error("'action' must be a string (e.g. \"SCMP_ACT_ALLOW\")");
                    continue;
                }
                if (!sc["names"].is_array()) {
                    r.error("'names' must be an array of syscall name strings");
                    continue;
                }
                std::string action = sc["action"].get<std::string>();
                for (auto& name_j : sc["names"]) {
                    if (!name_j.is_string()) {
                        r.error("Each entry in 'names' must be a syscall name string, not a number/bool/object");
                        continue;
                    }
                    std::string name = name_j.get<std::string>();
                    if (!known_syscalls().count(name))
                        r.warn(fmt::format(
                            "Syscall '{}' is not recognized — check for a typo, "
                            "otherwise this rule is silently ineffective", name));
                    if (action == "SCMP_ACT_ALLOW" && high_risk_syscalls().count(name))
                        seen_high_risk.insert(name);
                }
            }
            for (auto& name : seen_high_risk)
                r.warn(fmt::format(
                    "'{}' is allowed without an explicit justification — "
                    "confirm the workload genuinely needs it", name));
        }
        if (!j.contains("architectures"))
            r.warn("No 'architectures' specified — profile may not be portable");
        else if (!j["architectures"].is_array())
            r.error("'architectures' must be an array of strings");
        else {
            for (auto& a_j : j["architectures"]) {
                if (!a_j.is_string()) {
                    r.error("Each entry in 'architectures' must be a string");
                    continue;
                }
                std::string a = a_j.get<std::string>();
                bool found = false;
                for (auto& va : VALID_ARCHS) if (va == a) { found = true; break; }
                if (!found) r.warn(fmt::format("Unknown architecture: {}", a));
            }
        }

        static const std::vector<std::string> VALID_ACTIONS = {
            "SCMP_ACT_ALLOW","SCMP_ACT_ERRNO","SCMP_ACT_KILL","SCMP_ACT_TRAP",
            "SCMP_ACT_LOG","SCMP_ACT_TRACE","SCMP_ACT_NOTIFY"
        };
        if (j.contains("defaultAction")) {
            if (!j["defaultAction"].is_string()) {
                r.error("'defaultAction' must be a string");
            } else {
                std::string da = j["defaultAction"].get<std::string>();
                bool found = false;
                for (auto& a : VALID_ACTIONS) if (a == da) { found = true; break; }
                if (!found) r.error(fmt::format("Unknown defaultAction: {}", da));
                else if (da == "SCMP_ACT_ALLOW")
                    r.warn("defaultAction=SCMP_ACT_ALLOW is unsafe for production: "
                           "every syscall not explicitly handled is permitted");
            }
        }
        return r;
    }

    ValidationResult validate_yaml_profile(const YAML::Node& y) {
        ValidationResult r;
        if (!y["capabilities"]) r.warn("No 'capabilities' section");
        if (!y["filesystem"])   r.warn("No 'filesystem' section");
        if (!y["network"])      r.warn("No 'network' section");
        if (y["capabilities"]) {
            if (!y["capabilities"]["drop"]) r.warn("capabilities.drop not set (recommend: drop ALL)");
        }
        return r;
    }
}

void register_validate(CLI::App& app) {
    auto* sub   = app.add_subcommand("validate", "Validate a security profile file");
    auto input  = std::make_shared<std::string>();
    auto format = std::make_shared<std::string>("auto");

    sub->add_option("-i,--input",  *input,  "Profile file to validate")->required();
    sub->add_option("-f,--format", *format, "Format: auto|oci-seccomp|yaml");

    sub->callback([=]() {
        std::ifstream f(*input);
        if (!f) throw std::runtime_error("Cannot open: " + *input);

        // Detect format
        std::string detected = *format;
        if (detected == "auto") {
            if (input->size() >= 5 && input->substr(input->size()-5) == ".json")
                detected = "oci-seccomp";
            else
                detected = "yaml";
        }

        ValidationResult result;
        std::cout << fmt::format("Validating {} as {}...\n\n", *input, detected);

        if (detected == "oci-seccomp") {
            try {
                auto j = nlohmann::json::parse(f);
                result = validate_seccomp_json(j);
            } catch (const std::exception& ex) {
                result.error(fmt::format("JSON parse error: {}", ex.what()));
            }
        } else {
            try {
                auto y = YAML::Load(f);
                result = validate_yaml_profile(y);
            } catch (const std::exception& ex) {
                result.error(fmt::format("YAML parse error: {}", ex.what()));
            }
        }

        for (auto& e : result.errors)   std::cout << fmt::format("  [ERROR]   {}\n", e);
        for (auto& w : result.warnings) std::cout << fmt::format("  [WARNING] {}\n", w);

        if (result.ok)
            std::cout << "\nStatus: VALID\n";
        else {
            std::cout << "\nStatus: INVALID\n";
            throw std::runtime_error("profile validation failed");
        }
    });
}

} // namespace docktrace::cli
