#include <CLI/CLI.hpp>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace docktrace::cli {

namespace {
    bool file_exists(const std::string& p) { struct stat s{}; return stat(p.c_str(), &s) == 0; }
    bool readable(const std::string& p) { return std::ifstream(p).good(); }

    void check(const std::string& label, bool ok, const std::string& hint = "") {
        // Use ANSI colours if stdout is a tty
        bool colour = isatty(STDOUT_FILENO);
        std::string status = ok
            ? (colour ? "\033[32mOK\033[0m     " : "OK     ")
            : (colour ? "\033[33mWARNING\033[0m" : "WARNING");
        std::cout << fmt::format("  {:<40} {}\n", label, status);
        if (!ok && !hint.empty())
            std::cout << fmt::format("    -> {}\n", hint);
    }

    void check_err(const std::string& label, bool ok, const std::string& hint = "") {
        bool colour = isatty(STDOUT_FILENO);
        std::string status = ok
            ? (colour ? "\033[32mOK\033[0m     " : "OK     ")
            : (colour ? "\033[31mERROR\033[0m  " : "ERROR  ");
        std::cout << fmt::format("  {:<40} {}\n", label, status);
        if (!ok && !hint.empty())
            std::cout << fmt::format("    -> {}\n", hint);
    }
}

void register_doctor(CLI::App& app) {
    app.add_subcommand("doctor", "Check system compatibility for docktrace")
       ->callback([]() {
        struct utsname u{};
        uname(&u);

        std::cout << "=== docktrace doctor ===\n\n";
        std::cout << fmt::format("  Kernel:    {}\n", u.release);
        std::cout << fmt::format("  Arch:      {}\n", u.machine);
        std::cout << fmt::format("  User:      {}\n\n", geteuid() == 0 ? "root" : "not root");

        std::cout << "[ Kernel / BPF ]\n";
        check_err("BTF (/sys/kernel/btf/vmlinux)",
            file_exists("/sys/kernel/btf/vmlinux"),
            "Enable CONFIG_DEBUG_INFO_BTF in kernel config");
        check("BPF filesystem (/sys/fs/bpf)",
            file_exists("/sys/fs/bpf"),
            "Run: mount -t bpf bpf /sys/fs/bpf");
        check("/proc filesystem",
            readable("/proc/self/status"), "");

        std::cout << "\n[ Privileges ]\n";
        check("Running as root",
            geteuid() == 0,
            "Run: sudo docktrace observe ...  or grant CAP_BPF + CAP_PERFMON");

        // Check unprivileged BPF setting
        std::ifstream ubpf("/proc/sys/kernel/unprivileged_bpf_disabled");
        int ubpf_val = -1;
        if (ubpf) ubpf >> ubpf_val;
        check("Unprivileged BPF allowed",
            ubpf_val == 0,
            "echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled  (or run as root)");

        std::cout << "\n[ Container runtimes ]\n";
        check("Docker socket (/var/run/docker.sock)",
            file_exists("/var/run/docker.sock"),
            "Start Docker: sudo systemctl start docker");
        check("containerd socket (/run/containerd/containerd.sock)",
            file_exists("/run/containerd/containerd.sock"),
            "Start containerd: sudo systemctl start containerd");

        std::cout << "\n[ Build / tools ]\n";
        // Check if this binary was compiled with eBPF support
#ifdef DOCKTRACE_EBPF_ENABLED
        check("eBPF support compiled in", true, "");
#else
        check("eBPF support compiled in", false,
            "Rebuild: cmake -DDOCKTRACE_ENABLE_EBPF=ON (needs clang + libbpf-dev)");
#endif

        // Check tools useful for development (use PATH search, no system())
        auto has_cmd = [](const char* cmd) -> bool {
            const char* path_env = getenv("PATH");
            if (!path_env) return false;
            std::string path(path_env);
            std::istringstream ss(path);
            std::string dir;
            while (std::getline(ss, dir, ':')) {
                struct stat st{};
                if (stat((dir + "/" + cmd).c_str(), &st) == 0 &&
                    (st.st_mode & S_IXUSR)) return true;
            }
            return false;
        };
        check("clang available",   has_cmd("clang"),   "sudo apt install clang");
        check("bpftool available", has_cmd("bpftool"), "sudo apt install linux-tools-common");

        std::cout << "\n[ Quick test ]\n";
        std::cout << "  docktrace report --input examples/sample-report.json\n";
        std::cout << "  sudo docktrace observe --pid $(pgrep -n bash) --duration 5s\n";
        std::cout << "  sudo docktrace observe --container <name> --duration 30s -o report.json\n\n";
    });
}

} // namespace docktrace::cli
