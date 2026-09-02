#include <CLI/CLI.hpp>
#include <memory>
#include "docktrace/container/oci_resolver.hpp"
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h>

namespace docktrace::cli {

namespace {
    void print_info(const ContainerInfo& info) {
        std::cout << fmt::format("Name:        {}\n", info.name);
        std::cout << fmt::format("ID:          {}\n", info.id);
        std::cout << fmt::format("Image:       {}\n", info.image);
        std::cout << fmt::format("Runtime:     {}\n", info.runtime);
        std::cout << fmt::format("Root PID:    {}\n", info.root_pid);
        std::cout << fmt::format("CGroup ID:   {}\n", info.cgroup_id);
        std::cout << fmt::format("Privileged:  {}\n", info.privileged ? "yes" : "no");
        std::cout << fmt::format("Read-only FS: {}\n", info.readonly_rootfs ? "yes" : "no");
        std::cout << "Capabilities:\n";
        if (info.capabilities_configured.empty())
            std::cout << "  (default / none added)\n";
        else
            for (auto& c : info.capabilities_configured)
                std::cout << "  " << c << "\n";
        if (!info.seccomp_profile.empty())
            std::cout << fmt::format("Seccomp:     {}\n", info.seccomp_profile);
        if (!info.volumes.empty()) {
            std::cout << "Volumes:\n";
            for (auto& v : info.volumes) std::cout << "  " << v << "\n";
        }
        if (info.root_pid != 0) {
            // Show PID namespace inode
            uint64_t ns = container::read_pid_ns_inode(info.root_pid);
            if (ns) std::cout << fmt::format("PID NS inode: {}\n", ns);
            // Show /proc/<pid>/status excerpt
            std::ifstream st("/proc/" + std::to_string(info.root_pid) + "/status");
            std::string line;
            while (std::getline(st, line)) {
                if (line.rfind("Uid:", 0) == 0 || line.rfind("Gid:", 0) == 0)
                    std::cout << "  " << line << "\n";
            }
        }
    }
}

void register_inspect(CLI::App& app) {
    auto* sub       = app.add_subcommand("inspect", "Inspect a container without tracing");
    auto container = std::make_shared<std::string>();
    auto pid_opt   = std::make_shared<uint32_t>(0);
    auto bundle    = std::make_shared<std::string>();

    sub->add_option("-c,--container", *container, "Container name or ID");
    sub->add_option("-p,--pid",       *pid_opt,   "PID of container root process");
    sub->add_option("-b,--bundle",    *bundle,    "OCI bundle directory path");

    sub->callback([=]() {
        std::optional<ContainerInfo> info;

        if (!container->empty()) {
            info = container::resolve_any(*container);
            if (!info) {
                std::cerr << "Error: could not resolve container '" << *container << "'\n";
                std::cerr << "Tip: is the container running? Run 'docker ps' to check.\n";
                return;
            }
        } else if (!bundle->empty()) {
            info = container::resolve_oci_bundle(*bundle);
            if (!info) { std::cerr << "Error: invalid OCI bundle at " << *bundle << "\n"; return; }
        } else if (*pid_opt != 0) {
            ContainerInfo ci;
            ci.root_pid  = *pid_opt;
            ci.name      = "pid:" + std::to_string(*pid_opt);
            ci.cgroup_id = container::read_cgroup_id_v2(*pid_opt);
            info = ci;
        } else {
            std::cerr << "Error: provide --container, --pid, or --bundle\n";
            return;
        }

        print_info(*info);
    });
}

} // namespace docktrace::cli
