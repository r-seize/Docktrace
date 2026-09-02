#include "docktrace/container/oci_resolver.hpp"
#include "docktrace/container/docker_resolver.hpp"
#include <dirent.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace docktrace::container {

namespace {
    // Minimal containerd API: query /run/containerd/containerd.sock
    // containerd uses gRPC/ttrpc; we use a simplified HTTP-like approach via
    // the shim API or read from /var/run/containerd/io.containerd.runtime.v2.task/<ns>/<id>/
    std::optional<ContainerInfo> resolve_containerd_shim(const std::string& name_or_id) {
        // Look for shim state files
        const std::string base = "/run/containerd/io.containerd.runtime.v2.task";
        std::vector<std::string> namespaces{"default", "k8s.io", "moby"};

        for (auto& ns : namespaces) {
            std::string state_path = base + "/" + ns + "/" + name_or_id + "/state.json";
            std::ifstream f(state_path);
            if (!f) continue;
            try {
                auto j = nlohmann::json::parse(f);
                ContainerInfo info;
                info.id      = j.value("id", name_or_id);
                info.name    = info.id;
                info.runtime = "containerd";
                info.root_pid = j.value("pid", 0u);
                if (info.root_pid == 0) return std::nullopt;
                info.cgroup_id = read_cgroup_id_v2(info.root_pid);
                spdlog::debug("Resolved via containerd shim: {} -> PID {}", info.id, info.root_pid);
                return info;
            } catch (...) {}
        }
        return std::nullopt;
    }
}

uint64_t read_cgroup_id_v2(uint32_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/cgroup");
    std::string line;
    while (std::getline(f, line)) {
        auto p2 = line.rfind(':');
        if (p2 == std::string::npos) continue;
        std::string rel = line.substr(p2 + 1);
        while (!rel.empty() && (rel.back() == '\n' || rel.back() == '\r')) rel.pop_back();
        std::string full = "/sys/fs/cgroup" + rel;
        struct stat st{};
        if (stat(full.c_str(), &st) == 0) return static_cast<uint64_t>(st.st_ino);
    }
    return 0;
}

uint64_t read_pid_ns_inode(uint32_t pid) {
    std::string link = "/proc/" + std::to_string(pid) + "/ns/pid";
    struct stat st{};
    if (stat(link.c_str(), &st) == 0) return st.st_ino;
    return 0;
}

std::vector<uint32_t> pids_in_namespace(uint64_t ns_inode) {
    std::vector<uint32_t> result;
    DIR* d = opendir("/proc");
    if (!d) return result;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (!isdigit(e->d_name[0])) continue;
        uint32_t pid = std::stoul(e->d_name);
        struct stat st{};
        std::string ns_path = "/proc/" + std::string(e->d_name) + "/ns/pid";
        if (stat(ns_path.c_str(), &st) == 0 && st.st_ino == ns_inode)
            result.push_back(pid);
    }
    closedir(d);
    return result;
}

std::optional<ContainerInfo> resolve_containerd(const std::string& name_or_id,
                                                const std::string&)
{
    return resolve_containerd_shim(name_or_id);
}

std::optional<ContainerInfo> resolve_oci_bundle(const std::string& bundle_path) {
    std::string config_path = bundle_path + "/config.json";
    std::ifstream f(config_path);
    if (!f) {
        spdlog::error("Cannot open OCI config: {}", config_path);
        return std::nullopt;
    }
    try {
        auto j = nlohmann::json::parse(f);
        ContainerInfo info;
        info.runtime = "oci-bundle";
        info.name    = bundle_path;

        if (j.contains("process")) {
            if (j["process"].contains("capabilities")) {
                for (auto& cap : j["process"]["capabilities"].value(
                        "bounding", std::vector<std::string>{}))
                    info.capabilities_configured.push_back(cap);
            }
        }

        // Try to find the PID from state.json
        std::ifstream sf(bundle_path + "/state.json");
        if (sf) {
            auto sj = nlohmann::json::parse(sf);
            info.root_pid  = sj.value("pid", 0u);
            info.id        = sj.value("id", "");
        }

        if (info.root_pid != 0)
            info.cgroup_id = read_cgroup_id_v2(info.root_pid);

        return info;
    } catch (const std::exception& ex) {
        spdlog::error("Failed to parse OCI bundle: {}", ex.what());
        return std::nullopt;
    }
}

std::optional<ContainerInfo> resolve_any(const std::string& name_or_id) {
    // 1. Try Docker
    if (auto r = resolve_docker(name_or_id)) return r;
    // 2. Try containerd shim
    if (auto r = resolve_containerd(name_or_id)) return r;
    // 3. Try as OCI bundle path
    struct stat st{};
    if (stat(name_or_id.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
        if (auto r = resolve_oci_bundle(name_or_id)) return r;
    return std::nullopt;
}

} // namespace docktrace::container
