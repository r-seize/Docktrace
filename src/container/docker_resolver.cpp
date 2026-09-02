#include "docktrace/container/docker_resolver.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sstream>

namespace docktrace::container {

namespace {
    // Send an HTTP GET request over the Docker Unix socket and return the body.
    std::string docker_api_get(const std::string& path) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return {};

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/var/run/docker.sock", sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return {};
        }

        std::string req = "GET " + path + " HTTP/1.0\r\nHost: localhost\r\n\r\n";
        if (write(fd, req.data(), req.size()) < 0) { close(fd); return {}; }

        std::string response;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            response.append(buf, n);
        close(fd);

        // Strip HTTP headers
        auto pos = response.find("\r\n\r\n");
        if (pos == std::string::npos) return {};
        return response.substr(pos + 4);
    }

    uint64_t read_cgroup_id(uint32_t pid) {
        // Read /proc/<pid>/cgroup, last field is the cgroup path
        std::ifstream f("/proc/" + std::to_string(pid) + "/cgroup");
        std::string line;
        while (std::getline(f, line)) {
            // format: hierarchy-ID:controllers:path
            auto p1 = line.find(':');
            auto p2 = line.rfind(':');
            if (p1 != std::string::npos && p2 != p1) {
                std::string cg_path = "/sys/fs/cgroup" + line.substr(p2 + 1);
                // Just return a hash of the path as a proxy for cgroup id
                return std::hash<std::string>{}(cg_path);
            }
        }
        return 0;
    }
}

std::optional<uint32_t> find_container_root_pid(const std::string& container_id) {
    std::string body = docker_api_get("/containers/" + container_id + "/json");
    if (body.empty()) return std::nullopt;
    try {
        auto j = nlohmann::json::parse(body);
        uint32_t pid = j["State"]["Pid"].get<uint32_t>();
        if (pid == 0) return std::nullopt;
        return pid;
    } catch (...) { return std::nullopt; }
}

std::optional<ContainerInfo> resolve_docker(const std::string& name_or_id) {
    // Reject names with chars that could inject HTTP headers (\r, \n, space, /)
    for (unsigned char c : name_or_id) {
        if (c < 0x20 || c == ' ' || c == '\r' || c == '\n')
            return std::nullopt;
    }
    std::string body = docker_api_get("/containers/" + name_or_id + "/json");
    if (body.empty()) {
        spdlog::error("Cannot reach Docker socket at /var/run/docker.sock");
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(body);
        ContainerInfo info;
        info.id      = j.value("Id", "");
        info.name    = j.value("Name", "");
        if (!info.name.empty() && info.name[0] == '/') info.name = info.name.substr(1);
        info.image   = j.at("Config").value("Image", "");
        info.runtime = "runc"; // default; read from HostConfig if needed
        info.root_pid = j["State"]["Pid"].get<uint32_t>();
        if (info.root_pid == 0) {
            std::string status = j["State"].value("Status", "unknown");
            spdlog::error("Container '{}' is not running (status: {})", name_or_id, status);
            return std::nullopt;
        }
        info.privileged = j.at("HostConfig").value("Privileged", false);

        // Capabilities — CapAdd is null when no extra caps are added
        auto& hc = j.at("HostConfig");
        if (hc.contains("CapAdd") && hc["CapAdd"].is_array()) {
            info.capabilities_configured = hc["CapAdd"].get<std::vector<std::string>>();
        }

        // Read-only rootfs
        info.readonly_rootfs = hc.value("ReadonlyRootfs", false);

        // Volumes / mounts
        if (j.contains("Mounts") && j["Mounts"].is_array()) {
            for (auto& m : j["Mounts"])
                info.volumes.push_back(
                    m.value("Source","") + ":" + m.value("Destination",""));
        }

        // Seccomp profile name
        if (hc.contains("SecurityOpt") && hc["SecurityOpt"].is_array()) {
            for (auto& opt : hc["SecurityOpt"]) {
                std::string s = opt.get<std::string>();
                if (s.rfind("seccomp=", 0) == 0)
                    info.seccomp_profile = s.substr(8);
            }
        }

        info.cgroup_id = read_cgroup_id(info.root_pid);

        spdlog::debug("Resolved container '{}' -> PID {} cgroup_id {}",
            info.name, info.root_pid, info.cgroup_id);
        return info;
    } catch (const std::exception& ex) {
        spdlog::error("Failed to parse Docker inspect response: {}", ex.what());
        return std::nullopt;
    }
}

} // namespace docktrace::container
