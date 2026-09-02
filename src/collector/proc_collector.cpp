#include "docktrace/collector/proc_collector.hpp"
#include <chrono>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_set>

namespace docktrace::collector {

namespace {
    std::string read_file(const std::string& path) {
        std::ifstream f(path);
        if (!f) return {};
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    std::string read_comm(uint32_t pid) {
        auto s = read_file("/proc/" + std::to_string(pid) + "/comm");
        if (!s.empty() && s.back() == '\n') s.pop_back();
        return s;
    }

    std::string read_exe(uint32_t pid) {
        std::string link = "/proc/" + std::to_string(pid) + "/exe";
        char buf[4096];
        ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
        if (n <= 0) return {};
        buf[n] = '\0';
        return buf;
    }

    std::vector<uint32_t> child_pids(uint32_t pid) {
        std::vector<uint32_t> result;
        std::string task_path = "/proc/" + std::to_string(pid) + "/task";
        DIR* d = opendir(task_path.c_str());
        if (!d) return result;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] == '.') continue;
            std::string children_path =
                task_path + "/" + e->d_name + "/children";
            std::ifstream f(children_path);
            uint32_t child;
            while (f >> child) result.push_back(child);
        }
        closedir(d);
        return result;
    }

    std::vector<std::string> open_fds(uint32_t pid) {
        std::vector<std::string> paths;
        std::string fd_path = "/proc/" + std::to_string(pid) + "/fd";
        DIR* d = opendir(fd_path.c_str());
        if (!d) return paths;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] == '.') continue;
            std::string link = fd_path + "/" + e->d_name;
            char buf[4096];
            ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
            if (n > 0) { buf[n] = '\0'; paths.emplace_back(buf); }
        }
        closedir(d);
        return paths;
    }
}

void ProcCollector::scan_pid(uint32_t pid, const EventCallback& cb,
                             std::unordered_set<uint32_t>& visited) const {
    if (!visited.insert(pid).second) return;
    std::string exe = read_exe(pid);
    if (exe.empty()) exe = read_comm(pid);
    if (exe.empty()) return;

    // Emit a synthetic ProcessExec event
    Event ev;
    ev.type         = EventType::ProcessExec;
    ev.pid          = pid;
    ev.path         = exe;
    ev.process_name = exe;
    ev.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cb(ev);

    // Emit FileOpen events for open file descriptors
    for (auto& path : open_fds(pid)) {
        if (path.rfind("socket:", 0) == 0) continue; // skip sockets here
        Event fev;
        fev.type         = EventType::FileOpen;
        fev.pid          = pid;
        fev.process_name = exe;
        fev.path         = path;
        fev.timestamp_ns = ev.timestamp_ns;
        cb(fev);
    }

    // Recurse into children
    for (uint32_t child : child_pids(pid))
        scan_pid(child, cb, visited);
}

bool ProcCollector::start(const CollectorOptions& opts, EventCallback cb) {
    if (opts.target_pid == 0) return false;

    auto deadline = std::chrono::steady_clock::now() + opts.duration;
    do {
        std::unordered_set<uint32_t> visited;
        scan_pid(opts.target_pid, cb, visited);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } while (std::chrono::steady_clock::now() < deadline);

    return true;
}

} // namespace docktrace::collector
