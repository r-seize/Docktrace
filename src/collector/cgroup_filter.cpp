#include "docktrace/collector/cgroup_filter.hpp"
#include <dirent.h>
#include <fstream>
#include <functional>
#include <sstream>
#include <sys/stat.h>

namespace docktrace::collector {

bool CgroupFilter::matches(uint64_t cgroup_id, uint32_t pid) const {
    if (target_cgroup_id != 0 && cgroup_id != target_cgroup_id) return false;
    if (!known_pids.empty() && !known_pids.count(pid))           return false;
    return true;
}

void CgroupFilter::add_pid(uint32_t pid) { known_pids.insert(pid); }
void CgroupFilter::clear() { known_pids.clear(); target_cgroup_id = 0; target_pid_ns = 0; }

namespace {
    void collect_children(uint32_t pid, std::unordered_set<uint32_t>& out) {
        if (!out.insert(pid).second) return; // already visited (cycle guard)

        std::string task = "/proc/" + std::to_string(pid) + "/task";
        DIR* d = opendir(task.c_str());
        if (!d) return;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] == '.') continue;
            std::ifstream f(task + "/" + e->d_name + "/children");
            uint32_t child;
            while (f >> child) collect_children(child, out);
        }
        closedir(d);
    }

    uint64_t read_cgroup_id(uint32_t pid) {
        // Parse /proc/<pid>/cgroup and get the cgroup path, then stat the cgroup dir
        std::ifstream f("/proc/" + std::to_string(pid) + "/cgroup");
        std::string line;
        while (std::getline(f, line)) {
            auto colon2 = line.rfind(':');
            if (colon2 == std::string::npos) continue;
            std::string path = "/sys/fs/cgroup" + line.substr(colon2 + 1);
            // trim trailing newline
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
                path.pop_back();
            struct stat st{};
            if (stat(path.c_str(), &st) == 0)
                return static_cast<uint64_t>(st.st_ino);
        }
        return 0;
    }
}

CgroupFilter CgroupFilter::from_pid(uint32_t root_pid) {
    CgroupFilter f;
    collect_children(root_pid, f.known_pids);
    f.target_cgroup_id = read_cgroup_id(root_pid);
    return f;
}

} // namespace docktrace::collector
