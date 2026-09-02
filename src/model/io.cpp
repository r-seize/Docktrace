#include "docktrace/model/io.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace docktrace::model {

namespace {
    using json = nlohmann::json;

    FileAccess parse_access(const std::string& s) {
        if (s == "WRITE")    return FileAccess::Write;
        if (s == "CREATE")   return FileAccess::Create;
        if (s == "DELETE")   return FileAccess::Delete;
        if (s == "RENAME")   return FileAccess::Rename;
        if (s == "METADATA") return FileAccess::MetadataChange;
        return FileAccess::Read;
    }

    const char* access_to_str(FileAccess a) {
        switch (a) {
            case FileAccess::Write:          return "WRITE";
            case FileAccess::Create:         return "CREATE";
            case FileAccess::Delete:         return "DELETE";
            case FileAccess::Rename:         return "RENAME";
            case FileAccess::MetadataChange: return "METADATA";
            default:                         return "READ";
        }
    }
}

Report load_report(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    json j = json::parse(f);

    Report r;
    r.schema_version = j.value("schema_version", "1.0");

    if (j.contains("container")) {
        auto& jc = j["container"];
        r.container.name      = jc.value("name", "");
        r.container.id        = jc.value("id", "");
        r.container.image     = jc.value("image", "");
        r.container.runtime   = jc.value("runtime", "");
        r.container.root_pid  = jc.value("root_pid", 0u);
        r.container.cgroup_id = jc.value("cgroup_id", 0ULL);
        r.container.capabilities_configured =
            jc.value("capabilities_configured", std::vector<std::string>{});
    }
    if (j.contains("observation")) {
        auto& jo = j["observation"];
        r.observation.started_at       = jo.value("started_at", "");
        r.observation.duration_seconds = jo.value("duration_seconds", 0ULL);
        r.observation.kernel           = jo.value("kernel", "");
        r.observation.architecture     = jo.value("architecture", "");
    }
    if (j.contains("processes")) {
        for (auto& p : j["processes"]) {
            ProcessObservation obs;
            obs.path       = p.value("path", "");
            obs.exec_count = p.value("exec_count", 0ULL);
            obs.pid_count  = p.value("pid_count", 0u);
            r.processes.push_back(obs);
        }
    }
    if (j.contains("files")) {
        for (auto& fi : j["files"]) {
            FileObservation obs;
            obs.path    = fi.value("path", "");
            obs.process = fi.value("process", "");
            obs.count   = fi.value("count", 0ULL);
            obs.access  = parse_access(fi.value("access", "READ"));
            r.files.push_back(obs);
        }
    }
    if (j.contains("network")) {
        for (auto& n : j["network"]) {
            NetworkObservation obs;
            obs.protocol            = n.value("protocol", "tcp");
            obs.destination_address = n.value("destination", "");
            obs.destination_port    = n.value("port", 0);
            obs.process             = n.value("process", "");
            obs.count               = n.value("count", 0ULL);
            r.network.push_back(obs);
        }
    }
    if (j.contains("syscalls"))
        for (auto& [k, v] : j["syscalls"].items())
            r.syscalls[k] = v.get<uint64_t>();
    if (j.contains("capabilities")) {
        auto& jcap = j["capabilities"];
        if (jcap.contains("configured"))
            r.capabilities.configured = jcap["configured"].get<std::vector<std::string>>();
        if (jcap.contains("observed"))
            r.capabilities.observed = jcap["observed"].get<std::vector<std::string>>();
        if (jcap.contains("not_evidenced"))
            r.capabilities.not_evidenced = jcap["not_evidenced"].get<std::vector<std::string>>();
    }
    if (j.contains("warnings"))
        r.warnings = j["warnings"].get<std::vector<std::string>>();
    return r;
}

void save_report(const Report& report, const std::string& path) {
    json j;
    j["schema_version"] = report.schema_version;
    j["container"] = {
        {"name",  report.container.name},
        {"id",    report.container.id},
        {"image", report.container.image},
        {"runtime", report.container.runtime},
        {"root_pid", report.container.root_pid},
        {"cgroup_id", report.container.cgroup_id},
        {"capabilities_configured", report.container.capabilities_configured},
    };
    j["observation"] = {
        {"started_at",       report.observation.started_at},
        {"duration_seconds", report.observation.duration_seconds},
        {"kernel",           report.observation.kernel},
        {"architecture",     report.observation.architecture},
    };
    j["processes"] = json::array();
    for (auto& p : report.processes)
        j["processes"].push_back({{"path", p.path}, {"exec_count", p.exec_count}});
    j["files"] = json::array();
    for (auto& f : report.files)
        j["files"].push_back({
            {"path", f.path}, {"access", access_to_str(f.access)},
            {"process", f.process}, {"count", f.count},
        });
    j["network"] = json::array();
    for (auto& n : report.network)
        j["network"].push_back({
            {"protocol", n.protocol}, {"destination", n.destination_address},
            {"port", n.destination_port}, {"process", n.process}, {"count", n.count},
        });
    j["syscalls"] = report.syscalls;
    j["capabilities"] = {
        {"configured",    report.capabilities.configured},
        {"observed",      report.capabilities.observed},
        {"not_evidenced", report.capabilities.not_evidenced},
    };
    j["warnings"] = report.warnings;

    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write to: " + path);
    f << j.dump(2) << "\n";
}

} // namespace docktrace::model
