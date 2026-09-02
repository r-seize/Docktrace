#include "docktrace/model/aggregator.hpp"
#include <functional>
#include <algorithm>

namespace docktrace {

namespace {
    const char* syscall_name_for(EventType t) {
        switch (t) {
            case EventType::ProcessExec:    return "execve";
            case EventType::FileOpen:       return "openat";
            case EventType::FileWrite:      return "write";
            case EventType::FileDelete:     return "unlinkat";
            case EventType::NetworkConnect: return "connect";
            case EventType::NetworkBind:    return "bind";
            default: return nullptr;
        }
    }

    FileAccess flags_to_access(int flags, EventType t) {
        if (t == EventType::FileWrite)  return FileAccess::Write;
        if (t == EventType::FileDelete) return FileAccess::Delete;
        if (flags & 1 || flags & 2)     return FileAccess::Write; // O_WRONLY | O_RDWR
        return FileAccess::Read;
    }
}

size_t Aggregator::FileKeyHash::operator()(const FileKey& k) const noexcept {
    size_t h = std::hash<std::string>{}(k.path);
    h ^= std::hash<std::string>{}(k.process) * 2654435761ULL;
    h ^= std::hash<int>{}(static_cast<int>(k.access)) * 40503ULL;
    return h;
}

void Aggregator::ingest(const Event& e) {
    switch (e.type) {
        case EventType::ProcessExec: {
            auto& obs = processes_[e.path];
            obs.path = e.path;
            obs.exec_count++;
            obs.pid_count = 1; // will be deduplicated later
            break;
        }
        case EventType::FileOpen:
        case EventType::FileWrite:
        case EventType::FileDelete: {
            FileAccess access = flags_to_access(e.flags, e.type);
            FileKey key{e.path, e.process_name, access};
            auto& obs = files_[key];
            if (obs.count == 0) {
                obs.path        = e.path;
                obs.access      = access;
                obs.process     = e.process_name;
                obs.first_seen_ns = e.timestamp_ns;
            }
            obs.count++;
            obs.last_seen_ns = e.timestamp_ns;

            // Confidence: if opened O_RDWR but no actual write syscall seen
            if (e.type == EventType::FileOpen && (e.flags & 2)) {
                obs.confidence        = FileObservation::Confidence::Medium;
                obs.confidence_reason = "opened with O_RDWR but no write() observed";
            }
            break;
        }
        case EventType::NetworkConnect:
        case EventType::NetworkBind: {
            bool found = false;
            for (auto& obs : network_) {
                if (obs.process == e.process_name &&
                    obs.destination_address == e.remote_address &&
                    obs.destination_port == e.remote_port) {
                    obs.count++;
                    found = true;
                    break;
                }
            }
            if (!found) {
                NetworkObservation obs;
                obs.process             = e.process_name;
                obs.protocol            = "tcp";
                obs.destination_address = e.remote_address;
                obs.destination_port    = e.remote_port;
                obs.count               = 1;
                network_.push_back(obs);
            }
            break;
        }
        case EventType::CapabilityUse:
            if (!e.path.empty()) {
                if (std::find(cap_observed_.begin(), cap_observed_.end(), e.path)
                        == cap_observed_.end())
                    cap_observed_.push_back(e.path);
            }
            break;
        default:
            break;
    }

    if (const char* name = syscall_name_for(e.type))
        syscalls_[name]++;
}

Report Aggregator::build(const ContainerInfo& container, const ObservationMeta& meta) const {
    Report r;
    r.container   = container;
    r.observation = meta;
    r.syscalls    = syscalls_;

    for (auto& [path, obs] : processes_)
        r.processes.push_back(obs);

    for (auto& [key, obs] : files_)
        r.files.push_back(obs);

    r.network = network_;

    r.capabilities.configured   = container.capabilities_configured;
    r.capabilities.observed     = cap_observed_;
    for (auto& cap : container.capabilities_configured) {
        if (std::find(cap_observed_.begin(), cap_observed_.end(), cap)
                == cap_observed_.end())
            r.capabilities.not_evidenced.push_back(cap);
    }

    r.warnings.emplace_back("Observation may not cover error-handling paths");
    r.warnings.emplace_back("DNS names were not resolved");
    return r;
}

} // namespace docktrace
