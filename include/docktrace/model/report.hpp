#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "docktrace/model/container.hpp"
#include "docktrace/model/event.hpp"

namespace docktrace {

struct ProcessObservation {
    std::string path;
    uint32_t    pid_count{0};
    uint64_t    exec_count{0};
    std::vector<std::string> args;
};

struct FileObservation {
    std::string path;
    FileAccess  access{FileAccess::Read};
    std::string process;
    uint64_t    count{0};
    uint64_t    first_seen_ns{0};
    uint64_t    last_seen_ns{0};

    enum class Confidence { High, Medium, Low };
    Confidence  confidence{Confidence::High};
    std::string confidence_reason;
};

struct NetworkObservation {
    std::string process;
    std::string protocol;
    std::string source_address;
    uint16_t    source_port{0};
    std::string destination_address;
    uint16_t    destination_port{0};
    uint64_t    count{0};
};

struct ObservationMeta {
    std::string started_at;
    uint64_t    duration_seconds{0};
    std::string kernel;
    std::string architecture;
};

struct CapabilityObservation {
    std::vector<std::string> configured;
    std::vector<std::string> observed;
    std::vector<std::string> not_evidenced;
};

struct Report {
    std::string               schema_version{"1.0"};
    ContainerInfo             container;
    ObservationMeta           observation;
    std::vector<ProcessObservation>   processes;
    std::vector<FileObservation>      files;
    std::vector<NetworkObservation>   network;
    std::map<std::string, uint64_t>   syscalls;
    CapabilityObservation     capabilities;
    std::vector<std::string>  warnings;
};

} // namespace docktrace
