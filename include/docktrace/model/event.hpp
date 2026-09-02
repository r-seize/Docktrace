#pragma once
#include <cstdint>
#include <string>

namespace docktrace {

enum class EventType : uint32_t {
    ProcessExec   = 1,
    ProcessExit   = 2,
    FileOpen      = 3,
    FileWrite     = 4,
    FileDelete    = 5,
    FileRename    = 6,
    NetworkConnect = 7,
    NetworkBind   = 8,
    CapabilityUse = 9,
    Syscall       = 10,
};

enum class FileAccess {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    MetadataChange,
};

struct Event {
    EventType       type;
    uint64_t        timestamp_ns{0};
    uint32_t        pid{0};
    uint32_t        uid{0};
    uint64_t        cgroup_id{0};
    std::string     process_name;
    std::string     path;
    std::string     command;
    std::string     remote_address;
    uint16_t        remote_port{0};
    int             syscall_id{-1};
    int             result{0};
    int             flags{0};
};

} // namespace docktrace
