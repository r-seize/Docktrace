#pragma once
#include <unordered_map>
#include <vector>
#include "docktrace/model/event.hpp"
#include "docktrace/model/report.hpp"

namespace docktrace {

class Aggregator {
public:
    void ingest(const Event& e);
    Report build(const ContainerInfo& container, const ObservationMeta& meta) const;

private:
    struct FileKey {
        std::string path;
        std::string process;
        FileAccess  access;
        bool operator==(const FileKey&) const = default;
    };
    struct FileKeyHash {
        size_t operator()(const FileKey& k) const noexcept;
    };

    std::unordered_map<std::string, ProcessObservation>           processes_;
    std::unordered_map<FileKey, FileObservation, FileKeyHash>     files_;
    std::vector<NetworkObservation>                               network_;
    std::map<std::string, uint64_t>                               syscalls_;
    std::vector<std::string>                                      cap_observed_;
};

} // namespace docktrace
