#pragma once
#include "docktrace/collector/collector.hpp"
#include <unordered_set>

namespace docktrace::collector {

// Reads /proc/<pid>/... to build a snapshot of process/file state.
// Does not produce continuous events; returns a one-shot batch.
class ProcCollector : public ICollector {
public:
    bool start(const CollectorOptions& opts, EventCallback cb) override;
    void stop() override {}
private:
    void scan_pid(uint32_t pid, const EventCallback& cb,
                  std::unordered_set<uint32_t>& visited) const;
};

} // namespace docktrace::collector
