#pragma once
#include "docktrace/collector/collector.hpp"
#include <atomic>
#include <memory>

// Only available when DOCKTRACE_EBPF_ENABLED is defined (build with -DDOCKTRACE_ENABLE_EBPF=ON)
#ifdef DOCKTRACE_EBPF_ENABLED
struct ring_buffer;
#endif

namespace docktrace::collector {

class EbpfCollector : public ICollector {
public:
    EbpfCollector();
    ~EbpfCollector() override;

    bool start(const CollectorOptions& opts, EventCallback cb) override;
    void stop() override;

    // Returns false if eBPF support is not compiled in or system lacks capabilities
    static bool is_available();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::atomic<bool> running_{false};
};

} // namespace docktrace::collector
