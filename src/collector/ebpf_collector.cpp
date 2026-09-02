#include "docktrace/collector/ebpf_collector.hpp"
#include <spdlog/spdlog.h>
#include <unistd.h>

#ifdef DOCKTRACE_EBPF_ENABLED
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>

// Generated skeleton headers (produced by: bpftool gen skeleton <prog>.bpf.o)
// These are created during the CMake build step.
#include "process.skel.h"
#include "filesystem.skel.h"
#include "network.skel.h"

namespace {
    // Shared event layout matching common.h
    struct bpf_event {
        uint64_t timestamp_ns;
        uint64_t cgroup_id;
        uint32_t pid;
        uint32_t uid;
        uint32_t type;
        int32_t  result;
        int32_t  flags;
        uint16_t remote_port;
        uint8_t  pad[2];
        char     comm[16];
        char     path[256];
        char     remote_addr[48];
    };

    enum bpf_event_type {
        BPF_EVENT_PROCESS_EXEC    = 1,
        BPF_EVENT_PROCESS_EXIT    = 2,
        BPF_EVENT_FILE_OPEN       = 3,
        BPF_EVENT_FILE_WRITE      = 4,
        BPF_EVENT_NETWORK_CONNECT = 7,
    };
}
#endif

namespace docktrace::collector {

struct EbpfCollector::Impl {
#ifdef DOCKTRACE_EBPF_ENABLED
    process_bpf*    proc_skel{nullptr};
    filesystem_bpf* fs_skel{nullptr};
    network_bpf*    net_skel{nullptr};
    ring_buffer*    rb{nullptr};
    EventCallback   cb;
    uint64_t        target_cgroup{0};

    static int handle_event(void* ctx, void* data, size_t) {
        auto* self = static_cast<Impl*>(ctx);
        auto* e    = static_cast<bpf_event*>(data);

        if (self->target_cgroup != 0 && e->cgroup_id != self->target_cgroup)
            return 0;

        docktrace::Event ev;
        ev.timestamp_ns  = e->timestamp_ns;
        ev.pid           = e->pid;
        ev.uid           = e->uid;
        ev.cgroup_id     = e->cgroup_id;
        ev.result        = e->result;
        ev.flags         = e->flags;
        ev.remote_port   = e->remote_port;
        ev.process_name  = e->comm;
        ev.path          = e->path;
        ev.remote_address = e->remote_addr;

        switch (static_cast<bpf_event_type>(e->type)) {
            case BPF_EVENT_PROCESS_EXEC:    ev.type = EventType::ProcessExec;     break;
            case BPF_EVENT_PROCESS_EXIT:    ev.type = EventType::ProcessExit;     break;
            case BPF_EVENT_FILE_OPEN:       ev.type = EventType::FileOpen;        break;
            case BPF_EVENT_FILE_WRITE:      ev.type = EventType::FileWrite;       break;
            case BPF_EVENT_NETWORK_CONNECT: ev.type = EventType::NetworkConnect;  break;
            default: return 0;
        }

        self->cb(ev);
        return 0;
    }

    void set_cgroup_filter(uint64_t cgroup_id) {
        target_cgroup = cgroup_id;
        // Write cgroup_id into all programs' target_cgroup map
        auto set_map = [&](int map_fd) {
            uint32_t key = 0;
            bpf_map_update_elem(map_fd, &key, &cgroup_id, BPF_ANY);
        };
        if (proc_skel) set_map(bpf_map__fd(proc_skel->maps.target_cgroup));
        if (fs_skel)   set_map(bpf_map__fd(fs_skel->maps.target_cgroup));
        if (net_skel)  set_map(bpf_map__fd(net_skel->maps.target_cgroup));
    }
#endif
};

EbpfCollector::EbpfCollector() : impl_(std::make_unique<Impl>()) {}

EbpfCollector::~EbpfCollector() { stop(); }

bool EbpfCollector::is_available() {
#ifdef DOCKTRACE_EBPF_ENABLED
    return geteuid() == 0 || access("/proc/sys/kernel/unprivileged_bpf_disabled", F_OK) == 0;
#else
    return false;
#endif
}

bool EbpfCollector::start(const CollectorOptions& opts, EventCallback cb) {
#ifndef DOCKTRACE_EBPF_ENABLED
    (void)opts; (void)cb;
    spdlog::warn("eBPF support not compiled in. Rebuild with -DDOCKTRACE_ENABLE_EBPF=ON");
    return false;
#else
    // Raise rlimit for locked memory (needed for BPF maps)
    struct rlimit rl{RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    impl_->cb = cb;

    // Suppress libbpf verbose output unless in debug mode
    libbpf_set_print([](libbpf_print_level lvl, const char* fmt, va_list args) -> int {
        if (lvl == LIBBPF_DEBUG) return 0;
        return vfprintf(stderr, fmt, args);
    });

    // Load and attach programs
    if (opts.trace_process) {
        impl_->proc_skel = process_bpf__open_and_load();
        if (!impl_->proc_skel) { spdlog::error("Failed to load process eBPF"); return false; }
        if (process_bpf__attach(impl_->proc_skel) < 0) {
            spdlog::error("Failed to attach process eBPF"); return false;
        }
    }
    if (opts.trace_file) {
        impl_->fs_skel = filesystem_bpf__open_and_load();
        if (!impl_->fs_skel) { spdlog::error("Failed to load filesystem eBPF"); return false; }
        if (filesystem_bpf__attach(impl_->fs_skel) < 0) {
            spdlog::error("Failed to attach filesystem eBPF"); return false;
        }
    }
    if (opts.trace_network) {
        impl_->net_skel = network_bpf__open_and_load();
        if (!impl_->net_skel) { spdlog::error("Failed to load network eBPF"); return false; }
        if (network_bpf__attach(impl_->net_skel) < 0) {
            spdlog::error("Failed to attach network eBPF"); return false;
        }
    }

    // Set cgroup filter
    if (opts.target_cgroup_id != 0)
        impl_->set_cgroup_filter(opts.target_cgroup_id);

    // Create ring buffer: first loaded program owns the rb, others are added
    int first_fd = -1;
    if (impl_->proc_skel) first_fd = bpf_map__fd(impl_->proc_skel->maps.events);
    else if (impl_->fs_skel)  first_fd = bpf_map__fd(impl_->fs_skel->maps.events);
    else if (impl_->net_skel) first_fd = bpf_map__fd(impl_->net_skel->maps.events);
    if (first_fd < 0) { spdlog::error("No eBPF programs loaded"); return false; }

    impl_->rb = ring_buffer__new(first_fd, Impl::handle_event, impl_.get(), nullptr);
    if (!impl_->rb) { spdlog::error("ring_buffer__new failed"); return false; }

    auto add_rb = [&](int map_fd) {
        if (map_fd >= 0 && map_fd != first_fd)
            ring_buffer__add(impl_->rb, map_fd, Impl::handle_event, impl_.get());
    };
    if (impl_->proc_skel) add_rb(bpf_map__fd(impl_->proc_skel->maps.events));
    if (impl_->fs_skel)   add_rb(bpf_map__fd(impl_->fs_skel->maps.events));
    if (impl_->net_skel)  add_rb(bpf_map__fd(impl_->net_skel->maps.events));

    running_ = true;
    auto deadline = std::chrono::steady_clock::now() + opts.duration;
    while (running_ && std::chrono::steady_clock::now() < deadline) {
        int err = ring_buffer__poll(impl_->rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            spdlog::error("ring_buffer__poll error: {}", err);
            break;
        }
    }
    return true;
#endif
}

void EbpfCollector::stop() {
    running_ = false;
#ifdef DOCKTRACE_EBPF_ENABLED
    if (impl_->rb)        { ring_buffer__free(impl_->rb);              impl_->rb = nullptr; }
    if (impl_->proc_skel) { process_bpf__destroy(impl_->proc_skel);   impl_->proc_skel = nullptr; }
    if (impl_->fs_skel)   { filesystem_bpf__destroy(impl_->fs_skel);  impl_->fs_skel = nullptr; }
    if (impl_->net_skel)  { network_bpf__destroy(impl_->net_skel);    impl_->net_skel = nullptr; }
#endif
}

} // namespace docktrace::collector
