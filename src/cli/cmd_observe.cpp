#include <CLI/CLI.hpp>
#include <memory>
#include "docktrace/collector/cgroup_filter.hpp"
#include "docktrace/collector/proc_collector.hpp"
#include "docktrace/container/oci_resolver.hpp"
#include "docktrace/model/aggregator.hpp"
#include "docktrace/model/io.hpp"
#include "docktrace/output/renderer.hpp"
#include <cctype>
#include <chrono>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <spdlog/spdlog.h>

#ifdef DOCKTRACE_EBPF_ENABLED
#include "docktrace/collector/ebpf_collector.hpp"
#endif

namespace docktrace::cli {

namespace {
    uint64_t parse_duration(const std::string& s) {
        if (s.empty()) return 30;
        char unit = s.back();
        uint64_t val = std::stoull(std::isdigit(static_cast<unsigned char>(unit)) ? s : s.substr(0, s.size() - 1));
        if (unit == 'm') return val * 60;
        if (unit == 'h') return val * 3600;
        return val;
    }

    collector::CollectorOptions build_options(uint32_t pid, uint64_t cgroup_id,
                                              const std::string& dur,
                                              const std::string& events)
    {
        collector::CollectorOptions opts;
        opts.target_pid       = pid;
        opts.target_cgroup_id = cgroup_id;
        opts.duration         = std::chrono::seconds(parse_duration(dur));
        bool all = (events == "all");
        opts.trace_process = all || events.find("process") != std::string::npos;
        opts.trace_file    = all || events.find("file")    != std::string::npos;
        opts.trace_network = all || events.find("network") != std::string::npos;
        opts.trace_syscall = all || events.find("syscall") != std::string::npos;
        return opts;
    }

    void do_observe(const collector::CollectorOptions& opts, Aggregator& agg) {
        auto ingest = [&](const Event& e) { agg.ingest(e); };

#ifdef DOCKTRACE_EBPF_ENABLED
        if (collector::EbpfCollector::is_available()) {
            spdlog::debug("Using eBPF collector");
            collector::EbpfCollector ebpf;
            ebpf.start(opts, ingest);
            return;
        }
        spdlog::warn("eBPF requires root. Falling back to /proc collector.");
#endif
        spdlog::debug("Using /proc collector");
        collector::ProcCollector proc;
        proc.start(opts, ingest);
    }
}

void register_observe(CLI::App& app) {
    auto* sub       = app.add_subcommand("observe", "Observe a container or PID and collect events");
    auto container = std::make_shared<std::string>();
    auto pid_opt   = std::make_shared<uint32_t>(0);
    auto duration  = std::make_shared<std::string>("30s");
    auto events    = std::make_shared<std::string>("process,file,network");
    auto output    = std::make_shared<std::string>();
    auto format    = std::make_shared<std::string>("terminal");

    sub->add_option("-c,--container", *container, "Container name or ID (Docker/containerd/OCI)");
    sub->add_option("-p,--pid",       *pid_opt,   "PID of root process");
    sub->add_option("-d,--duration",  *duration,  "Observation duration (e.g. 30s, 2m, 1h)");
    sub->add_option("-e,--events",    *events,    "Event types: process,file,network,syscall (or 'all')");
    sub->add_option("-o,--output",    *output,    "Output file (JSON report). Use '-' for stdout.");
    sub->add_option("-f,--format",    *format,    "Display format when not saving: terminal|json|markdown");

    sub->callback([=]() {
        ContainerInfo info;

        if (!container->empty()) {
            auto opt = container::resolve_any(*container);
            if (!opt) {
                std::cerr << "Error: could not resolve container '" << *container << "'\n";
                std::cerr << "Tip: is the container running? Run 'docker ps' to check.\n";
                return;
            }
            info = *opt;
        } else if (*pid_opt != 0) {
            info.root_pid  = *pid_opt;
            info.name      = "pid:" + std::to_string(*pid_opt);
            info.cgroup_id = container::read_cgroup_id_v2(*pid_opt);
        } else {
            std::cerr << "Error: provide --container <name> or --pid <pid>\n";
            return;
        }

        auto opts = build_options(info.root_pid, info.cgroup_id, *duration, *events);

        std::cout << fmt::format("[docktrace] Observing '{}' (PID {}) for {}...\n",
            info.name.empty() ? info.id : info.name, info.root_pid, *duration);
        if (info.cgroup_id != 0)
            std::cout << fmt::format("[docktrace] cgroup_id filter: {}\n", info.cgroup_id);

        Aggregator agg;
        do_observe(opts, agg);

        ObservationMeta meta;
        meta.duration_seconds = parse_duration(*duration);
        meta.architecture     = "x86_64";

        // Read kernel version
        std::ifstream osrel("/proc/version");
        if (osrel) { std::string s; std::getline(osrel, s); meta.kernel = s.substr(0, s.find(' ', 15)); }

        Report report = agg.build(info, meta);

        if (!output->empty() && *output != "-") {
            model::save_report(report, *output);
            std::cout << fmt::format("[docktrace] Report saved to {}\n", *output);
            std::cout << "[docktrace] Run: docktrace report --input " << *output << "\n";
        } else {
            auto fmt = output::parse_format(*format);
            output::render(report, fmt, "");
        }
    });
}

} // namespace docktrace::cli
