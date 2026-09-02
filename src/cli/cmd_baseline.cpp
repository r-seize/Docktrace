#include <CLI/CLI.hpp>
#include <memory>
#include "docktrace/collector/proc_collector.hpp"
#include "docktrace/container/oci_resolver.hpp"
#include "docktrace/model/aggregator.hpp"
#include "docktrace/model/io.hpp"
#include "docktrace/output/renderer.hpp"
#include <cctype>
#include <chrono>
#include <fmt/format.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>

#ifdef DOCKTRACE_EBPF_ENABLED
#include "docktrace/collector/ebpf_collector.hpp"
#endif

namespace docktrace::cli {

namespace {
    uint64_t parse_dur(const std::string& s) {
        if (s.empty()) return 30;
        char u = s.back();
        uint64_t v = std::stoull(std::isdigit(static_cast<unsigned char>(u)) ? s : s.substr(0, s.size()-1));
        if (u == 'm') return v * 60;
        if (u == 'h') return v * 3600;
        return v;
    }

    Report run_observation(const std::string& container_name,
                           uint32_t pid_opt,
                           const std::string& duration_str)
    {
        ContainerInfo info;
        if (!container_name.empty()) {
            auto opt = container::resolve_any(container_name);
            if (!opt) throw std::runtime_error("Cannot resolve container '" + container_name + "' — is it running?");
            info = *opt;
        } else if (pid_opt != 0) {
            info.root_pid = pid_opt;
            info.name     = "pid:" + std::to_string(pid_opt);
        } else {
            throw std::runtime_error("Provide --container or --pid");
        }

        std::string display = info.name.empty() ? info.id : info.name;
        std::cout << fmt::format("[baseline] Observing '{}' (PID {}) for {}...\n",
            display, info.root_pid, duration_str);

        uint64_t secs = parse_dur(duration_str);
        collector::CollectorOptions opts;
        opts.target_pid      = info.root_pid;
        opts.target_cgroup_id = info.cgroup_id;
        opts.duration        = std::chrono::seconds(secs);
        opts.trace_process   = true;
        opts.trace_file      = true;
        opts.trace_network   = true;

        Aggregator agg;
        auto do_collect = [&](collector::ICollector& col) {
            col.start(opts, [&](const Event& e){ agg.ingest(e); });
        };

#ifdef DOCKTRACE_EBPF_ENABLED
        if (collector::EbpfCollector::is_available()) {
            collector::EbpfCollector ebpf;
            do_collect(ebpf);
        } else {
#endif
            collector::ProcCollector proc;
            do_collect(proc);
#ifdef DOCKTRACE_EBPF_ENABLED
        }
#endif

        ObservationMeta meta;
        meta.duration_seconds = secs;
        meta.architecture     = "x86_64";
        return agg.build(info, meta);
    }

    // Extract a fingerprint set from a report for comparison
    struct Fingerprint {
        std::set<std::string> processes;
        std::set<std::string> network;
        std::set<std::string> file_writes;
        std::set<std::string> syscalls;
    };

    Fingerprint fingerprint(const Report& r) {
        Fingerprint f;
        for (auto& p : r.processes) f.processes.insert(p.path);
        for (auto& n : r.network)
            f.network.insert(fmt::format("{}:{}:{}", n.protocol,
                n.destination_address, n.destination_port));
        for (auto& fi : r.files)
            if (fi.access == FileAccess::Write || fi.access == FileAccess::Create)
                f.file_writes.insert(fi.path);
        for (auto& [k, v] : r.syscalls) f.syscalls.insert(k);
        return f;
    }

    bool diff_sets(const std::set<std::string>& base,
                   const std::set<std::string>& curr,
                   const std::string& label)
    {
        bool failed = false;
        for (auto& item : curr)
            if (!base.count(item)) {
                std::cout << fmt::format("  + {} {}\n", label, item);
                failed = true;
            }
        for (auto& item : base)
            if (!curr.count(item))
                std::cout << fmt::format("  - {} {}\n", label, item);
        return failed;
    }
}

void register_baseline(CLI::App& app) {
    auto* sub = app.add_subcommand("baseline", "Manage behavioral baselines");
    sub->require_subcommand(1);

    // baseline create
    {
        auto* create     = sub->add_subcommand("create", "Observe and save a behavioral baseline");
        auto container  = std::make_shared<std::string>();
        auto pid_opt    = std::make_shared<uint32_t>(0);
        auto duration   = std::make_shared<std::string>("60s");
        auto output     = std::make_shared<std::string>("baseline.json");

        create->add_option("-c,--container", *container, "Container name or ID");
        create->add_option("-p,--pid",       *pid_opt,   "Root PID");
        create->add_option("-d,--duration",  *duration,  "Observation duration");
        create->add_option("-o,--output",    *output,    "Baseline file to write");

        create->callback([=]() {
            Report r = run_observation(*container, *pid_opt, *duration);
            model::save_report(r, *output);
            std::cout << fmt::format("[baseline] Saved to {}\n", *output);
            output::render(r, output::Format::Terminal, "");
        });
    }

    // baseline check
    {
        auto* check     = sub->add_subcommand("check",
            "Observe and compare against a saved baseline (returns exit 1 on deviation)");
        auto container  = std::make_shared<std::string>();
        auto pid_opt    = std::make_shared<uint32_t>(0);
        auto duration   = std::make_shared<std::string>("60s");
        auto baseline   = std::make_shared<std::string>("baseline.json");
        auto output     = std::make_shared<std::string>();

        check->add_option("-c,--container", *container, "Container name or ID");
        check->add_option("-p,--pid",       *pid_opt,   "Root PID");
        check->add_option("-d,--duration",  *duration,  "Observation duration");
        check->add_option("-b,--baseline",  *baseline,  "Baseline JSON file")->required();
        check->add_option("-o,--output",    *output,    "Save current report to file");

        check->callback([=]() {
            Report base_report = model::load_report(*baseline);
            Report curr_report = run_observation(*container, *pid_opt, *duration);

            if (!output->empty()) model::save_report(curr_report, *output);

            auto base_fp = fingerprint(base_report);
            auto curr_fp = fingerprint(curr_report);

            bool failed = false;
            std::cout << "\n=== Baseline comparison ===\n\n";
            failed |= diff_sets(base_fp.processes,   curr_fp.processes,   "process:");
            failed |= diff_sets(base_fp.network,     curr_fp.network,     "network:");
            failed |= diff_sets(base_fp.file_writes, curr_fp.file_writes, "file write:");
            failed |= diff_sets(base_fp.syscalls,    curr_fp.syscalls,    "syscall:");

            if (!failed) std::cout << "  (no unexpected changes)\n";
            std::cout << "\nStatus: " << (failed ? "FAILED" : "OK") << "\n";
            if (failed) std::exit(1);
        });
    }

    // baseline list
    {
        auto* list_sub = sub->add_subcommand("list", "Show contents of a baseline file");
        auto input    = std::make_shared<std::string>("baseline.json");
        list_sub->add_option("-i,--input", *input, "Baseline file");
        list_sub->callback([=]() {
            Report r = model::load_report(*input);
            output::render(r, output::Format::Terminal, "");
        });
    }
}

} // namespace docktrace::cli
