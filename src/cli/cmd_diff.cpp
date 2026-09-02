#include <CLI/CLI.hpp>
#include <memory>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>

namespace docktrace::cli {

namespace {
    struct SimpleSummary {
        std::set<std::string> processes;
        std::set<std::string> network;   // "proto:dest:port"
        std::set<std::string> file_writes;
        std::set<std::string> syscalls;
    };

    SimpleSummary load_summary(const std::string& path) {
        std::ifstream f(path);
        if (!f) throw std::runtime_error("Cannot open: " + path);
        auto j = nlohmann::json::parse(f);
        SimpleSummary s;
        if (j.contains("processes"))
            for (auto& p : j["processes"]) s.processes.insert(p.value("path", ""));
        if (j.contains("network"))
            for (auto& n : j["network"])
                s.network.insert(fmt::format("{}:{}:{}",
                    n.value("protocol","tcp"),
                    n.value("destination",""),
                    n.value("port",0)));
        if (j.contains("files"))
            for (auto& fi : j["files"]) {
                std::string acc = fi.value("access", "READ");
                if (acc == "WRITE" || acc == "CREATE")
                    s.file_writes.insert(fi.value("path", ""));
            }
        if (j.contains("syscalls"))
            for (auto& [k, v] : j["syscalls"].items()) s.syscalls.insert(k);
        return s;
    }

    void diff_set(const std::set<std::string>& base,
                  const std::set<std::string>& curr,
                  const std::string& label,
                  std::ostream& out,
                  bool& failed)
    {
        for (auto& item : curr)
            if (!base.count(item)) {
                out << fmt::format("+ {} {}\n", label, item);
                failed = true;
            }
        for (auto& item : base)
            if (!curr.count(item))
                out << fmt::format("- {} {}\n", label, item);
    }
}

void register_diff(CLI::App& app) {
    auto* sub      = app.add_subcommand("diff", "Compare baseline and current behavior");
    auto baseline = std::make_shared<std::string>();
    auto current  = std::make_shared<std::string>();

    sub->add_option("-b,--baseline", *baseline, "Baseline report JSON")->required();
    sub->add_option("-c,--current",  *current,  "Current report JSON")->required();

    sub->callback([=]() {
        auto base = load_summary(*baseline);
        auto curr = load_summary(*current);

        bool failed = false;
        diff_set(base.processes,   curr.processes,   "process:",    std::cout, failed);
        diff_set(base.network,     curr.network,     "network:",    std::cout, failed);
        diff_set(base.file_writes, curr.file_writes, "file write:", std::cout, failed);
        diff_set(base.syscalls,    curr.syscalls,    "syscall:",    std::cout, failed);

        if (failed)
            std::cout << "\nUnexpected behavior detected — see diff above.\n";
        else
            std::cout << "(no unexpected changes)\n";
        std::cout << "\nStatus: " << (failed ? "FAILED" : "OK") << "\n";
        if (failed) std::exit(1);
    });
}

} // namespace docktrace::cli
