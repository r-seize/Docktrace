#include "cmd_report.hpp"
#include <fmt/format.h>
#include <iostream>
#include <memory>
#include "docktrace/model/io.hpp"
#include "docktrace/output/renderer.hpp"

namespace docktrace::cli {

namespace {
    // A very short, CI-friendly summary: one line, no tables.
    void print_summary(const Report& r) {
        std::cout << fmt::format(
            "{} | collector={} | {}s | processes={} files={} network={} syscalls={} | warnings={}\n",
            r.container.name.empty() ? (r.container.id.empty() ? "unknown" : r.container.id) : r.container.name,
            r.observation.mode,
            r.observation.duration_seconds,
            r.observation.coverage.processes,
            r.observation.coverage.files,
            r.observation.coverage.network_connections,
            r.observation.coverage.syscalls,
            r.warnings.size());
        for (auto& w : r.warnings) std::cout << "  [!] " << w << "\n";
    }
}

void register_report(CLI::App& app) {
    auto* sub    = app.add_subcommand("report", "Render a collected report");
    auto input  = std::make_shared<std::string>();
    auto format = std::make_shared<std::string>("terminal");
    auto output = std::make_shared<std::string>();
    auto summary = std::make_shared<bool>(false);

    sub->add_option("-i,--input",  *input,  "Input report JSON file")->required();
    sub->add_option("-f,--format", *format, "Output format: terminal|json|markdown|html");
    sub->add_option("-o,--output", *output, "Output file (default: stdout)");
    sub->add_flag("--summary", *summary, "Print a single-line summary instead of the full report (for CI logs)");

    sub->callback([=]() {
        Report r = model::load_report(*input);
        if (*summary) {
            print_summary(r);
            return;
        }
        auto fmt = output::parse_format(*format);
        output::render(r, fmt, *output);
    });
}

} // namespace docktrace::cli
