#include "docktrace/output/renderer.hpp"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace docktrace::output {

namespace {
    using json = nlohmann::json;

    const char* access_str(FileAccess a) {
        switch (a) {
            case FileAccess::Read:           return "READ";
            case FileAccess::Write:          return "WRITE";
            case FileAccess::Create:         return "CREATE";
            case FileAccess::Delete:         return "DELETE";
            case FileAccess::Rename:         return "RENAME";
            case FileAccess::MetadataChange: return "METADATA";
        }
        return "UNKNOWN";
    }

    const char* confidence_str(FileObservation::Confidence c) {
        switch (c) {
            case FileObservation::Confidence::High:   return "high";
            case FileObservation::Confidence::Medium: return "medium";
            case FileObservation::Confidence::Low:    return "low";
        }
        return "unknown";
    }

    void render_terminal(const Report& r, std::ostream& out) {
        out << fmt::format("Container: {}\n", r.container.name.empty() ? "unknown" : r.container.name);
        out << fmt::format("Runtime:   {}\n", r.container.runtime.empty() ? "unknown" : r.container.runtime);
        out << fmt::format("Root PID:  {}\n", r.container.root_pid);
        out << fmt::format("Duration:  {}s\n\n", r.observation.duration_seconds);

        out << "Processes:\n";
        for (auto& p : r.processes)
            out << fmt::format("  {} (exec: {})\n", p.path, p.exec_count);

        out << "\nNetwork:\n";
        if (r.network.empty()) {
            out << "  (none observed)\n";
        } else {
            out << fmt::format("  {:<20} {:<8} {:<22} {}\n", "PROCESS", "PROTO", "DESTINATION", "COUNT");
            for (auto& n : r.network)
                out << fmt::format("  {:<20} {:<8} {:<22} {}\n",
                    n.process, n.protocol,
                    fmt::format("{}:{}", n.destination_address, n.destination_port),
                    n.count);
        }

        out << "\nFiles:\n";
        for (auto& f : r.files)
            out << fmt::format("  {:<8} {} (x{}, confidence: {})\n",
                access_str(f.access), f.path, f.count, confidence_str(f.confidence));

        out << "\nCapabilities:\n";
        out << "  Configured: ";
        if (r.capabilities.configured.empty()) out << "(none)\n";
        else { for (auto& c : r.capabilities.configured) out << c << " "; out << "\n"; }
        out << "  Observed:   ";
        if (r.capabilities.observed.empty()) out << "(none)\n";
        else { for (auto& c : r.capabilities.observed) out << c << " "; out << "\n"; }
        if (!r.capabilities.not_evidenced.empty()) {
            out << "  Not evidenced this run:";
            for (auto& c : r.capabilities.not_evidenced) out << " " << c;
            out << "\n";
        }

        if (!r.syscalls.empty()) {
            out << "\nSyscalls (top 10):\n";
            std::vector<std::pair<std::string,uint64_t>> sc(r.syscalls.begin(), r.syscalls.end());
            std::sort(sc.begin(), sc.end(), [](auto& a, auto& b){ return a.second > b.second; });
            int n = 0;
            for (auto& [name, cnt] : sc) {
                out << fmt::format("  {:<20} {}\n", name, cnt);
                if (++n >= 10) break;
            }
        }

        if (!r.warnings.empty()) {
            out << "\nWarnings:\n";
            for (auto& w : r.warnings) out << "  [!] " << w << "\n";
        }
    }

    json report_to_json(const Report& r) {
        json j;
        j["schema_version"] = r.schema_version;
        j["container"] = {
            {"name",  r.container.name},
            {"id",    r.container.id},
            {"image", r.container.image},
            {"runtime", r.container.runtime},
            {"root_pid", r.container.root_pid},
            {"cgroup_id", r.container.cgroup_id},
        };
        j["observation"] = {
            {"started_at",       r.observation.started_at},
            {"duration_seconds", r.observation.duration_seconds},
            {"kernel",           r.observation.kernel},
            {"architecture",     r.observation.architecture},
        };

        j["processes"] = json::array();
        for (auto& p : r.processes)
            j["processes"].push_back({{"path", p.path}, {"exec_count", p.exec_count}});

        j["files"] = json::array();
        for (auto& f : r.files)
            j["files"].push_back({
                {"path",    f.path},
                {"access",  access_str(f.access)},
                {"process", f.process},
                {"count",   f.count},
                {"confidence", confidence_str(f.confidence)},
            });

        j["network"] = json::array();
        for (auto& n : r.network)
            j["network"].push_back({
                {"protocol",    n.protocol},
                {"destination", n.destination_address},
                {"port",        n.destination_port},
                {"process",     n.process},
                {"count",       n.count},
            });

        j["syscalls"] = r.syscalls;
        j["capabilities"] = {
            {"configured",   r.capabilities.configured},
            {"observed",     r.capabilities.observed},
            {"not_evidenced", r.capabilities.not_evidenced},
        };
        j["warnings"] = r.warnings;
        return j;
    }

    void render_markdown(const Report& r, std::ostream& out) {
        out << fmt::format("# Docktrace Report: {}\n\n", r.container.name);
        out << fmt::format("| Field | Value |\n|---|---|\n");
        out << fmt::format("| Runtime | {} |\n", r.container.runtime);
        out << fmt::format("| Root PID | {} |\n", r.container.root_pid);
        out << fmt::format("| Duration | {}s |\n\n", r.observation.duration_seconds);

        out << "## Processes\n\n";
        for (auto& p : r.processes)
            out << fmt::format("- `{}` (exec: {})\n", p.path, p.exec_count);

        out << "\n## Network\n\n";
        out << "| Process | Protocol | Destination | Count |\n|---|---|---|---|\n";
        for (auto& n : r.network)
            out << fmt::format("| {} | {} | {}:{} | {} |\n",
                n.process, n.protocol, n.destination_address, n.destination_port, n.count);

        out << "\n## Files\n\n";
        out << "| Access | Path | Process | Count |\n|---|---|---|---|\n";
        for (auto& f : r.files)
            out << fmt::format("| {} | `{}` | {} | {} |\n",
                access_str(f.access), f.path, f.process, f.count);

        out << "\n## Warnings\n\n";
        for (auto& w : r.warnings) out << fmt::format("- {}\n", w);
    }
}

Format parse_format(const std::string& s) {
    if (s == "terminal") return Format::Terminal;
    if (s == "json")     return Format::Json;
    if (s == "markdown") return Format::Markdown;
    if (s == "html")     return Format::Html;
    throw std::invalid_argument("Unknown format: " + s);
}

void render(const Report& report, Format fmt, const std::string& output_path) {
    auto write_stream = [&](auto fn) {
        if (output_path.empty() || output_path == "-") {
            fn(std::cout);
        } else {
            std::ofstream f(output_path);
            if (!f) throw std::runtime_error("Cannot open output file: " + output_path);
            fn(f);
        }
    };

    switch (fmt) {
        case Format::Terminal:
            write_stream([&](auto& s){ render_terminal(report, s); });
            break;
        case Format::Json:
            write_stream([&](auto& s){ s << report_to_json(report).dump(2) << "\n"; });
            break;
        case Format::Markdown:
            write_stream([&](auto& s){ render_markdown(report, s); });
            break;
        case Format::Html:
            write_stream([&](auto& s){
                s << "<html><body><pre>";
                render_terminal(report, s);
                s << "</pre></body></html>\n";
            });
            break;
    }
}

} // namespace docktrace::output
