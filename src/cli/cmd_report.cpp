#include "cmd_report.hpp"
#include <memory>
#include "docktrace/model/io.hpp"
#include "docktrace/output/renderer.hpp"

namespace docktrace::cli {

void register_report(CLI::App& app) {
    auto* sub    = app.add_subcommand("report", "Render a collected report");
    auto input  = std::make_shared<std::string>();
    auto format = std::make_shared<std::string>("terminal");
    auto output = std::make_shared<std::string>();

    sub->add_option("-i,--input",  *input,  "Input report JSON file")->required();
    sub->add_option("-f,--format", *format, "Output format: terminal|json|markdown|html");
    sub->add_option("-o,--output", *output, "Output file (default: stdout)");

    sub->callback([=]() {
        Report r   = model::load_report(*input);
        auto   fmt = output::parse_format(*format);
        output::render(r, fmt, *output);
    });
}

} // namespace docktrace::cli
