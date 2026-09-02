#include <CLI/CLI.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <iostream>
#include <stdexcept>

namespace docktrace::cli {
    void register_inspect (CLI::App& app);
    void register_observe (CLI::App& app);
    void register_report  (CLI::App& app);
    void register_profile (CLI::App& app);
    void register_diff    (CLI::App& app);
    void register_doctor  (CLI::App& app);
    void register_baseline(CLI::App& app);
    void register_validate(CLI::App& app);
}

int main(int argc, char** argv) {
    CLI::App app{
        "docktrace — Observe a container. Understand its behavior. "
        "Generate a safer runtime profile."
    };
    app.set_version_flag("--version", "0.1.0");

    // Pre-scan argv so -v takes effect before subcommand callbacks run inside parse()
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "-v" || arg == "--verbose")
            spdlog::set_level(spdlog::level::debug);
    }

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose/debug logging");

    docktrace::cli::register_inspect (app);
    docktrace::cli::register_observe (app);
    docktrace::cli::register_report  (app);
    docktrace::cli::register_profile (app);
    docktrace::cli::register_diff    (app);
    docktrace::cli::register_doctor  (app);
    docktrace::cli::register_baseline(app);
    docktrace::cli::register_validate(app);

    app.require_subcommand(1);

    if (argc == 1) {
        std::cout << app.help();
        return 0;
    }

    // Parse args — CLI11_PARSE calls exit() on --help/--version which is fine.
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const std::exception& e) {
        std::cerr << fmt::format("Error: {}\n", e.what());
        return 1;
    } catch (...) {
        std::cerr << "Error: unknown exception\n";
        return 1;
    }

    if (verbose) spdlog::set_level(spdlog::level::debug);
    return 0;
}
