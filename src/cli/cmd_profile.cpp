#include <CLI/CLI.hpp>
#include <memory>
#include "docktrace/model/io.hpp"
#include "docktrace/policy/policy_generator.hpp"
#include <fstream>
#include <iostream>

namespace docktrace::cli {

void register_profile(CLI::App& app) {
    auto* sub    = app.add_subcommand("profile", "Generate a suggested security profile");
    auto input  = std::make_shared<std::string>();
    auto fmt    = std::make_shared<std::string>("yaml");
    auto output = std::make_shared<std::string>();

    sub->add_option("-i,--input",  *input,  "Input report JSON file")->required();
    sub->add_option("-f,--format", *fmt,    "Profile format: yaml|oci-seccomp");
    sub->add_option("-o,--output", *output, "Output file (default: stdout)");

    sub->callback([=]() {
        Report r       = model::load_report(*input);
        auto   profile = policy::generate(r);

        std::string result;
        auto pf = policy::parse_profile_format(*fmt);
        if (pf == policy::ProfileFormat::OciSeccomp)
            result = policy::to_oci_seccomp(profile, r);
        else
            result = policy::to_yaml(profile);

        if (output->empty() || *output == "-") {
            std::cout << result;
            if (result.empty() || result.back() != '\n') std::cout << '\n';
        } else {
            std::ofstream f(*output);
            if (!f) throw std::runtime_error("Cannot write profile to: " + *output);
            f << result;
            std::cout << "Profile written to " << *output << "\n";
        }
    });
}

} // namespace docktrace::cli
