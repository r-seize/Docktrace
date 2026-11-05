#include <CLI/CLI.hpp>
#include <memory>
#include "docktrace/model/io.hpp"
#include "docktrace/policy/policy_generator.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace docktrace::cli {

void register_profile(CLI::App& app) {
    auto* sub    = app.add_subcommand("profile", "Generate a suggested security profile");
    auto input  = std::make_shared<std::string>();
    auto fmt    = std::make_shared<std::string>("yaml");
    auto output = std::make_shared<std::string>();
    auto base       = std::make_shared<std::string>("docker-default");
    auto strictness = std::make_shared<std::string>("conservative");
    auto explain_flag = std::make_shared<bool>(false);

    sub->add_option("-i,--input",  *input,  "Input report JSON file")->required();
    sub->add_option("-f,--format", *fmt,    "Profile format: yaml|oci-seccomp");
    sub->add_option("-o,--output", *output, "Output file (default: stdout)");
    sub->add_option("--base", *base,
        "Seccomp base allow-set for oci-seccomp: docker-default|none "
        "(docker-default keeps vital + commonly-safe syscalls even if unobserved)");
    sub->add_option("--strictness", *strictness,
        "Seccomp strictness for oci-seccomp: conservative|minimal|audit (default: conservative)");
    sub->add_flag("--explain", *explain_flag,
        "Print why each syscall/capability was kept instead of the profile itself");

    sub->callback([=]() {
        Report r       = model::load_report(*input);
        auto   profile = policy::generate(r);
        auto   pf      = policy::parse_profile_format(*fmt);

        if (*base != "none" && *base != "docker-default")
            throw std::runtime_error("Unknown --base: " + *base + " (expected docker-default|none)");
        bool use_base = (*base != "none");

        std::string result;
        if (*explain_flag) {
            if (pf != policy::ProfileFormat::OciSeccomp)
                throw std::runtime_error("--explain currently requires --format oci-seccomp");
            auto strict_v = policy::parse_strictness(*strictness);
            result = policy::explain(profile, r, strict_v, use_base);
        } else if (pf == policy::ProfileFormat::OciSeccomp) {
            auto strict_v = policy::parse_strictness(*strictness);
            result = policy::to_oci_seccomp(profile, r, strict_v, use_base);
        } else
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
