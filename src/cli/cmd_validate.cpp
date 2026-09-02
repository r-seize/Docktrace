#include <CLI/CLI.hpp>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace docktrace::cli {

namespace {
    struct ValidationResult {
        bool ok{true};
        std::vector<std::string> errors;
        std::vector<std::string> warnings;

        void error(const std::string& msg) { errors.push_back(msg); ok = false; }
        void warn(const std::string& msg)  { warnings.push_back(msg); }
    };

    ValidationResult validate_seccomp_json(const nlohmann::json& j) {
        ValidationResult r;
        if (!j.contains("defaultAction"))
            r.error("Missing 'defaultAction' field");
        if (!j.contains("syscalls"))
            r.error("Missing 'syscalls' array");
        else if (!j["syscalls"].is_array())
            r.error("'syscalls' must be an array");
        else {
            for (auto& sc : j["syscalls"]) {
                if (!sc.contains("names") || !sc.contains("action"))
                    r.error("Each syscall entry needs 'names' and 'action'");
            }
        }
        if (!j.contains("architectures"))
            r.warn("No 'architectures' specified — profile may not be portable");

        static const std::vector<std::string> VALID_ACTIONS = {
            "SCMP_ACT_ALLOW","SCMP_ACT_ERRNO","SCMP_ACT_KILL","SCMP_ACT_TRAP",
            "SCMP_ACT_LOG","SCMP_ACT_TRACE","SCMP_ACT_NOTIFY"
        };
        if (j.contains("defaultAction")) {
            std::string da = j["defaultAction"];
            bool found = false;
            for (auto& a : VALID_ACTIONS) if (a == da) { found = true; break; }
            if (!found) r.error(fmt::format("Unknown defaultAction: {}", da));
        }
        return r;
    }

    ValidationResult validate_yaml_profile(const YAML::Node& y) {
        ValidationResult r;
        if (!y["capabilities"]) r.warn("No 'capabilities' section");
        if (!y["filesystem"])   r.warn("No 'filesystem' section");
        if (!y["network"])      r.warn("No 'network' section");
        if (y["capabilities"]) {
            if (!y["capabilities"]["drop"]) r.warn("capabilities.drop not set (recommend: drop ALL)");
        }
        return r;
    }
}

void register_validate(CLI::App& app) {
    auto* sub   = app.add_subcommand("validate", "Validate a security profile file");
    auto input  = std::make_shared<std::string>();
    auto format = std::make_shared<std::string>("auto");

    sub->add_option("-i,--input",  *input,  "Profile file to validate")->required();
    sub->add_option("-f,--format", *format, "Format: auto|oci-seccomp|yaml");

    sub->callback([=]() {
        std::ifstream f(*input);
        if (!f) throw std::runtime_error("Cannot open: " + *input);

        // Detect format
        std::string detected = *format;
        if (detected == "auto") {
            if (input->size() >= 5 && input->substr(input->size()-5) == ".json")
                detected = "oci-seccomp";
            else
                detected = "yaml";
        }

        ValidationResult result;
        std::cout << fmt::format("Validating {} as {}...\n\n", *input, detected);

        if (detected == "oci-seccomp") {
            try {
                auto j = nlohmann::json::parse(f);
                result = validate_seccomp_json(j);
            } catch (const std::exception& ex) {
                result.error(fmt::format("JSON parse error: {}", ex.what()));
            }
        } else {
            try {
                auto y = YAML::Load(f);
                result = validate_yaml_profile(y);
            } catch (const std::exception& ex) {
                result.error(fmt::format("YAML parse error: {}", ex.what()));
            }
        }

        for (auto& e : result.errors)   std::cout << fmt::format("  [ERROR]   {}\n", e);
        for (auto& w : result.warnings) std::cout << fmt::format("  [WARNING] {}\n", w);

        if (result.ok)
            std::cout << "\nStatus: VALID\n";
        else {
            std::cout << "\nStatus: INVALID\n";
            throw std::runtime_error("profile validation failed");
        }
    });
}

} // namespace docktrace::cli
