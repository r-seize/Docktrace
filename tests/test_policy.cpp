#include <catch2/catch_all.hpp>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include "docktrace/policy/policy_generator.hpp"

using namespace docktrace;
using namespace docktrace::policy;

static Report make_report() {
    Report r;
    r.container.capabilities_configured = {"CAP_CHOWN", "CAP_NET_BIND_SERVICE"};
    r.capabilities.configured            = {"CAP_CHOWN", "CAP_NET_BIND_SERVICE"};
    r.capabilities.observed              = {"CAP_NET_BIND_SERVICE"};
    r.capabilities.not_evidenced         = {"CAP_CHOWN"};

    FileObservation fw;
    fw.path    = "/tmp/cache.db";
    fw.access  = FileAccess::Write;
    fw.process = "/usr/local/bin/api";
    fw.count   = 18;
    r.files.push_back(fw);

    FileObservation fr;
    fr.path    = "/etc/resolv.conf";
    fr.access  = FileAccess::Read;
    fr.process = "/usr/local/bin/api";
    fr.count   = 12;
    r.files.push_back(fr);

    NetworkObservation n;
    n.protocol            = "tcp";
    n.destination_address = "10.0.0.12";
    n.destination_port    = 5432;
    n.process             = "/usr/local/bin/api";
    n.count               = 84;
    r.network.push_back(n);

    r.syscalls["read"]    = 100;
    r.syscalls["write"]   = 50;
    r.syscalls["ptrace"]  = 1; // sensitive
    return r;
}

TEST_CASE("Policy - caps drop ALL add observed", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);

    REQUIRE(prof.caps_drop.size() == 1);
    CHECK(prof.caps_drop[0] == "ALL");
    REQUIRE(prof.caps_add.size() == 1);
    CHECK(prof.caps_add[0] == "CAP_NET_BIND_SERVICE");
}

TEST_CASE("Policy - readonly_root true when only /tmp written", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    // /tmp is a known-writable path, so readonly_root should be true
    CHECK(prof.readonly_root == true);
}

TEST_CASE("Policy - readonly_root false when rootfs written", "[policy]") {
    auto r = make_report();
    FileObservation fw;
    fw.path   = "/app/data/db";
    fw.access = FileAccess::Write;
    fw.count  = 5;
    r.files.push_back(fw);

    auto prof = generate(r);
    CHECK(prof.readonly_root == false);
}

TEST_CASE("Policy - sensitive syscalls detected", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    REQUIRE(!prof.syscalls_sensitive.empty());
    CHECK(prof.syscalls_sensitive[0] == "ptrace");
}

TEST_CASE("Policy - network rules generated", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    REQUIRE(prof.network_allow.size() == 1);
    CHECK(prof.network_allow[0].port == 5432);
}

TEST_CASE("Policy - YAML output contains capabilities block", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    std::string yaml = to_yaml(prof);
    CHECK(yaml.find("capabilities:") != std::string::npos);
    CHECK(yaml.find("drop:") != std::string::npos);
    CHECK(yaml.find("readonly_root:") != std::string::npos);
}

TEST_CASE("Policy - OCI seccomp output is valid JSON", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    std::string sec = to_oci_seccomp(prof, r);
    auto j = nlohmann::json::parse(sec); // throws on invalid
    CHECK(j.contains("defaultAction"));
    CHECK(j.contains("syscalls"));
}

TEST_CASE("Policy - parse_strictness accepts known values and rejects others", "[policy]") {
    CHECK(parse_strictness("conservative") == Strictness::Conservative);
    CHECK(parse_strictness("minimal")      == Strictness::Minimal);
    CHECK(parse_strictness("audit")        == Strictness::Audit);
    CHECK_THROWS_AS(parse_strictness("bogus"), std::invalid_argument);
}

TEST_CASE("Policy - minimal strictness never exceeds conservative's allow-set", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);

    auto minimal_json      = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Minimal, true));
    auto conservative_json = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Conservative, true));

    auto names = [](nlohmann::json& j) {
        std::set<std::string> s;
        if (!j["syscalls"].empty())
            for (auto& n : j["syscalls"][0]["names"]) s.insert(n.get<std::string>());
        return s;
    };
    auto minimal_names      = names(minimal_json);
    auto conservative_names = names(conservative_json);

    for (auto& n : minimal_names)
        CHECK(conservative_names.count(n) == 1);
    CHECK(conservative_names.size() >= minimal_names.size());
}

TEST_CASE("Policy - every observed syscall is always kept regardless of strictness", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);

    for (auto strict : {Strictness::Minimal, Strictness::Conservative, Strictness::Audit}) {
        auto j = nlohmann::json::parse(to_oci_seccomp(prof, r, strict, true));
        std::set<std::string> names;
        if (!j["syscalls"].empty())
            for (auto& n : j["syscalls"][0]["names"]) names.insert(n.get<std::string>());
        for (auto& observed : prof.syscalls_observed)
            CHECK(names.count(observed) == 1);
    }
}

TEST_CASE("Policy - audit strictness logs instead of blocking", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    auto j = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Audit, true));
    CHECK(j["defaultAction"] == "SCMP_ACT_LOG");

    auto j_conservative = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Conservative, true));
    CHECK(j_conservative["defaultAction"] == "SCMP_ACT_ERRNO");
}

TEST_CASE("Policy - base=none restricts to observed syscalls plus vital set only", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);

    auto with_base    = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Conservative, true));
    auto without_base = nlohmann::json::parse(to_oci_seccomp(prof, r, Strictness::Conservative, false));

    size_t with_count    = with_base["syscalls"].empty()    ? 0 : with_base["syscalls"][0]["names"].size();
    size_t without_count = without_base["syscalls"].empty() ? 0 : without_base["syscalls"][0]["names"].size();
    CHECK(with_count >= without_count);
}

TEST_CASE("Policy - explain mentions every observed syscall", "[policy]") {
    auto r = make_report();
    auto prof = generate(r);
    std::string text = explain(prof, r, Strictness::Conservative, true);
    for (auto& observed : prof.syscalls_observed)
        CHECK(text.find(observed) != std::string::npos);
}
