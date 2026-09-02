#include <catch2/catch_all.hpp>
#include <nlohmann/json.hpp>
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
