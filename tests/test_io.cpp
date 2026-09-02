#include <catch2/catch_all.hpp>
#include "docktrace/model/io.hpp"
#include <filesystem>
#include <fstream>

using namespace docktrace;
using namespace docktrace::model;

static Report make_full_report() {
    Report r;
    r.container.name      = "api";
    r.container.id        = "abc123";
    r.container.image     = "myimage:1.0";
    r.container.runtime   = "runc";
    r.container.root_pid  = 1234;
    r.container.cgroup_id = 567890;
    r.container.capabilities_configured = {"CAP_NET_BIND_SERVICE"};

    r.observation.started_at       = "2026-08-25T00:00:00Z";
    r.observation.duration_seconds = 60;
    r.observation.kernel           = "6.12.0";
    r.observation.architecture     = "x86_64";

    ProcessObservation p;
    p.path       = "/usr/bin/api";
    p.exec_count = 3;
    r.processes.push_back(p);

    FileObservation f;
    f.path    = "/etc/hosts";
    f.access  = FileAccess::Read;
    f.process = "/usr/bin/api";
    f.count   = 5;
    r.files.push_back(f);

    NetworkObservation n;
    n.protocol            = "tcp";
    n.destination_address = "10.0.0.1";
    n.destination_port    = 443;
    n.process             = "/usr/bin/api";
    n.count               = 12;
    r.network.push_back(n);

    r.syscalls["read"]  = 100;
    r.syscalls["write"] = 50;

    r.capabilities.configured   = {"CAP_NET_BIND_SERVICE"};
    r.capabilities.observed     = {"CAP_NET_BIND_SERVICE"};
    r.warnings.push_back("test warning");
    return r;
}

TEST_CASE("IO - save and reload report round-trips correctly", "[io]") {
    auto tmp = std::filesystem::temp_directory_path() / "docktrace_test_report.json";
    Report orig = make_full_report();

    save_report(orig, tmp.string());
    Report loaded = load_report(tmp.string());

    CHECK(loaded.container.name         == orig.container.name);
    CHECK(loaded.container.id           == orig.container.id);
    CHECK(loaded.container.root_pid     == orig.container.root_pid);
    CHECK(loaded.container.cgroup_id    == orig.container.cgroup_id);
    CHECK(loaded.observation.duration_seconds == orig.observation.duration_seconds);
    CHECK(loaded.processes.size()       == orig.processes.size());
    CHECK(loaded.processes[0].exec_count == orig.processes[0].exec_count);
    CHECK(loaded.files.size()           == orig.files.size());
    CHECK(loaded.files[0].access        == orig.files[0].access);
    CHECK(loaded.files[0].count         == orig.files[0].count);
    CHECK(loaded.network.size()         == orig.network.size());
    CHECK(loaded.network[0].destination_port == orig.network[0].destination_port);
    CHECK(loaded.syscalls["read"]       == orig.syscalls["read"]);
    CHECK(loaded.warnings.size()        == orig.warnings.size());

    std::filesystem::remove(tmp);
}

TEST_CASE("IO - load_report throws on missing file", "[io]") {
    CHECK_THROWS_AS(load_report("/nonexistent/path/report.json"), std::runtime_error);
}

TEST_CASE("IO - save_report throws on unwritable path", "[io]") {
    CHECK_THROWS_AS(save_report(Report{}, "/nonexistent/dir/out.json"), std::runtime_error);
}
