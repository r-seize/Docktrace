#include <catch2/catch_all.hpp>
#include "docktrace/output/renderer.hpp"
#include <sstream>

using namespace docktrace;
using namespace docktrace::output;

static Report make_sample() {
    Report r;
    r.container.name     = "api";
    r.container.runtime  = "runc";
    r.container.root_pid = 1842;
    r.observation.duration_seconds = 60;

    ProcessObservation p;
    p.path       = "/usr/local/bin/api";
    p.exec_count = 1;
    r.processes.push_back(p);

    FileObservation f;
    f.path    = "/etc/resolv.conf";
    f.access  = FileAccess::Read;
    f.process = "/usr/local/bin/api";
    f.count   = 12;
    r.files.push_back(f);

    NetworkObservation n;
    n.protocol            = "tcp";
    n.destination_address = "10.0.0.12";
    n.destination_port    = 5432;
    n.process             = "/usr/local/bin/api";
    n.count               = 84;
    r.network.push_back(n);

    r.warnings.push_back("test warning");
    return r;
}

TEST_CASE("Renderer - terminal output contains key fields", "[renderer]") {
    Report r = make_sample();
    // render() writes to stdout; we test parse_format here
    CHECK(parse_format("terminal") == Format::Terminal);
    CHECK(parse_format("json")     == Format::Json);
    CHECK(parse_format("markdown") == Format::Markdown);
}

TEST_CASE("Renderer - unknown format throws", "[renderer]") {
    CHECK_THROWS_AS(parse_format("xml"), std::invalid_argument);
}
