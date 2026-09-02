#include <catch2/catch_all.hpp>
#include "docktrace/model/aggregator.hpp"

using namespace docktrace;

TEST_CASE("Aggregator - process exec events", "[aggregator]") {
    Aggregator agg;

    Event e;
    e.type         = EventType::ProcessExec;
    e.pid          = 100;
    e.path         = "/usr/bin/curl";
    e.process_name = "/usr/bin/curl";
    e.timestamp_ns = 1000;

    agg.ingest(e);
    agg.ingest(e); // second exec of same binary

    ContainerInfo ci;
    ci.name = "test";
    ObservationMeta meta;
    meta.duration_seconds = 10;

    Report r = agg.build(ci, meta);

    REQUIRE(r.processes.size() == 1);
    CHECK(r.processes[0].path == "/usr/bin/curl");
    CHECK(r.processes[0].exec_count == 2);
    // execve syscall should be counted
    CHECK(r.syscalls.count("execve") == 1);
    CHECK(r.syscalls.at("execve") == 2);
}

TEST_CASE("Aggregator - file open read", "[aggregator]") {
    Aggregator agg;

    Event e;
    e.type         = EventType::FileOpen;
    e.flags        = 0; // O_RDONLY
    e.path         = "/etc/resolv.conf";
    e.process_name = "/usr/bin/api";
    e.timestamp_ns = 2000;

    for (int i = 0; i < 12; ++i) agg.ingest(e);

    Report r = agg.build({}, {});

    REQUIRE(r.files.size() == 1);
    CHECK(r.files[0].path    == "/etc/resolv.conf");
    CHECK(r.files[0].access  == FileAccess::Read);
    CHECK(r.files[0].count   == 12);
    CHECK(r.files[0].confidence == FileObservation::Confidence::High);
}

TEST_CASE("Aggregator - file open O_RDWR gets medium confidence", "[aggregator]") {
    Aggregator agg;

    Event e;
    e.type         = EventType::FileOpen;
    e.flags        = 2; // O_RDWR
    e.path         = "/tmp/cache.db";
    e.process_name = "/app/server";
    e.timestamp_ns = 3000;
    agg.ingest(e);

    Report r = agg.build({}, {});
    REQUIRE(!r.files.empty());
    CHECK(r.files[0].confidence == FileObservation::Confidence::Medium);
}

TEST_CASE("Aggregator - network connections deduplicated", "[aggregator]") {
    Aggregator agg;

    Event e;
    e.type           = EventType::NetworkConnect;
    e.process_name   = "/usr/bin/api";
    e.remote_address = "10.0.0.12";
    e.remote_port    = 5432;

    for (int i = 0; i < 84; ++i) agg.ingest(e);

    Report r = agg.build({}, {});

    REQUIRE(r.network.size() == 1);
    CHECK(r.network[0].destination_address == "10.0.0.12");
    CHECK(r.network[0].destination_port    == 5432);
    CHECK(r.network[0].count               == 84);
}

TEST_CASE("Aggregator - capabilities not evidenced", "[aggregator]") {
    Aggregator agg;

    ContainerInfo ci;
    ci.capabilities_configured = {"CAP_CHOWN", "CAP_NET_BIND_SERVICE"};

    // Only observe NET_BIND_SERVICE
    Event cap_ev;
    cap_ev.type = EventType::CapabilityUse;
    cap_ev.path = "CAP_NET_BIND_SERVICE";
    agg.ingest(cap_ev);

    Report r = agg.build(ci, {});

    CHECK(r.capabilities.observed.size()     == 1);
    CHECK(r.capabilities.not_evidenced.size() == 1);
    CHECK(r.capabilities.not_evidenced[0]     == "CAP_CHOWN");
}
