#include <catch2/catch_all.hpp>
#include "docktrace/collector/cgroup_filter.hpp"
#include <unistd.h>

using namespace docktrace::collector;

TEST_CASE("CgroupFilter - no filter accepts all", "[cgroup]") {
    CgroupFilter f;
    // target_cgroup_id = 0, known_pids empty => accept all
    CHECK(f.matches(12345, 100) == true);
    CHECK(f.matches(0, 999)     == true);
}

TEST_CASE("CgroupFilter - cgroup_id filter", "[cgroup]") {
    CgroupFilter f;
    f.target_cgroup_id = 12345;
    CHECK(f.matches(12345, 1) == true);
    CHECK(f.matches(99999, 1) == false);
}

TEST_CASE("CgroupFilter - pid whitelist filter", "[cgroup]") {
    CgroupFilter f;
    f.add_pid(100);
    f.add_pid(200);
    CHECK(f.matches(0, 100) == true);
    CHECK(f.matches(0, 200) == true);
    CHECK(f.matches(0, 999) == false);
}

TEST_CASE("CgroupFilter - combined filter: both must match", "[cgroup]") {
    CgroupFilter f;
    f.target_cgroup_id = 42;
    f.add_pid(100);
    CHECK(f.matches(42, 100) == true);
    CHECK(f.matches(42, 999) == false); // wrong PID
    CHECK(f.matches(99, 100) == false); // wrong cgroup
}

TEST_CASE("CgroupFilter - clear resets state", "[cgroup]") {
    CgroupFilter f;
    f.target_cgroup_id = 99;
    f.add_pid(42);
    f.clear();
    CHECK(f.matches(0, 0) == true); // empty filter: accept all
}

TEST_CASE("CgroupFilter - from_pid reads /proc for current process", "[cgroup]") {
    // Use our own PID — it should always be found
    uint32_t self = static_cast<uint32_t>(getpid());
    auto f = CgroupFilter::from_pid(self);
    CHECK(f.known_pids.count(self) > 0);
    // cgroup_id may or may not be available depending on cgroupfs
    // just confirm it doesn't throw
}
