#include <catch2/catch_all.hpp>
// diff is a CLI subcommand; test its core logic via set operations
#include <set>
#include <string>

// Lightweight re-implementation of diff logic for unit testing
static std::vector<std::string> new_items(
    const std::set<std::string>& base,
    const std::set<std::string>& curr)
{
    std::vector<std::string> result;
    for (auto& item : curr)
        if (!base.count(item)) result.push_back(item);
    return result;
}

TEST_CASE("Diff - detects new process", "[diff]") {
    std::set<std::string> base = {"/usr/bin/api"};
    std::set<std::string> curr = {"/usr/bin/api", "/bin/bash"};
    auto added = new_items(base, curr);
    REQUIRE(added.size() == 1);
    CHECK(added[0] == "/bin/bash");
}

TEST_CASE("Diff - no change returns empty", "[diff]") {
    std::set<std::string> s = {"/usr/bin/api", "/usr/bin/curl"};
    auto added = new_items(s, s);
    CHECK(added.empty());
}

TEST_CASE("Diff - detects new network connection", "[diff]") {
    std::set<std::string> base = {"tcp:10.0.0.12:5432"};
    std::set<std::string> curr = {"tcp:10.0.0.12:5432", "tcp:185.199.108.133:443"};
    auto added = new_items(base, curr);
    REQUIRE(added.size() == 1);
    CHECK(added[0] == "tcp:185.199.108.133:443");
}
