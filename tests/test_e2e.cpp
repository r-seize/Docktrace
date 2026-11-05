#include <catch2/catch_all.hpp>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/wait.h>

// End-to-end tests driving the actual docktrace binary through the
// profile -> validate -> report pipeline on the bundled sample report.
// There is no running container in this environment, so `observe` /
// `baseline` themselves are not exercised here.

namespace {
    // Captures stdout of a shell command and returns {exit_code, output}.
    std::pair<int, std::string> run(const std::string& cmd) {
        std::string full = cmd + " 2>&1";
        FILE* pipe = popen(full.c_str(), "r");
        REQUIRE(pipe != nullptr);
        std::ostringstream out;
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
            out.write(buf, static_cast<std::streamsize>(n));
        int status = pclose(pipe);
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return {code, out.str()};
    }

    std::string bin()      { return DOCKTRACE_BIN; }
    std::string examples()  { return DOCKTRACE_EXAMPLES_DIR; }

    std::string profile_cmd(const std::string& strictness, const std::string& out_path) {
        return bin() + " profile --input " + examples() + "/sample-report.json"
             + " --format oci-seccomp --strictness " + strictness
             + " -o " + out_path;
    }
}

TEST_CASE("E2E - report --summary on sample report", "[e2e]") {
    auto [code, out] = run(bin() + " report --input " + examples() + "/sample-report.json --summary");
    CHECK(code == 0);
    CHECK(out.find("collector=") != std::string::npos);
}

TEST_CASE("E2E - profile -> validate pipeline for every strictness level", "[e2e]") {
    auto tmp = std::filesystem::temp_directory_path() / "docktrace-e2e-profile.json";

    for (std::string strictness : {"conservative", "minimal", "audit"}) {
        auto [gen_code, gen_out] = run(profile_cmd(strictness, tmp.string()));
        CHECK(gen_code == 0);

        auto [val_code, val_out] = run(bin() + " validate --input " + tmp.string() + " --format oci-seccomp");
        CHECK(val_code == 0);
        CHECK(val_out.find("Status: VALID") != std::string::npos);
    }

    std::filesystem::remove(tmp);
}

TEST_CASE("E2E - validate rejects an unknown action and warns on ALLOW default", "[e2e]") {
    auto tmp = std::filesystem::temp_directory_path() / "docktrace-e2e-bad.json";
    std::ofstream f(tmp);
    f << R"({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["read","not_a_real_syscall"],"action":"SCMP_ACT_ALLOW"}]})";
    f.close();

    auto [code, out] = run(bin() + " validate --input " + tmp.string() + " --format oci-seccomp");
    CHECK(code == 0); // warnings only, not hard errors
    CHECK(out.find("not_a_real_syscall") != std::string::npos);
    CHECK(out.find("unsafe for production") != std::string::npos);

    std::filesystem::remove(tmp);
}

TEST_CASE("E2E - profile --explain runs without producing a profile file", "[e2e]") {
    auto [code, out] = run(bin() + " profile --input " + examples() + "/sample-report.json --format oci-seccomp --explain");
    CHECK(code == 0);
    CHECK(out.find("Syscalls kept") != std::string::npos);
}
