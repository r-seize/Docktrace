# Changelog

All notable changes to Docktrace are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-05

Focus: trusted, reproducible profiles and a clearer first-run experience.

### Added

- Every report now carries `observation.mode` (`ebpf`/`proc`),
  `observation.btf_available`, and an `observation.coverage` block
  (processes/files/network/syscalls counted), so `diff`/`baseline check`
  never silently compare runs with different visibility. Reports collected
  via the `/proc` fallback, with a very short duration, or with no activity
  at all now carry an explicit warning explaining why.
- `profile --format oci-seccomp` gained `--base docker-default|none` and
  `--strictness conservative|minimal|audit`:
  - `conservative` (default) keeps docktrace's curated baseline of
    syscalls generally considered safe for containerized workloads,
    filtered down to what was observed or is vital for process
    startup/exit.
  - `minimal` keeps only observed syscalls plus the vital set.
  - `audit` uses the `conservative` allow-set with `SCMP_ACT_LOG` instead
    of `SCMP_ACT_ERRNO`, for a safe first rollout (see
    [docs/progressive-rollout.md](docs/progressive-rollout.md)).
  - `profile --explain` prints why each syscall/capability was kept
    instead of emitting the profile.
- `validate` now flags unrecognized/misspelled syscall names, high-risk
  syscalls allowed without justification (`mount`, `bpf`, `ptrace`,
  `unshare`, `init_module`, `keyctl`, ...), `defaultAction:
  SCMP_ACT_ALLOW`, and unknown architecture strings.
- `report --summary` prints a single CI-friendly line instead of the full
  report.
- `baseline check --fail-on` makes the deviation categories that gate CI
  (`new-process`, `new-network`, `new-file-write`, `new-syscall`)
  configurable instead of failing on any change.
- `SECURITY.md`, `THREAT-MODEL.md`, and
  [docs/progressive-rollout.md](docs/progressive-rollout.md).
- End-to-end tests driving the real `docktrace` binary through the
  profile → validate pipeline at every strictness level
  (`tests/test_e2e.cpp`), plus unit tests for the new strictness logic.
- CI workflow building and testing on push/PR, and a release workflow
  producing multi-arch (`amd64`/`arm64`) `.deb` packages with checksums
  and a CycloneDX SBOM.

## [0.1.0] - 2025-09-02

Initial release.

### Added

- `observe`: watch a running container's processes, file access, and
  network connections (eBPF, with `/proc` fallback).
- `profile`: generate a minimal Seccomp/capabilities profile from an
  observation report.
- `validate`: check that a generated profile is well-formed.
- `doctor`: report on the local environment's ability to run Docktrace.
- `.deb` packaging and CMake-based build from source.
