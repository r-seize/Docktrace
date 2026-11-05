# Threat model

This document describes what docktrace observes, what it cannot see, and
what guarantees a generated profile does and does not provide. Read this
before enforcing a docktrace-generated profile in production.

## What docktrace observes

- **Process execution**: `execve` events for the observed cgroup/PID tree.
- **File access**: opens, writes, deletes, with a path, process, and access
  type.
- **Network activity**: outbound connections and binds, by process,
  protocol, address, and port.
- **Syscalls**: a counted table of syscalls seen on the eBPF collector path
  (the `/proc` fallback collector infers a smaller, derived subset — see
  below).
- **Capabilities**: which of the container's *configured* capabilities were
  actually exercised during the run.

Every report records `observation.mode` (`ebpf` or `proc`) and a `coverage`
block (counts of processes/files/network/syscalls seen), so a profile's
inputs are auditable after the fact.

## What docktrace cannot see

- **Anything outside the observation window.** A 30-second or 60-second
  window will not exercise cron jobs, periodic health checks, log rotation,
  backup jobs, graceful-shutdown paths, or rare error-handling branches.
  Any syscall, file, or network destination exclusive to those paths will
  be absent from the report and therefore missing from a generated profile.
- **DNS resolution.** Destinations are recorded as the resolved IP the
  process actually connected to, not the hostname that was requested.
- **Behavior gated behind external state** that didn't occur during the
  run (a retry path, a specific HTTP error code, a failover).
- **Full syscall visibility under the `/proc` fallback collector.** The
  eBPF collector observes syscalls directly; the `/proc` collector
  approximates file/network/process activity by polling and can miss
  short-lived processes and does not have equivalent syscall-level
  visibility. Every report generated with `mode: proc` carries an explicit
  warning for this reason — treat such reports as lower-confidence input.
- **Dropped events.** Under heavy load, the eBPF ring buffer can in
  principle drop events faster than they're consumed. The report schema has
  a `dropped_events` counter reserved for this, but as of v0.1.1 neither
  collector actually instruments it — it is always `0`. Treat it as "not
  yet measured," not as a guarantee that nothing was dropped.

## What a generated profile is (and is not)

A docktrace-generated seccomp/capabilities profile is a **starting point**,
derived from what was observed, not a formal security guarantee. In
particular:

- It is **not** a substitute for code review, dependency auditing, or
  standard container hardening (non-root user, read-only rootfs where
  possible, resource limits).
- A "minimal" profile is only as complete as the observation that produced
  it. If the workload wasn't exercised end-to-end during observation, a
  minimal profile **will** break the untested code paths.
- `--strictness conservative` (the default) is deliberately more permissive
  than `--strictness minimal`: it starts from docktrace's curated baseline
  of syscalls generally considered safe for containerized workloads, and
  removes only syscalls that were neither observed nor required for clean
  process startup/exit. This trades a larger attack surface for a lower
  chance of breaking an untested path. It is **not** a byte-for-byte copy
  of any particular container runtime's own default seccomp profile.
- `--strictness audit` keeps the same allow-set as `conservative` but sets
  `defaultAction` to `SCMP_ACT_LOG` instead of `SCMP_ACT_ERRNO`: nothing is
  blocked, deviations are only logged. Use this for a first rollout (see
  [docs/progressive-rollout.md](docs/progressive-rollout.md)), never as a
  final production profile.

## Trust boundary

docktrace itself typically runs with elevated privileges (root, or
`CAP_BPF`/`CAP_PERFMON`) to attach eBPF programs or read `/proc` for other
processes. Treat the machine running `docktrace observe` as being inside
the same trust boundary as the containers it observes — it is not a
sandboxed analysis tool.

## Reporting issues

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, including
cases where the vulnerability is "a generated profile is unsafe" rather
than a traditional memory-safety bug.
