# Rolling out a docktrace profile progressively

A profile generated from a single observation window is a hypothesis about
what the workload needs, not a certainty. Enforcing it immediately in
production risks breaking any code path that wasn't exercised while
observing. This guide describes a safer rollout sequence.

## 1. Observe realistically

Run `docktrace observe` (or `docktrace baseline create`) while exercising
the container's real workload — not just a health check. The longer and
more representative the window, the fewer surprises later.

```bash
docktrace observe --container myapp --duration 5m -o report.json
```

Check the report's warnings and `observation.coverage` before trusting it:

```bash
docktrace report --input report.json --summary
```

If `observation.mode` is `proc`, visibility is reduced — see
[THREAT-MODEL.md](../THREAT-MODEL.md).

## 2. Generate an audit-mode profile first

```bash
docktrace profile --input report.json --format oci-seccomp \
    --strictness audit -o seccomp.audit.json
docktrace validate --input seccomp.audit.json --format oci-seccomp
```

`--strictness audit` sets `defaultAction` to `SCMP_ACT_LOG`: nothing is
blocked, but anything outside the allow-set is logged by the kernel. Deploy
this version first and let it run under real traffic for a representative
period (hours to days, depending on traffic patterns).

## 3. Review what got logged

Check your logging pipeline (`dmesg`, `auditd`, or your container runtime's
seccomp logging integration) for `SECCOMP` audit events referencing your
container. Any syscall logged there was exercised by the real workload but
missed by the observation window — it needs to be in the enforced profile.

## 4. Switch to a conservative, then minimal, enforced profile

Once the audit period shows no unexpected syscalls:

```bash
docktrace profile --input report.json --format oci-seccomp \
    --strictness conservative -o seccomp.json
docktrace validate --input seccomp.json --format oci-seccomp
```

Deploy `seccomp.json` with enforcement (`SCMP_ACT_ERRNO`). Monitor
application error rates and logs closely after the switch — an `EPERM`
from a blocked syscall often surfaces as a generic crash or hang, not an
obvious seccomp-related error message.

Only move to `--strictness minimal` once you're confident the workload's
behavior is fully covered by observation; it trims syscalls that
`conservative` keeps defensively, and is more likely to need another audit
pass.

## 5. Re-baseline on every meaningful change

Treat the profile like a dependency: regenerate and re-audit it whenever
the application's dependencies, code paths, or runtime configuration
change in a way that could touch new syscalls, files, or network
destinations. `docktrace baseline check` can be wired into CI to catch
behavioral drift between releases:

```bash
docktrace baseline check --container myapp --baseline baseline.json \
    --fail-on new-process,new-network
```
