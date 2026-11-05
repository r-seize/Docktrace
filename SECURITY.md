# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, report them privately through GitHub's
[private vulnerability reporting](https://github.com/r-seize/docktrace/security/advisories/new)
feature on this repository ("Security" tab → "Report a vulnerability").

Include, where possible:

- a description of the issue and its impact (e.g. a generated profile that
  under-restricts a container, a crash, a privilege escalation path);
- steps to reproduce, including the docktrace version and the command line
  used;
- whether the issue affects observation (`observe`, `baseline`), profile
  generation (`profile`), or validation (`validate`).

We aim to acknowledge reports within 5 business days.

## Scope

Docktrace generates *suggested* security profiles from observed container
behavior. A profile that is more permissive than intended, or an observation
that misses real behavior, is a security-relevant bug even though it does
not require memory-safety or privilege-escalation characteristics to be
impactful — see [THREAT-MODEL.md](THREAT-MODEL.md) for what docktrace does
and does not guarantee.

Issues in third-party dependencies (CLI11, nlohmann/json, fmt, spdlog,
yaml-cpp) should generally be reported upstream, unless docktrace's usage of
them introduces an additional vulnerability.

## Supported versions

Only the latest released version receives security fixes. There is no
long-term support branch at this stage of the project.
