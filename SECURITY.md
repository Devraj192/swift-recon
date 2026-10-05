# Security Policy

## Authorized use only

SwiftRecon is built for testing systems you own or have written permission
to test. Do not use it against third-party systems. The tool itself
refuses to help with exploitation, credential attacks, brute-forcing
logins, evasion, or destructive testing — and contributions adding such
capabilities will be declined (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Reporting a vulnerability

**Do not open a public issue.** Instead:

1. Use GitHub's private vulnerability reporting on the
   [security tab](https://github.com/Devraj192/swift-recon/security)
   (Security → Report a vulnerability).
2. Include: affected version/commit, exact command or input, what you
   observed, what you expected, and full logs. Proof-of-concept code
   against loopback/fixture targets is welcome; live targets are not.

You will receive an acknowledgment, and we will coordinate a fix and a
release before any public disclosure. Please allow reasonable time for
remediation.

## Scope of this policy

In scope: the SwiftRecon workspace in this repository (engine, CLI, TUI,
report rendering of untrusted target data, SQLite handling, dependency
supply chain as pinned in `Cargo.lock`).

Out of scope: the sibling
[`sentinel-scanner`](https://github.com/Devraj192/sentinel-scanner)
project (report there), third-party passive sources (crt.sh, Wayback),
and scans of systems you are not authorized to test.

## Hardening posture

- Every connection passes the scope guard, including redirect hops, with
  post-resolution IP re-checks.
- Hostile input is assumed: timeouts on all network operations, bounded
  channels, capped bodies with decompression guards, linear-time regex,
  escaped reports, stripped terminal output, redacted secrets.
- Releases ship SHA-256 checksums; `cargo-audit` and `cargo-deny` gate
  the dependency tree.
