# SwiftRecon — Changelog

## Phase 3 — Live hosts (pending commit)

- Port discovery via pinned `sentinelscan-core` rev `a5deb6f` (API inspected in vendored source first); dual-guard bridge, per-IP dedup, `web` set = 80/443/8000/8080/8443; `top100` deferred.
- HTTP probing with manual redirect chains + per-hop scope checks, soft-404 filtering, cookie-name-only capture; bounded 16-way probe concurrency.
- TLS metadata via recording verifier (completes handshake, records validity); SANs feed back into discovery.
- Fingerprint rule engine v1 (`rules/fingerprint.toml`, TOML): evidence + capped confidence rubric; lab precision 1.0000.
- Reports: JSON, CSV, single-file HTML (escaped, CSP); migration 002 (ports, http_services, tls_info, technologies).
- Fixes found by live smoke: single crypto provider (ring), body-read timeouts, probe concurrency.
- Limitations: no live TLS-cert proof in sandbox; peer-IP pinning gap (D16); sequential brute-force DNS.

- New `crates/net`: resolver pool (google, per-resolver rate limit, health skip), TTL cache, distinct NXDOMAIN/SERVFAIL/timeout/refused outcomes, scope-gated queries.
- New `crates/discover`: `Source` trait, crt.sh passive source, mini wordlist brute-force with re-validation, wildcard detect + filter, provenance merge with agreement boost.
- CLI: `scan --passive`, `--output terminal|jsonl` (JSONL facts on stdout, summary on stderr); facts persisted to SQLite.
- Lab corpus precision 1.0000, recall 0.9167 (fixture, 12 hosts).
- Limitations: passive sources beyond crt.sh, API-key sources, NS/MX/CNAME derivation, reverse DNS, permutations — later.

## Phase 1 — Foundation (committed)

- Workspace scaffold: core, scope, engine, store, cli; TOML config; CI (fmt/clippy/test).
- `ScopeGuard` enforces scope on DNS/TCP/redirect hops with IP re-check.
- Scheduler skeleton: bounded channels, concurrency cap, global rate limit, backoff retry, timeout, cancellation.
- SQLite WAL store with single writer; empty scan persists and resumes.
- CLI: `scan`, `scope check`, `doctor`, `init`; authorized-use warning + `--yes`.
- Limitations: no discovery/DNS/ports/HTTP yet (Phases 2-4); writer not yet batched; lab metrics not yet measured.

## Phase 1 fixes (bug-hunt pass)

- Sanitize all target-controlled terminal output via `strip_control`.
- `run_unit` honors cancellation at unit start.
- `dedup_hostnames` drops empty entries; scope/IP docstrings corrected.
- Store docs state direct autocommit (batching deferred).
