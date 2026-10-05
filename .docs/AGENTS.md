# SwiftRecon — Agent Notes (Phase 1)

Source of truth: `.docs/SwiftRecon-PRD.md`. Rules: `.rules/rules.md`.
Docs live only in `.docs/` — root `*.md` is gitignored by project rule.

## Current phase

Phase 3 live hosts (PRD §11). Work only on this phase. One commit per phase.

## What exists (Phase 3 adds)

- `crates/engine/ports`: `SentinelPorts` over pinned `sentinelscan-core` (`scan_ports`), dual-guard bridge (`allow_ip` only for approved IPs), `parse_ports` (web/lists/ranges; top100 deferred), per-IP dedup.
- `crates/net/http`: manual redirect chains + per-hop scope check, soft-404 shapes, cookie-name-only capture, retry transient only, 30s body timeouts.
- `crates/net/tls`: recording verifier (completes handshake), version/cipher/subject/issuer/SANs/validity; ring-only crypto (D17).
- `crates/fingerprint`: TOML rule engine v1 (`rules/fingerprint.toml`), evidence + capped rubric, implies/excludes.
- `crates/report`: JSON/CSV/single-file HTML (escaped, CSP).
- Store migration 002 (ports, http_services, tls_info, technologies); CLI `--ports`, `--output terminal|jsonl|json|csv|html`.

## What exists (Phase 2 adds)

- `crates/net`: `DnsOutcome` (NXDOMAIN/SERVFAIL/timeout/refused distinct), TTL `DnsCache`, `ResolverPool` (google resolvers, per-resolver governor limit, unhealthy skip, scope-gated queries).
- `crates/discover`: `Source` trait, `CrtShSource` (timeout + per-source failure), `brute_force` (mini wordlist, fresh-lookup re-validation), `detect_wildcard`/`filter_wildcard`, `merge_sources` (agreement boost 0.6→0.85).
- CLI: `scan --passive`, `--output terminal|jsonl`; facts persisted via `store.insert_fact`.
- `lab/` accuracy fixture: precision 1.0000, recall 0.9167 (recorded in STATE).

## What exists (Phase 1)

- `crates/core`: `Fact`, `Evidence` (observed/inferred), `Confidence` (0.0-1.0, noisy-OR capped), `Event`, `merge` unions sources/evidence.
- `crates/scope`: TOML scope file, label-boundary wildcard, CIDR/IP, `ScopeGuard` (DNS/TCP/redirect-hop gate), IP re-check, `explain`, exact-set `dedup_hostnames`.
- `crates/engine`: `Scheduler` (bounded mpsc, semaphore, governor global limiter, backon retry, timeout, CancellationToken), `PortProvider` stub for Phase 3 `sentinelscan-core`.
- `crates/store`: SQLite WAL, single writer thread, `scans`/`work_units`/`facts`, `migrate`, resume via work-unit states.
- `crates/cli`: `swiftrecon scan [--scope --resume --yes]`, `scope check`, `doctor`, `init`. Warning + confirmation on every scan. Logs to stderr, data to stdout, control chars stripped.

## Invariants (do not break)

1. Every outbound connection incl. redirect hops goes through `ScopeGuard`.
2. Resolved IPs re-checked; private/loopback/link-local blocked unless IP/CIDR explicitly scoped.
3. DNS states kept distinct (Phase 2); port states open/closed/filtered/unknown with reason (Phase 3).
4. Exact dedup only — no Bloom filters. TOML only, never YAML. No `panic=abort`, no `unsafe`.
5. Single DB writer; stdout = data only; `tracing` to stderr.

## Verify before done

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (nextest absent → `cargo test` per rules).
