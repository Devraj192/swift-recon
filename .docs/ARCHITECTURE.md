# SwiftRecon — Architecture (Phase 1)

## Pipeline (PRD §4)

Scope → Discovery → DNS → Ports → HTTP/TLS → Fingerprint → Crawler → JS → Endpoints.
Typed events over bounded channels; slow stages apply backpressure.
Single SQLite writer; scheduler owns limits, retries, timeouts, cancellation.

## Phase 1 crates

```
crates/core    Fact/Evidence/Confidence/Event, thiserror
crates/scope   ScopeFile TOML, ScopeEntry (domain/wildcard/ip/cidr), Scope, ScopeGuard
crates/engine  Limits, Scheduler (mpsc + Semaphore + governor + backon + CancellationToken), PortProvider stub
crates/store   migrate (scans, work_units, facts), Store writer thread (sync_channel 1024)
crates/cli     clap derive, mimalloc, tracing-subscriber env-filter to stderr
```

## Key decisions

- Workspace `resolver = "2"`, Rust 1.75+, release `lto=fat, codegen-units=1, strip=true`.
- `psl` used only for `registrable_domain` helper; scope matching is label-boundary string logic + `ipnet`.
- `PortProvider::probe` has a default stub body so Phase 1-2 compile without `sentinelscan-core` (PRD open Q5 stays open).
- Store writer is direct autocommit per op in Phase 1 (correct, not yet batched 500-row transactions — batching lands with real volume in Phase 4).
- No `crates/net` yet — resolver pool/HTTP client arrive Phase 2-3 per anti-over-engineering rule.

## Data model (Phase 1 subset of PRD §7)

`scans(id, status, scope_json, started, finished)`, `work_units(scan_id, stage, key, state, attempts, last_error)`, `facts(...)`. Indexes on `(scan_id, kind)`.
