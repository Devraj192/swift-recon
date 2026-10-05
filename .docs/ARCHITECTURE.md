# SwiftRecon — Architecture (Phase 3)

## Pipeline (PRD §4)

Scope → Discovery → DNS → Ports → HTTP/TLS → Fingerprint → Crawler → JS → Endpoints.
Typed events over bounded channels; slow stages apply backpressure.
Single SQLite writer; scheduler owns limits, retries, timeouts, cancellation.

## Phase 1 crates

```
crates/core    Fact/Evidence/Confidence/Event, thiserror
crates/scope   ScopeFile TOML, ScopeEntry (domain/wildcard/ip/cidr), Scope, ScopeGuard
crates/net     DnsOutcome (distinct), DnsCache (TTL), ResolverPool (round-robin + governor + health skip)
crates/discover Source trait, CrtShSource, brute_force + re-validation, detect_wildcard/filter_wildcard, merge_sources
crates/engine  Limits, Scheduler (mpsc + Semaphore + governor + backon + CancellationToken), PortProvider stub
crates/store   migrate (scans, work_units, facts), Store writer thread (sync_channel 1024), insert_fact
crates/cli     clap derive, mimalloc, tracing-subscriber env-filter to stderr
crates/report  ScanReport, JSON/CSV/HTML (minijinja, escaped, CSP)
```

External (pinned): `sentinelscan-core` git rev `a5deb6f` (Apache-2.0) for port
probes; dual-guard bridge authorizes only our-approved IPs into its guard.
Workspace rusqlite unified at 0.31 for the single native link (D20).

Supporting data (not code): `wordlists/mini.txt` (24 names, embedded via
include_str), `lab/corpus.json` + `crtsh.json` + `bruteforce.json`
(12-host accuracy fixture with scripted answers, wildcard set).

## Key decisions

- Workspace `resolver = "2"`, Rust 1.75+, release `lto=fat, codegen-units=1, strip=true`.
- `psl` used only for `registrable_domain` helper; scope matching is label-boundary string logic + `ipnet`.
- `PortProvider` stub replaced by `ports::SentinelPorts` over pinned `sentinelscan-core` (PRD Q5 closed, D3 superseded).
- Store writer is direct autocommit per op (correct, not yet batched 500-row transactions — batching lands with real volume in Phase 4).

## Data model (Phase 1 subset of PRD §7)

`scans(id, status, scope_json, started, finished)`, `work_units(scan_id, stage, key, state, attempts, last_error)`, `facts(...)`. Indexes on `(scan_id, kind)`.
