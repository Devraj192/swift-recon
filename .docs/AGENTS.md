# SwiftRecon — Agent Notes (Phase 1)

Source of truth: `.docs/SwiftRecon-PRD.md`. Rules: `.rules/rules.md`.
Docs live only in `.docs/` — root `*.md` is gitignored by project rule.

## Current phase

Phase 1 Foundation (PRD §11). Work only on this phase. One commit per phase.

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
