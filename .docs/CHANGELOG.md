# SwiftRecon — Changelog

## Phase 1 — Foundation (unreleased, pending commit)

- Workspace scaffold: core, scope, engine, store, cli; TOML config; CI (fmt/clippy/test).
- `ScopeGuard` enforces scope on DNS/TCP/redirect hops with IP re-check.
- Scheduler skeleton: bounded channels, concurrency cap, global rate limit, backoff retry, timeout, cancellation.
- SQLite WAL store with single writer; empty scan persists and resumes.
- CLI: `scan`, `scope check`, `doctor`, `init`; authorized-use warning + `--yes`.
- Limitations: no discovery/DNS/ports/HTTP yet (Phases 2-4); writer not yet batched; lab metrics not yet measured.
