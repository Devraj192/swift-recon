# SwiftRecon — State

## Status

- Phase: 1 Foundation — implemented, verify loop green. Bug-hunt pass applied (see below).
- Tests: 19 passed (`cargo test --workspace`): core 3, scope 8 (incl. 3 proptest), engine 4, store 2, cli 2.
- Smoke: `doctor` ok; `scope check` correct for wildcard/label-boundary/exclude/CIDR; `scan --yes` persists empty scan, `--resume` reuses scan id, out-of-scope target recorded not probed, warning shown.
- Verify: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings` clean.

## Bug-hunt fixes (post-commit review)

- B1: target-controlled text printed raw in 3 terminal paths (Scope desc, out-of-scope target, `scope check` output) — now all pass through `strip_control` + regression test.
- B2: `run_unit` claimed cancellation but never checked the token — now returns `Shutdown` when cancelled at unit start + regression test.
- B3: `dedup_hostnames` kept empty keys — now drops empties + regression test; `ip_allowed`/`explain` docstrings corrected to strict direct-match.
- B4: store module docs claimed batched transactions — corrected to direct autocommit, batching deferred.
- B5: removed stale async-trait shim comment in engine.

## Performance (measured, not claimed)

- Warm `cargo test --workspace`: 1.5s total; cold (compile): 25.9s one-off.
- No hot paths in the Phase 1 skeleton (no network, no parsing loops over target data); no optimization applied. Write batching deferred to volume phases by design (D5).

## Next

- Phase 2 (DNS + subdomain discovery) — not started. Do not start until Phase 1 commit lands.
- Open: `sentinelscan-core` API (PRD Q5) still unresolved; stub stands.

## Not verified

- Lab precision/recall (Phase 2 gate, lab/ fixtures do not exist yet).
- Benchmarks, HTML report, TUI (Phases 3-5).
- `cargo nextest` not installed — used `cargo test` per rules fallback.
- `since-cutoff` skill is Python-only — N/A for this Rust workspace.
