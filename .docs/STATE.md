# SwiftRecon — State

## Status

- Phase: 1 Foundation — implemented, verify loop green.
- Tests: 16 passed (`cargo test --workspace`): core 3, scope 7 (incl. 3 proptest), engine 3, store 2, cli 1.
- Smoke: `doctor` ok; `scope check` correct for wildcard/label-boundary/exclude/CIDR; `scan --yes` persists empty scan, `--resume` reuses scan id, out-of-scope target recorded not probed, warning shown.
- Verify: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings` clean.

## Next

- Phase 2 (DNS + subdomain discovery) — not started. Do not start until Phase 1 commit lands.
- Open: `sentinelscan-core` API (PRD Q5) still unresolved; stub stands.

## Not verified

- Lab precision/recall (Phase 2 gate, lab/ fixtures do not exist yet).
- Benchmarks, HTML report, TUI (Phases 3-5).
- `cargo nextest` not installed — used `cargo test` per rules fallback.
- `since-cutoff` skill is Python-only — N/A for this Rust workspace.
