# SwiftRecon — State

## Status

- Phase: 2 DNS + subdomain discovery — implemented, verify loop green.
- Tests: 29 passed (`cargo test --workspace`): core 3, scope 8, net 3, discover 7, engine 4, store 2, cli 2.
- Lab corpus (`lab/`, 12-host fixture, scripted answers): precision 1.0000, recall 0.9167 — above PRD targets (≥0.98 / ≥0.90). Live-DNS lab pending.
- Smoke: `scan --passive --output jsonl` and active `scan` run end to end; JSONL on stdout, summary on stderr; source failure degrades gracefully (work unit marked failed, scan continues).
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

- Live crt.sh fetch in this sandbox: egress returns HTTP 502, so the passive source was exercised live only through its failure path (correct note + continue). Parsing covered by fixture tests.
- Live DNS here resolves via sandbox-doctored answers; brute-force found 0 for example.com as expected (no mini-list names exist). Trusted re-validation logic covered by code path, not live proof.
- `cargo nextest` not installed — used `cargo test` per rules fallback.
- `since-cutoff` skill is Python-only — N/A for this Rust workspace.
