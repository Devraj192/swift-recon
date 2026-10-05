# SwiftRecon — Decisions

- D1: Docs only in `.docs/` as `*.md`; root `*.md` gitignored (`/*.md`). Existing `*.txt` placeholders left untouched.
- D2: Phase 1 crates limited to core/scope/engine/store/cli; deferred `net/discover/web/fingerprint/report` per anti-over-engineering (no crate without two uses or PRD phase need).
- D3: `sentinelscan-core` unavailable — `PortProvider` trait with default stub body in `engine`; Phase 3 wires real backend. Keeps Phase 1-2 compilable.
- D4: `ip_allowed` (bare-IP input) is strict direct IP/CIDR match; hostname+resolved-IP path (`connection_allowed`) keeps non-routable re-check. Rationale: a CIDR in scope must not authorize arbitrary outside IPs.
- D5: Store writer uses direct autocommit in Phase 1 for correctness; 500-row batching deferred to volume phases. Documented limitation, not hidden.
- D6: `since-cutoff` skill evaluated — Python-only, not applicable to Rust workspace; pinned versions recorded in `Cargo.lock`.
- D7: `async-trait` not added (outside fixed stack, would need approval); used RPITIT default trait method instead.
