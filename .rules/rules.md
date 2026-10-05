# SwiftRecon — Agent Rules

Rust web-recon engine. Authorized-scope only. Source of truth: `docs/PRD.md` (SwiftRecon PRD).
These rules override default habits. Follow them literally.

---

## 1. Work Scope

- Work **only on the current phase** of the PRD roadmap. Read that phase section, not the whole PRD.
- One phase = one git commit. Do not start the next phase.
- Build only what the task names. No extra features, flags, commands, or "while I'm here" refactors.
- If the task is ambiguous, state the assumption in one line and proceed. Ask only when a wrong guess is expensive.
- Never touch the "Later" list (dashboard, API, AI, headless browser, distributed workers).

---

## 2. Fixed Stack (do not swap)

Rust stable · Tokio · reqwest + rustls · hickory-resolver · tokio-rustls + x509-parser · url + psl + ipnet · scraper · oxc_parser (+ `regex` fallback) · xxhash-rust · hashbrown/dashmap · governor · backon · rusqlite (bundled, WAL) · petgraph · serde / serde_json / toml / csv · clap · ratatui · minijinja · thiserror / anyhow · tracing · mimalloc.
Port scanning reuses `sentinelscan-core`.
Tests: cargo-nextest, proptest, insta, criterion, wiremock/local fixtures.

- **Do not add a dependency** outside this list without asking. State the crate, why, and the alternative you rejected.
- Config files are **TOML**, never YAML.
- No Bloom filters or probabilistic structures for dedup. Use exact sets.
- No `panic = "abort"`. No `unsafe` unless asked.

---

## 3. Anti-Over-Engineering

- Write the simplest code that meets the current phase's exit criteria.
- No trait unless there are already two implementations or the PRD names it (`Source` is allowed).
- No generics, builders, macros, or plugin systems "for later".
- No new crate in the workspace unless the PRD layout lists it.
- Prefer a plain function over a struct, a struct over a trait, a trait over a framework.
- Do not rewrite working code to be "cleaner". Change only what the task requires.
- Three similar lines are fine. Abstract on the third real duplicate, not before.
- No speculative config options. Every option must be used by code in this phase.

---

## 4. No AI Slop

- No comments that restate code. Comment only *why* something non-obvious is done.
- No emojis, no banner comments, no "// TODO: implement" placeholders, no stub functions that return `Ok(())`.
- No invented APIs. If unsure a crate function exists, open the crate source/docs in `~/.cargo/registry` or run `cargo doc`. Do not guess signatures.
- No fake data, fake benchmark numbers, or fake test results anywhere (code, README, commit messages).
- No marketing words in docs or output ("blazing", "superfast", "robust", "seamless"). State measured facts only.
- Error messages are plain and specific: what failed, on what input, what to do.
- Docs and README describe what the code does today, including limitations.

---

## 5. Safety Invariants (non-negotiable)

1. **Every** outbound DNS query, TCP connect, and HTTP request, **including each redirect hop**, goes through `ScopeGuard`. No code path bypasses it.
2. After DNS resolution, re-check the IP. Block private, loopback, and link-local ranges unless explicitly in scope.
3. Show the authorized-use warning and require confirmation before sending traffic (`--yes` for scripts).
4. **Forbidden in this codebase:** exploitation, credential guessing, login brute-forcing, evasion/stealth, destructive requests, directory brute-forcing beyond the fixed well-known recon paths in the PRD. If a task seems to need one, stop and say so.
5. Test only against `127.0.0.1`, `::1`, the local `lab/` fixtures, or domains the user owns. Never scan a third-party target in tests or examples.

---

## 6. Accuracy Invariants

- Keep DNS outcomes distinct: `NXDOMAIN`, `SERVFAIL`, `timeout`, `refused`. A timeout is never "not found".
- Port states: open / closed / filtered / unknown, always with the raw reason.
- Every discovered fact carries `sources`, `evidence`, `confidence`, timestamps. Keep **observed** and **inferred** separate.
- Duplicates merge sources and evidence; they never create a second row.
- Normalize before dedup (URLs, hostnames, endpoints). Normalization must be idempotent (proptest it).
- Wildcard-DNS filtering and soft-404 detection are required before results are reported as "live".
- Confidence is the tool's own 0.0–1.0 scale. Never describe it as a probability.

---

## 7. Rust Standards

- Libraries: `thiserror`. Binaries: `anyhow`. No `unwrap()` / `expect()` in library code outside tests; use them only for proven invariants with a message that says why.
- Every network operation has a timeout. Every channel is **bounded**. Every body read has a size cap.
- Treat all target responses as hostile: cap sizes, cap decompressed size, no unbounded recursion, linear-time regex only.
- Strip control characters from target-controlled text before terminal output; HTML-escape it in reports.
- Redact cookie values and secret-like strings before storing.
- All DB writes go through the single writer task, batched. No per-row commits, no writes from modules.
- `stdout` carries data only (JSON/JSONL/CSV). Logs and prompts go to `stderr`.
- Use `tracing` for logs. No `println!` for diagnostics.
- Names: modules/crates `snake_case`, no abbreviations a stranger can't read.
- Keep functions small enough to read in one screen; split when a function does two jobs.

---

## 8. Verify Loop (before saying "done")

Run, in order, and fix until all pass:

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run        # or: cargo test
```

- Phases 2+ also run the lab accuracy check and record precision/recall.
- If a command fails, read the error, fix the cause, rerun. Do not suppress warnings, delete failing tests, or add `#[allow]` to get green.
- Do not claim a command passed unless you ran it and saw the output.
- If something cannot be verified (needs network, needs a target), say exactly what was not verified.
- Add or update tests with the code: unit tests for logic, proptest for scope/normalization, fixtures for network modules, `insta` snapshots for reports.
- Never mark a PRD exit criterion as met without evidence from a test or benchmark.

---

## 9. Git

- Work on the current branch. One commit per phase, only when the verify loop is green.
- Message format: `phase N: <what changed>` followed by 2–4 short lines of detail.
- No commits of secrets, `target/`, local `.db` files, or scan output.
- Do not rewrite history, force-push, or change CI/release config unless the task says so.

---

## 10. Communication

- Be terse. Lead with the result, then the minimum needed context.
- No preamble, no recap of the task, no closing summary that repeats the diff.
- Report in this shape: **Done** (what changed, files) · **Verified** (commands run + result) · **Not done / risks** (honest gaps).
- When blocked or when a rule conflicts with the task, stop and state the conflict in one or two lines.
- Never apologize at length or praise the code. Facts only.

---

## 11. Definition of Done

A task is done only when:
1. It meets the named exit criteria of the current phase.
2. The verify loop is green.
3. No new dependency, crate, or feature was added outside these rules without approval.
4. README/docs reflect reality, including limitations.
5. The report lists anything unverified.
