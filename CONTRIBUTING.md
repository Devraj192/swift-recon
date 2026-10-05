# Contributing to SwiftRecon

Thanks for stopping by. This project moves in small, reviewed, tested
steps. The notes below keep contributions mergeable on the first try.

## Ground rules

- **Authorized scope only.** Never add exploitation, credential guessing,
  login brute-forcing, evasion/stealth, destructive requests, or directory
  brute-forcing. A contribution that needs any of these will be declined.
- **Apache-2.0 inbound.** Contributions are accepted under the same
  [LICENSE](LICENSE). If you did not write a change yourself, say where it
  came from and confirm its license allows it.
- **No secrets, ever.** Do not commit tokens, keys, cookies, or scan output
  containing them. The scanner itself redacts these; contributors must too.

## How to contribute

1. **Start from the docs.** Read `.docs/SwiftRecon-PRD.md` (what the
   product must do), `.docs/ARCHITECTURE.md` (how it is built),
   `.docs/DECISIONS.md` (why), and `.docs/STATE.md` (where it stands).
   Propose anything that contradicts them *before* coding it.
2. **Keep the stack fixed.** Rust stable, Tokio, reqwest+rustls,
   hickory-resolver, rusqlite (bundled), ratatui, and the crates already in
   `Cargo.toml`. A new dependency needs a recorded reason: what it does,
   why nothing in-tree suffices, and what you rejected.
3. **Smallest change that meets the exit criteria.** No speculative flags,
   builders, plugin systems, or "while I'm here" refactors. Config files
   are TOML, never YAML. Dedup is exact sets, never probabilistic filters.
4. **Tests with the code.** Unit tests for logic, `proptest` for
   normalization/matching, fixture servers for network paths, accuracy
   numbers recorded (never invented). A failing network-dependent test
   must degrade to a clearly-marked skip, not a silent pass.
5. **One focused commit per change.** Message format:
   `phase N: <what changed>` for roadmap work, otherwise
   `type: <imperative subject>` (`docs:`, `fix:`, `chore:` …), ≤ 50 chars,
   with 2–4 lines explaining *why*.

## Verify loop (must be green)

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Do not suppress warnings, delete failing tests, or add `#[allow]` to get
green. If a check cannot run in your environment, say exactly which one
and why.

## Safety invariants (non-negotiable)

1. Every outbound DNS query, TCP connect, and HTTP request — including
   each redirect hop — goes through the scope guard.
2. Resolved IPs are re-checked; private/loopback/link-local stay blocked
   unless explicitly scoped.
3. Every network operation has a timeout; every channel is bounded; every
   body read has a size cap.
4. Target-controlled text is stripped (terminal) or escaped (HTML) before
   display; secrets are redacted before storage.

## Reporting bugs

Open an issue with: exact command, expected vs actual behavior, full
error output, and OS/toolchain (`rustc --version`). For suspected
vulnerabilities, read [SECURITY.md](SECURITY.md) first — do not file them
publicly.
