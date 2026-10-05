# SwiftRecon

[![ci](https://github.com/Devraj192/swift-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/Devraj192/swift-recon/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust: stable](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

Fast, scope-safe, evidence-backed web reconnaissance engine. Give it an
authorized scope — domains, wildcards, IPs, CIDRs — and it produces a
deduplicated, correlated, evidence-backed attack-surface inventory:

```
Scope → Subdomains → DNS → IPs → Ports → HTTP/TLS → Technologies
      → URLs → JavaScript → Endpoints → Parameters → Candidate findings
```

Three properties define the tool:

1. **Correlation, not concatenation.** Every asset links to the assets it
   came from and leads to. The entity graph answers "all hosts running X"
   and "all endpoints with parameter `id`".
2. **Evidence on every fact.** Each result carries its sources, raw
   evidence, and a confidence score on the tool's own 0.0–1.0 scale.
3. **Scope enforced at every connection.** No module opens a connection the
   scope guard has not approved — including redirect hops and resolved IPs.

> **Authorized use only.** Run SwiftRecon only against systems you own or
> have written permission to test. Every scan prints this warning with the
> exact scope and asks for confirmation before sending traffic (`--yes`
> for scripts).

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Outputs](#outputs)
- [Scope file](#scope-file)
- [How it works](#how-it-works)
- [Accuracy](#accuracy)
- [Performance](#performance)
- [Limitations](#limitations)
- [Safety model](#safety-model)
- [Development](#development)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Install

Requires Rust stable. No system dependencies (SQLite is bundled).

Build from source:

```sh
git clone https://github.com/Devraj192/swift-recon
cd swift-recon
cargo build --release
./target/release/swiftrecon --help
```

Tagged releases ship installers via
[cargo-dist](https://github.com/axodotdev/cargo-dist): shell and
PowerShell installers plus Linux (`x86_64-unknown-linux-gnu`) and Windows
(`x86_64-pc-windows-msvc`) archives, all with SHA-256 checksums. See
[Releases](https://github.com/Devraj192/swift-recon/releases).

---

## Quick start

```sh
# Passive discovery only: third-party sources, zero packets to the target.
swiftrecon scan example.com --passive --yes

# Full pipeline: discovery, ports, HTTP/TLS, fingerprints, crawl, endpoints.
swiftrecon scan example.com --yes

# Stream machine-readable facts (logs stay on stderr, data on stdout).
swiftrecon scan example.com --output jsonl --yes

# Ask why a value is in scope before you scan it.
swiftrecon scope check admin.example.com --scope scope.toml
```

First run prints the authorized-use warning and asks for confirmation.
`--yes` is for scripts; humans answer the prompt.

---

## Commands

```
swiftrecon scan <target> [--passive] [--scope scope.toml] [--ports web|80,443|1-1024]
                         [--output terminal|jsonl|json|csv|html] [--resume ID] [--yes]
swiftrecon scope check <value> [--scope scope.toml]
swiftrecon history                              # stored scans, newest first
swiftrecon show <scan-id>                       # counts plus every fact with sources
swiftrecon compare <scan-a> <scan-b>            # added / removed / changed facts
swiftrecon explain <fact-id>                    # evidence, sources, confidence
swiftrecon graph <scan-id> [--format terminal|json|dot|mermaid]
swiftrecon export <scan-id> [--format json|csv|html]
swiftrecon completions <bash|zsh|fish|powershell|elvish>
swiftrecon tui                                  # full-screen scan browser (q quits)
swiftrecon doctor | init

Every command accepts a global `--db FILE` (default `swiftrecon.db`).
```

Port discovery wraps
[`sentinelscan-core`](https://github.com/Devraj192/sentinel-scanner)
(pinned rev `a5deb6f`) behind a dual-guard bridge: our scope guard approves
each hostname/IP pair first, and only approved IPs are authorized into its
guard, which starts empty.

---

## Outputs

| Format     | Contents                                              |
|------------|-------------------------------------------------------|
| `terminal` | Human summary on stderr; nothing on stdout            |
| `jsonl`    | One fact per line on stdout (streaming)               |
| `json`     | Canonical report: subdomains, ports, HTTP, TLS, tech, endpoints, params |
| `csv`      | Fixed-column port rows, RFC 4180 quoting              |
| `html`     | Single offline file, escaped content, strict CSP      |

With machine formats, stdout stays pure data; logs and prompts go to
stderr. Terminal output strips control characters from target-controlled
text; cookie values and secret-like strings are redacted before storage.

---

## Scope file

```toml
[scope]
include = ["*.example.com", "203.0.113.0/28"]
exclude = ["admin.example.com"]

[limits]
max_concurrency = 200
global_rate = 300          # operations/sec
per_host_rate = 5          # requests/sec per host
max_depth = 3
max_urls_per_host = 5000
max_body_bytes = 2097152
scan_deadline_secs = 3600
```

Wildcards match on label boundaries: `*.example.com` matches
`a.example.com`, never `badexample.com`. After DNS resolution the IP is
re-checked: private, loopback, and link-local ranges are blocked unless an
IP or CIDR is explicitly in scope. Out-of-scope references are recorded as
"referenced, not probed" — never contacted.

---

## How it works

```
             ┌────────────────── Scope Engine + ScopeGuard ──────────────────┐
             │              (every outbound connection passes here)           │
Scope ─► Discovery ─► DNS ─► Ports ─► HTTP/TLS ─► Fingerprint ─► Crawler ─► JS ─► Endpoints
           sources      pool   (core)    probe        rules        queue    AST     + params
             └──────────────┴──────┴────────┴────────────┴──────────┴────────┴────────┘
                                    typed events over bounded channels
                                               │
                           Dedup + Correlator (entity graph) ─► Single SQLite writer
                                               │
                          CLI · TUI · JSON/JSONL/CSV · HTML report · graph export
```

| Crate                | Responsibility                                                  |
|----------------------|-----------------------------------------------------------------|
| `core`               | Fact, Evidence, Confidence, shared stored-row types              |
| `scope`              | Scope parsing/matching, ScopeGuard, TOML config                  |
| `net`                | Resolver pool + TTL cache, HTTP probing, TLS metadata            |
| `discover`           | `Source` trait, crt.sh, wordlist brute-force, wildcard filter    |
| `fingerprint`        | Data-driven rule engine (`rules/fingerprint.toml`)               |
| `web`                | Canonicalizer, crawler, JS AST analysis, OpenAPI/Wayback sources |
| `engine`             | Scheduler, port adapter, adaptive limiter, entity graph          |
| `store`              | SQLite schema, migrations, single-writer actor, history queries  |
| `report`             | JSON/CSV/HTML rendering                                          |
| `cli`                | Binary: commands + TUI                                           |

Key behaviors:

- **Discovery.** Passive certificate-transparency source plus active
  wordlist brute-force. Random-label probes detect wildcard DNS and filter
  matches; brute-force hits are re-validated; confidence rises when
  independent sources agree. `--passive` sends nothing to the target.
- **DNS.** A/AAAA with TTL cache. `NXDOMAIN`, `SERVFAIL`, timeout, and
  refused stay distinct — a timeout is never "not found".
- **Ports.** Each IP scanned once even when many hostnames point to it.
  States are open / closed / filtered / unknown, always with the raw
  reason (`handshake`, `refused`, `timeout`, …).
- **HTTP.** Probes `http` and `https` on open ports using the hostname.
  Redirects are followed manually with a scope check per hop; the full
  chain is recorded. A per-host random-path probe fingerprints the
  not-found shape so soft-404s are never reported as live.
- **TLS.** Version, cipher, subject/issuer, SANs (fed back into
  discovery), validity window, self-signed/expired flags. The handshake
  completes on bad certificates; the validation result is recorded.
- **Crawl + JS.** Depth-limited, per-host polite, trap-collapsed crawler;
  each unique JS file parsed once as an AST (regex fallback flagged lower
  confidence); secret-like matches store kinds, never values.
- **Endpoints.** Canonicalized (lowercase, default ports dropped,
  sorted query params, tracking params stripped), ID-like segments
  templated (`/users/123` → `/users/{id}`), parameters recorded with
  location, method, and sources.

---

## Accuracy

Measured on labeled fixture corpora (`lab/`), tracked as regression gates:

| Corpus                            | Metric              | Result  | Target |
|-----------------------------------|---------------------|---------|--------|
| Subdomains, 12 hosts (scripted)    | precision / recall  | 1.00 / 0.92 | ≥ 0.98 / ≥ 0.90 |
| Technologies, 6 fixtures           | precision           | 1.00    | ≥ 0.95 |
| SPA endpoints (7) / params (5)     | recall / recall     | 1.00 / 1.00 | ≥ 0.85 |

Kill-and-resume is proven against a hit-counting local server: a resumed
run refetches exactly the missing pages and sends zero new requests for
completed work units.

---

## Performance

Local CPU-only micro-benchmarks (`cargo bench -p swiftrecon`,
single dev machine — rerun yours before quoting):

| Benchmark            | Time              |
|----------------------|-------------------|
| Canonicalize 200 URLs | ~726 µs (~275k urls/s) |
| Merge 1,000 hosts     | ~625 µs           |
| JS analysis (~3.4 KB) | ~100 µs           |
| Fingerprint one page  | ~3.4 µs           |

Design envelopes: bounded channels (slow stages apply backpressure),
pooled connections and resolvers, capped bodies with decompression guards,
single batched SQLite writer, adaptive concurrency that backs off on
timeouts/429s/5xx and recovers gradually. Peak memory target for a typical
scan is under 500 MB. No "fastest" claims are made beyond the table above.

---

## Limitations

Honest boundaries, by design:

- Passive sources beyond certificate transparency (API-key feeds, URLScan,
  OTX, Wayback expansion), NS/MX/CNAME-derived hosts, reverse DNS, and
  name permutations are parked for a later discovery batch.
- No exploitation, credential guessing, login brute-forcing, evasion,
  destructive requests, or directory brute-forcing — none exist here.
- HTTP probes use hostname URLs (virtual-host aware); socket-level
  peer-IP pinning inside pooled HTTP connections is a known gap.
- JavaScript deobfuscation is out of scope; the AST path degrades to
  regex with lower confidence on parse failure.
- History is a local SQLite file, not a server.

---

## Safety model

- Every DNS query, TCP connect, and HTTP request — including each redirect
  hop — passes the scope guard. No code path bypasses it.
- Resolved IPs are re-checked; non-routable ranges stay blocked unless
  explicitly scoped (anti-rebinding).
- All target responses are treated as hostile: timeouts everywhere, size
  caps on bodies and decompressed output, linear-time regex only, escaped
  report output, stripped terminal output, redacted secrets.
- Test and example targets are loopback, fixtures, or documentation
  domains only — never third-party systems.

---

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # unit + proptest + live-loopback suites
cargo bench -p swiftrecon
```

Rules of the road: work one PRD phase at a time, keep the fixed stack
(Rust stable, Tokio, reqwest+rustls, hickory, rusqlite, ratatui…), no new
dependencies without a recorded decision, TOML for config, exact dedup
sets (never probabilistic), tests with the code. Details live in
`.docs/` (`SwiftRecon-PRD.md`, `ARCHITECTURE.md`, `DECISIONS.md`,
`STATE.md`, `CHANGELOG.md`).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: pick an open phase or a
recorded limitation, add tests with the code, keep the verify loop green,
one focused commit per change.

---

## Security

See [SECURITY.md](SECURITY.md). Do not file public issues for suspected
vulnerabilities — report them privately so a fix can ship first.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
