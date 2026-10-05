# PRD — SwiftRecon

**Product:** Fast, scope-safe, evidence-backed web reconnaissance engine
**Language:** Rust · **Status:** Draft v1.0 · **Replaces:** ReconForge draft
**Sibling project:** SentinelScan (its `sentinelscan-core` crate is reused for port discovery)

---

## 1. Overview

SwiftRecon takes an **authorized scope** (domains, wildcards, IPs, CIDRs) and produces a **deduplicated, correlated, evidence-backed attack-surface inventory**:

```
Scope → Subdomains → DNS → IPs → Ports → HTTP/TLS → Technologies
      → URLs → JavaScript → Endpoints → Parameters → Candidate findings
```

### Problem
Typical recon chains 5–8 separate tools. The result is duplicated output, no link between assets, no explanation of *why* something was reported, and no consistent scope enforcement.

### Differentiators
1. **Correlation, not concatenation.** Every asset is linked to the assets it came from and leads to.
2. **Evidence on every fact.** Each result carries its sources, raw evidence, and a confidence score.
3. **Accuracy first.** Wildcard-DNS filtering, trusted-resolver validation, soft-404 detection, exact (non-probabilistic) dedup.
4. **Scope enforced at the socket level.** No module can open a connection that the scope guard has not approved, including redirects and resolved IPs.
5. **Single static binary.** Streaming results, resumable scans, zero infrastructure.

### Principle
**The engine is the product.** CLI, TUI, HTML report, and the later dashboard/API are thin consumers of the same structured data.

---

## 2. Goals, Non-goals, Success Metrics

### Goals (V1)
- High throughput with bounded memory and bounded concurrency
- Accurate, explainable results (precision over raw volume)
- Scope enforcement and polite scanning by default
- Resume interrupted scans; partial results are always saved
- Pluggable modules (new discovery source = one trait impl)
- Outputs: terminal, JSON, JSONL, CSV, single-file HTML report

### Non-goals (V1)
Exploitation, credential attacks, auth bypass, brute-forcing logins, directory brute-forcing, evasion/stealth features, destructive testing, distributed workers, web dashboard, AI features.

### Success metrics (targets to validate by benchmark, not guarantees)

| Area | Target | Measured by |
|---|---|---|
| Subdomain precision / recall | ≥ 98% / ≥ 90% on the lab corpus | Labeled lab zone (§9) |
| Tech detection precision | ≥ 95% on the lab corpus | Fixture apps with known stacks |
| Engine overhead | Network-bound, not CPU-bound, at target concurrency | Local fixture servers |
| Peak memory | < 500 MB on a typical scan | Peak RSS in benchmarks |
| Resume | Re-run skips ≥ 99% of completed work units | Kill-and-resume test |
| Baselines | Competitive with subfinder / httpx / katana on the same scope | Side-by-side runs |

---

## 3. Users and Key Stories

| User | Story |
|---|---|
| Bug bounty hunter | "Give me every live host, URL, JS-derived endpoint and parameter in scope, fast." |
| Penetration tester | "Give me repeatable, evidence-backed scans I can diff and put in a report." |
| Security team | "Show me what is exposed on my own domains and what changed since last week." |
| Student / learner | "Show me *why* the tool thinks this is true." (evidence view) |

---

## 4. Architecture

```
            ┌────────────────────── Scope Engine + ScopeGuard ──────────────────────┐
            │                  (every outbound connection passes here)               │
Scope ─► Discovery ─► DNS ─► Ports ─► HTTP/TLS ─► Fingerprint ─► Crawler ─► JS ─► Endpoints
          sources      pool   (core)    probe        rules        queue    AST     + params
            └──────────────┴──────┴────────┴────────────┴──────────┴────────┴────────┘
                                   typed events over bounded channels
                                              │
                          Dedup + Correlator (entity graph) ─► Single SQLite writer
                                              │
                         CLI · TUI · JSON/JSONL/CSV · HTML report · (later) API/dashboard
```

**Rules**
- Stages are async tasks connected by **bounded `mpsc` channels**: slow stages apply backpressure instead of growing memory.
- A central **scheduler** owns global, per-host, and per-resolver limits, retries, timeouts, and cancellation.
- All writes go through **one writer task** that batches transactions. No module writes to the DB directly.
- Every work unit has a persisted state (`pending / done / failed`) so scans can resume.

### Workspace layout

```
swiftrecon/
├── crates/
│   ├── core/         # Fact, Evidence, Confidence, events, errors, config types
│   ├── scope/        # scope parsing/matching, ScopeGuard, PSL, CIDR
│   ├── net/          # resolver pool, HTTP client, TLS probe, rate limiters
│   ├── discover/     # subdomain Source trait + sources, wildcard filter, wordlists
│   ├── web/          # crawler, JS analyzer, endpoint/param extraction, canonicalizer
│   ├── fingerprint/  # rule engine, rule files, favicon hash
│   ├── engine/       # scheduler, dedup, correlator, resume
│   ├── store/        # SQLite schema, migrations, writer actor, queries
│   ├── report/       # JSON/JSONL/CSV/HTML, graph export
│   └── cli/          # binary: commands + TUI
├── rules/            # fingerprint rule files (data, not code)
├── lab/              # docker-compose lab + local DNS zone for accuracy tests
├── benches/  tests/  migrations/  configs/
└── (later) crates/api, frontend/
```

---

## 5. Ideal Tech Stack

Chosen for three things: **speed** (async, pooled, low overhead), **accuracy** (correct parsing, exact data structures), and **efficiency** (bounded memory, single binary).

| Layer | Choice | Why |
|---|---|---|
| Language | **Rust (stable)** | Memory safety on hostile input, predictable performance, no GC pauses, reuses SentinelScan patterns. |
| Async runtime | **Tokio** (multi-thread) + `tokio-util` | Mature; `Semaphore`, bounded `mpsc`, timers, `CancellationToken` for clean cancellation. |
| HTTP client | **reqwest** (hyper + rustls, pooling, HTTP/2) | Fast enough and ergonomic. Redirects handled **manually** so chains are recorded and scope-checked per hop. Drop to raw `hyper-util` only if profiling shows a need. |
| TLS metadata | **tokio-rustls** + **x509-parser** | reqwest does not expose peer certs conveniently. A custom verifier records validity but still completes the handshake, since recon must probe expired/self-signed hosts. SANs feed subdomain discovery. |
| DNS | **hickory-resolver** with a resolver **pool** | Async, controllable, per-resolver rate limits; cache layered on top. |
| Port discovery | **`sentinelscan-core`** (your crate) | Reuse proven scheduler, port states, and scope guard. May need a small stable public API. |
| URL / domain handling | **url**, **psl** (public suffix list), **ipnet** | Correct normalization, IDNA, registrable-domain detection (`co.uk` etc.), CIDR math. Wrong here = wrong scope and wrong dedup. |
| HTML parsing | **scraper** (DOM); **lol_html** optional for streaming | Selector-based extraction; streaming parser if profiling demands it. |
| JavaScript analysis | **oxc_parser** (AST) + `regex` fallback | AST extraction of string literals and call sites is more accurate than regex alone. `regex` crate is linear-time (no ReDoS). |
| Fingerprinting | Data-driven rules (YAML/JSON files) + **mmh3** favicon hash | Rules are data, tested independently, easy to extend. Check licenses before importing community rule sets. |
| Hashing / dedup | **xxhash-rust** (xxh3), **hashbrown**, **dashmap** | Fast fingerprints. **Exact sets, not Bloom filters**: a Bloom false positive silently drops a real URL. |
| Rate limiting | **governor** | Token buckets: global, per-host, per-resolver. |
| Retry/backoff | **backon** (jittered) | Retry only transient errors. |
| Storage | **SQLite via rusqlite (bundled), WAL mode** | Single writer actor with batched transactions is faster and simpler than a pooled async layer. Postgres is a later option. |
| Graph | Relational tables + **petgraph** in memory | No graph DB needed; petgraph for traversal and DOT/Mermaid export. |
| Config / serialization | **serde**, `serde_json`, **toml**, `csv` | Use **TOML** for scope/config (`serde_yaml` is unmaintained). |
| CLI / TUI | **clap** (derive) + `clap_complete`; **ratatui** + crossterm | Same approach as SentinelScan. |
| Reports | **minijinja** (or askama) → single-file HTML | Offline, no external assets; all target-controlled text escaped. |
| Errors / logs | **thiserror** (libs), **anyhow** (bin), **tracing** | Structured logs to stderr. |
| Allocator | **mimalloc** | Cheap win for allocation-heavy workloads; works on Linux and Windows. |
| Release profile | `lto = "fat"`, `codegen-units = 1`, `strip = true` | Smaller, faster binary. **Do not use `panic = "abort"`**: one task panic should not kill the scan. |
| Testing | **cargo-nextest**, **proptest**, **insta**, **criterion**, **cargo-fuzz**, **wiremock** / local fixture servers | Property tests for normalization, fuzzing for parsers, benchmarks for speed. |
| CI / release | GitHub Actions, **cargo-dist**, **cargo-deny**, **cargo-audit** | Matches SentinelScan. |
| Later: API | **Axum** + SSE, `rust-embed` | Dashboard ships inside the binary. |
| Later: UI | **React + TypeScript + Tailwind + React Flow** | Graph view; consumes the same API as everything else. |
| Later: JS rendering | **chromiumoxide** (feature-gated) | SPAs and screenshots; off by default. |

**Why not Go?** Go (used by many recon tools) is fine, but Rust gives stronger safety on hostile input, lower memory, and direct reuse of SentinelScan. The cost is slower compile times.

---

## 6. Functional Requirements

Priority: **M** = must (V1), **S** = should, **C** = could.

### FR-1 Scope and safety (M)
- Accept domains, `*.example.com`, subdomains, IPs, CIDRs; TOML include/exclude lists.
- Wildcards match on **label boundaries** (`*.example.com` matches `a.example.com`, never `badexample.com`).
- `ScopeGuard` approves every outbound DNS query target, TCP connect, and **every redirect hop**. After DNS resolution the **IP is re-checked**: private/loopback/link-local ranges are blocked unless explicitly in scope (anti-rebinding / SSRF-style protection).
- Out-of-scope references are recorded as "referenced, not probed".
- First run and every scan show the authorized-use warning with exact scope and ask for confirmation (`--yes` for scripts).

### FR-2 Subdomain discovery (M)
- Pluggable `Source` trait. Passive sources: certificate transparency (e.g., crt.sh, CertSpotter), public datasets (e.g., URLScan, OTX, Wayback), optional API-key sources, and SANs from live TLS.
- Active sources: wordlist brute-force, NS/MX/CNAME-derived hosts, reverse DNS for in-scope CIDRs; permutations (S, opt-in).
- Modes: `--passive` (no packets to the target) and default (passive + active).
- **Accuracy:** wildcard detection (random-label probes, compare answer sets, filter matches), resolver health checks, trusted-resolver re-validation of brute-force hits, provenance per hostname, confidence boost when ≥ 2 independent sources agree.
- A failing source never fails the scan: per-source timeout, rate limit, cache, and a clear "source X failed" note.

### FR-3 DNS (M)
- Records: A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, with resolver, timestamp, TTL, status.
- Keep **NXDOMAIN, SERVFAIL, timeout, and refused distinct**. Never collapse a timeout into "doesn't exist".
- Cache respects TTL; CNAME chains followed with a loop cap.
- Dangling-CNAME **candidates** flagged as "unverified candidate" (no exploitation).

### FR-4 Port discovery (M)
- Wrap `sentinelscan-core`; default web-oriented port set, larger sets opt-in.
- Scan each **IP once** even if many hostnames point to it.
- States open / closed / filtered / unknown with raw reason.
- Skip IPs that look CDN-fronted by default (S), since they are usually not the target's own infrastructure.

### FR-5 HTTP probing (M)
- Probe `http` and `https` on discovered ports using the **hostname** (virtual-host aware).
- Record: final URL, redirect chain, status, length, title, server, headers, cookie **names and flags only**, content type, HTTP version, response time, body hash, capped body excerpt.
- **Soft-404 detection:** request a random path per host and fingerprint the "not found" shape so later "live path" results are trustworthy.
- Retry transient errors only; accept invalid certs but record the validation result.

### FR-6 TLS (M)
- Version, cipher, chain subject/issuer, SANs, validity window, self-signed/expired flags.

### FR-7 Technology fingerprinting (M)
- Signals: headers, cookies, meta generator, HTML patterns, script/asset URLs, favicon mmh3, TLS, URL patterns.
- Rule-engine output: technology, optional version, confidence, **evidence list**. Independent signals combine (noisy-OR style) and are capped below 1.0.
- Rules support `implies` / `excludes`. Rules live in data files with unit tests.

### FR-8 Crawler (M)
- Depth limit, same-origin or in-scope-subdomain mode, per-host politeness, max URLs per host, max response size, decompression-bomb guard, content-type filter.
- Extract links, forms, scripts, iframes, API references; parse `robots.txt` and `sitemap.xml` for paths.
- `robots` policy configurable (`parse-only` default: used for discovery, not as a block list).
- **Crawler-trap protection:** collapse repeating patterns (calendars, infinite pagination).

### FR-9 JavaScript analysis (M for extraction, S for flags)
- Download each unique file once (by hash); parse with AST; extract string literals, URL/API paths, `fetch`/XHR/axios call sites, WebSocket URLs, parameter names, `sourceMappingURL` references.
- If parsing fails, fall back to regex and mark results lower confidence.
- (S) Flag high-signal secret formats as **candidate findings**, stored **redacted**.
- No deobfuscation in V1.

### FR-10 Endpoints and parameters (M)
- Sources: crawler, JS, HTML forms, robots/sitemap, OpenAPI/Swagger (`/openapi.json`, `/swagger.json`, `/v3/api-docs`), historical URLs (Wayback CDX, passive).
- **Canonicalization:** lowercase scheme/host, drop default ports and fragments, collapse `//`, consistent trailing-slash policy, sort query params, strip configurable tracking params.
- Group ID-like segments into templates (`/users/123` → `/users/{id}`).
- Parameter record: name, location (query/body/path/header), method, sources.

### FR-11 Correlation (M)
- Entity graph: domain → subdomain → DNS record → IP → port → service → HTTP service → technology / URL → JS file → endpoint → parameter.
- Shared-infrastructure grouping (same IP, certificate, favicon hash, title cluster).
- Queries such as "all hosts running X" and "all endpoints with parameter `id`".
- Export as JSON, DOT, Mermaid.

### FR-12 Deduplication (M)
- Canonical keys per entity type; duplicates **merge sources and evidence** instead of creating new rows.
- Exact sets in memory with SQLite `UNIQUE` constraints as the backstop when sets get large.

### FR-13 Evidence and confidence (M)
Every fact has: `id, scan_id, kind, value, sources[], evidence[], confidence, first_seen, last_seen`.
- Keep **observed** (directly seen) separate from **inferred** (concluded).
- Document the confidence rubric. Scores are the tool's own scale, not verified probabilities.

### FR-14 Scheduler and resume (M)
- Stage DAG with dependencies; global, per-host, per-resolver limits; priority queues; retries with jittered backoff; timeouts; cancellation; pause/resume.
- **Adaptive concurrency (S):** reduce rate when timeouts, 429s, or 5xx rise; recover gradually.
- Every work unit persisted, so `--resume <scan_id>` skips completed work. Finished scans refuse to resume.

### FR-15 Storage (M)
- SQLite in WAL mode; single writer actor; batch commit every ~500 rows or ~250 ms.
- Versioned migrations; DB directory `0700`, file `0600` on Unix.
- Scan history and **diff between two scans** (added / removed / changed).

### FR-16 Output (M)
- Terminal summary; **JSON** (canonical), **JSONL** (one fact per line, streaming), **CSV**, **HTML** (single file, offline).
- With machine formats, **stdout stays pure data**; logs go to stderr.
- Terminal output strips control characters from target-controlled text.

### FR-17 CLI and TUI (M CLI, S TUI)

```
swiftrecon scan example.com [--passive] [--profile quick|standard|deep]
                            [--scope scope.toml] [--ports web|top100|1-1024]
                            [--concurrency N] [--rate N] [--output json|jsonl|csv|html]
                            [--resume ID] [--yes]
swiftrecon scope check <value>        # why is this in/out of scope?
swiftrecon history | compare A B | show ID | export ID --format ...
swiftrecon explain <fact-id>          # evidence + sources + confidence
swiftrecon graph ID --format dot|mermaid|json
swiftrecon doctor | config | init | completions <shell> | tui
```

### FR-18 API and dashboard (Later)
Axum REST + SSE, embedded React dashboard with attack-surface graph. Built only after the engine and report are solid.

---

## 7. Data Model (SQLite)

| Table | Key columns |
|---|---|
| `scans` | id, status, scope_json, started, finished, version |
| `work_units` | scan_id, stage, key, state, attempts, last_error |
| `assets` | id, scan_id, kind (domain/subdomain/ip), value, confidence |
| `asset_sources` | asset_id, source, first_seen |
| `dns_records` | asset_id, type, value, ttl, resolver, status, ts |
| `ports` | ip, port, proto, state, reason, service, version, confidence |
| `http_services` | asset_id, url, status, title, server, headers_json, body_hash, ms, tls_id |
| `tls_info` | id, version, cipher, subject, issuer, sans_json, not_before, not_after, flags |
| `technologies` | http_service_id, name, version, confidence, evidence_json |
| `urls` | id, canonical, template, source_set, first_seen |
| `js_files` | url_id, hash, parsed_ok, size |
| `endpoints` | id, host_id, canonical_path, methods, sources |
| `parameters` | endpoint_id, name, location, method, sources |
| `findings` | id, kind, subject_id, confidence, evidence_json (candidates only) |
| `edges` | scan_id, from_kind, from_id, to_kind, to_id, relation |

Indexes on `(scan_id, kind, value)` and all foreign keys; `UNIQUE` on canonical keys.

---

## 8. Performance Strategy

- **CPU:** mimalloc, LTO, avoid per-request allocations in hot paths, reuse buffers, parse only what is needed.
- **Network:** pooled connections, HTTP/2 where offered, DNS resolver pool with caching, per-IP port scan dedup.
- **Memory:** bounded channels, capped bodies, JS hashed so each file is parsed once, SQLite as overflow for large sets.
- **I/O:** single batched writer; WAL mode; no per-row commits.
- **Politeness is performance:** adaptive concurrency avoids bans, retries, and noisy timeouts that hurt accuracy.

| Metric | V1 target (tune after benchmarks) |
|---|---|
| Concurrent DNS queries | 1,000+ across a resolver pool |
| HTTP concurrency | 500+ (configurable) |
| URL dedup | 100k+ URLs with bounded memory |
| Event → DB persisted | p95 < 100 ms |
| Peak memory (typical scan) | < 500 MB |

Do not publish "fast" claims until the benchmark suite backs them.

---

## 9. Accuracy and Testing Plan

**Lab corpus (`lab/`)**: a local authoritative DNS zone with known subdomains, a wildcard zone, CNAME chains, and a dangling CNAME; docker-compose fixture apps with known stacks (e.g., WordPress, nginx, Node/Express, an SPA with a known API surface, an OpenAPI doc).

- Compute **precision and recall** for subdomains, technologies, endpoints, and parameters; track them in CI as regression gates.
- **Property tests** (`proptest`) for scope matching and URL canonicalization (idempotence, equivalence classes).
- **Fuzzing** (`cargo-fuzz`) for HTML, JS, robots/sitemap, and DNS-response parsing.
- **Snapshot tests** (`insta`) for report output and fingerprint results.
- **Kill-and-resume** test: interrupt at random points, resume, assert identical final result.
- **Baseline comparison** against subfinder, httpx, and katana on the same authorized scope.
- Real-world runs only on targets you own or have written permission to test.

---

## 10. Safety, Ethics, and Tool Hardening

**Authorized use only.** Warning and confirmation on every scan, in every install channel.

**Not in the codebase, by design:** exploitation, credential guessing, login brute-forcing, evasion, destructive requests, directory brute-forcing beyond a tiny fixed list of well-known recon paths.

**Politeness defaults:** conservative per-host rate, adaptive back-off, honest `User-Agent` (`SwiftRecon/<ver> (+repo URL)`, configurable), `--passive` mode for zero-contact discovery.

**Hardening against hostile targets** (the data is untrusted):
- Timeouts on every operation; size caps on bodies, headers, and decompressed output.
- Escape **all** target-controlled strings in the HTML report (page titles are an XSS vector); no external assets; strict CSP in the report.
- Strip control characters before terminal output.
- Linear-time regex only; parser fuzzing.
- Redact cookie values and secret-like strings before storing.
- Block private/loopback targets unless explicitly scoped.

---

## 11. Roadmap — 5 Phases (one commit per phase)

### Phase 1 — Foundation
Workspace, `core` types (Fact, Evidence, Confidence, events), scope engine + `ScopeGuard`, TOML config, scheduler skeleton with bounded channels and rate limiters, SQLite writer + migrations, CLI skeleton (`scope check`, `doctor`, `init`), tracing, CI.
**Exit:** proptests for scope matching pass; an empty scan persists and resumes; authorized-use confirmation works.

### Phase 2 — DNS and subdomain discovery
Resolver pool, DNS records and cache, `Source` trait, passive sources, wordlist brute-force, wildcard filtering, trusted-resolver validation, provenance, dedup, terminal + JSONL output.
**Exit:** lab precision/recall measured and recorded; passive mode sends nothing to the target.

### Phase 3 — Live hosts: ports, HTTP, TLS, fingerprints
`sentinelscan-core` integration, HTTP probing with redirect chains and soft-404 detection, TLS metadata, fingerprint rule engine v1 with evidence and confidence, JSON/CSV/HTML report.
**Exit:** `swiftrecon scan example.com` works end to end; fingerprint precision measured on the lab. **This is the first genuinely useful release.**

### Phase 4 — Crawl, JS, endpoints, parameters
Crawler with trap protection, robots/sitemap, JS AST analysis, OpenAPI discovery, historical URLs, canonicalization and templating, parameter extraction, resume across all stages, adaptive concurrency.
**Exit:** kill-and-resume test passes; endpoint/parameter recall measured on the lab SPA.

### Phase 5 — Correlation, history, TUI, release
Entity graph + shared-infrastructure grouping, `explain`, `compare`, graph export, ratatui TUI, benchmarks vs baselines, cargo-dist packaging, README with honest limitations, security policy.
**Exit:** benchmark table published; release installs on Linux and Windows.

### Later (post-V1)
Axum API + SSE + embedded React dashboard · headless-browser rendering and screenshots (feature-gated) · plugin system · scheduled scans and change alerts · takeover *verification* · PostgreSQL and distributed workers · optional AI-assisted triage.

---

## 12. Risks

| Risk | Mitigation |
|---|---|
| Passive sources (e.g., crt.sh) are flaky or rate-limited | Multiple sources, caching, backoff, graceful degradation |
| Public resolvers rate-limit or lie | Resolver pool, health checks, trusted re-validation |
| Fingerprint false positives | Multi-signal rules, evidence, lab regression gates |
| Scope creep (dashboard, AI, distributed) | Engine first; "Later" list is frozen until Phase 5 ships |
| Over-claiming speed | Publish only benchmarked numbers |
| Misuse | Scope guard, confirmation, no offensive code, clear policy |
| Solo-developer capacity | Phases are independently shippable; each ends in a usable state |

## 13. Open Questions
1. Default web port set (e.g., 80, 443, 8080, 8443 plus a few) — decide in Phase 3.
2. Which API-key sources to support first.
3. Fingerprint rule sources and their licenses (own rules vs. importing a community set).
4. `robots` default policy (`parse-only` proposed).
5. Does `sentinelscan-core` expose a stable library API for ports, or does it need a small refactor first?
6. Screenshots: ship in "Later" behind a headless-browser feature flag?

---

## Appendix A — Scope file (`scope.toml`)

```toml
[scope]
include = ["*.example.com", "203.0.113.0/28"]
exclude = ["admin.example.com", "internal.example.com"]

[limits]
max_concurrency = 200
global_rate = 300          # operations/sec
per_host_rate = 5          # requests/sec per host
max_depth = 3
max_urls_per_host = 5000
max_body_bytes = 2097152
scan_deadline_secs = 3600
```

## Appendix B — Example fact (JSONL line)

```json
{"kind":"technology","host":"api.example.com","value":"nginx","version":null,
 "confidence":0.91,"observed":[{"type":"header","key":"server","value":"nginx"}],
 "inferred":[],"sources":["http_probe"],"first_seen":1759650000,"scan_id":"01H..."}
```
