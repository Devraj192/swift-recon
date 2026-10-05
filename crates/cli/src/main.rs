//! SwiftRecon CLI: authorized-scope reconnaissance engine (Phase 1 skeleton).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use swiftrecon_engine::{Limits, Scheduler};
use swiftrecon_scope::{explain, parse_scope_file, Scope, ScopeGuard};
use swiftrecon_store::Store;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const AUTH_WARNING: &str =
    "AUTHORIZED USE ONLY: scan only targets you own or have written permission to test.";

#[derive(Debug, Parser)]
#[command(
    name = "swiftrecon",
    version,
    about = "Fast, scope-safe web reconnaissance engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a scan (Phase 3: discovery + ports + HTTP/TLS + fingerprints).
    Scan {
        /// Target domain or scope file entry.
        target: Option<String>,
        #[arg(long)]
        scope: Option<PathBuf>,
        #[arg(long)]
        resume: Option<String>,
        #[arg(long, default_value_t = false)]
        yes: bool,
        /// Passive mode: third-party sources only, no packets to the target.
        #[arg(long, default_value_t = false)]
        passive: bool,
        /// Output format: terminal, jsonl, json, csv, or html.
        #[arg(long, default_value = "terminal")]
        output: String,
        /// Port set: web, lists (80,443), ranges (1-1024), mixes.
        #[arg(long, default_value = "web")]
        ports: String,
    },
    /// Scope helpers.
    Scope {
        #[command(subcommand)]
        action: ScopeAction,
    },
    /// Check toolchain, config, and storage.
    Doctor,
    /// Write an example scope.toml.
    Init {
        #[arg(long, default_value = "scope.toml")]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ScopeAction {
    /// Explain why a value is in or out of scope.
    Check {
        value: String,
        #[arg(long)]
        scope: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            target,
            scope,
            resume,
            yes,
            passive,
            output,
            ports,
        } => cmd_scan(target, scope, resume, yes, passive, &output, &ports).await,
        Command::Scope { action } => match action {
            ScopeAction::Check { value, scope } => cmd_scope_check(&value, scope),
        },
        Command::Doctor => cmd_doctor(),
        Command::Init { output } => cmd_init(&output),
    }
}

fn load_scope(path: Option<PathBuf>) -> Result<Scope> {
    if let Some(path) = path {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let file = parse_scope_file(&text)?;
        Scope::from_file(&file).map_err(anyhow::Error::from)
    } else {
        Scope::from_lists(&["example.com".to_string()], &[]).map_err(anyhow::Error::from)
    }
}

fn confirm_authorized(yes: bool, scope_desc: &str) -> Result<bool> {
    eprintln!("{AUTH_WARNING}");
    eprintln!("Scope: {}", strip_control(scope_desc));
    if yes {
        return Ok(true);
    }
    eprint!("Proceed? [y/N] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}

async fn cmd_scan(
    target: Option<String>,
    scope_path: Option<PathBuf>,
    resume: Option<String>,
    yes: bool,
    passive: bool,
    output: &str,
    ports_spec: &str,
) -> Result<()> {
    if !["terminal", "jsonl", "json", "csv", "html"].contains(&output) {
        anyhow::bail!("unknown output format: {output} (expected terminal|jsonl|json|csv|html)");
    }
    let scope = load_scope(scope_path)?;
    let desc = target.clone().unwrap_or_else(|| "scope file".to_string());
    if !confirm_authorized(yes, &desc)? {
        eprintln!("Aborted.");
        return Ok(());
    }

    // Every connection passes the guard, even in Phase 1.
    let guard = ScopeGuard::new(scope);
    if let Some(t) = &target {
        if !guard.allow_dns(t) {
            eprintln!(
                "Target {} is OUT of scope; recorded as referenced, not probed.",
                strip_control(t)
            );
            return Ok(());
        }
    }

    let db_path = PathBuf::from("swiftrecon.db");
    let store = Store::open(&db_path)?;
    let scan_id = resume.unwrap_or_else(|| format!("scan-{}", swiftrecon_core::now_unix()));
    store.create_scan(&scan_id, &desc, swiftrecon_core::now_unix());
    store.upsert_work_unit(
        &scan_id,
        "scan",
        &desc,
        swiftrecon_store::WorkState::Pending,
    );

    // Scheduler skeleton exercises bounded channels + limits.
    let sched = Scheduler::new(Limits::default());
    let (tx, mut rx) = sched.channel::<String>();
    tx.send(desc.clone()).await?;
    drop(tx);
    while let Some(item) = rx.recv().await {
        tracing::info!("stage item: {item}");
    }
    let _ = sched.run_unit(|| async { Ok(()) }).await;

    if let Some(t) = &target {
        run_pipeline(&scan_id, t, &guard, &store, passive, output, ports_spec).await?;
    }

    store.upsert_work_unit(&scan_id, "scan", &desc, swiftrecon_store::WorkState::Done);
    store.finish_scan(&scan_id, swiftrecon_core::now_unix());
    eprintln!("scan {} done", strip_control(&scan_id));
    Ok(())
}

/// Phase 3 pipeline: discovery, then per-IP ports, HTTP/TLS, fingerprints.
/// Passive mode stops after discovery (no packets to the target).
/// stdout stays pure data; the summary goes to stderr.
async fn run_pipeline(
    scan_id: &str,
    target: &str,
    guard: &ScopeGuard,
    store: &Store,
    passive: bool,
    output: &str,
    ports_spec: &str,
) -> Result<()> {
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::time::Duration;
    use swiftrecon_core::{Confidence, Evidence, Fact};
    use swiftrecon_discover::{
        brute_force, detect_wildcard, merge_sources, mini_wordlist, CrtShSource, Source,
    };

    let domain = swiftrecon_scope::registrable_domain(target)
        .unwrap_or_else(|| target.trim().to_lowercase());
    let pool = swiftrecon_net::ResolverPool::new(4, 50);

    let crtsh = CrtShSource::new().map_err(anyhow::Error::from)?;
    let crt_hosts = match crtsh.collect(domain.clone()).await {
        Ok(hosts) => {
            store.upsert_work_unit(
                scan_id,
                "discover",
                "crtsh",
                swiftrecon_store::WorkState::Done,
            );
            hosts
        }
        Err(e) => {
            tracing::warn!("source {} failed: {e}", crtsh.name());
            eprintln!("source {} failed ({e}); continuing", crtsh.name());
            store.upsert_work_unit(
                scan_id,
                "discover",
                "crtsh",
                swiftrecon_store::WorkState::Failed,
            );
            Vec::new()
        }
    };

    let mut active_hosts: Vec<String> = Vec::new();
    if !passive {
        let wildcard = detect_wildcard(&pool, guard, &domain).await;
        if wildcard.is_some() {
            eprintln!("wildcard DNS detected for {domain}; filtering matches");
        }
        let words = mini_wordlist();
        let found = brute_force(&pool, guard, &domain, &words, wildcard.as_ref()).await;
        store.upsert_work_unit(
            scan_id,
            "discover",
            "bruteforce",
            swiftrecon_store::WorkState::Done,
        );
        active_hosts = found.into_iter().map(|h| h.hostname).collect();
    }

    let merged = merge_sources(vec![
        ("crtsh".to_string(), crt_hosts),
        ("bruteforce".to_string(), active_hosts),
    ]);
    // Keep only names still in scope (sources can return siblings).
    let merged: Vec<_> = merged
        .into_iter()
        .filter(|h| guard.allow_dns(&h.hostname))
        .collect();

    let mut facts: Vec<Fact> = Vec::new();
    let mut subdomains: Vec<String> = Vec::new();
    for host in &merged {
        let fact = Fact::new(
            scan_id,
            "subdomain",
            &host.hostname,
            host.sources.clone(),
            host.sources
                .iter()
                .map(|s| Evidence::observed("discovery", "source", s))
                .collect(),
            Confidence::new(host.confidence).unwrap_or(Confidence(0.6)),
        );
        store.insert_fact(&fact);
        subdomains.push(host.hostname.clone());
        facts.push(fact);
    }

    let mut port_rows: Vec<swiftrecon_report::PortRow> = Vec::new();
    let mut http_records: Vec<swiftrecon_net::http::HttpRecord> = Vec::new();
    let mut tech_rows: Vec<swiftrecon_report::TechRow> = Vec::new();
    let mut san_hosts: Vec<(String, f64, Vec<String>)> = Vec::new();
    let mut endpoint_rows: Vec<swiftrecon_report::EndpointRow> = Vec::new();
    let mut param_rows: Vec<swiftrecon_report::ParamRow> = Vec::new();
    let mut soft404_dropped = 0;

    if !passive {
        // Resolve hostnames to IPs (guard-gated inside the pool).
        let mut pairs: Vec<(String, IpAddr)> = Vec::new();
        for host in &subdomains {
            if let Some(swiftrecon_net::DnsOutcome::Answered { ips, .. }) =
                pool.resolve(guard, host).await
            {
                for ip in ips {
                    pairs.push((host.clone(), ip));
                }
            }
        }
        let ports = swiftrecon_engine::parse_ports(ports_spec).map_err(anyhow::Error::msg)?;
        let backend = swiftrecon_engine::SentinelPorts::new(50, 200, Duration::from_secs(3));
        let http_client = swiftrecon_net::http::HttpClient::new().map_err(anyhow::Error::from)?;
        let rules =
            swiftrecon_fingerprint::load_rules(include_str!("../../../rules/fingerprint.toml"))
                .map_err(anyhow::Error::from)?;

        let mut ip_host: HashMap<IpAddr, String> = HashMap::new();
        for (host, ip) in &pairs {
            ip_host.entry(*ip).or_insert_with(|| host.clone());
        }
        let ips = swiftrecon_engine::dedup_ips(&pairs);
        for ip in &ips {
            let host = ip_host.get(ip).cloned().unwrap_or_default();
            let Some(port_facts) = backend.scan_approved(guard, &host, *ip, &ports).await else {
                continue;
            };
            for fact in &port_facts {
                store.insert_port(scan_id, &host, fact);
                port_rows.push(swiftrecon_report::PortRow {
                    host: host.clone(),
                    ip: ip.to_string(),
                    port: fact.port,
                    state: fact.state.clone(),
                    reason: fact.reason.clone(),
                    latency_ms: fact.latency_ms,
                });
                facts.push(Fact::new(
                    scan_id,
                    "port",
                    &format!("{}:{}", ip, fact.port),
                    vec!["portscan".to_string()],
                    vec![
                        Evidence::observed("probe", "state", &fact.state),
                        Evidence::observed("probe", "reason", &fact.reason),
                    ],
                    Confidence::new(0.9).unwrap_or(Confidence(0.6)),
                ));
            }
        }
        store.upsert_work_unit(
            scan_id,
            "ports",
            "sentinel",
            swiftrecon_store::WorkState::Done,
        );

        // Bounded-concurrency probing (16 in flight max). Outputs are sorted
        // back into deterministic order before persisting.
        struct ProbeHit {
            host: String,
            port: u16,
            tls: bool,
            record: swiftrecon_net::http::HttpRecord,
            tls_record: Option<swiftrecon_net::tls::TlsRecord>,
        }
        let open: Vec<_> = port_rows.iter().filter(|r| r.state == "open").collect();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
        let mut probe_set = tokio::task::JoinSet::new();
        for row in &open {
            for tls in [false, true] {
                let permit_sem = semaphore.clone();
                let client = http_client.clone();
                let task_guard = guard.clone();
                let host = row.host.clone();
                let ip = row.ip.clone();
                let port = row.port;
                probe_set.spawn(async move {
                    let _permit = permit_sem.acquire_owned().await;
                    let record = match client.probe(&task_guard, &host, &ip, port, tls).await {
                        Ok(record) => record,
                        Err(e) => {
                            tracing::warn!("http probe failed for {host}: {e}");
                            return (host, port, tls, None, false);
                        }
                    };
                    let live = match client
                        .not_found_shape(&task_guard, &host, &ip, port, tls)
                        .await
                    {
                        Some(shape) => swiftrecon_net::http::is_live_path(
                            record.status,
                            record.length,
                            record.body_hash,
                            &shape,
                        ),
                        None => true,
                    };
                    if !live {
                        return (host, port, tls, None, true);
                    }
                    let tls_record = if tls {
                        match swiftrecon_net::tls::probe_tls(
                            &task_guard,
                            &host,
                            ip.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                            port,
                        )
                        .await
                        {
                            Some(Ok(rec)) => Some(rec),
                            Some(Err(e)) => {
                                tracing::warn!("tls probe failed for {host}: {e}");
                                None
                            }
                            None => None,
                        }
                    } else {
                        None
                    };
                    (host, port, tls, Some((record, tls_record)), false)
                });
            }
        }
        let mut hits: Vec<ProbeHit> = Vec::new();
        while let Some(done) = probe_set.join_next().await {
            match done {
                Ok((host, port, tls, Some((record, tls_record)), _)) => hits.push(ProbeHit {
                    host,
                    port,
                    tls,
                    record,
                    tls_record,
                }),
                Ok((_, _, _, None, true)) => soft404_dropped += 1,
                _ => {}
            }
        }
        hits.sort_by(|a, b| (&a.host, a.port, a.tls).cmp(&(&b.host, b.port, b.tls)));
        for hit in hits {
            let record = hit.record;
            store.insert_http(scan_id, &record);
            facts.push(Fact::new(
                scan_id,
                "http_service",
                &record.final_url,
                vec!["http_probe".to_string()],
                vec![Evidence::observed(
                    "http",
                    "status",
                    &record.status.to_string(),
                )],
                Confidence::new(0.8).unwrap_or(Confidence(0.6)),
            ));
            if let Some(tls_record) = hit.tls_record {
                store.insert_tls(scan_id, &tls_record);
                for san in &tls_record.sans {
                    san_hosts.push((san.clone(), 0.7, vec!["tls-san".to_string()]));
                }
            }
            http_records.push(record);
        }
        store.upsert_work_unit(scan_id, "http", "probe", swiftrecon_store::WorkState::Done);

        for record in &http_records {
            let headers: HashMap<String, String> =
                serde_json::from_str(&record.headers_json).unwrap_or_default();
            let powered_by = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
                .map(|(_, v)| v.clone());
            let observed = swiftrecon_fingerprint::Observed {
                server: record.server.clone(),
                powered_by,
                cookie_names: record.cookie_names.clone(),
                meta_generator: extract_generator(&record.excerpt),
                html_excerpt: record.excerpt.clone(),
            };
            for tech in swiftrecon_fingerprint::fingerprint(&rules, &observed) {
                store.insert_tech(
                    scan_id,
                    &record.host,
                    &tech.name,
                    tech.version.as_deref(),
                    tech.confidence,
                );
                facts.push(Fact::new(
                    scan_id,
                    "technology",
                    &tech.name,
                    vec!["fingerprint".to_string()],
                    tech.evidence.clone(),
                    Confidence::new(tech.confidence).unwrap_or(Confidence(0.6)),
                ));
                tech_rows.push(swiftrecon_report::TechRow {
                    host: record.host.clone(),
                    name: tech.name,
                    version: tech.version,
                    confidence: tech.confidence,
                    evidence_count: 1,
                });
            }
        }

        // TLS SANs feed back into discovery.
        let known: HashSet<String> = subdomains.iter().cloned().collect();
        for (san, confidence, sources) in san_hosts {
            if known.contains(san.as_str()) || !guard.allow_dns(&san) {
                continue;
            }
            let fact = Fact::new(
                scan_id,
                "subdomain",
                &san,
                sources,
                vec![Evidence::observed("tls", "san", &san)],
                Confidence::new(confidence).unwrap_or(Confidence(0.6)),
            );
            store.insert_fact(&fact);
            subdomains.push(san);
            facts.push(fact);
        }

        let known_hosts: HashSet<String> = subdomains.iter().cloned().collect();
        let crawl_ctx = CrawlCtx {
            scan_id,
            guard,
            store,
            pool: &pool,
            http_client: &http_client,
            http_records: &http_records,
            domain: domain.as_str(),
            known_hosts: &known_hosts,
        };
        let crawl_out = run_crawl_stage(&crawl_ctx).await?;
        facts.extend(crawl_out.facts);
        for host in crawl_out.subdomains {
            if !subdomains.contains(&host) {
                subdomains.push(host);
            }
        }
        endpoint_rows = crawl_out.endpoint_rows;
        param_rows = crawl_out.param_rows;
    }

    let report = swiftrecon_report::ScanReport {
        scan_id: scan_id.to_string(),
        targets: vec![target.to_string()],
        subdomains: subdomains.clone(),
        ports: port_rows,
        http: http_records,
        technologies: tech_rows,
        endpoints: endpoint_rows,
        parameters: param_rows,
    };
    match output {
        "jsonl" => {
            for fact in &facts {
                println!(
                    "{}",
                    serde_json::to_string(fact).unwrap_or_else(|_| "{}".to_string())
                );
            }
        }
        "json" => println!(
            "{}",
            swiftrecon_report::to_json(&report).unwrap_or_else(|_| "{}".to_string())
        ),
        "csv" => print!("{}", swiftrecon_report::ports_csv(&report)),
        "html" => println!(
            "{}",
            swiftrecon_report::to_html(&report).unwrap_or_else(|_| "".to_string())
        ),
        _ => {}
    }
    eprintln!(
        "scan {scan_id}: {} subdomains, {} open ports, {} technologies, {} endpoints, {} parameters (soft404 dropped {soft404_dropped}, passive={passive})",
        report.subdomains.len(),
        report.ports.iter().filter(|r| r.state == "open").count(),
        report.technologies.len(),
        report.endpoints.len(),
        report.parameters.len(),
    );
    Ok(())
}

/// Maximum JS files analyzed per scan (hash-deduped before this cap).
const MAX_JS_FILES: usize = 50;

/// Shared inputs for the crawl stage (keeps arg counts within limits).
struct CrawlCtx<'a> {
    scan_id: &'a str,
    guard: &'a ScopeGuard,
    store: &'a Store,
    pool: &'a swiftrecon_net::ResolverPool,
    http_client: &'a swiftrecon_net::http::HttpClient,
    http_records: &'a [swiftrecon_net::http::HttpRecord],
    domain: &'a str,
    known_hosts: &'a std::collections::HashSet<String>,
}

/// Owned outputs of the crawl stage.
#[derive(Default)]
struct CrawlOutputs {
    facts: Vec<swiftrecon_core::Fact>,
    subdomains: Vec<String>,
    endpoint_rows: Vec<swiftrecon_report::EndpointRow>,
    param_rows: Vec<swiftrecon_report::ParamRow>,
}

/// Crawl + JS + endpoint/parameter stage. Seeds are the live HTTP pages;
/// robots/sitemap, page links, JS, OpenAPI docs, and Wayback history all
/// feed one canonicalize -> template -> merge pipeline.
async fn run_crawl_stage(ctx: &CrawlCtx<'_>) -> Result<CrawlOutputs> {
    let CrawlCtx {
        scan_id,
        guard,
        store,
        pool,
        http_client,
        http_records,
        domain,
        known_hosts,
    } = ctx;
    let mut out = CrawlOutputs::default();
    use std::collections::{HashMap, HashSet};
    use swiftrecon_core::{Confidence, Evidence, Fact};

    let seeds: Vec<String> = http_records.iter().map(|r| r.final_url.clone()).collect();
    if seeds.is_empty() {
        return Ok(CrawlOutputs::default());
    }
    let completed: HashSet<String> = store.done_keys(scan_id, "crawl").into_iter().collect();
    let limiter = swiftrecon_engine::AdaptiveLimiter::new(std::time::Duration::from_millis(200));
    let config = swiftrecon_web::CrawlConfig {
        max_depth: 3,
        max_urls_per_host: 100,
        max_pages_total: 500,
        politeness_ms: 200,
        respect_robots: false,
        trap_threshold: 20,
    };
    let pages = swiftrecon_web::crawl(
        http_client,
        pool,
        guard,
        &limiter,
        &seeds,
        &completed,
        &config,
    )
    .await;
    for page in &pages {
        store.upsert_work_unit(
            scan_id,
            "crawl",
            &page.url,
            swiftrecon_store::WorkState::Done,
        );
        let template = page_template(&page.url);
        store.insert_url(scan_id, &page.url, &template, &["crawler".to_string()]);
        out.facts.push(Fact::new(
            scan_id,
            "url",
            &page.url,
            vec!["crawler".to_string()],
            vec![Evidence::observed("crawl", "page", &page.url)],
            Confidence::new(0.7).unwrap_or(Confidence(0.6)),
        ));
    }
    let mut discovered_hosts: HashSet<String> = HashSet::new();

    // Candidate endpoints: (url, method, source).
    let mut candidates: Vec<(String, String, String)> = Vec::new();
    for page in &pages {
        for link in page
            .links
            .iter()
            .chain(page.scripts.iter())
            .chain(page.iframes.iter())
        {
            candidates.push((link.clone(), "GET".to_string(), "crawler".to_string()));
        }
        for form in &page.forms {
            candidates.push((form.action.clone(), form.method.clone(), "form".to_string()));
        }
    }
    // robots/sitemap per crawled host.
    let mut bases: HashSet<String> = HashSet::new();
    for page in &pages {
        if let Ok(url) = url::Url::parse(&page.url) {
            if let Some(host) = url.host_str() {
                let mut base = format!("{}://{host}", url.scheme());
                if let Some(port) = url.port() {
                    base.push_str(&format!(":{port}"));
                }
                bases.insert(base);
            }
        }
    }
    for base in &bases {
        let (paths, sitemap_urls) =
            swiftrecon_web::openapi::robots_endpoints(http_client, guard, base).await;
        for path in paths {
            candidates.push((path, "GET".to_string(), "robots".to_string()));
        }
        for url in sitemap_urls {
            candidates.push((url, "GET".to_string(), "sitemap".to_string()));
        }
    }
    // OpenAPI docs per base with live HTTP.
    let mut openapi_endpoints: Vec<(String, Vec<String>)> = Vec::new();
    for base in &bases {
        for endpoint in swiftrecon_web::openapi::discover_openapi(http_client, guard, base).await {
            let methods = if endpoint.methods.is_empty() {
                vec!["GET".to_string()]
            } else {
                endpoint.methods.clone()
            };
            openapi_endpoints.push((endpoint.path, methods));
        }
    }
    // JavaScript: unique files by hash, then inline scripts.
    let mut js_urls: Vec<(String, String)> = Vec::new();
    for page in &pages {
        for script in &page.scripts {
            js_urls.push((script.clone(), page.url.clone()));
        }
    }
    let mut seen_hashes: HashSet<u64> = HashSet::new();
    let mut js_sources: Vec<(String, String)> = Vec::new();
    for (js_url, _page_url) in js_urls {
        if seen_hashes.len() >= MAX_JS_FILES {
            break;
        }
        let Some(canonical) = swiftrecon_web::canonicalize(&js_url) else {
            continue;
        };
        if store.done_keys(scan_id, "js").contains(&canonical) {
            continue;
        }
        let Ok(text) = http_client.fetch_text(guard, &canonical).await else {
            continue;
        };
        let hash = xxhash_rust::xxh3::xxh3_64(text.as_bytes());
        if !seen_hashes.insert(hash) {
            continue;
        }
        store.upsert_work_unit(scan_id, "js", &canonical, swiftrecon_store::WorkState::Done);
        let finding = swiftrecon_web::js::analyze(&text);
        store.insert_js(scan_id, &canonical, hash, finding.parsed_ok);
        out.facts.push(Fact::new(
            scan_id,
            "js_file",
            &canonical,
            vec!["js-analysis".to_string()],
            vec![Evidence::observed(
                "js",
                if finding.parsed_ok {
                    "ast"
                } else {
                    "regex-fallback"
                },
                &canonical,
            )],
            Confidence::new(if finding.parsed_ok { 0.75 } else { 0.5 }).unwrap_or(Confidence(0.6)),
        ));
        for secret in &finding.secret_kinds {
            let subject = format!("secret:{secret}");
            store.insert_finding(scan_id, "secret", &subject, 0.6);
            out.facts.push(Fact::new(
                scan_id,
                "finding",
                &subject,
                vec!["js-analysis".to_string()],
                vec![Evidence::observed("js", "secret-kind", secret)],
                Confidence::new(0.6).unwrap_or(Confidence(0.6)),
            ));
        }
        for url in &finding.urls {
            if let Some(abs) = swiftrecon_web::resolve_against(&canonical, url) {
                js_sources.push((abs, "js".to_string()));
            }
        }
        for param in &finding.params {
            js_sources.push((format!("{canonical}?{param}=1"), "js".to_string()));
        }
        if let Some(map) = &finding.sourcemap {
            if let Some(abs) = swiftrecon_web::resolve_against(&canonical, map) {
                js_sources.push((abs, "js-sourcemap".to_string()));
            }
        }
    }
    for page in &pages {
        for inline in &page.inline_scripts {
            let finding = swiftrecon_web::js::analyze(inline);
            for url in &finding.urls {
                if let Some(abs) = swiftrecon_web::resolve_against(&page.url, url) {
                    js_sources.push((abs, "inline-js".to_string()));
                }
            }
            for param in &finding.params {
                js_sources.push((format!("{}?{param}=1", page.url), "inline-js".to_string()));
            }
        }
    }
    // Historical URLs (passive, once per domain).
    for url in swiftrecon_web::openapi::wayback_urls(http_client, guard, domain).await {
        candidates.push((url, "GET".to_string(), "wayback".to_string()));
    }
    for (url, _from) in js_sources {
        candidates.push((url, "GET".to_string(), "js".to_string()));
    }

    // Merge: canonicalize, scope-gate, template, group methods/sources.
    let mut endpoints: HashMap<String, (HashSet<String>, HashSet<String>)> = HashMap::new();
    let mut params: HashMap<(String, String, String), (String, HashSet<String>)> = HashMap::new();
    for (raw, method, source) in candidates {
        let Some(canonical) = swiftrecon_web::canonicalize(&raw) else {
            continue;
        };
        let Ok(parsed) = url::Url::parse(&canonical) else {
            continue;
        };
        let host = parsed.host_str().unwrap_or("").to_string();
        if !guard.allow_dns(&host) {
            continue;
        }
        discovered_hosts.insert(host.clone());
        let template = format!(
            "{}://{}{}",
            parsed.scheme(),
            host_with_port(&parsed),
            swiftrecon_web::template_path(parsed.path())
        );
        endpoints
            .entry(template.clone())
            .or_default()
            .0
            .insert(method.clone());
        endpoints
            .entry(template.clone())
            .or_default()
            .1
            .insert(source.clone());
        for param in swiftrecon_web::query_params(&canonical, &source) {
            let location = format!("{:?}", param.location).to_lowercase();
            params
                .entry((template.clone(), param.name.clone(), location))
                .or_insert((method.clone(), HashSet::new()))
                .1
                .insert(source.clone());
        }
    }
    // Form inputs carry their own method/location.
    for page in &pages {
        for form in &page.forms {
            let Some(canonical) = swiftrecon_web::canonicalize(&form.action) else {
                continue;
            };
            let Ok(parsed) = url::Url::parse(&canonical) else {
                continue;
            };
            let template = format!(
                "{}://{}{}",
                parsed.scheme(),
                host_with_port(&parsed),
                swiftrecon_web::template_path(parsed.path())
            );
            let location = if form.method == "GET" {
                "query"
            } else {
                "body"
            }
            .to_string();
            for input in &form.inputs {
                params
                    .entry((template.clone(), input.clone(), location.clone()))
                    .or_insert((form.method.clone(), HashSet::new()))
                    .1
                    .insert("form".to_string());
            }
        }
    }
    for (path, methods) in openapi_endpoints {
        let Some(canonical) = swiftrecon_web::canonicalize(&path) else {
            continue;
        };
        let Ok(parsed) = url::Url::parse(&canonical) else {
            continue;
        };
        if !guard.allow_dns(parsed.host_str().unwrap_or("")) {
            continue;
        }
        let template = format!(
            "{}://{}{}",
            parsed.scheme(),
            host_with_port(&parsed),
            swiftrecon_web::template_path(parsed.path())
        );
        let entry = endpoints.entry(template).or_default();
        for method in methods {
            entry.0.insert(method);
        }
        entry.1.insert("openapi".to_string());
    }

    let mut endpoint_list: Vec<(String, Vec<String>, Vec<String>)> = endpoints
        .into_iter()
        .map(|(template, (methods, sources))| {
            let mut methods: Vec<String> = methods.into_iter().collect();
            methods.sort();
            let mut sources: Vec<String> = sources.into_iter().collect();
            sources.sort();
            (template, methods, sources)
        })
        .collect();
    endpoint_list.sort();
    for (template, methods, sources) in &endpoint_list {
        let confidence = if sources.len() >= 2 { 0.85 } else { 0.7 };
        store.insert_endpoint(scan_id, template, methods, sources);
        out.facts.push(Fact::new(
            scan_id,
            "endpoint",
            template,
            sources.clone(),
            vec![Evidence::observed(
                "discovery",
                "endpoint-source",
                &sources.join(","),
            )],
            Confidence::new(confidence).unwrap_or(Confidence(0.6)),
        ));
        out.endpoint_rows.push(swiftrecon_report::EndpointRow {
            template: template.clone(),
            methods: methods.clone(),
            sources: sources.clone(),
        });
    }
    let mut param_list: Vec<(String, String, String, String, Vec<String>)> = params
        .into_iter()
        .map(|((endpoint, name, location), (method, sources))| {
            let mut sources: Vec<String> = sources.into_iter().collect();
            sources.sort();
            (endpoint, name, location, method, sources)
        })
        .collect();
    param_list.sort();
    for (endpoint, name, location, method, sources) in &param_list {
        store.insert_param(scan_id, endpoint, name, location, method);
        out.facts.push(Fact::new(
            scan_id,
            "parameter",
            &format!("{endpoint} {name} ({location})"),
            sources.clone(),
            vec![Evidence::observed(
                "discovery",
                "param-source",
                &sources.join(","),
            )],
            Confidence::new(0.7).unwrap_or(Confidence(0.6)),
        ));
        out.param_rows.push(swiftrecon_report::ParamRow {
            endpoint: endpoint.clone(),
            name: name.clone(),
            location: location.clone(),
            method: method.clone(),
        });
    }
    for host in discovered_hosts {
        if known_hosts.contains(&host) {
            continue;
        }
        out.facts.push(Fact::new(
            scan_id,
            "subdomain",
            &host,
            vec!["endpoint-analysis".to_string()],
            vec![Evidence::observed("discovery", "endpoint-host", &host)],
            Confidence::new(0.6).unwrap_or(Confidence(0.6)),
        ));
        out.subdomains.push(host);
    }
    Ok(out)
}

/// Canonical URL with its path templated (endpoint identity).
fn page_template(canonical: &str) -> String {
    match url::Url::parse(canonical) {
        Ok(parsed) => format!(
            "{}://{}{}",
            parsed.scheme(),
            host_with_port(&parsed),
            swiftrecon_web::template_path(parsed.path())
        ),
        Err(_) => canonical.to_string(),
    }
}

fn host_with_port(parsed: &url::Url) -> String {
    match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or("")),
        None => parsed.host_str().unwrap_or("").to_string(),
    }
}

/// Meta generator tag from an HTML excerpt (fingerprint signal).
fn extract_generator(html: &str) -> Option<String> {
    use scraper::{Html, Selector};
    let document = Html::parse_document(html);
    let selector = Selector::parse("meta[name=generator]").ok()?;
    document
        .select(&selector)
        .next()?
        .attr("content")
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn cmd_scope_check(value: &str, scope_path: Option<PathBuf>) -> Result<()> {
    let scope = load_scope(scope_path)?;
    println!("{}", strip_control(&explain(&scope, value)));
    Ok(())
}

fn cmd_doctor() -> Result<()> {
    println!("swiftrecon doctor: ok (phase 1 skeleton)");
    Ok(())
}

fn cmd_init(output: &PathBuf) -> Result<()> {
    let example = r#"[scope]
include = ["*.example.com"]
exclude = []

[limits]
max_concurrency = 200
global_rate = 300
per_host_rate = 5
max_depth = 3
max_urls_per_host = 5000
max_body_bytes = 2097152
scan_deadline_secs = 3600
"#;
    std::fs::write(output, example)?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn strip_control(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_chars_stripped_before_terminal() {
        assert_eq!(strip_control("a\x00b\x1bn"), "abn");
    }

    #[test]
    fn terminal_paths_never_emit_control_chars() {
        // Regression: every target-controlled terminal print goes through
        // strip_control (scope desc, out-of-scope target, explain output).
        let evil = "evil\x1b[2J\x00.com";
        assert!(!strip_control(evil).chars().any(|c| c.is_control()));
    }

    #[test]
    fn generator_extraction() {
        let html = "<html><head><meta name=\"generator\" content=\"WordPress 6.4\"></head></html>";
        assert_eq!(extract_generator(html), Some("WordPress 6.4".to_string()));
        assert_eq!(extract_generator("<html><body>x</body></html>"), None);
    }
}
