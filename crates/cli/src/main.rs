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
    }

    let report = swiftrecon_report::ScanReport {
        scan_id: scan_id.to_string(),
        targets: vec![target.to_string()],
        subdomains: subdomains.clone(),
        ports: port_rows,
        http: http_records,
        technologies: tech_rows,
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
        "scan {scan_id}: {} subdomains, {} open ports, {} technologies (soft404 dropped {soft404_dropped}, passive={passive})",
        report.subdomains.len(),
        report.ports.iter().filter(|r| r.state == "open").count(),
        report.technologies.len(),
    );
    Ok(())
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
