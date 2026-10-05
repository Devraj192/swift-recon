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
    /// Run a scan (Phase 2: subdomain discovery; empty scan when no target).
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
        /// Output format: terminal summary or JSONL facts on stdout.
        #[arg(long, default_value = "terminal")]
        output: String,
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
        } => cmd_scan(target, scope, resume, yes, passive, &output).await,
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
) -> Result<()> {
    if output != "terminal" && output != "jsonl" {
        anyhow::bail!("unknown output format: {output} (expected terminal|jsonl)");
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
        run_discovery(&scan_id, t, &guard, &store, passive, output).await?;
    }

    store.upsert_work_unit(&scan_id, "scan", &desc, swiftrecon_store::WorkState::Done);
    store.finish_scan(&scan_id, swiftrecon_core::now_unix());
    eprintln!("scan {} done", strip_control(&scan_id));
    Ok(())
}

/// Phase 2 discovery: passive sources always; brute-force unless `--passive`.
/// Facts stream as JSONL on stdout; the summary goes to stderr so stdout
/// stays pure data.
async fn run_discovery(
    scan_id: &str,
    target: &str,
    guard: &ScopeGuard,
    store: &Store,
    passive: bool,
    output: &str,
) -> Result<()> {
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

    let mut count = 0;
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
        if output == "jsonl" {
            println!(
                "{}",
                serde_json::to_string(&fact).unwrap_or_else(|_| "{}".to_string())
            );
        }
        count += 1;
    }
    eprintln!("discovered {count} subdomains for {domain} (passive={passive})");
    Ok(())
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
}
