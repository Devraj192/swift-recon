//! Subdomain discovery: pluggable `Source` trait, passive sources,
//! wordlist brute-force, wildcard filtering, trusted-resolver validation.
//!
//! A failing source never fails the scan: callers log the source name and
//! continue with the remaining sources.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use swiftrecon_net::{DnsOutcome, ResolverPool};
use swiftrecon_scope::{dedup_hostnames, ScopeGuard};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Source trait
// ---------------------------------------------------------------------------

/// One hostname with provenance. Confidence rises when independent sources
/// agree on the same name.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredHost {
    pub hostname: String,
    pub sources: Vec<String>,
    pub confidence: f64,
}

/// Pluggable discovery source. Passive sources send no packets to the target.
pub trait Source: Send + Sync {
    fn name(&self) -> &str;

    fn collect(
        &self,
        domain: String,
    ) -> impl std::future::Future<Output = Result<Vec<String>, DiscoverError>> + Send + '_;
}

/// Merge per-source host lists: union by hostname, union sources, boost
/// confidence when two or more independent sources agree.
pub fn merge_sources(lists: Vec<(String, Vec<String>)>) -> Vec<DiscoveredHost> {
    let mut by_host: HashMap<String, Vec<String>> = HashMap::new();
    for (source, hosts) in lists {
        for host in dedup_hostnames(&hosts) {
            by_host.entry(host).or_default().push(source.clone());
        }
    }
    let mut out: Vec<DiscoveredHost> = by_host
        .into_iter()
        .map(|(hostname, mut sources)| {
            sources.sort();
            sources.dedup();
            let confidence = if sources.len() >= 2 { 0.85 } else { 0.6 };
            DiscoveredHost {
                hostname,
                sources,
                confidence,
            }
        })
        .collect();
    out.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    out
}

// ---------------------------------------------------------------------------
// Passive source: certificate transparency (crt.sh)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CrtShRow {
    #[serde(default)]
    name_value: String,
}

/// Parse crt.sh JSON output into candidate hostnames. Pure function so the
/// parsing is unit-testable without network.
pub fn parse_crtsh_json(text: &str, domain: &str) -> Vec<String> {
    let rows: Vec<CrtShRow> = match serde_json::from_str(text) {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let domain = domain.trim().to_lowercase();
    let mut out = Vec::new();
    for row in rows {
        for part in row.name_value.split(['\n', ',', ' ']) {
            let candidate = part
                .trim()
                .to_lowercase()
                .trim_start_matches('*')
                .trim_start_matches('.')
                .to_string();
            if candidate.is_empty() {
                continue;
            }
            if candidate == domain || candidate.ends_with(&format!(".{domain}")) {
                out.push(candidate);
            }
        }
    }
    out
}

pub struct CrtShSource {
    client: reqwest::Client,
}

impl CrtShSource {
    pub fn new() -> Result<Self, DiscoverError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("SwiftRecon/0.1 (+local recon)")
            .build()
            .map_err(|e| DiscoverError::SourceFailed("crtsh".to_string(), e.to_string()))?;
        Ok(Self { client })
    }
}

impl Default for CrtShSource {
    fn default() -> Self {
        Self::new().expect("reqwest client builds with static config")
    }
}

impl Source for CrtShSource {
    fn name(&self) -> &str {
        "crtsh"
    }

    async fn collect(&self, domain: String) -> Result<Vec<String>, DiscoverError> {
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let response = tokio::time::timeout(Duration::from_secs(30), self.client.get(&url).send())
            .await
            .map_err(|_| {
                DiscoverError::SourceFailed("crtsh".to_string(), "request timed out".to_string())
            })?
            .map_err(|e| DiscoverError::SourceFailed("crtsh".to_string(), e.to_string()))?;
        if !response.status().is_success() {
            return Err(DiscoverError::SourceFailed(
                "crtsh".to_string(),
                format!("http {}", response.status()),
            ));
        }
        let text = response
            .text()
            .await
            .map_err(|e| DiscoverError::SourceFailed("crtsh".to_string(), e.to_string()))?;
        Ok(parse_crtsh_json(&text, &domain))
    }
}

// ---------------------------------------------------------------------------
// Wildcard detection and filtering
// ---------------------------------------------------------------------------

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Pseudo-random probe label (no rand crate in the fixed stack; uniqueness
/// across concurrent scans is what matters, not unpredictability).
fn probe_label() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut value = nanos ^ (u128::from(count).wrapping_mul(0x9E3779B97F4A7C15));
    let mut label = String::from("swrprobe");
    for _ in 0..10 {
        let digit = (value % 36) as u8;
        label.push(
            (if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            }) as char,
        );
        value /= 36;
    }
    label
}

/// Probe random labels under `domain`. When they resolve, the zone is a
/// wildcard; returns the wildcard answer set for filtering.
pub async fn detect_wildcard(
    pool: &ResolverPool,
    guard: &ScopeGuard,
    domain: &str,
) -> Option<HashSet<IpAddr>> {
    let mut answer_sets: Vec<HashSet<IpAddr>> = Vec::new();
    for _ in 0..3 {
        let probe = format!("{}.{}", probe_label(), domain);
        match pool.resolve(guard, &probe).await {
            Some(DnsOutcome::Answered { ips, .. }) if !ips.is_empty() => {
                answer_sets.push(ips.into_iter().collect());
            }
            _ => return None,
        }
    }
    // Wildcard confirmed only when probes agree.
    if answer_sets.windows(2).all(|w| w[0] == w[1]) {
        Some(answer_sets.into_iter().next().unwrap_or_default())
    } else {
        None
    }
}

/// Drop hits whose full answer set is the wildcard set.
pub fn filter_wildcard(
    hits: Vec<(String, Vec<IpAddr>)>,
    wildcard_ips: &HashSet<IpAddr>,
) -> Vec<String> {
    hits.into_iter()
        .filter(|(_, ips)| !ips.is_empty() && !ips.iter().all(|ip| wildcard_ips.contains(ip)))
        .map(|(host, _)| host)
        .collect()
}

// ---------------------------------------------------------------------------
// Active source: wordlist brute-force with trusted re-validation
// ---------------------------------------------------------------------------

/// Brute-force `words` under `domain` through the pooled resolvers.
/// Hits are re-validated with a fresh lookup before being returned.
pub async fn brute_force(
    pool: &ResolverPool,
    guard: &ScopeGuard,
    domain: &str,
    words: &[String],
    wildcard_ips: Option<&HashSet<IpAddr>>,
) -> Vec<DiscoveredHost> {
    let mut hits: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for word in words {
        let candidate = format!("{word}.{domain}");
        match pool.resolve(guard, &candidate).await {
            Some(DnsOutcome::Answered { ips, .. }) if !ips.is_empty() => {
                // Trusted re-validation: confirm with a second lookup.
                match pool.resolve(guard, &candidate).await {
                    Some(DnsOutcome::Answered { ips: ips2, .. }) if !ips2.is_empty() => {
                        hits.push((candidate, ips2));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let names = match wildcard_ips {
        Some(set) => filter_wildcard(hits, set),
        None => hits.into_iter().map(|(host, _)| host).collect(),
    };
    names
        .into_iter()
        .map(|hostname| DiscoveredHost {
            hostname,
            sources: vec!["bruteforce".to_string()],
            confidence: 0.7,
        })
        .collect()
}

/// Embedded minimal wordlist for the default active pass.
pub fn mini_wordlist() -> Vec<String> {
    include_str!("../../../wordlists/mini.txt")
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect()
}

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("source {0} failed: {1}")]
    SourceFailed(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRTSH_FIXTURE: &str = r#"[
        {"name_value": "www.example.com"},
        {"name_value": "*.example.com\nmail.example.com"},
        {"name_value": "unrelated.org"},
        {"name_value": "BADexample.com"}
    ]"#;

    #[test]
    fn crtsh_parsing_keeps_only_in_scope_names() {
        let hosts = parse_crtsh_json(CRTSH_FIXTURE, "example.com");
        assert!(hosts.contains(&"www.example.com".to_string()));
        assert!(hosts.contains(&"mail.example.com".to_string()));
        assert!(hosts.contains(&"example.com".to_string()));
        assert!(!hosts.iter().any(|h| h == "unrelated.org"));
        assert!(!hosts.iter().any(|h| h == "badexample.com"));
    }

    #[test]
    fn crtsh_parsing_survives_garbage() {
        assert!(parse_crtsh_json("not json", "example.com").is_empty());
        assert!(parse_crtsh_json("[]", "example.com").is_empty());
    }

    #[test]
    fn merge_boosts_agreeing_sources() {
        let merged = merge_sources(vec![
            ("crtsh".to_string(), vec!["a.example.com".to_string()]),
            (
                "bruteforce".to_string(),
                vec!["a.example.com".to_string(), "b.example.com".to_string()],
            ),
        ]);
        let a = merged
            .iter()
            .find(|h| h.hostname == "a.example.com")
            .unwrap();
        let b = merged
            .iter()
            .find(|h| h.hostname == "b.example.com")
            .unwrap();
        assert_eq!(a.sources.len(), 2);
        assert!(a.confidence > b.confidence);
    }

    #[test]
    fn wildcard_filter_drops_only_wildcard_answers() {
        let wildcard: HashSet<IpAddr> = ["9.9.9.9".parse().unwrap()].into_iter().collect();
        let out = filter_wildcard(
            vec![
                (
                    "fake.example.com".to_string(),
                    vec!["9.9.9.9".parse().unwrap()],
                ),
                (
                    "real.example.com".to_string(),
                    vec!["1.2.3.4".parse().unwrap()],
                ),
            ],
            &wildcard,
        );
        assert_eq!(out, vec!["real.example.com".to_string()]);
    }

    #[test]
    fn probe_labels_are_unique() {
        let labels: HashSet<String> = (0..50).map(|_| probe_label()).collect();
        assert_eq!(labels.len(), 50);
    }

    #[test]
    fn mini_wordlist_loads() {
        let words = mini_wordlist();
        assert!(words.contains(&"www".to_string()));
        assert!(words.iter().all(|w| !w.is_empty()));
    }

    /// Phase 2 exit gate: fixture-corpus precision/recall.
    /// Scripted answers (no live network); the parsing, wildcard filter,
    /// merge, and scope gate under test are the real functions.
    #[test]
    fn lab_corpus_precision_recall() {
        use serde::Deserialize;
        use std::collections::HashSet;
        use swiftrecon_scope::Scope;

        #[derive(Deserialize)]
        struct Corpus {
            domain: String,
            truth: Vec<String>,
            wildcard_ips: Vec<IpAddr>,
        }
        #[derive(Deserialize)]
        struct Answer {
            host: String,
            ips: Vec<IpAddr>,
        }
        #[derive(Deserialize)]
        struct BruteFixture {
            answers: Vec<Answer>,
        }

        let corpus: Corpus =
            serde_json::from_str(include_str!("../../../lab/corpus.json")).unwrap();
        let crt_text = include_str!("../../../lab/crtsh.json");
        let brute: BruteFixture =
            serde_json::from_str(include_str!("../../../lab/bruteforce.json")).unwrap();

        let crt_hosts = parse_crtsh_json(crt_text, &corpus.domain);
        let wildcard: HashSet<IpAddr> = corpus.wildcard_ips.into_iter().collect();
        let raw: Vec<(String, Vec<IpAddr>)> =
            brute.answers.into_iter().map(|a| (a.host, a.ips)).collect();
        let brute_hosts = filter_wildcard(raw, &wildcard);

        let merged = merge_sources(vec![
            ("crtsh".to_string(), crt_hosts),
            ("bruteforce".to_string(), brute_hosts),
        ]);
        let scope = Scope::from_lists(&[format!("*.{}", corpus.domain)], &[]).unwrap();
        let found: Vec<String> = merged
            .into_iter()
            .map(|h| h.hostname)
            .filter(|h| scope.host_allowed(h))
            .collect();

        let truth: HashSet<&str> = corpus.truth.iter().map(String::as_str).collect();
        let true_positives = found.iter().filter(|h| truth.contains(h.as_str())).count();
        let precision = true_positives as f64 / found.len() as f64;
        let recall = true_positives as f64 / truth.len() as f64;
        eprintln!(
            "lab corpus: precision={precision:.4} recall={recall:.4} found={}",
            found.len()
        );
        assert!(
            precision >= 0.98,
            "precision {precision:.3} below 0.98: {found:?}"
        );
        assert!(recall >= 0.90, "recall {recall:.3} below 0.90");
    }
}
