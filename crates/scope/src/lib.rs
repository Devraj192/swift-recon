//! Authorized-scope parsing, matching, and the `ScopeGuard`.
//!
//! Every outbound connection (DNS, TCP, each HTTP redirect hop) must pass
//! through `ScopeGuard`. After DNS resolution the IP is re-checked against
//! private/loopback/link-local ranges unless explicitly in scope.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeFile {
    #[serde(default)]
    pub scope: ScopeSection,
    #[serde(default)]
    pub limits: LimitsSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeSection {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsSection {
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_global_rate")]
    pub global_rate: u64,
    #[serde(default = "default_per_host_rate")]
    pub per_host_rate: u64,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_max_urls_per_host")]
    pub max_urls_per_host: usize,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_scan_deadline_secs")]
    pub scan_deadline_secs: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_concurrency: default_max_concurrency(),
            global_rate: default_global_rate(),
            per_host_rate: default_per_host_rate(),
            max_depth: default_max_depth(),
            max_urls_per_host: default_max_urls_per_host(),
            max_body_bytes: default_max_body_bytes(),
            scan_deadline_secs: default_scan_deadline_secs(),
        }
    }
}

fn default_max_concurrency() -> usize {
    200
}
fn default_global_rate() -> u64 {
    300
}
fn default_per_host_rate() -> u64 {
    5
}
fn default_max_depth() -> u32 {
    3
}
fn default_max_urls_per_host() -> usize {
    5000
}
fn default_max_body_bytes() -> usize {
    2_097_152
}
fn default_scan_deadline_secs() -> u64 {
    3600
}

pub fn parse_scope_file(text: &str) -> Result<ScopeFile, ScopeError> {
    let file: ScopeFile = toml::from_str(text)?;
    if file.scope.include.is_empty() {
        return Err(ScopeError::EmptyScope);
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// Scope entries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeEntry {
    Domain(String),
    Wildcard(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

impl ScopeEntry {
    fn parse(raw: &str) -> Result<Self, ScopeError> {
        let value = raw.trim().to_lowercase();
        if value.is_empty() {
            return Err(ScopeError::InvalidEntry(raw.to_string()));
        }
        if let Ok(net) = IpNet::from_str(&value) {
            return Ok(Self::Cidr(net));
        }
        if let Ok(ip) = IpAddr::from_str(&value) {
            return Ok(Self::Ip(ip));
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || suffix.contains('/') {
                return Err(ScopeError::InvalidEntry(raw.to_string()));
            }
            normalize_hostname(suffix)?;
            return Ok(Self::Wildcard(suffix.to_string()));
        }
        if value.contains('*') || value.contains('/') {
            return Err(ScopeError::InvalidEntry(raw.to_string()));
        }
        normalize_hostname(&value)?;
        Ok(Self::Domain(value))
    }

    fn matches_host(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        match self {
            Self::Domain(d) => host == *d,
            // Label-boundary match: *.example.com matches a.example.com,
            // never badexample.com.
            Self::Wildcard(suffix) => {
                host.len() > suffix.len()
                    && host.ends_with(suffix.as_str())
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            Self::Ip(_) | Self::Cidr(_) => false,
        }
    }

    fn matches_ip(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Ip(addr) => addr == ip,
            Self::Cidr(net) => net.contains(ip),
            Self::Domain(_) | Self::Wildcard(_) => false,
        }
    }
}

fn normalize_hostname(host: &str) -> Result<String, ScopeError> {
    let host = host.trim().to_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(ScopeError::InvalidEntry(host));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ScopeError::InvalidEntry(host));
        }
    }
    Ok(host)
}

/// Returns the registrable domain (eTLD+1) when the public suffix list knows it.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let domain = psl::domain(host.as_bytes())?;
    String::from_utf8(domain.as_bytes().to_vec()).ok()
}

// ---------------------------------------------------------------------------
// Scope + ScopeGuard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Scope {
    include: Vec<ScopeEntry>,
    exclude: Vec<ScopeEntry>,
    explicit_private_allowed: bool,
}

impl Scope {
    pub fn from_lists(include: &[String], exclude: &[String]) -> Result<Self, ScopeError> {
        if include.is_empty() {
            return Err(ScopeError::EmptyScope);
        }
        let include = include
            .iter()
            .map(|s| ScopeEntry::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let exclude = exclude
            .iter()
            .map(|s| ScopeEntry::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let explicit_private_allowed = include
            .iter()
            .any(|e| matches!(e, ScopeEntry::Ip(_) | ScopeEntry::Cidr(_)));
        Ok(Self {
            include,
            exclude,
            explicit_private_allowed,
        })
    }

    pub fn from_file(file: &ScopeFile) -> Result<Self, ScopeError> {
        Self::from_lists(&file.scope.include, &file.scope.exclude)
    }

    fn excluded(&self, host: &str, ip: Option<&IpAddr>) -> bool {
        self.exclude.iter().any(|e| {
            e.matches_host(host)
                || ip.map(|addr| e.matches_ip(addr)).unwrap_or(false)
                || e.matches_host(&host.to_lowercase())
        })
    }

    fn included(&self, host: &str, ip: Option<&IpAddr>) -> bool {
        self.include
            .iter()
            .any(|e| e.matches_host(host) || ip.map(|addr| e.matches_ip(addr)).unwrap_or(false))
    }

    /// Hostname check before any connection (DNS query, TCP connect, redirect hop).
    pub fn host_allowed(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        if host.is_empty() {
            return false;
        }
        // Raw IPs go through the IP path.
        if let Ok(ip) = IpAddr::from_str(&host) {
            return self.ip_allowed(&ip);
        }
        if self.excluded(&host, None) {
            return false;
        }
        self.included(&host, None)
    }

    /// IP check for bare-IP input. Strict direct match: only an explicit
    /// IP/CIDR entry allows it. Hostname entries never match here; resolved
    /// IPs behind hostname scans go through `connection_allowed`, which
    /// applies the non-routable re-check.
    pub fn ip_allowed(&self, ip: &IpAddr) -> bool {
        if self.exclude.iter().any(|e| e.matches_ip(ip)) {
            return false;
        }
        if self.include.iter().any(|e| e.matches_ip(ip)) {
            return true;
        }
        false
    }

    /// Full check: hostname in scope AND resolved IP re-checked.
    pub fn connection_allowed(&self, host: &str, resolved_ip: Option<&IpAddr>) -> bool {
        if !self.host_allowed(host) {
            return false;
        }
        match resolved_ip {
            None => true,
            Some(ip) => {
                if self.exclude.iter().any(|e| e.matches_ip(ip)) {
                    return false;
                }
                if self.include.iter().any(|e| e.matches_ip(ip)) {
                    return true;
                }
                if is_non_routable(ip) && !self.explicit_private_allowed {
                    return false;
                }
                true
            }
        }
    }
}

/// ScopeGuard: the single gate every outbound connection passes through.
#[derive(Debug, Clone)]
pub struct ScopeGuard {
    scope: Scope,
    blocked_log: Vec<String>,
}

impl ScopeGuard {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            blocked_log: Vec::new(),
        }
    }

    pub fn allow_dns(&self, host: &str) -> bool {
        self.scope.host_allowed(host)
    }

    /// Non-mutating hostname + resolved-IP check (no block log).
    pub fn allow_connection(&self, host: &str, ip: Option<&IpAddr>) -> bool {
        self.scope.connection_allowed(host, ip)
    }

    pub fn allow_tcp(&mut self, host: &str, ip: Option<&IpAddr>) -> bool {
        let allowed = self.scope.connection_allowed(host, ip);
        if !allowed {
            self.blocked_log.push(format!(
                "blocked tcp {} {}",
                host,
                ip.map(|a| a.to_string()).unwrap_or_default()
            ));
        }
        allowed
    }

    pub fn allow_http_hop(&mut self, url: &str, resolved_ip: Option<&IpAddr>) -> bool {
        let host = match url::Url::parse(url) {
            Ok(u) => u.host_str().unwrap_or("").to_string(),
            Err(_) => return false,
        };
        self.allow_tcp(&host, resolved_ip)
    }

    pub fn blocked(&self) -> &[String] {
        &self.blocked_log
    }
}

fn is_non_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || *v4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("scope include list is empty")]
    EmptyScope,
    #[error("invalid scope entry: {0}")]
    InvalidEntry(String),
    #[error("config parse error: {0}")]
    Config(String),
}

impl From<toml::de::Error> for ScopeError {
    fn from(err: toml::de::Error) -> Self {
        Self::Config(err.to_string())
    }
}

/// Explain helper for `scope check`: why is this value in or out of scope.
pub fn explain(scope: &Scope, value: &str) -> String {
    let value = value.trim().to_lowercase();
    if let Ok(ip) = IpAddr::from_str(&value) {
        if scope.ip_allowed(&ip) {
            return format!("{value} is IN scope (direct IP/CIDR match)");
        }
        return format!("{value} is OUT of scope (no IP/CIDR match or excluded)");
    }
    if scope.host_allowed(&value) {
        return format!("{value} is IN scope (hostname match)");
    }
    format!("{value} is OUT of scope (no include match or excluded)")
}

/// Deduplicate hostnames after normalization (exact sets, never Bloom).
/// Empty entries are dropped.
pub fn dedup_hostnames(hosts: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for h in hosts {
        let key = h.trim().to_lowercase();
        if key.is_empty() {
            continue;
        }
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_scope() -> Scope {
        Scope::from_lists(
            &["*.example.com".to_string(), "example.com".to_string()],
            &["admin.example.com".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn wildcard_matches_label_boundary_only() {
        let scope = test_scope();
        assert!(scope.host_allowed("a.example.com"));
        assert!(scope.host_allowed("deep.a.example.com"));
        assert!(!scope.host_allowed("badexample.com"));
        assert!(!scope.host_allowed("example.com.evil.com"));
        assert!(!scope.host_allowed("admin.example.com"));
        assert!(scope.host_allowed("example.com"));
    }

    #[test]
    fn private_ip_blocked_unless_explicit() {
        let scope = test_scope();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!scope.connection_allowed("a.example.com", Some(&loopback)));

        let explicit = Scope::from_lists(
            &["*.example.com".to_string(), "127.0.0.0/8".to_string()],
            &[],
        )
        .unwrap();
        assert!(explicit.connection_allowed("a.example.com", Some(&loopback)));
    }

    #[test]
    fn cidr_matching() {
        let scope = Scope::from_lists(&["203.0.113.0/28".to_string()], &[]).unwrap();
        let inside: IpAddr = "203.0.113.5".parse().unwrap();
        let outside: IpAddr = "203.0.113.200".parse().unwrap();
        assert!(scope.ip_allowed(&inside));
        assert!(!scope.ip_allowed(&outside));
    }

    #[test]
    fn dedup_drops_empty_entries() {
        let out = dedup_hostnames(&[
            "a.example.com".to_string(),
            "".to_string(),
            "  ".to_string(),
        ]);
        assert_eq!(out, vec!["a.example.com".to_string()]);
    }

    #[test]
    fn redirect_hop_checked() {
        let scope = test_scope();
        let mut guard = ScopeGuard::new(scope);
        assert!(!guard.allow_http_hop("https://evil.com/", None));
        assert!(guard.allow_http_hop("https://a.example.com/", None));
        assert!(!guard.blocked().is_empty());
    }

    proptest! {
        #[test]
        fn scope_matching_is_deterministic(host in "[a-z0-9.-]{1,40}") {
            let scope = test_scope();
            let a = scope.host_allowed(&host);
            let b = scope.host_allowed(&host);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn wildcard_never_matches_bare_suffix_trick(s in "[a-z0-9]{1,12}") {
            let scope = test_scope();
            let evil = format!("{}example.com", s);
            if s.is_empty() {
                return Ok(());
            }
            prop_assert!(!scope.host_allowed(&evil) || evil.ends_with(".example.com"));
        }

        #[test]
        fn dedup_is_idempotent(hosts in proptest::collection::vec("[a-z0-9.]{1,20}", 0..30)) {
            let once = dedup_hostnames(&hosts);
            let twice = dedup_hostnames(&once);
            prop_assert_eq!(once, twice);
        }
    }
}
