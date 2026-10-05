//! Port discovery behind `PortProvider`, backed by `sentinelscan-core`
//! (pinned git rev, see workspace Cargo.toml).
//!
//! Dual-guard rule: our `ScopeGuard` approves the (hostname, IP) pair first;
//! only approved IPs are fed to their guard via `allow_ip`, which starts
//! empty. A probe neither guard approved reports `unknown/out_of_scope`
//! without touching the wire.

use sentinelscan_core::scanner::scheduler::scan_ports;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use swiftrecon_scope::ScopeGuard;

/// Default web-oriented port set (PRD Q1 decision).
pub const WEB_PORTS: &[u16] = &[80, 443, 8000, 8080, 8443];

/// One classified port result, with their raw reason preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortFact {
    pub ip: IpAddr,
    pub port: u16,
    pub state: String,
    pub reason: String,
    pub latency_ms: u64,
}

/// Parse `--ports`: `web`, comma lists (`80,443`), ranges (`1-1024`),
/// mixes (`22,80-85,443`). `top100` is deferred (CHANGELOG).
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim().to_lowercase();
    if spec == "web" {
        return Ok(WEB_PORTS.to_vec());
    }
    if spec == "top100" {
        return Err("top100 is deferred; use web or an explicit list/range".to_string());
    }
    let mut ports: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("bad port range: {part}"))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("bad port range: {part}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("bad port range: {part}"));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().map_err(|_| format!("bad port: {part}"))?;
            if port == 0 {
                return Err(format!("bad port: {part}"));
            }
            ports.push(port);
        }
    }
    if ports.is_empty() {
        return Err("no ports selected".to_string());
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Group hostnames by resolved IP so each IP is scanned once.
pub fn dedup_ips(pairs: &[(String, IpAddr)]) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (_, ip) in pairs {
        if seen.insert(*ip) {
            out.push(*ip);
        }
    }
    out.sort();
    out
}

/// Port backend: wraps their proven scheduler. Construct per scan from our
/// limits; the guard bridge authorizes only IPs our guard approved.
pub struct SentinelPorts {
    max_concurrency: usize,
    max_rate: u64,
    connect_timeout: Duration,
}

impl SentinelPorts {
    pub fn new(max_concurrency: usize, max_rate: u64, connect_timeout: Duration) -> Self {
        Self {
            max_concurrency: max_concurrency.max(1),
            max_rate: max_rate.max(1),
            connect_timeout,
        }
    }

    /// Scan one approved (hostname, IP) pair. Returns `None` without sending
    /// any packet when our guard rejects the pair.
    pub async fn scan_approved(
        &self,
        guard: &ScopeGuard,
        host: &str,
        ip: IpAddr,
        ports: &[u16],
    ) -> Option<Vec<PortFact>> {
        if !guard.allow_connection(host, Some(&ip)) {
            return None;
        }
        let mut their_guard = sentinelscan_core::safety::scope::ScopeGuard::default();
        their_guard.allow_ip(&ip);
        let limits = sentinelscan_core::config::Limits {
            max_concurrency: self.max_concurrency,
            max_rate: self.max_rate,
            connect_timeout_ms: self.connect_timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            ..Default::default()
        };
        let rate = Arc::new(sentinelscan_core::scanner::rate_limit::RateLimiter::new(
            self.max_rate,
        ));
        let skip = HashSet::new();
        let result = scan_ports(&[ip], ports, &limits, &their_guard, rate, &skip).await;
        Some(
            result
                .probes
                .into_iter()
                .map(|probe| PortFact {
                    ip: probe.ip,
                    port: probe.port,
                    state: probe.outcome.state.to_string(),
                    reason: probe.outcome.reason.to_string(),
                    latency_ms: probe.outcome.latency_ms,
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swiftrecon_scope::Scope;

    fn local_guard() -> ScopeGuard {
        ScopeGuard::new(Scope::from_lists(&["127.0.0.1".to_string()], &[]).unwrap())
    }

    #[test]
    fn port_specs_parse() {
        assert_eq!(parse_ports("web").unwrap(), vec![80, 443, 8000, 8080, 8443]);
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports("22,80-82").unwrap(), vec![22, 80, 81, 82]);
        assert_eq!(parse_ports("443,80,443").unwrap(), vec![80, 443]);
        assert!(parse_ports("top100").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("99-10").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn ips_dedup_to_one_scan_each() {
        let pairs = vec![
            ("a.test".to_string(), "127.0.0.1".parse().unwrap()),
            ("b.test".to_string(), "127.0.0.1".parse().unwrap()),
            ("c.test".to_string(), "127.0.0.2".parse().unwrap()),
        ];
        let ips = dedup_ips(&pairs);
        assert_eq!(ips.len(), 2);
    }

    #[tokio::test]
    async fn rejected_pair_sends_no_packet() {
        let backend = SentinelPorts::new(10, 100, Duration::from_secs(2));
        let guard = local_guard();
        let other: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(backend
            .scan_approved(&guard, "other.test", other, &[80])
            .await
            .is_none());
    }

    #[tokio::test]
    async fn closed_loopback_port_is_classified() {
        // Port 0 can never be open; asserts classification, not a state.
        let backend = SentinelPorts::new(10, 100, Duration::from_secs(2));
        let guard = local_guard();
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        let facts = backend
            .scan_approved(&guard, "127.0.0.1", localhost, &[0])
            .await
            .expect("loopback is in scope");
        assert_eq!(facts.len(), 1);
        assert_ne!(facts[0].state, "open");
        assert!(!facts[0].reason.is_empty());
    }
}
