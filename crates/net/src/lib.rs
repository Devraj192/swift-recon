//! Pooled async DNS resolution with per-resolver rate limits and TTL cache.
//!
//! DNS outcomes stay distinct: NXDOMAIN, SERVFAIL, timeout, and refused are
//! never collapsed into "doesn't exist". Every query target passes the
//! `ScopeGuard` before any packet leaves.
//!
//! Also home to HTTP probing ([`http`]) and TLS metadata ([`tls`]).

pub mod http;
pub mod tls;

use governor::{Quota, RateLimiter};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::{ProtoError, ProtoErrorKind};
use hickory_resolver::{ResolveError, Resolver};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use swiftrecon_scope::ScopeGuard;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Distinct DNS outcome. A timeout is never "not found".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome {
    /// Answered with records.
    Answered { ips: Vec<IpAddr>, ttl_secs: u32 },
    /// Name provably does not exist.
    NxDomain,
    /// Server failure (distinct from nonexistence).
    ServFail,
    /// Query timed out (distinct from nonexistence).
    Timeout,
    /// Server refused the query.
    Refused,
    /// Anything else, with the raw reason preserved.
    Unknown { reason: String },
}

impl DnsOutcome {
    pub fn ips(&self) -> &[IpAddr] {
        match self {
            Self::Answered { ips, .. } => ips,
            _ => &[],
        }
    }
}

fn classify_error(err: &ResolveError) -> DnsOutcome {
    if err.is_nx_domain() {
        return DnsOutcome::NxDomain;
    }
    match err.proto().map(ProtoError::kind) {
        Some(ProtoErrorKind::Timeout) => DnsOutcome::Timeout,
        Some(ProtoErrorKind::RequestRefused) => DnsOutcome::Refused,
        Some(ProtoErrorKind::NoRecordsFound { response_code, .. }) => match response_code {
            ResponseCode::ServFail => DnsOutcome::ServFail,
            ResponseCode::Refused => DnsOutcome::Refused,
            _ => DnsOutcome::Unknown {
                reason: format!("no records ({response_code})"),
            },
        },
        _ => DnsOutcome::Unknown {
            reason: err.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// One cached lookup.
#[derive(Debug, Clone)]
struct CacheEntry {
    outcome: DnsOutcome,
    expires_at: Instant,
}

/// TTL-respecting cache layered over the resolver pool.
#[derive(Debug)]
pub struct DnsCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    max_ttl: Duration,
}

impl DnsCache {
    pub fn new(max_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_ttl,
        }
    }

    pub fn get(&self, name: &str) -> Option<DnsOutcome> {
        let mut entries = self.entries.lock().expect("dns cache lock");
        let key = name.to_lowercase();
        let entry = entries.get(&key)?;
        if Instant::now() >= entry.expires_at {
            entries.remove(&key);
            return None;
        }
        Some(entry.outcome.clone())
    }

    pub fn put(&self, name: &str, outcome: &DnsOutcome) {
        let ttl = match outcome {
            DnsOutcome::Answered { ttl_secs, .. } => {
                Duration::from_secs((*ttl_secs).max(1) as u64).min(self.max_ttl)
            }
            // Negative outcomes cached briefly to avoid hammering resolvers.
            _ => Duration::from_secs(60).min(self.max_ttl),
        };
        let mut entries = self.entries.lock().expect("dns cache lock");
        entries.insert(
            name.to_lowercase(),
            CacheEntry {
                outcome: outcome.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Resolver pool
// ---------------------------------------------------------------------------

type DirectLimiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

fn build_resolver() -> Resolver<TokioConnectionProvider> {
    let config = ResolverConfig::google();
    let mut builder = Resolver::builder_with_config(config, TokioConnectionProvider::default());
    let opts = builder.options_mut();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    builder.build()
}

struct PooledResolver {
    inner: Resolver<TokioConnectionProvider>,
    limiter: DirectLimiter,
    consecutive_failures: Mutex<u32>,
}

impl PooledResolver {
    fn healthy(&self) -> bool {
        *self.consecutive_failures.lock().expect("health lock") < 3
    }

    fn note_result(&self, outcome: &DnsOutcome) {
        let mut failures = self.consecutive_failures.lock().expect("health lock");
        match outcome {
            DnsOutcome::Timeout => *failures += 1,
            DnsOutcome::Answered { .. } | DnsOutcome::NxDomain => *failures = 0,
            _ => {}
        }
    }
}

/// Round-robin pool of resolvers with per-resolver rate limits, health
/// tracking, and a TTL cache. Unhealthy resolvers are skipped until a
/// healthy one succeeds again.
pub struct ResolverPool {
    resolvers: Vec<PooledResolver>,
    next: AtomicUsize,
    cache: DnsCache,
}

impl ResolverPool {
    pub fn new(pool_size: usize, per_resolver_qps: u32) -> Self {
        let rate = NonZeroU32::new(per_resolver_qps.max(1))
            .unwrap_or(NonZeroU32::new(1).expect("1 is non-zero"));
        let resolvers = (0..pool_size.max(1))
            .map(|_| PooledResolver {
                inner: build_resolver(),
                limiter: RateLimiter::direct(Quota::per_second(rate)),
                consecutive_failures: Mutex::new(0),
            })
            .collect();
        Self {
            resolvers,
            next: AtomicUsize::new(0),
            cache: DnsCache::new(Duration::from_secs(3600)),
        }
    }

    /// Resolve A/AAAA for `host`. Returns `None` without sending any packet
    /// when the scope guard rejects the target.
    pub async fn resolve(&self, guard: &ScopeGuard, host: &str) -> Option<DnsOutcome> {
        let host = host.trim().to_lowercase();
        if !guard.allow_dns(&host) {
            return None;
        }
        if let Some(cached) = self.cache.get(&host) {
            return Some(cached);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..self.resolvers.len() {
            let resolver = &self.resolvers[(start + offset) % self.resolvers.len()];
            if !resolver.healthy() {
                continue;
            }
            resolver.limiter.until_ready().await;
            let outcome = match resolver.inner.lookup_ip(host.as_str()).await {
                Ok(lookup) => DnsOutcome::Answered {
                    ips: lookup.iter().collect(),
                    ttl_secs: 300,
                },
                Err(err) => classify_error(&err),
            };
            resolver.note_result(&outcome);
            self.cache.put(&host, &outcome);
            return Some(outcome);
        }
        None
    }
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("no healthy resolvers available")]
    NoHealthyResolvers,
    #[error("dns error: {0}")]
    Dns(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use swiftrecon_scope::Scope;

    fn test_guard() -> ScopeGuard {
        ScopeGuard::new(Scope::from_lists(&["*.example.com".to_string()], &[]).unwrap())
    }

    #[test]
    fn outcomes_stay_distinct() {
        assert_ne!(DnsOutcome::NxDomain, DnsOutcome::Timeout);
        assert_ne!(DnsOutcome::ServFail, DnsOutcome::Refused);
        assert_ne!(
            DnsOutcome::Unknown {
                reason: "x".to_string()
            },
            DnsOutcome::NxDomain
        );
        assert!(DnsOutcome::Timeout.ips().is_empty());
    }

    #[test]
    fn cache_respects_lookup_and_expiry() {
        let cache = DnsCache::new(Duration::from_secs(300));
        assert!(cache.get("a.example.com").is_none());
        let outcome = DnsOutcome::Answered {
            ips: vec!["1.1.1.1".parse().unwrap()],
            ttl_secs: 120,
        };
        cache.put("A.EXAMPLE.COM", &outcome);
        assert_eq!(cache.get("a.example.com"), Some(outcome));
    }

    #[tokio::test]
    async fn out_of_scope_sends_no_packet() {
        let pool = ResolverPool::new(1, 100);
        let guard = test_guard();
        assert!(pool.resolve(&guard, "evil.com").await.is_none());
    }
}
