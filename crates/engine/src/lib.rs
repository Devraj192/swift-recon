//! Scheduler skeleton: bounded channels, global/per-host limits,
//! retries with jittered backoff, timeouts, cancellation, pause/resume.
//!
//! Phase 1 only: the DAG, channels, and limiters. Actual discovery stages
//! arrive in later phases. Port scanning plugs in here behind the
//! `ports::SentinelPorts` adapter over `sentinelscan-core`.

use backon::{ExponentialBuilder, Retryable};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::warn;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_concurrency: usize,
    pub global_rate_per_sec: u32,
    pub per_host_rate_per_sec: u32,
    pub op_timeout: Duration,
    pub channel_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrency: 200,
            global_rate_per_sec: 300,
            per_host_rate_per_sec: 5,
            op_timeout: Duration::from_secs(30),
            channel_capacity: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub mod adaptive;
pub mod ports;

pub use adaptive::AdaptiveLimiter;

pub use ports::{dedup_ips, parse_ports, PortFact, SentinelPorts, WEB_PORTS};

pub struct Scheduler {
    limits: Limits,
    semaphore: Arc<Semaphore>,
    global_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
    cancel: CancellationToken,
}

impl Scheduler {
    pub fn new(limits: Limits) -> Self {
        let permits = limits.max_concurrency.max(1);
        let rate = NonZeroU32::new(limits.global_rate_per_sec.max(1))
            .unwrap_or(NonZeroU32::new(1).expect("1 is non-zero"));
        Self {
            limits,
            semaphore: Arc::new(Semaphore::new(permits)),
            global_limiter: Arc::new(RateLimiter::direct(Quota::per_second(rate))),
            cancel: CancellationToken::new(),
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Bounded channel for stage events. Slow stages apply backpressure.
    pub fn channel<T>(&self) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
        mpsc::channel(self.limits.channel_capacity.max(1))
    }

    /// Run one work unit with global rate limit, concurrency cap, timeout,
    /// and cooperative cancellation (checked at unit start; in-flight work
    /// is bounded by the op timeout). Retries transient failures with
    /// jittered backoff.
    pub async fn run_unit<F, Fut>(&self, work: F) -> Result<(), EngineError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<(), EngineError>>,
    {
        if self.is_cancelled() {
            return Err(EngineError::Shutdown);
        }
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| EngineError::Shutdown)?;
        self.global_limiter.until_ready().await;
        let result = tokio::time::timeout(self.limits.op_timeout, async {
            (work).retry(ExponentialBuilder::default()).await
        })
        .await;
        drop(permit);
        match result {
            Err(_) => {
                warn!("work unit timed out");
                Err(EngineError::Timeout)
            }
            Ok(inner) => inner.map_err(|e| {
                warn!("work unit failed after retries");
                e
            }),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("scheduler is shut down")]
    Shutdown,
    #[error("work unit timed out")]
    Timeout,
    #[error("transient failure: {0}")]
    Transient(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_channel_applies_backpressure() {
        let sched = Scheduler::new(Limits {
            channel_capacity: 2,
            ..Default::default()
        });
        let (tx, mut rx) = sched.channel::<u32>();
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        assert!(tx.try_send(3).is_err());
        assert_eq!(rx.recv().await, Some(1));
    }

    #[tokio::test]
    async fn run_unit_respects_cancellation_token() {
        let sched = Scheduler::new(Limits::default());
        assert!(!sched.is_cancelled());
        sched.shutdown();
        assert!(sched.is_cancelled());
    }

    #[tokio::test]
    async fn run_unit_refuses_work_after_shutdown() {
        let sched = Scheduler::new(Limits::default());
        sched.shutdown();
        let out = sched.run_unit(|| async { Ok(()) }).await;
        assert!(matches!(out, Err(EngineError::Shutdown)));
    }

    #[tokio::test]
    async fn run_unit_times_out() {
        let sched = Scheduler::new(Limits {
            op_timeout: Duration::from_millis(50),
            ..Default::default()
        });
        let out = sched
            .run_unit(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            })
            .await;
        assert!(matches!(out, Err(EngineError::Timeout)));
    }
}
