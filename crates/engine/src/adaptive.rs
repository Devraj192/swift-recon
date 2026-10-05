//! Adaptive concurrency (AIMD): back off when timeouts, 429s, or 5xx rise;
//! recover gradually on success. Callers `pause()` before each request and
//! report the outcome. Pure timing logic, unit-tested without network.

use std::sync::Mutex;
use std::time::Duration;

const MAX_SHIFT: u32 = 6;
const RECOVER_EVERY_SUCCESSES: u32 = 20;

#[derive(Debug)]
struct State {
    failures: u32,
    successes_since_recovery: u32,
}

/// Adaptive politeness delay shared across a stage's requests.
#[derive(Debug)]
pub struct AdaptiveLimiter {
    base: Duration,
    state: Mutex<State>,
}

impl AdaptiveLimiter {
    pub fn new(base: Duration) -> Self {
        Self {
            base,
            state: Mutex::new(State {
                failures: 0,
                successes_since_recovery: 0,
            }),
        }
    }

    /// Current extra delay (zero when healthy). Exposed for tests and logs.
    pub fn delay(&self) -> Duration {
        let state = self.state.lock().expect("limiter lock");
        self.base
            .checked_mul(1 << state.failures.min(MAX_SHIFT))
            .unwrap_or(Duration::from_secs(60))
            .saturating_sub(self.base)
    }

    /// Wait the adaptive delay before sending a request.
    pub async fn pause(&self) {
        let delay = self.delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    /// Report a failed request (timeout, 429, or 5xx).
    pub fn note_failure(&self) {
        let mut state = self.state.lock().expect("limiter lock");
        state.failures = state.failures.saturating_add(1).min(MAX_SHIFT + 1);
        state.successes_since_recovery = 0;
    }

    /// Report a successful request. Recovery is gradual.
    pub fn note_success(&self) {
        let mut state = self.state.lock().expect("limiter lock");
        state.successes_since_recovery += 1;
        if state.successes_since_recovery >= RECOVER_EVERY_SUCCESSES {
            state.successes_since_recovery = 0;
            state.failures = state.failures.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_recovers() {
        let limiter = AdaptiveLimiter::new(Duration::from_millis(100));
        assert_eq!(limiter.delay(), Duration::ZERO);
        limiter.note_failure();
        assert_eq!(limiter.delay(), Duration::from_millis(100));
        limiter.note_failure();
        assert_eq!(limiter.delay(), Duration::from_millis(300));
        for _ in 0..RECOVER_EVERY_SUCCESSES {
            limiter.note_success();
        }
        assert_eq!(limiter.delay(), Duration::from_millis(100));
    }

    #[test]
    fn delay_is_capped() {
        let limiter = AdaptiveLimiter::new(Duration::from_millis(100));
        for _ in 0..20 {
            limiter.note_failure();
        }
        assert!(limiter.delay() <= Duration::from_secs(60));
    }
}
