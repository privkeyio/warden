#![forbid(unsafe_code)]

use rand::Rng;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    Timeout,
    RateLimited,
    Transient,
    Unauthorized,
    InvalidArgument,
    NotFound,
    Permanent,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RetryDecision {
    Retry { after: Duration },
    Abort,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub initial_interval: Duration,
    pub backoff_coefficient: f64,
    pub maximum_interval: Duration,
    pub maximum_attempts: u32,
    pub jitter_percent: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_interval: Duration::from_secs(1),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(60),
            maximum_attempts: 3,
            jitter_percent: 0.2,
        }
    }
}

impl RetryPolicy {
    pub fn next_backoff(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.maximum_attempts {
            return None;
        }

        let base =
            self.initial_interval.as_secs_f64() * self.backoff_coefficient.powi(attempt as i32);
        let capped = base.min(self.maximum_interval.as_secs_f64());

        let jittered = self.apply_jitter(capped);
        Some(Duration::from_secs_f64(jittered.max(0.0)))
    }

    fn apply_jitter(&self, value: f64) -> f64 {
        if self.jitter_percent <= 0.0 {
            return value;
        }
        let random: f64 = rand::thread_rng().gen();
        value * (1.0 - self.jitter_percent * (1.0 - random))
    }

    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        self.next_backoff(attempt.saturating_sub(1))
            .unwrap_or(self.maximum_interval)
    }

    pub fn with_jitter(mut self, percent: f64) -> Self {
        self.jitter_percent = percent.clamp(0.0, 1.0);
        self
    }

    pub fn aggressive() -> Self {
        Self {
            initial_interval: Duration::from_millis(100),
            backoff_coefficient: 1.5,
            maximum_interval: Duration::from_secs(5),
            maximum_attempts: 5,
            jitter_percent: 0.2,
        }
    }

    pub fn throttle() -> Self {
        Self {
            initial_interval: Duration::from_secs(1),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(30),
            maximum_attempts: 10,
            jitter_percent: 0.2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TieredRetryPolicy {
    pub standard: RetryPolicy,
    pub throttle: RetryPolicy,
    pub non_retryable_errors: Vec<ErrorKind>,
}

impl Default for TieredRetryPolicy {
    fn default() -> Self {
        Self {
            standard: RetryPolicy::default(),
            throttle: RetryPolicy::throttle(),
            non_retryable_errors: vec![
                ErrorKind::Unauthorized,
                ErrorKind::InvalidArgument,
                ErrorKind::NotFound,
                ErrorKind::Permanent,
            ],
        }
    }
}

impl TieredRetryPolicy {
    pub fn should_retry(&self, error_kind: ErrorKind, attempt: u32) -> RetryDecision {
        if self.non_retryable_errors.contains(&error_kind) {
            return RetryDecision::Abort;
        }

        let policy = if error_kind == ErrorKind::RateLimited {
            &self.throttle
        } else {
            &self.standard
        };

        match policy.next_backoff(attempt) {
            Some(delay) => RetryDecision::Retry { after: delay },
            None => RetryDecision::Abort,
        }
    }

    pub fn with_standard(mut self, policy: RetryPolicy) -> Self {
        self.standard = policy;
        self
    }

    pub fn with_throttle(mut self, policy: RetryPolicy) -> Self {
        self.throttle = policy;
        self
    }

    pub fn with_non_retryable(mut self, errors: Vec<ErrorKind>) -> Self {
        self.non_retryable_errors = errors;
        self
    }
}

pub trait ClassifyError {
    fn error_kind(&self) -> ErrorKind;

    fn is_retryable(&self) -> bool {
        !matches!(
            self.error_kind(),
            ErrorKind::Unauthorized
                | ErrorKind::InvalidArgument
                | ErrorKind::NotFound
                | ErrorKind::Permanent
        )
    }
}

impl TieredRetryPolicy {
    pub async fn execute<T, E, F, Fut>(&self, mut operation: F) -> Result<T, E>
    where
        E: ClassifyError,
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let mut attempt = 0u32;
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => match self.should_retry(e.error_kind(), attempt) {
                    RetryDecision::Retry { after } => {
                        attempt += 1;
                        tokio::time::sleep(after).await;
                    }
                    RetryDecision::Abort => return Err(e),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.maximum_attempts, 3);
        assert!((policy.jitter_percent - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_next_backoff_exponential() {
        let policy = RetryPolicy {
            initial_interval: Duration::from_secs(1),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(60),
            maximum_attempts: 5,
            jitter_percent: 0.0,
        };

        let b0 = policy.next_backoff(0).unwrap();
        assert_eq!(b0, Duration::from_secs(1));

        let b1 = policy.next_backoff(1).unwrap();
        assert_eq!(b1, Duration::from_secs(2));

        let b2 = policy.next_backoff(2).unwrap();
        assert_eq!(b2, Duration::from_secs(4));
    }

    #[test]
    fn test_next_backoff_capped() {
        let policy = RetryPolicy {
            initial_interval: Duration::from_secs(10),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(30),
            maximum_attempts: 10,
            jitter_percent: 0.0,
        };

        let b3 = policy.next_backoff(3).unwrap();
        assert_eq!(b3, Duration::from_secs(30));
    }

    #[test]
    fn test_next_backoff_exhausted() {
        let policy = RetryPolicy {
            maximum_attempts: 3,
            ..Default::default()
        };

        assert!(policy.next_backoff(3).is_none());
        assert!(policy.next_backoff(4).is_none());
    }

    #[test]
    fn test_jitter_within_bounds() {
        let policy = RetryPolicy {
            initial_interval: Duration::from_secs(10),
            backoff_coefficient: 1.0,
            maximum_interval: Duration::from_secs(60),
            maximum_attempts: 5,
            jitter_percent: 0.2,
        };

        for _ in 0..100 {
            let delay = policy.next_backoff(0).unwrap();
            let secs = delay.as_secs_f64();
            assert!(secs >= 8.0 && secs <= 10.0, "delay was {}", secs);
        }
    }

    #[test]
    fn test_tiered_policy_non_retryable() {
        let policy = TieredRetryPolicy::default();

        assert_eq!(
            policy.should_retry(ErrorKind::Unauthorized, 0),
            RetryDecision::Abort
        );
        assert_eq!(
            policy.should_retry(ErrorKind::InvalidArgument, 0),
            RetryDecision::Abort
        );
        assert_eq!(
            policy.should_retry(ErrorKind::NotFound, 0),
            RetryDecision::Abort
        );
    }

    #[test]
    fn test_tiered_policy_transient() {
        let policy = TieredRetryPolicy::default();
        let decision = policy.should_retry(ErrorKind::Transient, 0);
        assert!(matches!(decision, RetryDecision::Retry { .. }));
    }

    #[test]
    fn test_tiered_policy_rate_limited_uses_throttle() {
        let policy = TieredRetryPolicy {
            standard: RetryPolicy {
                initial_interval: Duration::from_millis(100),
                jitter_percent: 0.0,
                ..Default::default()
            },
            throttle: RetryPolicy {
                initial_interval: Duration::from_secs(5),
                jitter_percent: 0.0,
                ..Default::default()
            },
            ..Default::default()
        };

        match policy.should_retry(ErrorKind::RateLimited, 0) {
            RetryDecision::Retry { after } => {
                assert_eq!(after, Duration::from_secs(5));
            }
            RetryDecision::Abort => panic!("expected retry"),
        }
    }

    #[test]
    fn test_delay_for_attempt() {
        let policy = RetryPolicy {
            initial_interval: Duration::from_secs(1),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(60),
            maximum_attempts: 5,
            jitter_percent: 0.0,
        };

        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(4));
    }
}
