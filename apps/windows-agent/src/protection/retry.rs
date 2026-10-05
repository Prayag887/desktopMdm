use std::time::{Duration, Instant};

/// Five attempts per outage; a genuinely healthy interval re-arms recovery.
#[derive(Debug, Default)]
pub struct RecoveryBudget {
    attempts: u32,
    next_attempt: Option<Instant>,
    healthy_since: Option<Instant>,
}
impl RecoveryBudget {
    pub fn observe_healthy(&mut self, now: Instant) {
        let since = *self.healthy_since.get_or_insert(now);
        if now.duration_since(since) >= Duration::from_secs(300) {
            *self = Self::default();
        }
    }
    pub fn attempt(&mut self, now: Instant) -> Option<Duration> {
        self.healthy_since = None;
        if self.attempts >= 5 || self.next_attempt.is_some_and(|next| now < next) {
            return None;
        }
        let delay = Duration::from_secs(30 * (1 << self.attempts));
        self.attempts += 1;
        self.next_attempt = Some(now + delay);
        Some(delay)
    }
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.attempts >= 5
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_retries_and_requires_sustained_health() {
        let mut budget = RecoveryBudget::default();
        let mut now = Instant::now();
        for expected in [30, 60, 120, 240, 480] {
            assert_eq!(budget.attempt(now), Some(Duration::from_secs(expected)));
            assert_eq!(budget.attempt(now), None);
            now += Duration::from_secs(expected);
        }
        assert!(budget.exhausted());
        budget.observe_healthy(now);
        assert_eq!(budget.attempt(now + Duration::from_secs(299)), None);
        budget.observe_healthy(now);
        budget.observe_healthy(now + Duration::from_secs(300));
        assert!(budget.attempt(now + Duration::from_secs(300)).is_some());
    }
}
