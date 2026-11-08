//! Per-client-IP failure window for password and API-token checks.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub const LOGIN_FAILURE_DELAY: Duration = Duration::from_millis(500);
pub const LOCKOUT_FAILURES: u32 = 5;
pub const LOCKOUT_WINDOW: Duration = Duration::from_secs(15 * 60);

pub struct Tracker {
    inner: Mutex<HashMap<IpAddr, Failures>>,
}

#[derive(Default)]
struct Failures {
    attempts: Vec<Instant>,
}

impl Failures {
    fn prune(&mut self, now: Instant) {
        self.attempts
            .retain(|at| now.saturating_duration_since(*at) < LOCKOUT_WINDOW);
    }

    fn retry_after(&self, now: Instant) -> Option<Duration> {
        if self.attempts.len() < LOCKOUT_FAILURES as usize {
            return None;
        }
        let oldest = *self.attempts.iter().min()?;
        let remaining = LOCKOUT_WINDOW.saturating_sub(now.saturating_duration_since(oldest));
        Some(remaining.max(Duration::from_millis(1)))
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// `Err(retry_after)` once this address has failed too often in the window.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut guard = self.inner.lock();
        let Some(failures) = guard.get_mut(&ip) else {
            return Ok(());
        };
        failures.prune(now);
        if let Some(retry_after) = failures.retry_after(now) {
            return Err(retry_after);
        }
        if failures.attempts.is_empty() {
            guard.remove(&ip);
        }
        Ok(())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        self.record_at(ip, Instant::now());
    }

    fn record_at(&self, ip: IpAddr, now: Instant) {
        let mut guard = self.inner.lock();
        let failures = guard.entry(ip).or_default();
        failures.prune(now);
        failures.attempts.push(now);
    }

    pub fn clear(&self, ip: IpAddr) {
        self.inner.lock().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn five_failures_lock_until_cleared() {
        let tracker = Tracker::new();
        let client = ip(1);
        for _ in 0..4 {
            tracker.record_failure(client);
            assert!(tracker.check(client).is_ok());
        }
        tracker.record_failure(client);

        let retry_after = tracker.check(client).unwrap_err();
        assert!(retry_after > Duration::ZERO);
        assert!(retry_after <= LOCKOUT_WINDOW);

        tracker.clear(client);
        assert!(tracker.check(client).is_ok());
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let tracker = Tracker::new();
        let client = ip(2);
        let start = Instant::now();
        for offset in 0..LOCKOUT_FAILURES {
            tracker.record_at(client, start + Duration::from_secs(u64::from(offset)));
        }
        assert!(tracker.check_at(client, start).is_err());

        let aged_out = start + LOCKOUT_WINDOW;
        assert!(tracker.check_at(client, aged_out).is_ok());
        assert!(tracker.check_at(ip(3), start).is_ok());
    }
}
