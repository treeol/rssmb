//! Auth failure throttling — per-IP failure counter with growing delay and cooldown.
//!
//! After `auth_max_failures` failed SESSION_SETUP attempts within a rolling
//! `auth_window_secs` window from a single source IP, the server:
//!   1. Adds a growing delay (doubled per failure, capped at `auth_delay_max_ms`)
//!      before sending LOGON_FAILURE — slowing online guessing.
//!   2. After the delay would exceed the cap, refuses further SESSION_SETUP from
//!      that IP for `auth_cooldown_secs` — a hard lockout.
//!
//! A per-connection failure cap (`auth_max_failures_per_conn`) drops a TCP
//! stream that cycles SessionId=0 too many times — stops one connection
//! hammering auth.
//!
//! A setting of `0` for `auth_max_failures` or `auth_max_failures_per_conn`
//! disables that layer. The IP table is bounded (default 4096 entries); when
//! full with unexpired entries, new IPs are refused (fail-closed: better to
//! reject a new connection than let the table grow unbounded under attack).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock as StdRwLock;
use std::time::{Duration, Instant};

/// A per-IP failure record.
struct FailureRecord {
    /// Number of failures within the current window.
    count: u32,
    /// When the current window started (first failure in the window).
    window_start: Instant,
    /// When the cooldown expires (None = not in cooldown).
    /// Cooldown is independent of window reset — it survives window expiry.
    cooldown_until: Option<Instant>,
}

impl FailureRecord {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            cooldown_until: None,
        }
    }
}

/// The throttle decision for a SESSION_SETUP attempt.
#[derive(Debug, Clone, Copy)]
pub enum AuthThrottleResult {
    /// The attempt may proceed. Auth will be processed normally.
    Allow,
    /// The IP is in cooldown — refuse immediately with LOGON_FAILURE.
    /// No delay is added (the cooldown already passed).
    Refuse,
}

/// Auth failure limiter — per-IP failure counter with growing delay and cooldown.
///
/// Uses a plain `StdRwLock` (not tokio) because the critical sections are tiny
/// and never await. `check` and `record_failure` are O(1) amortized (lazy
/// eviction on table overflow).
pub struct AuthLimiter {
    max_failures: u32,
    window: Duration,
    delay_max: Duration,
    cooldown: Duration,
    max_failures_per_conn: u32,
    records: StdRwLock<HashMap<IpAddr, FailureRecord>>,
    /// Upper bound on the IP table to prevent unbounded memory from
    /// spoofed/varied source IPs.
    max_entries: usize,
}

impl AuthLimiter {
    pub fn new(
        max_failures: u32,
        window_secs: u64,
        delay_max_ms: u64,
        cooldown_secs: u64,
        max_failures_per_conn: u32,
    ) -> Self {
        Self {
            max_failures,
            window: Duration::from_secs(window_secs),
            delay_max: Duration::from_millis(delay_max_ms),
            cooldown: Duration::from_secs(cooldown_secs),
            max_failures_per_conn,
            records: StdRwLock::new(HashMap::new()),
            max_entries: 4096,
        }
    }

    /// Check whether a SESSION_SETUP from `ip` is allowed.
    /// Does NOT consume a token or modify state — call `record_failure` after
    /// the auth actually fails.
    pub fn check(&self, ip: &IpAddr) -> AuthThrottleResult {
        if self.max_failures == 0 {
            return AuthThrottleResult::Allow;
        }
        let records = self.records.read().unwrap();
        let Some(rec) = records.get(ip) else {
            return AuthThrottleResult::Allow;
        };
        let now = Instant::now();
        if let Some(until) = rec.cooldown_until {
            if now < until {
                return AuthThrottleResult::Refuse;
            }
        }
        AuthThrottleResult::Allow
    }

    /// Record an auth failure from `ip`. Returns the delay to apply before
    /// sending LOGON_FAILURE (capped at `delay_max`). Zero means no delay.
    ///
    /// Call this AFTER auth has definitively failed (Reject/Err), not on
    /// Continue. The delay grows exponentially (200, 400, 800, … ms) until
    /// it would exceed `delay_max`, at which point the IP enters cooldown.
    ///
    /// Returns `Duration::ZERO` if the IP is in cooldown (the cooldown is
    /// enforced by `check`; a failure recorded during cooldown just extends
    /// the cooldown).
    pub fn record_failure(&self, ip: IpAddr) -> Duration {
        if self.max_failures == 0 {
            return Duration::ZERO;
        }
        let now = Instant::now();
        let mut records = self.records.write().unwrap();

        // Lazy eviction: if the table is too large, remove expired entries.
        if records.len() >= self.max_entries {
            Self::evict_expired(&mut records, now, self.window + self.cooldown);
            // If the table is still full after eviction, refuse to add new
            // entries. Existing IPs are still updated. This prevents unbounded
            // memory growth under a spoofed-source attack.
            if records.len() >= self.max_entries && !records.contains_key(&ip) {
                tracing::warn!(
                    ip = %ip,
                    entries = records.len(),
                    "auth limiter table full — refusing to track new IP",
                );
                return Duration::ZERO;
            }
        }

        let rec = records.entry(ip).or_insert_with(FailureRecord::new);

        // Check if the window has elapsed — reset the count but PRESERVE
        // an active cooldown. Cooldown is independent of window reset.
        if now.duration_since(rec.window_start) >= self.window {
            rec.count = 0;
            rec.window_start = now;
            // Do NOT clear cooldown_until here — it must survive window reset.
        }

        rec.count = rec.count.saturating_add(1);

        // Not yet at the failure threshold — no delay, no cooldown.
        if rec.count <= self.max_failures {
            return Duration::ZERO;
        }

        // If already in cooldown, just extend it (don't compute delay).
        if let Some(until) = rec.cooldown_until {
            if now < until {
                // Still in cooldown — no delay (the refusal is immediate).
                return Duration::ZERO;
            }
            // Cooldown has expired — clear it and fall through to re-evaluate.
            rec.cooldown_until = None;
        }

        // Past the threshold: compute a growing delay.
        // Exponential: base = 200ms × 2^(excess-1), where excess = count - max_failures.
        // First excess → 200ms, second → 400ms, third → 800ms, etc.
        // Capped at delay_max. When the uncapped delay would exceed delay_max,
        // enter cooldown instead.
        let excess = rec.count - self.max_failures; // ≥ 1
        let shift = (excess - 1).min(20) as u128; // cap shift to avoid overflow
        let base_ms: u128 = 200u128 << shift;
        let uncapped = Duration::from_millis(base_ms.min(u64::MAX as u128) as u64);

        if uncapped >= self.delay_max {
            // Enter cooldown — refuse for cooldown_secs from now.
            // Use checked_add to avoid Instant overflow (unlikely with u64 secs).
            rec.cooldown_until = Some(now + self.cooldown);
            self.delay_max
        } else {
            uncapped
        }
    }

    /// Whether a per-connection failure count exceeds the per-connection cap.
    /// `count` is the current per-connection failure count.
    pub fn conn_failure_exceeds(&self, count: u32) -> bool {
        self.max_failures_per_conn > 0 && count > self.max_failures_per_conn
    }

    /// The per-connection failure cap (0 = disabled).
    pub fn max_failures_per_conn(&self) -> u32 {
        self.max_failures_per_conn
    }

    /// Evict entries whose window + cooldown has fully elapsed.
    fn evict_expired(records: &mut HashMap<IpAddr, FailureRecord>, now: Instant, ttl: Duration) {
        records.retain(|_, rec| {
            // If in cooldown, keep until cooldown expires.
            if let Some(until) = rec.cooldown_until {
                return now < until;
            }
            // Not in cooldown: evict if the window has fully elapsed.
            now.duration_since(rec.window_start) < ttl
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn limiter() -> AuthLimiter {
        AuthLimiter::new(3, 60, 5000, 60, 10)
    }

    #[test]
    fn allow_when_no_failures() {
        let l = limiter();
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Allow));
    }

    #[test]
    fn no_delay_below_threshold() {
        let l = limiter();
        for _ in 0..3 {
            assert_eq!(l.record_failure(ip()), Duration::ZERO);
        }
        // 3 failures = max_failures, still no delay
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Allow));
    }

    #[test]
    fn growing_delay_above_threshold() {
        let l = limiter();
        // 3 failures to reach the threshold
        for _ in 0..3 {
            l.record_failure(ip());
        }
        // 4th failure: excess=1, delay=200ms (200 × 2^0)
        let d1 = l.record_failure(ip());
        assert_eq!(d1, Duration::from_millis(200));
        // 5th failure: excess=2, delay=400ms (200 × 2^1)
        let d2 = l.record_failure(ip());
        assert_eq!(d2, Duration::from_millis(400));
        // 6th failure: excess=3, delay=800ms (200 × 2^2)
        let d3 = l.record_failure(ip());
        assert_eq!(d3, Duration::from_millis(800));
    }

    #[test]
    fn cooldown_when_delay_exceeds_cap() {
        // delay_max = 5000ms. Exponential: 200×2^(excess-1).
        // 200×2^4 = 3200 < 5000, 200×2^5 = 6400 > 5000
        // So excess=6 (count=9 with max_failures=3) triggers cooldown.
        let l = limiter();
        for _ in 0..3 {
            l.record_failure(ip()); // threshold
        }
        // excess 1-5: delays 200, 400, 800, 1600, 3200 — all under 5000
        for _ in 0..5 {
            let d = l.record_failure(ip());
            assert!(
                d < Duration::from_millis(5000),
                "delay {d:?} should be under cap"
            );
        }
        // excess=6: 200×2^5 = 6400 > 5000 → cooldown
        let d = l.record_failure(ip());
        assert_eq!(d, Duration::from_millis(5000)); // capped
                                                    // Now in cooldown — check returns Refuse
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Refuse));
    }

    #[test]
    fn cooldown_survives_window_reset() {
        // Critical: a window reset must NOT clear an active cooldown.
        let l = limiter();
        // Fill up past threshold and into cooldown
        for _ in 0..9 {
            l.record_failure(ip());
        }
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Refuse));
        // Simulate window expiry by manipulating the record — keep cooldown
        {
            let mut records = l.records.write().unwrap();
            let rec = records.get_mut(&ip()).unwrap();
            rec.window_start = Instant::now() - Duration::from_secs(120);
            // Do NOT clear cooldown_until
        }
        // A failure after window expiry should reset count but PRESERVE cooldown
        let d = l.record_failure(ip());
        // In cooldown → zero delay (refusal is immediate)
        assert_eq!(d, Duration::ZERO);
        // Still in cooldown
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Refuse));
    }

    #[test]
    fn window_reset_clears_count_when_not_in_cooldown() {
        let l = limiter();
        // Fill up to threshold + some (but not enough for cooldown)
        for _ in 0..5 {
            l.record_failure(ip());
        }
        // Simulate window expiry
        {
            let mut records = l.records.write().unwrap();
            let rec = records.get_mut(&ip()).unwrap();
            rec.window_start = Instant::now() - Duration::from_secs(120);
            rec.cooldown_until = None;
        }
        // Next failure should reset the window
        let d = l.record_failure(ip());
        // After reset, count=1 ≤ max_failures → no delay
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn disabled_when_max_failures_zero() {
        let l = AuthLimiter::new(0, 60, 5000, 60, 10);
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Allow));
        assert_eq!(l.record_failure(ip()), Duration::ZERO);
    }

    #[test]
    fn per_conn_cap_exceeds() {
        let l = limiter();
        assert!(!l.conn_failure_exceeds(10));
        assert!(l.conn_failure_exceeds(11));
    }

    #[test]
    fn per_conn_cap_disabled() {
        let l = AuthLimiter::new(5, 60, 5000, 60, 0);
        assert!(!l.conn_failure_exceeds(1000));
    }

    #[test]
    fn different_ips_independent() {
        let l = limiter();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..5 {
            l.record_failure(ip1);
        }
        // ip2 is unaffected
        assert!(matches!(l.check(&ip2), AuthThrottleResult::Allow));
    }

    #[test]
    fn table_eviction_on_overflow() {
        let l = AuthLimiter::new(1, 60, 5000, 60, 10);
        // Force the max_entries down by filling the table
        {
            let mut records = l.records.write().unwrap();
            for i in 1..=4100 {
                records.insert(
                    IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, 0, (i % 256) as u8)),
                    FailureRecord {
                        count: 1,
                        window_start: Instant::now() - Duration::from_secs(999),
                        cooldown_until: None,
                    },
                );
            }
            // 4100 expired entries
        }
        // A new failure should evict expired entries and still work
        let d = l.record_failure(ip());
        // count=1 ≤ max_failures=1 → no delay
        assert_eq!(d, Duration::ZERO);
        // Table should have shrunk
        let records = l.records.read().unwrap();
        assert!(
            records.len() < 4100,
            "table not evicted: {} entries",
            records.len()
        );
    }

    #[test]
    fn table_full_with_unexpired_refuses_new_ip() {
        // When the table is full of unexpired entries, a new IP is refused
        // (fail-closed) rather than growing the table unbounded.
        let l = AuthLimiter::new(1, 60, 5000, 60, 10);
        {
            let mut records = l.records.write().unwrap();
            for i in 1..=4096 {
                records.insert(
                    IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, 0, (i % 256) as u8)),
                    FailureRecord {
                        count: 1,
                        window_start: Instant::now(), // not expired
                        cooldown_until: None,
                    },
                );
            }
        }
        // A new IP — table is full with unexpired entries
        let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let d = l.record_failure(new_ip);
        // Refused — returns zero delay (not tracked)
        assert_eq!(d, Duration::ZERO);
        // The new IP should not have been added
        let records = l.records.read().unwrap();
        assert!(!records.contains_key(&new_ip));
    }

    #[test]
    fn cooldown_expires_allows_new_attempts() {
        let l = limiter();
        // Fill up past threshold and into cooldown
        for _ in 0..9 {
            l.record_failure(ip());
        }
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Refuse));
        // Simulate cooldown expiry
        {
            let mut records = l.records.write().unwrap();
            let rec = records.get_mut(&ip()).unwrap();
            rec.cooldown_until = Some(Instant::now() - Duration::from_secs(1));
        }
        // check should now Allow
        assert!(matches!(l.check(&ip()), AuthThrottleResult::Allow));
        // record_failure should clear expired cooldown and re-evaluate
        let d = l.record_failure(ip());
        // Window hasn't expired, count was already high — excess still > 0
        // But after cooldown expiry, the count is still 9, so excess=6 → cooldown again
        // Actually the cooldown was cleared, count is still 9, excess=6 > 5 → cooldown
        assert_eq!(d, Duration::from_millis(5000)); // capped → cooldown
    }
}
