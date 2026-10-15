//! Credit tracking per MS-SMB2 §3.2 and §3.3.
//!
//! Credits are a flow-control mechanism. The server grants credits to clients,
//! and the client must have sufficient credits to send requests. Each request
//! has a credit charge (usually 1, or `ceil(payload_size / 65536)` for
//! multi-credit READ/WRITE/IOCTL/QUERY_DIRECTORY operations).
//!
//! ## Phase 1.5: MessageId sequence window
//!
//! Per MS-SMB2 3.3.1.1, the server tracks a per-connection sequence window
//! `[low, high)` whose width is bounded by `max_grant`. A request with
//! MessageId `m` and CreditCharge `c` must have all of `m..m+c` inside the
//! window and not already used. CANCEL is exempt (it doesn't consume credits).
//!
//! We use a `Mutex<CreditWindow>` rather than atomics because the dispatch
//! loop is serial per connection — there is no contention.
//!
//! ### Bounded memory
//!
//! The window width `(high - low)` is capped at `max_grant` (default 1024).
//! The `used` HashSet never exceeds `max_grant` entries because:
//! (a) the window width bounds the number of in-flight MessageIds, and
//! (b) `low` advances past consumed prefixes, removing entries from `used`.
//! A client that holds a gap at `low` while consuming higher IDs cannot grow
//! `used` beyond the window width — once `high - low` hits `max_grant`, no
//! more credits are granted until `low` advances.
//!
//! ### No cumulative counters
//!
//! We track `available: u32` directly instead of cumulative `granted`/`consumed`
//! counters. This eliminates overflow risk over long-lived connections.

use std::collections::HashSet;

/// Per-connection credit state with a MessageId sequence window.
///
/// The window covers `[low, high)`. The client may send any MessageId `m`
/// with charge `c` such that `m + c <= high` and none of `m..m+c` are already
/// used. CANCEL is exempt — it never consumes a MessageId.
pub struct CreditManager {
    window: std::sync::Mutex<CreditWindow>,
    /// Maximum credits we'll grant to a single connection (bounds window width).
    max_grant: u32,
    /// Maximum credit charge per request.
    max_charge: u32,
}

struct CreditWindow {
    /// Available credits (granted minus consumed). Directly tracked to
    /// avoid cumulative counter overflow on long-lived connections.
    available: u32,
    /// The low edge of the sequence window. A request with MessageId `m`
    /// must have `m >= low`. Starts at 0 (MS-SMB2: MessageId begins at 0).
    low: u64,
    /// The high edge of the sequence window. A request with MessageId `m`
    /// and charge `c` must have `m + c <= high`. `high - low - used.len()`
    /// equals `available`.
    high: u64,
    /// Used MessageIds inside the window (not yet advanced past `low`).
    /// Bounded by `max_grant` (the window width).
    used: HashSet<u64>,
}

impl std::fmt::Debug for CreditManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let w = self.window.lock().unwrap();
        f.debug_struct("CreditManager")
            .field("available", &w.available)
            .field("low", &w.low)
            .field("high", &w.high)
            .field("used_count", &w.used.len())
            .field("max_grant", &self.max_grant)
            .field("max_charge", &self.max_charge)
            .finish()
    }
}

impl CreditManager {
    pub fn new(max_grant: u32) -> Self {
        Self {
            window: std::sync::Mutex::new(CreditWindow {
                available: 1, // Start with 1 credit (granted in negotiate response)
                low: 0,
                high: 1, // [0, 1) — one credit available starting at MessageId 0
                used: HashSet::new(),
            }),
            max_grant,
            max_charge: 256,
        }
    }

    /// Check if the client has enough credits for a request with the given
    /// MessageId and charge. Returns Ok(()) if the request is inside the
    /// sequence window and all MessageIds `m..m+c` are unused; marks them
    /// as used and advances `low` past the contiguous used prefix.
    ///
    /// # Errors
    ///
    /// - `InsufficientCredits`: the MessageId is outside the window, already
    ///   used, or `m + c` overflows. This is a sequence-window violation
    ///   (MS-SMB2 3.3.5.2.3) — the connection must be terminated.
    /// - `ExcessiveCharge`: the charge exceeds our local policy cap (`max_charge`).
    ///   The credits are still spent — the client sent the request.
    ///
    /// On error, the window state is unchanged (no partial mutation).
    pub fn check_and_deduct(&self, message_id: u64, charge: u32) -> Result<(), CreditError> {
        let charge = charge.max(1);
        let mut w = self.window.lock().unwrap();

        let low = w.low;

        // The MessageId must be >= low (not before the window).
        if message_id < low {
            return Err(CreditError::InsufficientCredits {
                available: w.available,
                requested: charge,
            });
        }

        // Check the upper bound: m + c must be <= high.
        let end = message_id.checked_add(charge as u64).ok_or_else(|| {
            CreditError::InsufficientCredits {
                available: w.available,
                requested: charge,
            }
        })?;
        if end > w.high {
            return Err(CreditError::InsufficientCredits {
                available: w.available,
                requested: charge,
            });
        }

        // Check that none of m..m+c are already used.
        for mid in message_id..end {
            if w.used.contains(&mid) {
                return Err(CreditError::InsufficientCredits {
                    available: w.available,
                    requested: charge,
                });
            }
        }

        // --- Commit: all checks passed, mutate state ---
        // Mark all MessageIds in m..m+c as used.
        for mid in message_id..end {
            w.used.insert(mid);
        }

        // Consume the credits.
        w.available = w.available.saturating_sub(charge);

        // Advance low past the contiguous used prefix. This removes entries
        // from `used`, keeping its size bounded by the window width.
        loop {
            let cur_low = w.low;
            if !w.used.contains(&cur_low) {
                break;
            }
            w.used.remove(&cur_low);
            w.low = cur_low + 1;
        }

        // Policy cap: charge above max_charge is ExcessiveCharge (the credits
        // are still spent — the client sent the request).
        if charge > self.max_charge {
            return Err(CreditError::ExcessiveCharge(charge));
        }

        Ok(())
    }

    /// Grant credits in a response. Returns the number actually granted
    /// (may be less than requested if capped by `max_grant`).
    ///
    /// The grant extends `high`, widening the window. Both `available` and
    /// the window width `(high - low)` are capped at `max_grant`, which
    /// bounds `used.len()` and prevents unbounded memory growth.
    pub fn grant(&self, requested: u32) -> u32 {
        let mut w = self.window.lock().unwrap();
        // Cap by available ceiling (max_grant - current_available).
        let avail_cap = self.max_grant.saturating_sub(w.available);
        // Cap by window width ceiling (max_grant - current_width).
        // Window width = high - low. If there are holes (used entries above
        // low), the width can exceed available, so we need both caps.
        let width = (w.high - w.low) as u32;
        let width_cap = self.max_grant.saturating_sub(width);
        let to_grant = requested.min(avail_cap).min(width_cap);
        if to_grant > 0 {
            w.available = w.available.saturating_add(to_grant);
            // Extend the high edge of the window. Use checked_add to avoid
            // silent saturation — if the sequence space is exhausted, grant 0.
            match w.high.checked_add(to_grant as u64) {
                Some(new_high) => w.high = new_high,
                None => {
                    // Sequence space exhausted: roll back the available increase.
                    w.available = w.available.saturating_sub(to_grant);
                    return 0;
                }
            }
        }
        to_grant
    }

    /// Get current available credits (for diagnostics).
    pub fn available_credits(&self) -> u32 {
        let w = self.window.lock().unwrap();
        w.available
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreditError {
    #[error("insufficient credits: have {available}, need {requested}")]
    InsufficientCredits { available: u32, requested: u32 },
    #[error("excessive credit charge: {0}")]
    ExcessiveCharge(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_grant_and_deduct() {
        let mgr = CreditManager::new(1024);
        assert_eq!(mgr.available_credits(), 1);

        // Grant some credits
        let granted = mgr.grant(100);
        assert_eq!(granted, 100);
        assert_eq!(mgr.available_credits(), 101);

        // Deduct for a request
        mgr.check_and_deduct(0, 1).unwrap();
        assert_eq!(mgr.available_credits(), 100);

        // Try to deduct more than available
        let result = mgr.check_and_deduct(200, 200);
        assert!(matches!(result, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_credit_cap() {
        let mgr = CreditManager::new(1024);
        mgr.grant(100);
        mgr.grant(100);
        // Should be capped at max_grant
        assert_eq!(mgr.available_credits(), 201); // 1 initial + 100 + 100

        // Try to grant beyond cap
        let granted = mgr.grant(10000);
        assert_eq!(granted, 1024 - 201);
        assert_eq!(mgr.available_credits(), 1024);
    }

    #[test]
    fn test_excessive_charge_rejected() {
        let mgr = CreditManager::new(1024);
        mgr.grant(1023);
        let result = mgr.check_and_deduct(0, 1000);
        assert!(matches!(result, Err(CreditError::ExcessiveCharge(_))));
        assert_eq!(mgr.available_credits(), 24, "an affordable over-cap charge is still spent");
    }

    #[test]
    fn test_unaffordable_charge_is_insufficient_not_excessive() {
        // Over the cap AND over the balance: the window violation wins.
        let mgr = CreditManager::new(1024);
        let result = mgr.check_and_deduct(0, 1000);
        assert!(matches!(result, Err(CreditError::InsufficientCredits { .. })));
    }

    // --- Sequence window tests (Phase 1.5) ---

    #[test]
    fn test_sequential_message_ids() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 1 + 99 = 100 available, window [0..100)
        // Send messages 0, 1, 2 — all should succeed
        mgr.check_and_deduct(0, 1).unwrap();
        mgr.check_and_deduct(1, 1).unwrap();
        mgr.check_and_deduct(2, 1).unwrap();
        assert_eq!(mgr.available_credits(), 97);
    }

    #[test]
    fn test_out_of_order_message_ids() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total, window [0..100)
        // Send messages out of order: 5, then 3, then 4
        mgr.check_and_deduct(5, 1).unwrap();
        mgr.check_and_deduct(3, 1).unwrap();
        mgr.check_and_deduct(4, 1).unwrap();
        assert_eq!(mgr.available_credits(), 97);
        // low is still 0 (0 is not used). Now consume 0, 1, 2 to advance low past 5.
        mgr.check_and_deduct(0, 1).unwrap();
        mgr.check_and_deduct(1, 1).unwrap();
        mgr.check_and_deduct(2, 1).unwrap();
        // Now low should have advanced past 5 (0,1,2,3,4,5 all used)
        // next valid message_id is 6
        mgr.check_and_deduct(6, 1).unwrap();
    }

    #[test]
    fn test_multi_credit_charge() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total
        // Charge 5 for message_id 0: consumes 0,1,2,3,4
        mgr.check_and_deduct(0, 5).unwrap();
        assert_eq!(mgr.available_credits(), 95);
        // MessageId 5 is the next valid one
        mgr.check_and_deduct(5, 1).unwrap();
        // MessageId 3 should fail (already used)
        let r = mgr.check_and_deduct(3, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_message_id_before_low_rejected() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99);
        // Consume 0..10 sequentially, low advances past 10
        for m in 0..10 {
            mgr.check_and_deduct(m, 1).unwrap();
        }
        // Now low = 10. Sending message_id 0 should fail (below low)
        let r = mgr.check_and_deduct(0, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_message_id_beyond_high_rejected() {
        let mgr = CreditManager::new(1024);
        mgr.grant(9); // 10 total
        // First request initializes window [0..10)
        mgr.check_and_deduct(0, 1).unwrap();
        // MessageId 10 is at the edge — should fail (m+c > high)
        let r = mgr.check_and_deduct(10, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // Grant more credits to extend the window
        mgr.grant(1); // high becomes 11
        // Now message_id 10 should work
        mgr.check_and_deduct(10, 1).unwrap();
    }

    #[test]
    fn test_already_used_message_id_rejected() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99);
        mgr.check_and_deduct(5, 1).unwrap();
        // 5 is in the used set (low hasn't advanced past it yet).
        // Sending 5 again should fail — it's already in the used set.
        let r = mgr.check_and_deduct(5, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_grant_extends_window_high() {
        let mgr = CreditManager::new(1024);
        mgr.grant(9); // 10 total, window [0..10)
        // Consume 0..9
        for m in 0..10 {
            mgr.check_and_deduct(m, 1).unwrap();
        }
        assert_eq!(mgr.available_credits(), 0);
        // Window is now [10..10) — nothing available
        let r = mgr.check_and_deduct(10, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // Grant extends high
        mgr.grant(5);
        assert_eq!(mgr.available_credits(), 5);
        mgr.check_and_deduct(10, 1).unwrap();
    }

    #[test]
    fn test_low_advances_past_contiguous_used() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total, window [0..100)
        // Consume 0, 1, 2 — low should advance to 3
        mgr.check_and_deduct(0, 1).unwrap();
        mgr.check_and_deduct(1, 1).unwrap();
        mgr.check_and_deduct(2, 1).unwrap();
        // Now consume 5 (gap at 3,4)
        mgr.check_and_deduct(5, 1).unwrap();
        // 3 and 4 are still available
        mgr.check_and_deduct(3, 1).unwrap();
        mgr.check_and_deduct(4, 1).unwrap();
        // Now low should advance past 5
        mgr.check_and_deduct(6, 1).unwrap();
    }

    #[test]
    fn test_credit_charge_zero_counts_as_one() {
        let mgr = CreditManager::new(1024);
        mgr.grant(9); // 10 total
        // credit_charge 0 → treated as 1
        mgr.check_and_deduct(0, 0).unwrap();
        assert_eq!(mgr.available_credits(), 9);
    }

    #[test]
    fn test_large_charge_spanning_window() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total
        // Charge 50 starting at message_id 0
        mgr.check_and_deduct(0, 50).unwrap();
        assert_eq!(mgr.available_credits(), 50);
        // low should have advanced to 50
        // Next valid message_id is 50
        mgr.check_and_deduct(50, 1).unwrap();
    }

    #[test]
    fn test_grant_before_first_request() {
        // Grants before the first request extend the window from [0, high).
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total available, window [0..100)
        assert_eq!(mgr.available_credits(), 100);
        // First request at message_id 5 — inside the window
        mgr.check_and_deduct(5, 1).unwrap();
        // MessageId 100 is at the edge — should fail (100 + 1 > 100)
        let r = mgr.check_and_deduct(100, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // Grant more to extend the window
        mgr.grant(1); // high becomes 101
        mgr.check_and_deduct(100, 1).unwrap();
    }

    #[test]
    fn test_overflow_protection() {
        let mgr = CreditManager::new(1024);
        mgr.grant(1023); // 1024 total
        // MessageId near u64::MAX with charge 1 — end overflows
        let r = mgr.check_and_deduct(u64::MAX, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_failed_check_leaves_state_unchanged() {
        let mgr = CreditManager::new(1024);
        mgr.grant(9); // 10 total, window [0..10)
        mgr.check_and_deduct(0, 1).unwrap();
        assert_eq!(mgr.available_credits(), 9);

        // A failed check (out of window) must not change state.
        let r = mgr.check_and_deduct(100, 1);
        assert!(r.is_err());
        assert_eq!(mgr.available_credits(), 9, "failed check changed available");

        // A failed check (already used) must not change state.
        let r = mgr.check_and_deduct(0, 1);
        assert!(r.is_err());
        assert_eq!(mgr.available_credits(), 9, "failed check changed available");
    }

    #[test]
    fn test_used_set_bounded_by_max_grant() {
        // A client that holds a gap at `low` while consuming higher IDs
        // must not grow `used` beyond the window width, which is capped
        // by max_grant.
        let mgr = CreditManager::new(16);
        mgr.grant(15); // 16 total, window [0..16)

        // Consume 1..15, leaving a gap at 0. low stays at 0.
        for m in 1..16 {
            mgr.check_and_deduct(m, 1).unwrap();
        }
        assert_eq!(mgr.available_credits(), 1);

        // Try to grant more — should be capped. available is 1, max_grant 16.
        // avail_cap = 16 - 1 = 15. width = 16 - 0 = 16, width_cap = 16 - 16 = 0.
        // to_grant = min(100, 15, 0) = 0. No grant because window width is full.
        let granted = mgr.grant(100);
        assert_eq!(granted, 0, "window width is full, no grant possible");
        assert_eq!(mgr.available_credits(), 1);

        // Now consume 0 — low advances to 16, used is cleared.
        mgr.check_and_deduct(0, 1).unwrap();
        assert_eq!(mgr.available_credits(), 0);
        // Now width = 16 - 16 = 0, width_cap = 16. avail_cap = 16 - 0 = 16.
        let granted = mgr.grant(100);
        assert_eq!(granted, 16);
        assert_eq!(mgr.available_credits(), 16);
    }

    #[test]
    fn test_exact_high_boundary() {
        let mgr = CreditManager::new(1024);
        mgr.grant(9); // window [0..10)
        // MessageId 9 with charge 1: 9 + 1 = 10 = high. Should succeed.
        mgr.check_and_deduct(9, 1).unwrap();
        assert_eq!(mgr.available_credits(), 9);
    }

    #[test]
    fn test_partial_overlap_rejected() {
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // window [0..100)
        // Consume 5..10 (charge 5)
        mgr.check_and_deduct(5, 5).unwrap();
        // 3..8 overlaps at 5,6,7 — should fail
        let r = mgr.check_and_deduct(3, 5);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // State unchanged: 5..10 still used, available = 95
        assert_eq!(mgr.available_credits(), 95);
    }
}
