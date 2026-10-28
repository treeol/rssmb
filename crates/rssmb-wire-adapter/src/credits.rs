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
        // Start with 1 credit (granted in negotiate response) unless
        // max_grant is 0 — then no credits at all (max_grant=0 disables
        // granting; available is 0 and window [0,0) is empty).
        let initial = if max_grant > 0 { 1 } else { 0 };
        Self {
            window: std::sync::Mutex::new(CreditWindow {
                available: initial,
                low: 0,
                high: initial as u64, // [0, initial) — 0 or 1 credit
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
    ///   **State is unchanged** on this error.
    /// - `ExcessiveCharge`: the charge exceeds our local policy cap (`max_charge`).
    ///   The credits **are still spent** — the client sent the request and
    ///   consumed the MessageIds. State **is** mutated; the error is a policy
    ///   rejection, not a protocol violation.
    pub fn check_and_deduct(&self, message_id: u64, charge: u32) -> Result<(), CreditError> {
        // The credit charge is max(charge, 1) per MS-SMB2 3.3.1.2: "If the
        // CreditCharge field is 0, it MUST be treated as 1." This applies
        // to BOTH the balance and the MessageId window — smbd parity
        // (smb2_validate_message_id: credit_charge = MAX(charge, 1)):
        // every request consumes at least one MessageId, so `low` advances
        // with the contiguous prefix.
        let balance_charge = charge.max(1) as u64;
        // smbd parity (smb2_validate_message_id): the MessageId window
        // also charges max(charge, 1). The previous behavior
        // (window_charge = charge, a zero-charge request consumed no
        // MessageId — PR #31's model of impacket mid reuse) was based on
        // a wrong root-cause story: impacket never reuses a MessageId
        // (its WRITE charge is always >= 1 and its SequenceWindow
        // advances every send). Instead the 0-consumption left every
        // negotiate's MessageId unconsumed, pinning `low` behind a
        // phantom hole and eating grant budget (smb2.credits
        // off-by-N failures).
        let window_charge = balance_charge;
        let mut w = self.window.lock().unwrap();

        let low = w.low;

        // Check the credit balance first: the balance charge (max(charge, 1)
        // per MS-SMB2 3.3.1.2) must be available. This catches the case
        // where the MessageId is in-window (e.g. charge=0 → end=message_id,
        // which is always <= high when message_id >= low) but the balance
        // is exhausted.
        if (w.available as u64) < balance_charge {
            return Err(CreditError::InsufficientCredits {
                available: w.available,
                requested: balance_charge as u32,
            });
        }

        // The MessageId must be >= low (not before the window).
        if message_id < low {
            return Err(CreditError::InsufficientCredits {
                available: w.available,
                requested: balance_charge as u32,
            });
        }

        // Check the upper bound: m + c must be <= high.
        // With window_charge=0, end = message_id (always in-window if >= low).
        let end = message_id.checked_add(window_charge).ok_or_else(|| {
            CreditError::InsufficientCredits {
                available: w.available,
                requested: balance_charge as u32,
            }
        })?;
        if end > w.high {
            return Err(CreditError::InsufficientCredits {
                available: w.available,
                requested: balance_charge as u32,
            });
        }

        // Check that none of m..m+c are already used.
        for mid in message_id..end {
            if w.used.contains(&mid) {
                return Err(CreditError::InsufficientCredits {
                    available: w.available,
                    requested: balance_charge as u32,
                });
            }
        }

        // --- Commit: all checks passed, mutate state ---
        // Mark all MessageIds in m..m+c as used.
        for mid in message_id..end {
            w.used.insert(mid);
        }

        // Consume the credits (balance charge, not window charge).
        w.available = w.available.saturating_sub(balance_charge as u32);

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
        if balance_charge > self.max_charge as u64 {
            return Err(CreditError::ExcessiveCharge(balance_charge as u32));
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

    /// Grant credits for a regular response, matching smbd 4.19's
    /// `smb2_set_operation_credit` (source3/smbd/smb2_server.c):
    ///
    /// ```text
    /// additional_possible = max_grant - charge          // room after refund
    /// additional          = min(max(requested, 1) - 1, additional_possible)
    /// granted             = charge + additional        // refund + extra
    /// ```
    ///
    /// The request's own charge is refunded with every response (the
    /// client `available` balance is restored as the request completes),
    /// and additional credits are granted up to the window width budget
    /// (`max_grant`). The window (`high`) extends by `granted`, so the
    /// sequence window widens in lockstep with the credit balance —
    /// Samba's exact model.
    ///
    /// On an interim (async) response no credits are granted at all
    /// (smbd returns 0 when SMB2_HDR_FLAG_ASYNC is set); callers pass
    /// `interim = true` for that case. On NEGOTIATE responses and on
    /// SESSION_SETUP responses that did not complete authentication
    /// (`charge_only = true`), only the request's charge is refunded —
    /// no additional credits (smbd: `additional_max = 0` for
    /// SMB2_OP_NEGPROT and non-OK SMB2_OP_SESSSETUP).
    ///
    /// Returns the number granted (written into the response header's
    /// CreditRequest/Response field by the connection layer).
    pub fn grant_for_response(
        &self,
        charge: u32,
        requested: u32,
        interim: bool,
        charge_only: bool,
    ) -> u32 {
        if interim {
            return 0;
        }
        let mut w = self.window.lock().unwrap();
        let charge = charge.max(1) as u64;
        let requested = requested.max(1) as u64;
        // Room for additional credits after the charge refund, bounded by
        // the total window budget (max_grant). Samba: additional_possible =
        // credits.max - credit_charge.
        let additional_possible = (self.max_grant as u64).saturating_sub(charge);
        // The outstanding window width (high - low) also consumes budget:
        // the sequence range smbd tracks as seq_range. Budget for the
        // refund + additional must fit within max_grant - width.
        let width = w.high - w.low;
        let width_budget = (self.max_grant as u64).saturating_sub(width);
        // smbd: additional_credits = min(requested - 1, additional_possible);
        // credits_granted = charge + additional; then the final window
        // clamp: credits_granted = min(credits_granted, max - seq_range).
        let additional = if charge_only {
            0
        } else {
            (requested - 1).min(additional_possible)
        };
        let granted = (charge + additional).min(width_budget) as u32;
        if granted > 0 {
            w.available = w.available.saturating_add(granted);
            match w.high.checked_add(granted as u64) {
                Some(new_high) => w.high = new_high,
                None => {
                    // Sequence space exhausted: roll back.
                    w.available = w.available.saturating_sub(granted);
                    return 0;
                }
            }
        }
        granted
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
    use proptest::prelude::*;

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
        assert!(matches!(
            result,
            Err(CreditError::InsufficientCredits { .. })
        ));
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
        assert_eq!(
            mgr.available_credits(),
            24,
            "an affordable over-cap charge is still spent"
        );
    }

    #[test]
    fn test_unaffordable_charge_is_insufficient_not_excessive() {
        // Over the cap AND over the balance: the window violation wins.
        let mgr = CreditManager::new(1024);
        let result = mgr.check_and_deduct(0, 1000);
        assert!(matches!(
            result,
            Err(CreditError::InsufficientCredits { .. })
        ));
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
    fn test_zero_charge_reuses_message_id() {
        // smbd parity: a charge of 0 is treated as 1 for BOTH the balance
        // and the MessageId window (MS-SMB2 3.3.1.2,
        // smb2_validate_message_id), so the MessageId is consumed and
        // CANNOT be reused by the next request.
        //
        // Wire-observed impacket 0.13.1 sequence (the PR #31 repro path,
        // tmp/stress/repro_charge0.py): NEGPROT is the only charge-0
        // request (mid 0); every WRITE/CLOSE carries charge >= 1
        // (impacket computes 1 + (len-1)//65536) and mids are strictly
        // sequential — a client never reuses a MessageId. The old
        // 0-consumes-nothing behavior left mid 0 unconsumed, pinning
        // `low` at 0 forever (phantom hole) and eating window budget.
        let mgr = CreditManager::new(1024);
        // NEGPROT: charge 0, mid 0 — consumed like a charge of 1.
        mgr.check_and_deduct(0, 0).unwrap();
        assert_eq!(mgr.available_credits(), 0);
        // Reusing mid 0 must fail (already used / below low).
        let r = mgr.check_and_deduct(0, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // The next request (SESSION_SETUP, charge 1, mid 1) succeeds.
        mgr.grant(99);
        mgr.check_and_deduct(1, 1).unwrap();
        // A small WRITE: charge >= 1, next sequential mid — succeeds.
        mgr.check_and_deduct(2, 1).unwrap();
        // CLOSE: charge 1, NEXT sequential mid (impacket never reuses) —
        // succeeds under the smbd-parity window.
        mgr.check_and_deduct(3, 1).unwrap();
    }

    #[test]
    fn test_zero_charge_advances_low() {
        // smbd parity: a zero-charge request still consumes its MessageId,
        // so `low` advances past it on the contiguous prefix.
        let mgr = CreditManager::new(1024);
        mgr.grant(99); // 100 total, window [0..100)
                       // Consume 0..5 with charge 1 each — low advances to 5.
        for m in 0..5 {
            mgr.check_and_deduct(m, 1).unwrap();
        }
        assert_eq!(mgr.available_credits(), 95);
        // Zero-charge request at 5: balance -= 1 AND MessageId 5 consumed,
        // low advances to 6.
        mgr.check_and_deduct(5, 0).unwrap();
        assert_eq!(mgr.available_credits(), 94);
        // MessageId 5 is now below low — rejected.
        let r = mgr.check_and_deduct(5, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
        // MessageId 6 is the next valid one.
        mgr.check_and_deduct(6, 1).unwrap();
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
    fn test_new_zero_grants_no_credits() {
        let mgr = CreditManager::new(0);
        assert_eq!(
            mgr.available_credits(),
            0,
            "new(0) should start with 0 credits"
        );
        // Granting should not increase available (max_grant=0 caps everything).
        let granted = mgr.grant(100);
        assert_eq!(granted, 0);
        assert_eq!(mgr.available_credits(), 0);
        // Any deduction should fail (window [0,0) is empty).
        let r = mgr.check_and_deduct(0, 1);
        assert!(matches!(r, Err(CreditError::InsufficientCredits { .. })));
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

    // ---- Property tests ----

    proptest! {
        /// Deducting a valid MessageId should never panic, and after a
        /// successful deduction, available credits should decrease by the
        /// charge (clamped to 1 minimum).
        #[test]
        fn prop_deduct_decreases_available(
            max_grant in 1u32..=1024,
            grant_amount in 1u32..=1024,
            msg_id in 0u64..=2048,
            charge in 1u32..=256,
        ) {
            let mgr = CreditManager::new(max_grant);
            mgr.grant(grant_amount);
            let before = mgr.available_credits();
            let result = mgr.check_and_deduct(msg_id, charge);
            if result.is_ok() {
                let effective_charge = charge.max(1);
                let after = mgr.available_credits();
                prop_assert!(after <= before);
                // available decreases by exactly effective_charge (credits
                // are consumed). low advancing doesn't change available —
                // it only reclaims used entries for future grants.
                let decrease = before - after;
                prop_assert_eq!(decrease, effective_charge,
                    "decrease {} != effective_charge {}", decrease, effective_charge);
            }
        }

        /// A failed deduction must not change available credits.
        #[test]
        fn prop_failed_deduct_preserves_state(
            max_grant in 1u32..=1024,
            grant_amount in 1u32..=1024,
            msg_id in 2049u64..=4096, // outside window
            charge in 1u32..=256,
        ) {
            let mgr = CreditManager::new(max_grant);
            mgr.grant(grant_amount);
            let before = mgr.available_credits();
            let result = mgr.check_and_deduct(msg_id, charge);
            if result.is_err() {
                prop_assert_eq!(mgr.available_credits(), before,
                    "state changed on failed deduction");
            }
        }

        /// Granting credits should not panic and should not decrease
        /// available credits.
        #[test]
        fn prop_grant_never_decreases(
            max_grant in 1u32..=1024,
            grant_amount in 1u32..=1024,
        ) {
            let mgr = CreditManager::new(max_grant);
            let before = mgr.available_credits();
            mgr.grant(grant_amount);
            let after = mgr.available_credits();
            prop_assert!(after >= before,
                "grant decreased available: {} -> {}", before, after);
            // Grant is capped by max_grant
            prop_assert!(after <= max_grant,
                "available {} exceeds max_grant {}", after, max_grant);
        }

        /// Deducting the same MessageId twice should fail the second time
        /// (idempotency of used set).
        #[test]
        fn prop_double_deduct_fails(
            max_grant in 1u32..=1024,
            grant_amount in 1u32..=1024,
            msg_id in 0u64..=1024,
            charge in 1u32..=16,
        ) {
            let mgr = CreditManager::new(max_grant);
            mgr.grant(grant_amount);
            let first = mgr.check_and_deduct(msg_id, charge);
            if first.is_ok() {
                let second = mgr.check_and_deduct(msg_id, charge);
                prop_assert!(second.is_err(),
                    "double-deduct of {} succeeded", msg_id);
            }
        }

        /// Available credits should never exceed max_grant.
        #[test]
        fn prop_available_bounded(
            max_grant in 1u32..=1024,
            ops in proptest::collection::vec(
                (0u64..=2048, 1u32..=64), 0..20
            ),
        ) {
            let mgr = CreditManager::new(max_grant);
            mgr.grant(max_grant);
            for (msg_id, charge) in ops {
                let _ = mgr.check_and_deduct(msg_id, charge);
                prop_assert!(mgr.available_credits() <= max_grant,
                    "available {} exceeds max_grant {}",
                    mgr.available_credits(), max_grant);
            }
        }
    }

    // ---- smb2.credits parity tests (smbd smb2_set_operation_credit) ----

    /// Torture subtest 1: request 65535 on every SESSION_SETUP; the
    /// client's cur_credits after login must be >= 8192.
    /// Client model (smbXcli): cur -= charge per request; cur += grant
    /// per response. smbd parity: NEGOTIATE and non-OK SESSION_SETUP
    /// responses refund the charge only; the auth-complete SESSION_SETUP
    /// response grants the full window.
    #[test]
    fn test_credits_session_setup_grants_8192() {
        let mgr = CreditManager::new(8192);
        let mut cur: i64 = 1; // initial credit from negotiate (mid 0)
        // negotiate: deduct (mid 0), response refunds the charge only.
        mgr.check_and_deduct(0, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 1, false, true) as i64;
        // SESSION_SETUP #1 (NTLM negotiate, MORE_PROCESSING): charge only.
        mgr.check_and_deduct(1, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 65535, false, true) as i64;
        // SESSION_SETUP #2 (auth complete): full window.
        mgr.check_and_deduct(2, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 65535, false, false) as i64;
        assert!(cur >= 8192, "cur_credits {} < 8192", cur);
    }

    /// Torture subtest 2: connect with request 1 (cur must land at 1),
    /// then a single CREATE requesting 65535 — cur must be >= 8192.
    #[test]
    fn test_credits_single_req_grants_8192() {
        let mgr = CreditManager::new(8192);
        let mut cur: i64 = 1;
        mgr.check_and_deduct(0, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 1, false, true) as i64;
        for mid in 1..=2 {
            // session setups requesting exactly 1 (charge-only responses)
            mgr.check_and_deduct(mid, 1).unwrap();
            cur -= 1;
            cur += mgr.grant_for_response(1, 1, false, mid == 1) as i64;
        }
        assert_eq!(cur, 1, "cur after minimal-credit login");
        // tree connect + CREATE with CreditRequest 65535
        mgr.check_and_deduct(3, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 1, false, false) as i64; // tree connect
        mgr.check_and_deduct(4, 1).unwrap();
        cur -= 1;
        let g = mgr.grant_for_response(1, 65535, false, false);
        assert_eq!(g, 8192, "single big request must grant the full window");
        cur += g as i64;
        assert!(cur >= 8192, "cur_credits {} < 8192", cur);
    }

    /// Torture subtest 3 (skipped_mid): with an outstanding hole at `low`
    /// (a skipped MessageId), grants stay bounded by the window budget —
    /// 8191 sequential single-credit writes each request-and-receive one
    /// credit must keep working, and reusing the skipped mid then grants
    /// the full 8192 window.
    #[test]
    fn test_credits_skipped_mid_window() {
        let mgr = CreditManager::new(8192);
        let mut cur: i64 = 1;
        mgr.check_and_deduct(0, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 1, false, true) as i64;
        // two session setups; final one completes auth -> full window
        mgr.check_and_deduct(1, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 8192, false, true) as i64;
        mgr.check_and_deduct(2, 1).unwrap();
        cur -= 1;
        cur += mgr.grant_for_response(1, 8192, false, false) as i64;
        assert!(cur >= 8192, "cur {} < 8192 after setup", cur);
        // skip mid 3 (hole at low). Sequential single-credit writes must
        // keep being ADMITTED: the server-side balance (granted) covers
        // the charges even though the full window means per-response
        // grants are 0 (smbd: credits_possible = max - seq_range = 0).
        // The client lives off its 8192-credit balance for all 8191 writes.
        let hole = 3u64;
        for i in 0..200u64 {
            let mid = 4 + i;
            // Server-side admission: each write consumes one credit from
            // the balance granted during setup.
            mgr.check_and_deduct(mid, 1)
                .expect("write must stay inside the credit window");
            let _g = mgr.grant_for_response(1, 2, false, false);
        }
        // fill the hole: the window reclaims (low advances past 3+4..),
        // and a big ask grants the full 8192 again (budget restored).
        mgr.check_and_deduct(hole, 1).unwrap();
        let g = mgr.grant_for_response(1, 65535, false, false);
        assert!(g > 0, "no budget after hole filled: got {}", g);
    }

    /// Interim (async) responses grant nothing (smbd: ASYNC => 0).
    #[test]
    fn test_grant_for_response_interim_grants_zero() {
        let mgr = CreditManager::new(8192);
        assert_eq!(mgr.grant_for_response(1, 65535, true, false), 0);
        assert_eq!(mgr.available_credits(), 1);
    }

    /// grant_for_response never exceeds max_grant nor unbounds the window.
    #[test]
    fn test_grant_for_response_bounded() {
        let mgr = CreditManager::new(16);
        for _ in 0..100 {
            let _ = mgr.check_and_deduct(0, 0); // zero-charge admission
            let g = mgr.grant_for_response(1, 65535, false, false);
            assert!(g <= 16, "grant {} > max 16", g);
            assert!(mgr.available_credits() <= 16);
        }
    }
}
