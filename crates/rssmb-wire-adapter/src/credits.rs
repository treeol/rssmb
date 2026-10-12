//! Credit tracking per MS-SMB2 §3.2 and §3.3.
//!
//! Credits are a flow-control mechanism. The server grants credits to clients,
//! and the client must have sufficient credits to send requests. Each request
//! has a credit charge (usually 1, or the number of compounded operations).
//! The server grants credits in responses.

use std::sync::atomic::{AtomicU32, Ordering};

/// Per-connection credit state.
#[derive(Debug)]
pub struct CreditManager {
    /// Credits the client currently has available.
    available: AtomicU32,
    /// Maximum credits we'll grant to a single connection.
    max_grant: u32,
    /// Maximum credit charge per request.
    max_charge: u32,
}

impl CreditManager {
    pub fn new(max_grant: u32) -> Self {
        Self {
            available: AtomicU32::new(1), // Start with 1 credit (granted in negotiate response)
            max_grant,
            max_charge: 256,
        }
    }

    /// Check if the client has enough credits for a request with the given charge.
    /// Returns Ok(()) if sufficient, Err if not.
    ///
    /// Insufficiency is checked first: a charge the client has no credits for
    /// is a sequence-window violation (MS-SMB2 3.3.5.2.3, connection is
    /// terminated); only an affordable charge above `max_charge` (a local
    /// policy cap, not a protocol limit) is `ExcessiveCharge`.
    pub fn check_and_deduct(&self, charge: u32) -> Result<(), CreditError> {
        let current = self.available.load(Ordering::Acquire);
        if current < charge {
            return Err(CreditError::InsufficientCredits { available: current, requested: charge });
        }
        // Deduct even when the charge is over the cap: the client spent
        // those credits when it sent the request, and the ledger must
        // follow the client's view or later grants drift.
        self.available.fetch_sub(charge, Ordering::AcqRel);
        if charge > self.max_charge {
            return Err(CreditError::ExcessiveCharge(charge));
        }
        Ok(())
    }

    /// Grant credits in a response. Returns the number granted.
    pub fn grant(&self, requested: u32) -> u32 {
        let current = self.available.load(Ordering::Acquire);
        let to_grant = requested.min(self.max_grant.saturating_sub(current));
        if to_grant > 0 {
            self.available.fetch_add(to_grant, Ordering::AcqRel);
        }
        to_grant
    }

    /// Get current available credits (for diagnostics).
    pub fn available_credits(&self) -> u32 {
        self.available.load(Ordering::Acquire)
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
        mgr.check_and_deduct(1).unwrap();
        assert_eq!(mgr.available_credits(), 100);

        // Try to deduct more than available
        let result = mgr.check_and_deduct(200);
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
        let result = mgr.check_and_deduct(1000);
        assert!(matches!(result, Err(CreditError::ExcessiveCharge(_))));
        assert_eq!(mgr.available_credits(), 24, "an affordable over-cap charge is still spent");
    }

    #[test]
    fn test_unaffordable_charge_is_insufficient_not_excessive() {
        // Over the cap AND over the balance: the window violation wins.
        let mgr = CreditManager::new(1024);
        let result = mgr.check_and_deduct(1000);
        assert!(matches!(result, Err(CreditError::InsufficientCredits { .. })));
    }
}
