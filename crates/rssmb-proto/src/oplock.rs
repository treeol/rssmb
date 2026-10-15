//! SMB2 oplock and lease types.
//!
//! Re-exports from create.rs — OplockBreakMsg, LeaseBreakAckResponse,
//! LeaseBreakNotify, LeaseState, LeaseFlags are defined in create.rs.
//! This module exists for the `plain` module to import from.

pub use crate::create::{
    LeaseBreakAckResponse as LeaseBreakAck, LeaseBreakAckResponse as LeaseBreakResponse,
    LeaseBreakNotify, LeaseFlags, LeaseState, OplockBreakMsg as OplockBreakAck,
    OplockBreakMsg as OplockBreakNotify, OplockBreakMsg as OplockBreakResponse, OplockLevel,
};
