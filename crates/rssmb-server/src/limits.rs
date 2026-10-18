//! Size limits shared by the TCP and QUIC transports and the dispatcher.
//!
//! `max_frame_size` (config) is the maximum SMB2 *payload* size: it bounds
//! the advertised MaxTransactSize / MaxReadSize / MaxWriteSize. The wire
//! limit for an SMB2 frame is that payload plus a fixed header allowance,
//! so a compliant client sending a full MaxWriteSize WRITE (payload +
//! SMB2 header + WRITE request header + TRANSFORM_HEADER when encrypted)
//! is not mistaken for an oversized frame.

use crate::config::ServerConfig;

/// Largest READ/WRITE payload the server ever advertises (large MTU, 1 MiB).
pub const MAX_IO_SIZE: u32 = 1024 * 1024;

/// Fixed protocol overhead on top of a maximal READ/WRITE payload:
/// SMB2 header (64) + largest request header (WRITE, 48) + TRANSFORM_HEADER (52),
/// rounded up generously to also cover compound chains and padding.
pub const FRAME_OVERHEAD: usize = 64 * 1024;

/// Maximum accepted size of a single SMB2 (msg type 0x00) wire frame.
pub fn max_wire_frame(cfg: &ServerConfig) -> usize {
    max_wire_frame_for(cfg.max_frame_size)
}

/// [`max_wire_frame`] for callers that only carry the `max_frame_size` value.
pub fn max_wire_frame_for(max_frame_size: usize) -> usize {
    max_frame_size.saturating_add(FRAME_OVERHEAD)
}

/// Advertised (and enforced) MaxTransactSize / MaxReadSize / MaxWriteSize:
/// `min(MAX_IO_SIZE, max_frame_size)`.
pub fn max_io_size(cfg: &ServerConfig) -> u32 {
    (MAX_IO_SIZE as usize).min(cfg.max_frame_size) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let cfg = ServerConfig::for_testing();
        assert_eq!(cfg.max_frame_size, 1_048_576);
        assert_eq!(max_io_size(&cfg), 1_048_576);
        assert_eq!(max_wire_frame(&cfg), 1_048_576 + 65_536);
        // A full encrypted WRITE fits.
        assert!(1_048_576 + 64 + 48 + 52 <= max_wire_frame(&cfg));
    }

    #[test]
    fn test_small_max_frame_size_caps_io_size() {
        let mut cfg = ServerConfig::for_testing();
        cfg.max_frame_size = 65_536;
        assert_eq!(max_io_size(&cfg), 65_536);
        assert_eq!(max_wire_frame(&cfg), 131_072);
    }

    #[test]
    fn test_large_max_frame_size_does_not_raise_io_size() {
        let mut cfg = ServerConfig::for_testing();
        cfg.max_frame_size = 4 * 1024 * 1024;
        assert_eq!(max_io_size(&cfg), MAX_IO_SIZE);
    }
}
