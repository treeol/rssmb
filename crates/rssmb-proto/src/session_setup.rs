//! SMB2 session setup, logoff, and related types.
//!
//! MS-SMB2 2.2.5–2.2.8.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::dtyp::PosMarker;

/// SMB2 SESSION_SETUP Request.
///
/// MS-SMB2 2.2.5
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SessionSetupRequest {
    #[bw(calc = 25)]
    #[br(temp)]
    structure_size: u16,
    /// Combination of flags for SMB 3.x dialect family.
    pub flags: SetupRequestFlags,
    /// Security mode field specifying signing.
    pub security_mode: SessionSecurityMode,
    /// Protocol capabilities for the client.
    pub capabilities: NegotiateCapabilities,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    #[br(temp)]
    security_buffer_length: u16,
    /// Previously established session identifier for reconnection.
    pub previous_session_id: u64,
    /// Security buffer containing authentication token.
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
}

/// Security mode field for session setup.
///
/// MS-SMB2 2.2.5
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B6,
}

/// Flags field for SESSION_SETUP request.
///
/// MS-SMB2 2.2.5
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SetupRequestFlags {
    pub binding: bool,
    #[skip]
    __: B7,
}

/// Protocol capabilities for the client.
///
/// MS-SMB2 2.2.5
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NegotiateCapabilities {
    pub dfs: bool,
    #[skip]
    __: B31,
}

/// SMB2 SESSION_SETUP Response.
///
/// MS-SMB2 2.2.6
#[binrw::binrw]
#[derive(Debug, Default)]
#[brw(little)]
pub struct SessionSetupResponse {
    #[bw(calc = 9)]
    #[br(temp)]
    structure_size: u16,
    /// Flags indicating additional information about the session.
    pub session_flags: SessionFlags,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    #[br(temp)]
    security_buffer_length: u16,
    /// Security buffer containing authentication token.
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
}

/// Flags indicating additional information about the session.
///
/// MS-SMB2 2.2.6
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionFlags {
    pub is_guest: bool,
    pub is_null_session: bool,
    pub encrypt_data: bool,
    #[skip]
    __: B13,
}

impl SessionFlags {
    pub fn is_guest_or_null_session(&self) -> bool {
        self.is_guest() || self.is_null_session()
    }
}

/// SMB2 LOGOFF Request.
///
/// MS-SMB2 2.2.7
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct LogoffRequest {
    #[bw(calc = 4)]
    structure_size: u16,
    reserved: u16,
}

/// SMB2 LOGOFF Response.
///
/// MS-SMB2 2.2.8
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct LogoffResponse {
    #[bw(calc = 4)]
    structure_size: u16,
    reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_session_setup_roundtrip() {
        let req = SessionSetupRequest {
            flags: SetupRequestFlags::new(),
            security_mode: SessionSecurityMode::new().with_signing_enabled(true),
            capabilities: NegotiateCapabilities::new(),
            previous_session_id: 0,
            buffer: vec![0x60, 0x1c],
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: SessionSetupRequest = SessionSetupRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.buffer, vec![0x60, 0x1c]);
        assert!(decoded.security_mode.signing_enabled());
    }

    #[test]
    fn test_logoff_roundtrip() {
        let req = LogoffRequest::default();
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let _: LogoffResponse = LogoffResponse::read_le(&mut cursor).unwrap();
    }
}