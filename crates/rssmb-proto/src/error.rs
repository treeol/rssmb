//! SMB2 Error response message.
//!
//! MS-SMB2 2.2.2.

use binrw::prelude::*;

use crate::dtyp::PosMarker;

/// SMB2 ERROR Response (9-byte body).
///
/// MS-SMB2 2.2.2
#[binrw::binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct ErrorResponse {
    #[bw(calc = 9)]
    structure_size: u16,
    /// For SMB dialects other than 3.1.1, this must be 0.
    /// For 3.1.1, if nonzero, ErrorData is an array of ERROR_CONTEXT structs.
    #[bw(try_calc = error_data.len().try_into())]
    #[br(temp)]
    _error_context_count: u8,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u8,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _byte_count: PosMarker<u32>,
    /// Variable-length error data (ErrorContextCount entries or raw bytes).
    #[br(count = _error_context_count)]
    pub error_data: Vec<u8>,
}

/// The error response body is just the 9-byte fixed part plus raw error_data.
/// When we build it manually (e.g., in build_error_response), we serialize:
///   StructureSize=9 (u16 LE), ErrorContextCount=0 (u8), Reserved=0 (u8),
///   ByteCount=0 (u32 LE) = [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
///
/// The typed ErrorResponse above serializes to the same 9 bytes when
/// error_data is empty (the default).

impl ErrorResponse {
    /// Fixed size of the error response body in bytes.
    pub const STRUCT_SIZE: usize = 9;
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_error_response_empty() {
        let resp = ErrorResponse::default();
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // StructureSize(2) + ErrorContextCount(1) + Reserved(1) + ByteCount(4) = 8
        assert_eq!(bytes.len(), 8);
        // Golden bytes: [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        assert_eq!(&bytes, &[0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_error_response_with_data_roundtrip() {
        let resp = ErrorResponse {
            error_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // ErrorContextCount=4 → 8 fixed + 4 data = 12 bytes
        assert_eq!(bytes.len(), 12);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ErrorResponse = ErrorResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.error_data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}