//! SMB2 Cancel request.
//!
//! MS-SMB2 2.2.30.

use binrw::prelude::*;

/// SMB2 CANCEL Request structure.
///
/// Sent by the client to cancel a previously sent message on the same
/// SMB2 transport connection.
///
/// MS-SMB2 2.2.30
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct CancelRequest {
    #[bw(calc = 4)]
    structure_size: u16,
    reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_cancel_roundtrip() {
        let req = CancelRequest { reserved: 0, ..Default::default() };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes[..], &[0x04, 0x00, 0x00, 0x00]);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: CancelRequest = CancelRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, req);
    }
}