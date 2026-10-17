//! SMB2 Echo request and response.
//!
//! MS-SMB2 2.2.28, 2.2.29.

use binrw::prelude::*;

/// SMB2 Echo request/response (4 bytes each, identical structure).
///
/// MS-SMB2 2.2.28 / 2.2.29
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct EchoMessage {
    #[bw(calc = 4)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
}

/// Echo Request is the same as Echo Response.
pub use EchoMessage as EchoRequest;
/// Echo Response is the same as Echo Request.
pub use EchoMessage as EchoResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_echo_roundtrip() {
        let echo = EchoRequest::default();
        let mut buf = Cursor::new(Vec::new());
        echo.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes[..], &[0x04, 0x00, 0x00, 0x00]);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: EchoResponse = EchoResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, echo);
    }
}
