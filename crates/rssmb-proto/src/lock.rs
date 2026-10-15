//! SMB2 LOCK request and response messages.
//!
//! MS-SMB2 2.2.26–2.2.27.

use binrw::prelude::*;

use crate::create::FileId;

/// SMB2 LOCK Request.
///
/// MS-SMB2 2.2.26
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct LockRequest {
    #[bw(calc = 48)]
    #[br(temp)]
    structure_size: u16,
    /// Number of LOCK_ELEMENT structures in the Locks array.
    #[bw(try_calc(u16::try_from(locks.len())))]
    #[br(temp)]
    lock_count: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    lock_sequence: u32,
    /// The file handle to lock.
    pub file_id: FileId,
    /// Array of LOCK_ELEMENT structures (each 24 bytes).
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

/// A single lock element within a LOCK request.
///
/// MS-SMB2 2.2.26.1 — 24 bytes (Offset(8) + Length(8) + Flags(4) + Reserved(4)).
#[binrw::binrw]
#[derive(Debug, Clone, Copy)]
#[brw(little)]
pub struct LockElement {
    /// Starting byte offset of the lock range.
    pub offset: u64,
    /// Length in bytes of the lock range.
    pub length: u64,
    /// Lock flags (SMB2_LOCKFLAG_*).
    pub flags: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
}

/// SMB2 LOCK Response.
///
/// MS-SMB2 2.2.27
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct LockResponse {
    #[bw(calc = 4)]
    #[br(temp)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
}

/// Lock flags (MS-SMB2 2.2.26.1).
pub mod lock_flags {
    pub const SHARED: u32 = 0x01;
    pub const EXCLUSIVE: u32 = 0x02;
    pub const UNLOCK: u32 = 0x04;
    pub const FAIL_IMMEDIATELY: u32 = 0x10;
    pub const RANGE: u32 = 0x20;
    pub const ALL: u32 = 0x40;
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_lock_request_roundtrip() {
        let req = LockRequest {
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            locks: vec![LockElement {
                offset: 0,
                length: 1024,
                flags: lock_flags::EXCLUSIVE,
            }],
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 48); // 24 header + 24 first element
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LockRequest = LockRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.locks.len(), 1);
        assert_eq!(decoded.locks[0].offset, 0);
        assert_eq!(decoded.locks[0].length, 1024);
        assert_eq!(decoded.locks[0].flags, lock_flags::EXCLUSIVE);
    }

    #[test]
    fn test_lock_response_roundtrip() {
        let resp = LockResponse::default();
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LockResponse = LockResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, LockResponse::default());
    }

    #[test]
    fn test_lock_request_multiple_elements() {
        let req = LockRequest {
            file_id: FileId {
                persistent: 10,
                volatile: 20,
            },
            locks: vec![
                LockElement {
                    offset: 0,
                    length: 100,
                    flags: lock_flags::SHARED,
                },
                LockElement {
                    offset: 200,
                    length: 50,
                    flags: lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY,
                },
            ],
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // 24 header + 24*2 = 72
        assert_eq!(bytes.len(), 72);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LockRequest = LockRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.locks.len(), 2);
        assert_eq!(
            decoded.locks[1].flags,
            lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY
        );
    }
}
