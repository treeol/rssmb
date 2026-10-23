//! SMB2 file I/O messages: flush, read, write.
//!
//! MS-SMB2 2.2.17–2.2.22.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;
use crate::dtyp::PosMarker;

/// SMB2 FLUSH Request.
///
/// MS-SMB2 2.2.17
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct FlushRequest {
    #[bw(calc = 24)]
    #[br(temp)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
    pub file_id: FileId,
}

/// SMB2 FLUSH Response.
///
/// MS-SMB2 2.2.18
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct FlushResponse {
    #[bw(calc = 4)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
}

/// SMB2 READ Request.
///
/// MS-SMB2 2.2.19
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct ReadRequest {
    #[bw(calc = 49)]
    #[br(temp)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _padding: u8,
    pub flags: ReadFlags,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    #[bw(calc = CommunicationChannel::None)]
    #[br(assert(channel == CommunicationChannel::None))]
    #[br(temp)]
    channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(assert(_remaining_bytes == 0))]
    #[br(temp)]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_offset == 0))]
    #[br(temp)]
    _read_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_length == 0))]
    #[br(temp)]
    _read_channel_info_length: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _pad_blob_placeholder: u8,
}

/// SMB2 READ Response.
///
/// MS-SMB2 2.2.20
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct ReadResponse {
    #[bw(calc = 17)]
    structure_size: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _data_offset: PosMarker<u8>,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u8,
    #[bw(try_calc = buffer.len().try_into())]
    #[br(temp)]
    _data_length: u32,
    #[bw(calc = 0)]
    #[br(assert(_data_remaining == 0))]
    #[br(temp)]
    _data_remaining: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
    /// Data read from the file. May be empty: a 0-byte READ (Length=0) is
    /// a legal request answered with OK + DataLength=0 (torture
    /// zerobyteread; MS-SMB2 2.2.19 has no minimum DataLength).
    #[br(count = _data_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub buffer: Vec<u8>,
}

/// Flags for read operations.
///
/// MS-SMB2 2.2.19
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ReadFlags {
    pub read_unbuffered: bool,
    pub read_compressed: bool,
    #[skip]
    __: B6,
}

/// Communication channel types for SMB Direct.
///
/// MS-SMB2 2.2.19
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u32))]
pub enum CommunicationChannel {
    #[default]
    None = 0,
    RdmaV1 = 1,
    RdmaV1Invalidate = 2,
}

/// SMB2 WRITE Request.
///
/// MS-SMB2 2.2.21
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct WriteRequest {
    #[bw(calc = 49)]
    structure_size: u16,
    #[bw(calc = PosMarker::new(0))]
    #[br(temp)]
    _data_offset: PosMarker<u16>,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    #[bw(calc = CommunicationChannel::None)]
    #[br(temp)]
    #[br(assert(channel == CommunicationChannel::None))]
    pub channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_write_channel_info_offset == 0))]
    _write_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_write_channel_info_length == 0))]
    _write_channel_info_length: u16,
    pub flags: WriteFlags,
    /// Write data offset — the write data itself is extracted from the
    /// raw frame by the dispatcher, not by the binrw decoder.
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub _write_offset: (),
}

/// SMB2 WRITE Response.
///
/// MS-SMB2 2.2.22
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct WriteResponse {
    #[bw(calc = 17)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    pub count: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved3: u16,
}

/// Flags for write operations.
///
/// MS-SMB2 2.2.21
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct WriteFlags {
    pub write_unbuffered: bool,
    pub write_through: bool,
    #[skip]
    __: B30,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_flush_request_roundtrip() {
        let req = FlushRequest {
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 24);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FlushRequest = FlushRequest::read_le(&mut cursor).unwrap();
        assert_eq!(
            decoded.file_id,
            FileId {
                persistent: 1,
                volatile: 2
            }
        );
    }

    #[test]
    fn test_read_request_roundtrip() {
        let req = ReadRequest {
            flags: ReadFlags::new(),
            length: 1024,
            offset: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            minimum_count: 1,
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 49);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ReadRequest = ReadRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.length, 1024);
    }

    #[test]
    fn test_write_response_roundtrip() {
        let resp = WriteResponse { count: 42 };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: WriteResponse = WriteResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.count, 42);
    }

    #[test]
    fn test_write_request_roundtrip() {
        let req = WriteRequest {
            length: 1024,
            offset: 4096,
            file_id: FileId {
                persistent: 0xDEAD,
                volatile: 0xBEEF,
            },
            flags: WriteFlags::new().with_write_through(true),
            _write_offset: (),
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // WriteRequest fixed part: 2+2+4+8+16+4+2+2+4+1 = 47 bytes, but with
        // the _write_offset: () field (0 bytes), the total is 48 bytes.
        assert_eq!(bytes.len(), 48);
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 49);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: WriteRequest = WriteRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.length, 1024);
        assert_eq!(decoded.offset, 4096);
        assert_eq!(
            decoded.file_id,
            FileId {
                persistent: 0xDEAD,
                volatile: 0xBEEF
            }
        );
        assert!(decoded.flags.write_through());
    }

    #[test]
    fn test_read_response_roundtrip_with_data() {
        let resp = ReadResponse {
            buffer: vec![0x41; 16],
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ReadResponse = ReadResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.buffer, vec![0x41; 16]);
    }

    #[test]
    fn test_read_response_zero_byte_roundtrip() {
        // A 0-byte READ response (DataLength=0) is legal — torture
        // zerobyteread; the old encoder asserted non-empty and killed the
        // connection (encode_response returned empty).
        let resp = ReadResponse { buffer: vec![] };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 16, "StructureSize(2)+DataOffset(1)+Reserved(1)+DataLength(4)+DataRemaining(4)+Reserved(4), 0 data");
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ReadResponse = ReadResponse::read_le(&mut cursor).unwrap();
        assert!(decoded.buffer.is_empty());
    }

    #[test]
    fn test_read_flags_roundtrip() {
        let flags = ReadFlags::new().with_read_unbuffered(true);
        let mut buf = Cursor::new(Vec::new());
        flags.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0x01);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ReadFlags = ReadFlags::read_le(&mut cursor).unwrap();
        assert!(decoded.read_unbuffered());
        assert!(!decoded.read_compressed());
    }

    #[test]
    fn test_write_flags_roundtrip() {
        let flags = WriteFlags::new().with_write_through(true);
        let mut buf = Cursor::new(Vec::new());
        flags.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: WriteFlags = WriteFlags::read_le(&mut cursor).unwrap();
        assert!(decoded.write_through());
        assert!(!decoded.write_unbuffered());
    }

    #[test]
    fn test_flush_response_roundtrip() {
        let resp = FlushResponse::default();
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4); // StructureSize=4 per MS-SMB2 2.2.18
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FlushResponse = FlushResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, FlushResponse::default());
    }
}
