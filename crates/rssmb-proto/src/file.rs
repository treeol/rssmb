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
    #[br(assert(_data_length > 0))]
    #[br(temp)]
    _data_length: u32,
    #[bw(calc = 0)]
    #[br(assert(_data_remaining == 0))]
    #[br(temp)]
    _data_remaining: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
    /// Data read from the file.
    #[br(count = _data_length)]
    #[bw(assert(!buffer.is_empty()))]
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
            file_id: FileId { persistent: 1, volatile: 2 },
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 24);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FlushRequest = FlushRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.file_id, FileId { persistent: 1, volatile: 2 });
    }

    #[test]
    fn test_read_request_roundtrip() {
        let req = ReadRequest {
            flags: ReadFlags::new(),
            length: 1024,
            offset: 0,
            file_id: FileId { persistent: 1, volatile: 2 },
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
        let resp = WriteResponse { count: 42, ..Default::default() };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: WriteResponse = WriteResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.count, 42);
    }
}