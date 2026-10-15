//! SMB2 query/set info messages.
//!
//! MS-SMB2 2.2.37–2.2.40.

use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;
use crate::dtyp::PosMarker;

// ── InfoType (MS-SMB2 2.2.37) ─────────────────────────────────────

/// The type of information queried or set.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum InfoType {
    File = 0x1,
    FileSystem = 0x2,
    Security = 0x3,
    Quota = 0x4,
}

// ── QueryInfoClass ───────────────────────────────────────────────

/// Information class for query info requests — raw u8.
///
/// The interpretation depends on `InfoType` (a sibling field).
/// Use `QueryFileInfoClass::from(u8)` or `QueryFileSystemInfoClass::from(u8)`
/// to interpret the value based on InfoType.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(little)]
pub struct QueryInfoClass(pub u8);

/// Query file information class.
///
/// MS-FSCC §2.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u8))]
pub enum QueryFileInfoClass {
    #[default]
    BasicInformation = 4,
    StandardInformation = 5,
    InternalInformation = 6,
    EaInformation = 7,
    AccessInformation = 8,
    FileNameInformation = 9,
    NormalizedNameInformation = 10,
    AllInformation = 18,
    AttributeTagInformation = 35,
    NetworkOpenInformation = 34,
    StreamInformation = 22,
    CompressionInformation = 26,
    FullEaInformation = 15,
    PositionInformation = 14,
    ShortNameInformation = 36,
    ModeInformation = 16,
    RemoteProtocolInformation = 37,
}

impl From<u8> for QueryFileInfoClass {
    fn from(v: u8) -> Self {
        match v {
            4 => Self::BasicInformation,
            5 => Self::StandardInformation,
            6 => Self::InternalInformation,
            7 => Self::EaInformation,
            8 => Self::AccessInformation,
            9 => Self::FileNameInformation,
            10 => Self::NormalizedNameInformation,
            18 => Self::AllInformation,
            22 => Self::StreamInformation,
            34 => Self::NetworkOpenInformation,
            35 => Self::AttributeTagInformation,
            _ => Self::default(),
        }
    }
}

/// Query filesystem information class.
///
/// MS-FSCC §2.5
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u8))]
pub enum QueryFileSystemInfoClass {
    #[default]
    VolumeInformation = 1,
    SizeInformation = 3,
    DeviceInformation = 4,
    AttributeInformation = 5,
    FullSizeInformation = 7,
    SectorSizeInformation = 11,
}

impl From<u8> for QueryFileSystemInfoClass {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::VolumeInformation,
            3 => Self::SizeInformation,
            4 => Self::DeviceInformation,
            5 => Self::AttributeInformation,
            7 => Self::FullSizeInformation,
            11 => Self::SectorSizeInformation,
            _ => Self::default(),
        }
    }
}

/// Single null (0) byte.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct NullByte {
    #[bw(calc = 0)]
    #[br(assert(_null == 0))]
    _null: u8,
}

// ── AdditionalInfo (MS-SMB2 2.2.37) ───────────────────────────────

/// Additional information flags for security/EA queries.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct AdditionalInfo {
    pub owner_security_information: bool,
    pub group_security_information: bool,
    pub dacl_security_information: bool,
    pub sacl_security_information: bool,
    pub label_security_information: bool,
    pub attribute_security_information: bool,
    pub scope_security_information: bool,
    #[skip]
    __: B9,
    pub backup_security_information: bool,
    #[skip]
    __: B15,
}

// ── QueryInfoRequest (MS-SMB2 2.2.37) ────────────────────────────

/// SMB2 QUERY_INFO Request.
///
/// MS-SMB2 2.2.37
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct QueryInfoRequest {
    #[bw(calc = 41)]
    structure_size: u16,
    pub info_type: InfoType,
    pub info_class: QueryInfoClass,
    pub output_buffer_length: u32,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_buffer_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    input_buffer_length: PosMarker<u32>,
    pub additional_info: AdditionalInfo,
    pub flags: QueryInfoFlags,
    pub file_id: FileId,
    // Input buffer data is not parsed (no quota/EA queries in server).
}

/// Flags for query info EA enumeration.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct QueryInfoFlags {
    pub restart_scan: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    #[skip]
    __: B29,
}

// ── QueryInfoResponse (MS-SMB2 2.2.38) ────────────────────────────

/// SMB2 QUERY_INFO Response.
///
/// MS-SMB2 2.2.38
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct QueryInfoResponse {
    #[bw(calc = 9)]
    structure_size: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_length: PosMarker<u32>,
    /// Raw response data.
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_aoff_size, args(&output_buffer_offset, &output_buffer_length))]
    pub data: Vec<u8>,
}

impl QueryInfoResponse {
    /// Construct from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        QueryInfoResponse { data, ..Default::default() }
    }
}

// ── SetInfoRequest/Response (MS-SMB2 2.2.39–2.2.40) ───────────────

/// SMB2 SET_INFO Request.
///
/// MS-SMB2 2.2.39
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SetInfoRequest {
    #[bw(calc = 33)]
    structure_size: u16,
    pub info_type: InfoType,
    pub info_class: SetInfoClass,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    buffer_length: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _buffer_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    pub additional_information: AdditionalInfo,
    pub file_id: FileId,
    #[br(map_stream = |s| s.take_seek(buffer_length.value as u64))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_buffer_offset, &buffer_length))]
    pub data: SetInfoData,
}

/// Information class for SET_INFO — raw u8.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(little)]
pub struct SetInfoClass(pub u8);

/// Set info data — raw bytes for SET_INFO.
#[binrw::binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct SetInfoData {
    #[br(parse_with = binrw::helpers::until_eof)]
    pub raw: Vec<u8>,
}

impl SetInfoData {
    pub fn data(&self) -> &[u8] {
        &self.raw
    }
}

impl From<Vec<u8>> for SetInfoData {
    fn from(raw: Vec<u8>) -> Self {
        SetInfoData { raw }
    }
}

/// SMB2 SET_INFO Response.
///
/// MS-SMB2 2.2.40
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct SetInfoResponse {
    #[bw(calc = 2)]
    structure_size: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_query_info_response_from_bytes() {
        let resp = QueryInfoResponse::from_bytes(vec![0x01, 0x02, 0x03]);
        assert_eq!(resp.data.len(), 3);
    }

    #[test]
    fn test_set_info_response_roundtrip() {
        let resp = SetInfoResponse::default();
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn test_set_info_request_roundtrip_preserves_info_type() {
        // SET_INFO with InfoType::File, FileEndOfFileInformation (class 20).
        // This is the class that was broken by the #[br(temp)] discarding
        // info_type and dispatch using info_class as a proxy.
        let req = SetInfoRequest {
            info_type: InfoType::File,
            info_class: SetInfoClass(20),
            additional_information: AdditionalInfo::default(),
            file_id: FileId::default(),
            data: SetInfoData::from(vec![0x00; 8]),
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();

        let mut cursor = Cursor::new(&bytes[..]);
        let decoded = SetInfoRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.info_type, InfoType::File);
        assert_eq!(decoded.info_class, SetInfoClass(20));
    }

    #[test]
    fn test_set_info_request_non_file_info_type_preserved() {
        // A non-File InfoType must round-trip (it should be rejected by
        // dispatch, not silently misrouted).
        let req = SetInfoRequest {
            info_type: InfoType::Security,
            info_class: SetInfoClass(0),
            additional_information: AdditionalInfo::default(),
            file_id: FileId::default(),
            data: SetInfoData::from(vec![]),
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();

        let mut cursor = Cursor::new(&bytes[..]);
        let decoded = SetInfoRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.info_type, InfoType::Security);
    }
}
