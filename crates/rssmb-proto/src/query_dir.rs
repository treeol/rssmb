//! SMB2 query directory messages.
//!
//! MS-SMB2 2.2.33–2.2.34.

use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;
use crate::dtyp::{PosMarker, SizedWideString, SizedStringSize};

/// SMB2 QUERY_DIRECTORY Request.
///
/// MS-SMB2 2.2.33
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct QueryDirectoryRequest {
    #[bw(calc = 33)]
    structure_size: u16,
    /// Directory information class.
    pub file_information_class: QueryDirectoryInfoClass,
    /// Flags for the query.
    pub flags: QueryDirectoryFlags,
    #[bw(assert(flags.index_specified() || *file_index == 0))]
    pub file_index: u32,
    /// Directory file identifier.
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    pub file_name_offset: PosMarker<u16>,
    #[bw(try_calc = file_name.size_bytes().try_into())]
    #[br(temp)]
    file_name_length: u16,
    /// Maximum bytes the server can return.
    pub output_buffer_length: u32,
    /// Unicode search pattern.
    #[br(seek_before = SeekFrom::Start(file_name_offset.value as u64))]
    #[br(args { size: SizedStringSize::Bytes16(file_name_length) })]
    #[bw(write_with = PosMarker::write_aoff, args(&file_name_offset))]
    pub file_name: SizedWideString,
}

/// Directory information class.
///
/// MS-FSCC §2.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u8))]
pub enum QueryDirectoryInfoClass {
    #[default]
    IdBothDirectoryInformation = 37,
    IdFullDirectoryInformation = 38,
    BothDirectoryInformation = 3,
    DirectoryInformation = 2,
    FullDirectoryInformation = 14,
}

/// Flags for query directory.
///
/// MS-SMB2 2.2.33
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct QueryDirectoryFlags {
    pub restart_scans: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    pub reopen: bool,
    #[skip]
    __: B4,
}

/// SMB2 QUERY_DIRECTORY Response.
///
/// MS-SMB2 2.2.34
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct QueryDirectoryResponse {
    #[bw(calc = 9)]
    structure_size: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_offset: PosMarker<u16>,
    #[bw(try_calc = output_buffer.len().try_into())]
    #[br(temp)]
    output_buffer_length: u32,
    /// Directory enumeration data.
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length as u64), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_aoff, args(&output_buffer_offset))]
    pub output_buffer: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_query_directory_response_roundtrip() {
        let resp = QueryDirectoryResponse {
            output_buffer: vec![0x01, 0x02, 0x03],
            ..Default::default()
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: QueryDirectoryResponse = QueryDirectoryResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.output_buffer, vec![0x01, 0x02, 0x03]);
    }
}