//! SMB2 query directory messages.
//!
//! MS-SMB2 2.2.33–2.2.34.

use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;
use crate::dtyp::{PosMarker, SizedStringSize, SizedWideString};

/// SMB2 QUERY_DIRECTORY Request.
///
/// MS-SMB2 2.2.33
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct QueryDirectoryRequest {
    #[bw(calc = 33)]
    structure_size: u16,
    /// Directory information class, as the raw FileInformationClass byte.
    ///
    /// Kept raw so that a request with an unknown class still decodes and
    /// the server can answer STATUS_INVALID_INFO_CLASS (MS-SMB2 3.3.5.18)
    /// instead of failing the whole message. Use [`Self::info_class`].
    pub file_information_class: u8,
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

impl QueryDirectoryRequest {
    /// The requested directory information class, or `None` if the
    /// FileInformationClass byte is not a QUERY_DIRECTORY class.
    pub fn info_class(&self) -> Option<QueryDirectoryInfoClass> {
        QueryDirectoryInfoClass::try_from(self.file_information_class).ok()
    }
}

/// Directory information class (FileInformationClass values valid for
/// SMB2 QUERY_DIRECTORY).
///
/// Numeric values are the MS-FSCC §2.4 FileInformationClass codes; the
/// server's encoder (`fsinfo::build_directory_buffer`) is keyed on the
/// same numbers, so a mismatch here silently selects the wrong layout.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u8))]
pub enum QueryDirectoryInfoClass {
    /// FileDirectoryInformation (MS-FSCC §2.4.10).
    DirectoryInformation = 1,
    /// FileFullDirectoryInformation (MS-FSCC §2.4.17).
    FullDirectoryInformation = 2,
    /// FileBothDirectoryInformation (MS-FSCC §2.4.8).
    BothDirectoryInformation = 3,
    /// FileNamesInformation (MS-FSCC §2.4.33).
    NamesInformation = 12,
    /// FileIdBothDirectoryInformation (MS-FSCC §2.4.22).
    #[default]
    IdBothDirectoryInformation = 37,
    /// FileIdFullDirectoryInformation (MS-FSCC §2.4.24).
    IdFullDirectoryInformation = 38,
}

impl QueryDirectoryInfoClass {
    /// All directory information classes, in numeric order.
    pub const ALL: [Self; 6] = [
        Self::DirectoryInformation,
        Self::FullDirectoryInformation,
        Self::BothDirectoryInformation,
        Self::NamesInformation,
        Self::IdBothDirectoryInformation,
        Self::IdFullDirectoryInformation,
    ];
}

impl TryFrom<u8> for QueryDirectoryInfoClass {
    /// The unrecognised FileInformationClass byte.
    type Error = u8;

    fn try_from(code: u8) -> Result<Self, u8> {
        Self::ALL.into_iter().find(|c| *c as u8 == code).ok_or(code)
    }
}

impl From<QueryDirectoryInfoClass> for u8 {
    fn from(c: QueryDirectoryInfoClass) -> u8 {
        c as u8
    }
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
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: QueryDirectoryResponse = QueryDirectoryResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.output_buffer, vec![0x01, 0x02, 0x03]);
    }

    /// MS-FSCC §2.4 FileInformationClass codes.
    #[test]
    fn test_info_class_numeric_values() {
        use QueryDirectoryInfoClass::*;
        let expected: [(QueryDirectoryInfoClass, u8); 6] = [
            (DirectoryInformation, 1),
            (FullDirectoryInformation, 2),
            (BothDirectoryInformation, 3),
            (NamesInformation, 12),
            (IdBothDirectoryInformation, 37),
            (IdFullDirectoryInformation, 38),
        ];
        assert_eq!(expected.len(), QueryDirectoryInfoClass::ALL.len());
        for (class, code) in expected {
            assert_eq!(class as u8, code, "{class:?}");
            // Encode → single byte with the code.
            let mut buf = Cursor::new(Vec::new());
            class.write_le(&mut buf).unwrap();
            assert_eq!(buf.into_inner(), vec![code], "{class:?} encode");
            // Decode the code → same variant.
            let decoded = QueryDirectoryInfoClass::read_le(&mut Cursor::new(&[code][..])).unwrap();
            assert_eq!(decoded, class, "{code} decode");
        }
    }

    #[test]
    fn test_info_class_rejects_non_directory_codes() {
        // 14 = FilePositionInformation, 0 / 4 / 200 are not directory classes.
        for code in [0u8, 4, 14, 39, 200] {
            assert!(
                QueryDirectoryInfoClass::read_le(&mut Cursor::new(&[code][..])).is_err(),
                "code {code} must not decode as a directory class"
            );
        }
    }

    /// A QUERY_DIRECTORY request with FileDirectoryInformation (1) — what
    /// go-smb2 / rclone sends — must decode.
    #[test]
    fn test_query_directory_request_class_1_decodes() {
        let req = QueryDirectoryRequest {
            file_information_class: QueryDirectoryInfoClass::DirectoryInformation.into(),
            flags: QueryDirectoryFlags::new().with_restart_scans(true),
            file_index: 0,
            file_id: FileId::default(),
            output_buffer_length: 65536,
            file_name: "*".into(),
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes[2], 1, "FileInformationClass byte");
        let decoded = QueryDirectoryRequest::read_le(&mut Cursor::new(&bytes[..])).unwrap();
        assert_eq!(
            decoded.info_class(),
            Some(QueryDirectoryInfoClass::DirectoryInformation)
        );
        assert_eq!(decoded.file_name.to_string(), "*");
    }

    /// A request with a non-directory class (14 = FilePositionInformation,
    /// 200 = undefined) must still decode, exposing the raw byte, so the
    /// server can answer STATUS_INVALID_INFO_CLASS.
    #[test]
    fn test_query_directory_request_unknown_class_decodes_raw() {
        for code in [14u8, 200] {
            let req = QueryDirectoryRequest {
                file_information_class: code,
                flags: QueryDirectoryFlags::new(),
                file_index: 0,
                file_id: FileId::default(),
                output_buffer_length: 65536,
                file_name: "*".into(),
            };
            let mut buf = Cursor::new(Vec::new());
            req.write_le(&mut buf).unwrap();
            let decoded =
                QueryDirectoryRequest::read_le(&mut Cursor::new(&buf.into_inner()[..])).unwrap();
            assert_eq!(decoded.file_information_class, code);
            assert_eq!(decoded.info_class(), None, "code {code}");
        }
    }

    #[test]
    fn test_info_class_try_from_u8() {
        for class in QueryDirectoryInfoClass::ALL {
            assert_eq!(QueryDirectoryInfoClass::try_from(class as u8), Ok(class));
            assert_eq!(u8::from(class), class as u8);
        }
        for code in [0u8, 4, 14, 39, 200, 255] {
            assert_eq!(QueryDirectoryInfoClass::try_from(code), Err(code));
        }
    }
}
