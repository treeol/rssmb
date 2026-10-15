//! File System Control Codes (FSCC) wire types.
//!
//! See MS-FSCC for layout details. We implement only the types used by
//! the server: FileAttributes bitfield and the info classes for
//! QUERY_INFO / SET_INFO.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::dtyp::{Boolean, FileTime, FixedWideString, SizedStringSize, SizedWideString};

// ── FileAttributes (MS-FSCC §2.6) ──────────────────────────────────
// 4-byte LE bitfield.

/// File attributes (MS-FSCC §2.6).
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    #[skip]
    _reserved1: bool,
    pub directory: bool,
    pub archive: bool,
    #[skip]
    _reserved2: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
    pub integrity_stream: bool,
    #[skip]
    _reserved3: bool,
    pub no_scrub_data: bool,
    pub recall_on_open: bool,
    pub pinned: bool,
    pub unpinned: bool,
    #[skip]
    _reserved4: bool,
    pub recall_on_data_access: bool,
    #[skip]
    _reserved5: B9,
}

// ── FileBasicInformation (MS-FSCC §2.4.7) ──────────────────────────
// 40 bytes.

/// FileBasicInformation (MS-FSCC §2.4.7).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileBasicInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    _reserved: u32,
}

// ── FileEndOfFileInformation (MS-FSCC §2.4.13) ─────────────────────
// 8 bytes (information class 20).

/// FileEndOfFileInformation (MS-FSCC §2.4.13).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileEndOfFileInformation {
    pub end_of_file: u64,
}

// ── FileDispositionInformation (MS-FSCC §2.4.15) ──────────────────
// 1 byte (information class 13).

/// FileDispositionInformation (MS-FSCC §2.4.15).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct FileDispositionInformation {
    pub delete_pending: Boolean,
}

impl Default for FileDispositionInformation {
    fn default() -> Self {
        Self {
            delete_pending: Boolean::from(true),
        }
    }
}

// ── FileRenameInformation (MS-FSCC §2.4.36) ────────────────────────
// SMB2 variant: 20-byte fixed prefix + variable-length name.
// Information class 10.

/// FileRenameInformation SMB2 variant (MS-FSCC §2.4.36).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileRenameInformation {
    pub replace_if_exists: Boolean,
    #[bw(calc = 0u8)]
    #[br(temp)]
    _reserved1: u8,
    #[bw(calc = 0u16)]
    #[br(temp)]
    _reserved2: u16,
    #[bw(calc = 0u32)]
    #[br(temp)]
    _reserved3: u32,
    pub root_directory: u64,
    #[bw(calc = file_name.size_bytes())]
    #[br(temp)]
    _file_name_length: u32,
    #[br(args {
        size: SizedStringSize::Bytes(_file_name_length),
    })]
    pub file_name: SizedWideString,
}

// ── FileFsSectorSizeInformation (MS-FSCC §2.5.13) ────────────────
// 28 bytes.

/// SectorSizeInfoFlags (MS-FSCC §2.5.13).
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SectorSizeInfoFlags {
    pub aligned_device: bool,
    pub partition_aligned_on_device: bool,
    pub no_seek_penalty: bool,
    pub trim_enabled: bool,
    #[skip]
    _reserved: B28,
}

/// FileFsSectorSizeInformation (MS-FSCC §2.5.13).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileFsSectorSizeInformation {
    pub logical_bytes_per_sector: u32,
    pub physical_bytes_per_sector: u32,
    pub physical_bytes_per_sector_for_performance: u32,
    pub effective_physical_bytes_per_sector_for_atomicity: u32,
    pub flags: SectorSizeInfoFlags,
    pub byte_offset_for_sector_alignment: u32,
    pub byte_offset_for_partition_alignment: u32,
}

// ── Query file info types (MS-FSCC §2.4) ───────────────────────────

/// FileStandardInformation (MS-FSCC §2.4.47).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: Boolean,
    pub directory: Boolean,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,
}

/// FileInternalInformation (MS-FSCC §2.4.27).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileInternalInformation {
    pub index_number: u64,
}

/// FileEaInformation (MS-FSCC §2.4.13).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileEaInformation {
    pub ea_size: u32,
}

/// FileNetworkOpenInformation (MS-FSCC §2.4.34).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileNetworkOpenInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
}

/// Reparse tag values (MS-FSCC §2.4.21).
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u32))]
pub enum ReparseTag {
    #[default]
    ReservedZero = 0,
}

/// FileAttributeTagInformation (MS-FSCC §2.4.6).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileAttributeTagInformation {
    pub file_attributes: FileAttributes,
    pub reparse_tag: ReparseTag,
}

/// FileStreamInformation (MS-FSCC §2.4.63).
///
/// Information class 22. Reports named streams on a file.
/// Our server reports only the unnamed data stream (`::$DATA`).
///
/// Layout: NextEntryOffset(4) + StreamNameLength(4) + StreamSize(8) +
/// StreamAllocationSize(8) + StreamName(UTF-16LE, variable).
/// Last entry has NextEntryOffset = 0.
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileStreamInformation {
    /// Offset to the next entry; 0 for the last entry.
    #[bw(calc = 0u32)]
    #[br(temp)]
    _next_entry_offset: u32,
    /// Length of StreamName in bytes (UTF-16LE).
    #[bw(calc = stream_name.size())]
    #[br(temp)]
    _stream_name_length: u32,
    pub stream_size: u64,
    pub stream_allocation_size: u64,
    #[br(args { size: SizedStringSize::Bytes(_stream_name_length) })]
    pub stream_name: SizedWideString,
}

/// Stream type for FileStreamInformation (MS-FSCC §2.4.63).
/// Not used in the wire struct — the stream type is encoded in the stream
/// name (e.g. `::$DATA`). Kept for documentation.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u32))]
pub enum StreamType {
    #[default]
    DataStream = 1,
}

// ── Directory enumeration types (MS-FSCC §2.4) ────────────────────

/// FileDirectoryInformation (MS-FSCC §2.4.10).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileDirectoryInformation {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// FileFullDirectoryInformation (MS-FSCC §2.4.17).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileFullDirectoryInformation {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    pub ea_size: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reparse_tag: u32,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// FileBothDirectoryInformation (MS-FSCC §2.4.8).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileBothDirectoryInformation {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved1: u8,
    pub short_name: FixedWideString<12>,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// FileIdBothDirectoryInformation (MS-FSCC §2.4.22).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileIdBothDirectoryInformation {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved1: u8,
    pub short_name: FixedWideString<12>,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u16,
    pub file_id: u64,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// FileIdFullDirectoryInformation (MS-FSCC §2.4.24).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileIdFullDirectoryInformation {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    pub ea_size: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
    pub file_id: u64,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// FileNamesInformation (MS-FSCC §2.4.33).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileNamesInformation {
    pub file_index: u32,
    #[bw(calc = file_name.size())]
    #[br(temp)]
    _file_name_length: u32,
    #[br(args { size: SizedStringSize::Bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

// ── Filesystem info types (MS-FSCC §2.5) ──────────────────────────

/// FileFsVolumeInformation (MS-FSCC §2.5.9).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: FileTime,
    pub volume_serial_number: u32,
    #[bw(calc = volume_label.size())]
    #[br(temp)]
    _volume_label_length: u32,
    pub supports_objects: Boolean,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u8,
    #[br(args { size: SizedStringSize::Bytes(_volume_label_length) })]
    pub volume_label: SizedWideString,
}

/// FileFsSizeInformation (MS-FSCC §2.5.8).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// FileFsFullSizeInformation (MS-FSCC §2.5.4).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// FileSystemAttributes (MS-FSCC §2.5.1).
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileSystemAttributes {
    pub case_sensitive_search: bool,
    pub case_preserved_names: bool,
    pub unicode_on_disk: bool,
    pub persistent_acls: bool,
    pub file_compression: bool,
    pub volume_quotas: bool,
    pub supports_sparse_files: bool,
    pub supports_reparse_points: bool,
    pub supports_remote_storage: bool,
    #[skip]
    __: B6,
    pub volume_is_compressed: bool,
    pub supports_object_ids: bool,
    pub supports_encryption: bool,
    pub named_streams: bool,
    pub read_only_volume: bool,
    pub sequential_write_once: bool,
    pub supports_transactions: bool,
    pub supports_hard_links: bool,
    pub supports_extended_attributes: bool,
    pub supports_open_by_file_id: bool,
    pub supports_usn_journal: bool,
    pub support_integrity_streams: bool,
    pub supports_block_refcounting: bool,
    pub supports_sparse_vdl: bool,
    #[skip]
    __: B3,
}

/// FileFsAttributeInformation (MS-FSCC §2.5.1).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct FileFsAttributeInformation {
    pub attributes: FileSystemAttributes,
    pub maximum_component_name_length: u32,
    #[bw(calc = file_system_name.size())]
    #[br(temp)]
    _file_system_name_length: u32,
    #[br(args { size: SizedStringSize::Bytes(_file_system_name_length) })]
    pub file_system_name: SizedWideString,
}

/// FsDeviceType (MS-FSCC §2.5.10).
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u32))]
pub enum FsDeviceType {
    #[default]
    CdRom = 0x00000002,
    Disk = 0x00000007,
}

/// FsDeviceCharacteristics (MS-FSCC §2.5.10).
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FsDeviceCharacteristics {
    pub removable_media: bool,
    pub read_only: bool,
    pub floppy_diskette: bool,
    pub write_once_media: bool,
    pub remote: bool,
    pub device_is_mounted: bool,
    pub virtual_volume: bool,
    #[skip]
    __: bool,
    pub secure_open: bool,
    #[skip]
    __: B3,
    pub ts: bool,
    pub webda: bool,
    #[skip]
    __: B3,
    pub allow_appcontainer_traversal: bool,
    pub portable: bool,
    #[skip]
    __: B13,
}

/// FileFsDeviceInformation (MS-FSCC §2.5.10).
#[binrw::binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct FileFsDeviceInformation {
    pub device_type: FsDeviceType,
    pub characteristics: FsDeviceCharacteristics,
}

// ── ChainedItemList (MS-FSCC directory enumeration) ───────────────

use binrw::Endian;
use std::io::SeekFrom;

/// A chained item list — variable-length entries linked by next_entry_offset.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainedItemList<T, const OFFSET_PAD: u32 = 4> {
    values: Vec<T>,
}

impl<T, const OFFSET_PAD: u32> ChainedItemList<T, OFFSET_PAD> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

impl<T: binrw::BinWrite, const OFFSET_PAD: u32> binrw::BinWrite for ChainedItemList<T, OFFSET_PAD>
where
    for<'b> <T as binrw::BinWrite>::Args<'b>: Default,
{
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        for (i, item) in self.values.iter().enumerate() {
            let pos_before = writer.stream_position()?;
            let nc_pos = writer.stream_position()?;
            u32::write_options(&0u32, writer, endian, ())?;
            item.write_options(writer, endian, Default::default())?;
            if i == self.values.len() - 1 {
                break;
            }
            let pos_after_item = writer.stream_position()?;
            let pad =
                (OFFSET_PAD as u64 - (pos_after_item % OFFSET_PAD as u64)) % OFFSET_PAD as u64;
            writer.seek(SeekFrom::Current(pad as i64))?;
            let pos_after = writer.stream_position()?;
            let nc = (pos_after - pos_before) as u32;
            writer.seek(SeekFrom::Start(nc_pos))?;
            u32::write_options(&nc, writer, endian, ())?;
            writer.seek(SeekFrom::Start(pos_after))?;
        }
        Ok(())
    }
}

impl<T: binrw::BinRead, const OFFSET_PAD: u32> binrw::BinRead for ChainedItemList<T, OFFSET_PAD>
where
    for<'b> <T as binrw::BinRead>::Args<'b>: Default,
{
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let stream_end = {
            let cur = reader.stream_position()?;
            let end = reader.seek(SeekFrom::End(0))?;
            reader.seek(SeekFrom::Start(cur))?;
            end
        };
        if reader.stream_position()? == stream_end {
            return Ok(Self { values: Vec::new() });
        }
        let mut values = Vec::new();
        loop {
            let pos_before = reader.stream_position()?;
            if pos_before % OFFSET_PAD as u64 != 0 {
                return Err(binrw::Error::AssertFail {
                    pos: pos_before,
                    message: format!("ChainedItemList not aligned to {OFFSET_PAD}"),
                });
            }
            let next_off = u32::read_options(reader, endian, ())?;
            let item: T = T::read_options(reader, endian, Default::default())?;
            values.push(item);
            if next_off == 0 {
                break;
            }
            reader.seek(SeekFrom::Start(pos_before + next_off as u64))?;
        }
        Ok(Self { values })
    }
}

impl<T, const OFFSET_PAD: u32> From<Vec<T>> for ChainedItemList<T, OFFSET_PAD> {
    fn from(values: Vec<T>) -> Self {
        Self { values }
    }
}

impl<T, const OFFSET_PAD: u32> FromIterator<T> for ChainedItemList<T, OFFSET_PAD> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            values: iter.into_iter().collect(),
        }
    }
}

impl<T, const OFFSET_PAD: u32> std::ops::Deref for ChainedItemList<T, OFFSET_PAD> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T, const OFFSET_PAD: u32> std::ops::DerefMut for ChainedItemList<T, OFFSET_PAD> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T, const OFFSET_PAD: u32> Default for ChainedItemList<T, OFFSET_PAD> {
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_file_attributes_roundtrip() {
        let attrs = FileAttributes::new().with_normal(true).with_directory(true);
        let mut buf = Cursor::new(Vec::new());
        attrs.write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FileAttributes = FileAttributes::read(&mut cursor).unwrap();
        assert!(decoded.normal());
        assert!(decoded.directory());
        assert!(!attrs.archive());
    }

    #[test]
    fn test_file_attributes_archive() {
        let attrs = FileAttributes::new().with_archive(true);
        assert_eq!(attrs.into_bytes(), [0x20, 0, 0, 0]);
    }

    #[test]
    fn test_file_basic_information_size() {
        let info = FileBasicInformation::default();
        let mut buf = Cursor::new(Vec::new());
        info.write(&mut buf).unwrap();
        assert_eq!(buf.into_inner().len(), 40);
    }

    #[test]
    fn test_file_end_of_file_information() {
        let info = FileEndOfFileInformation { end_of_file: 777 };
        let mut buf = Cursor::new(Vec::new());
        info.write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[..], &[0x09, 0x03, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_file_rename_information() {
        let info = FileRenameInformation {
            replace_if_exists: Boolean::from(false),
            root_directory: 0,
            file_name: SizedWideString::from_str("test.txt"),
        };
        let mut buf = Cursor::new(Vec::new());
        info.write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 20 + 16); // prefix + "test.txt" in UTF-16LE
    }

    #[test]
    fn test_sector_size_info_flags() {
        let flags = SectorSizeInfoFlags::new()
            .with_aligned_device(true)
            .with_partition_aligned_on_device(true);
        assert_eq!(flags.into_bytes(), [0x03, 0, 0, 0]);
    }
}
