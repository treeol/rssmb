//! Filesystem metadata serialization — converts VFS `FileInfo` / `DirEntry`
//! into MS-FSCC wire structures serialized as `Vec<u8>`.
//!
//! Used by QUERY_INFO and QUERY_DIRECTORY handlers.

use binrw::BinWrite;
use rssmb_proto::FileTime;
use rssmb_proto::fscc::{
    FileAttributes, FileBasicInformation, FileStandardInformation, FileInternalInformation,
    FileEaInformation, FileNetworkOpenInformation, FileAttributeTagInformation,
    FileDirectoryInformation, FileFullDirectoryInformation, FileBothDirectoryInformation,
    FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, FileNamesInformation,
    FileFsVolumeInformation, FileFsSizeInformation, FileFsAttributeInformation,
    FileFsDeviceInformation, FileFsFullSizeInformation, FsDeviceType, FsDeviceCharacteristics,
    FileSystemAttributes, ChainedItemList, ReparseTag,
};
use rssmb_proto::Boolean;

use rssmb_vfs::{FileInfo, DirEntry, FileId as VfsFileId};

/// Serialize a value with BinWrite into a Vec<u8>. Returns empty on failure
/// (the caller should check and return STATUS_INTERNAL_ERROR).
fn serialize<T: BinWrite>(value: &T) -> Vec<u8>
where
    for<'a> T::Args<'a>: Default,
{
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    if value.write_le(&mut cursor).is_err() {
        return Vec::new();
    }
    buf
}

/// Convert VFS FileAttributes to smb-fscc FileAttributes.
pub fn file_attributes_to_fscc(attrs: &rssmb_vfs::FileAttributes) -> FileAttributes {
    FileAttributes::new()
        .with_hidden(attrs.hidden)
        .with_system(attrs.system)
        .with_directory(attrs.directory)
        .with_archive(attrs.archive)
        .with_normal(attrs.normal)
        .with_temporary(attrs.temporary)
        .with_sparse_file(attrs.sparse_file)
        .with_reparse_point(attrs.reparse_point)
        .with_readonly(attrs.read_only)
}

// ── File information classes ────────────────────────────────────────────

pub fn file_basic_info(info: &FileInfo) -> Vec<u8> {
    serialize(&FileBasicInformation {
        creation_time: FileTime::from(info.creation_time),
        last_access_time: FileTime::from(info.last_access_time),
        last_write_time: FileTime::from(info.last_write_time),
        change_time: FileTime::from(info.change_time),
        file_attributes: file_attributes_to_fscc(&info.attributes),
    })
}

pub fn file_standard_info(info: &FileInfo) -> Vec<u8> {
    serialize(&FileStandardInformation {
        allocation_size: info.allocation_size,
        end_of_file: info.size,
        number_of_links: 1,
        delete_pending: Boolean::from(false),
        directory: Boolean::from(info.attributes.directory),
    })
}

pub fn file_internal_info(info: &FileInfo) -> Vec<u8> {
    serialize(&FileInternalInformation {
        index_number: info.file_id.0,
    })
}

pub fn file_ea_info() -> Vec<u8> {
    serialize(&FileEaInformation { ea_size: 0 })
}

pub fn file_network_open_info(info: &FileInfo) -> Vec<u8> {
    serialize(&FileNetworkOpenInformation {
        creation_time: FileTime::from(info.creation_time),
        last_access_time: FileTime::from(info.last_access_time),
        last_write_time: FileTime::from(info.last_write_time),
        change_time: FileTime::from(info.change_time),
        allocation_size: info.allocation_size,
        end_of_file: info.size,
        file_attributes: file_attributes_to_fscc(&info.attributes),
    })
}

/// FileAllInformation (class 18, MS-FSCC 2.4.2). Written by hand from the
/// spec layout so the byte offsets are explicit:
///
/// | off | size | field |
/// |----:|-----:|-------|
/// |   0 |  40  | FileBasicInformation (4×FILETIME, Attributes u32, Reserved u32) |
/// |  40 |  24  | FileStandardInformation (Alloc u64, EOF u64, Links u32, DeletePending u8, Directory u8, Reserved u16) |
/// |  64 |   8  | FileInternalInformation (IndexNumber u64) |
/// |  72 |   4  | FileEaInformation (EaSize u32) |
/// |  76 |   4  | FileAccessInformation (AccessFlags u32) |
/// |  80 |   8  | FilePositionInformation (CurrentByteOffset u64) |
/// |  88 |   4  | FileModeInformation (Mode u32) |
/// |  92 |   4  | FileAlignmentInformation (AlignmentRequirement u32) |
/// |  96 |   4  | FileNameInformation.FileNameLength u32 |
/// | 100 |   n  | FileName (UTF-16LE) |
///
/// `name` is the share-relative path with a leading `\` (empty → `\`).
pub fn file_all_info(info: &FileInfo, name: &str, granted_access: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(104 + name.len() * 2);
    let attrs = file_attributes_to_fscc(&info.attributes);
    let attrs_u32 = u32::from_le_bytes(attrs.into_bytes());
    for t in [info.creation_time, info.last_access_time, info.last_write_time, info.change_time] {
        b.extend_from_slice(&t.to_le_bytes());
    }
    b.extend_from_slice(&attrs_u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&info.allocation_size.to_le_bytes());
    b.extend_from_slice(&info.size.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
    b.push(0); // DeletePending
    b.push(info.attributes.directory as u8);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&info.file_id.0.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // EaSize
    b.extend_from_slice(&granted_access.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes()); // CurrentByteOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // Mode
    b.extend_from_slice(&0u32.to_le_bytes()); // AlignmentRequirement: byte
    let mut path = name.replace('/', "\\");
    if !path.starts_with('\\') {
        path.insert(0, '\\');
    }
    let utf16: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    b.extend_from_slice(&utf16);
    b
}

pub fn file_attribute_tag_info(info: &FileInfo) -> Vec<u8> {
    serialize(&FileAttributeTagInformation {
        file_attributes: file_attributes_to_fscc(&info.attributes),
        reparse_tag: ReparseTag::ReservedZero,
    })
}

// ── Filesystem information classes ───────────────────────────────────────

pub fn fs_volume_info() -> Vec<u8> {
    serialize(&FileFsVolumeInformation {
        volume_creation_time: FileTime::ZERO,
        volume_serial_number: 0x12345678,
        supports_objects: Boolean::from(false),
        volume_label: "".into(),
    })
}

pub fn fs_size_info() -> Vec<u8> {
    serialize(&FileFsSizeInformation {
        total_allocation_units: 1_000_000,
        available_allocation_units: 500_000,
        sectors_per_allocation_unit: 1,
        bytes_per_sector: 512,
    })
}

pub fn fs_full_size_info() -> Vec<u8> {
    serialize(&FileFsFullSizeInformation {
        total_allocation_units: 1_000_000,
        caller_available_allocation_units: 500_000,
        actual_available_allocation_units: 500_000,
        sectors_per_allocation_unit: 1,
        bytes_per_sector: 512,
    })
}

pub fn fs_attribute_info() -> Vec<u8> {
    serialize(&FileFsAttributeInformation {
        attributes: FileSystemAttributes::new()
            .with_case_preserved_names(true)
            .with_unicode_on_disk(true),
        maximum_component_name_length: 255,
        file_system_name: "NTFS".into(),
    })
}

pub fn fs_device_info() -> Vec<u8> {
    serialize(&FileFsDeviceInformation {
        device_type: FsDeviceType::Disk,
        characteristics: FsDeviceCharacteristics::new(),
    })
}

pub fn fs_sector_size_info() -> Vec<u8> {
    serialize(&rssmb_proto::fscc::FileFsSectorSizeInformation {
        logical_bytes_per_sector: 512,
        physical_bytes_per_sector: 512,
        physical_bytes_per_sector_for_performance: 512,
        effective_physical_bytes_per_sector_for_atomicity: 512,
        flags: rssmb_proto::fscc::SectorSizeInfoFlags::new(),
        byte_offset_for_sector_alignment: 0xFFFFFFFF,
        byte_offset_for_partition_alignment: 0xFFFFFFFF,
    })
}

// ── Directory enumeration ────────────────────────────────────────────────

/// Build a directory enumeration buffer for the given info class.
///
/// `class_id` is the MS-FSCC FileInformationClass value:
/// 1=FileDirectoryInformation, 2=FileFullDirectoryInformation,
/// 3=FileBothDirectoryInformation, 12=FileNamesInformation,
/// 37=FileIdBothDirectoryInformation, 38=FileIdFullDirectoryInformation.
///
/// Returns `Some(buffer)` or `None` if the class is unknown.
pub fn build_directory_buffer(
    entries: &[DirEntry],
    class_id: u8,
) -> Option<Vec<u8>> {
    match class_id {
        1 => {
            let list: ChainedItemList<FileDirectoryInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                FileDirectoryInformation {
                    file_index: i as u32,
                    creation_time: FileTime::from(e.creation_time),
                    last_access_time: FileTime::from(e.last_access_time),
                    last_write_time: FileTime::from(e.last_write_time),
                    change_time: FileTime::from(e.change_time),
                    end_of_file: e.size,
                    allocation_size: e.allocation_size,
                    file_attributes: file_attributes_to_fscc(&e.attributes),
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        2 => {
            let list: ChainedItemList<FileFullDirectoryInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                FileFullDirectoryInformation {
                    file_index: i as u32,
                    creation_time: FileTime::from(e.creation_time),
                    last_access_time: FileTime::from(e.last_access_time),
                    last_write_time: FileTime::from(e.last_write_time),
                    change_time: FileTime::from(e.change_time),
                    end_of_file: e.size,
                    allocation_size: e.allocation_size,
                    file_attributes: file_attributes_to_fscc(&e.attributes),
                    ea_size: 0,
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        3 => {
            let list: ChainedItemList<FileBothDirectoryInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                let short = e.short_name.as_deref().unwrap_or("");
                FileBothDirectoryInformation {
                    file_index: i as u32,
                    creation_time: FileTime::from(e.creation_time),
                    last_access_time: FileTime::from(e.last_access_time),
                    last_write_time: FileTime::from(e.last_write_time),
                    change_time: FileTime::from(e.change_time),
                    end_of_file: e.size,
                    allocation_size: e.allocation_size,
                    file_attributes: file_attributes_to_fscc(&e.attributes),
                    ea_size: 0,
                    short_name_length: (short.encode_utf16().count() * 2) as u8,
                    short_name: rssmb_proto::FixedWideString::from_str(short),
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        12 => {
            let list: ChainedItemList<FileNamesInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                FileNamesInformation {
                    file_index: i as u32,
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        37 => {
            let list: ChainedItemList<FileIdBothDirectoryInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                let short = e.short_name.as_deref().unwrap_or("");
                FileIdBothDirectoryInformation {
                    file_index: i as u32,
                    creation_time: FileTime::from(e.creation_time),
                    last_access_time: FileTime::from(e.last_access_time),
                    last_write_time: FileTime::from(e.last_write_time),
                    change_time: FileTime::from(e.change_time),
                    end_of_file: e.size,
                    allocation_size: e.allocation_size,
                    file_attributes: file_attributes_to_fscc(&e.attributes),
                    ea_size: 0,
                    short_name_length: (short.encode_utf16().count() * 2) as u8,
                    short_name: rssmb_proto::FixedWideString::from_str(short),
                    file_id: e.file_id.map(|f| f.0).unwrap_or(0),
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        38 => {
            let list: ChainedItemList<FileIdFullDirectoryInformation, 8> = entries.iter().enumerate().map(|(i, e)| {
                FileIdFullDirectoryInformation {
                    file_index: i as u32,
                    creation_time: FileTime::from(e.creation_time),
                    last_access_time: FileTime::from(e.last_access_time),
                    last_write_time: FileTime::from(e.last_write_time),
                    change_time: FileTime::from(e.change_time),
                    end_of_file: e.size,
                    allocation_size: e.allocation_size,
                    file_attributes: file_attributes_to_fscc(&e.attributes),
                    ea_size: 0,
                    file_id: e.file_id.map(|f| f.0).unwrap_or(0),
                    file_name: e.file_name.as_str().into(),
                }
            }).collect();
            Some(serialize(&list))
        }
        _ => None,
    }
}

/// Synthesize `.` and `..` entries for a directory listing.
pub fn synthesize_dot_entries() -> Vec<DirEntry> {
    // Compute current time as Windows FILETIME (100ns since 1601-01-01)
    const UNIX_EPOCH_FILETIME_OFFSET: u64 = 11_644_473_600;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now = (now_secs + UNIX_EPOCH_FILETIME_OFFSET) * 10_000_000;
    vec![
        DirEntry {
            file_name: ".".to_string(),
            short_name: None,
            attributes: rssmb_vfs::FileAttributes {
                directory: true,
                ..Default::default()
            },
            size: 0,
            allocation_size: 0,
            file_id: Some(VfsFileId(0)),
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        },
        DirEntry {
            file_name: "..".to_string(),
            short_name: None,
            attributes: rssmb_vfs::FileAttributes {
                directory: true,
                ..Default::default()
            },
            size: 0,
            allocation_size: 0,
            file_id: Some(VfsFileId(0)),
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_file_info() -> FileInfo {
        FileInfo {
            file_id: VfsFileId(42),
            attributes: rssmb_vfs::FileAttributes {
                directory: true,
                ..Default::default()
            },
            size: 0,
            allocation_size: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            file_name: "test".to_string(),
        }
    }

    #[test]
    fn test_file_basic_info_serialization() {
        let info = test_file_info();
        let buf = file_basic_info(&info);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_file_standard_info_serialization() {
        let info = FileInfo {
            file_id: VfsFileId(1),
            attributes: rssmb_vfs::FileAttributes::default(),
            size: 1024,
            allocation_size: 4096,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            file_name: "test".to_string(),
        };
        let buf = file_standard_info(&info);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_fs_attribute_info_has_ntfs_name() {
        let buf = fs_attribute_info();
        let ntfs_utf16: Vec<u8> = "NTFS".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(buf.windows(8).any(|w| w == &ntfs_utf16[..]));
    }

    #[test]
    fn test_directory_buffer_file_directory_information() {
        let entries = vec![
            DirEntry {
                file_name: "hello.txt".to_string(),
                short_name: None,
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 100,
                allocation_size: 512,
                file_id: Some(VfsFileId(1)),
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
            },
            DirEntry {
                file_name: "world.txt".to_string(),
                short_name: None,
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 200,
                allocation_size: 512,
                file_id: Some(VfsFileId(2)),
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
            },
        ];
        let buf = build_directory_buffer(&entries, 1).expect("class 1 should work");
        assert!(!buf.is_empty());
        // First 4 bytes = next_entry_offset (non-zero since there are 2 entries)
        let next_offset = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert!(next_offset > 0, "first entry should have non-zero next_entry_offset");
    }

    #[test]
    fn test_directory_buffer_unknown_class() {
        let entries = vec![];
        assert!(build_directory_buffer(&entries, 99).is_none());
    }
}
