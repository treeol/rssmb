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
    FileStreamInformation,
};
use rssmb_proto::Boolean;

use rssmb_vfs::{FileInfo, DirEntry, FileId as VfsFileId, FsStats, SecurityInfo};

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

/// FileStreamInformation (class 22, MS-FSCC §2.4.63).
/// Reports the unnamed data stream (`::$DATA`) only.
/// Returns an empty buffer for directories (directories have no streams).
pub fn file_stream_info(info: &FileInfo) -> Vec<u8> {
    if info.attributes.directory {
        // Directories don't have a $DATA stream. Return empty buffer.
        return Vec::new();
    }
    let stream = FileStreamInformation {
        stream_size: info.size,
        stream_allocation_size: info.allocation_size,
        stream_name: "::$DATA".into(),
    };
    serialize(&stream)
}

// ── Filesystem information classes ───────────────────────────────────────

pub fn fs_volume_info(share_name: &str) -> Vec<u8> {
    // Stable volume serial: hash of the share name. This is stable across
    // restarts and unique per share (deterministic).
    let serial = {
        let mut hash: u32 = 0x811c9dc5; // FNV-1a offset basis
        for b in share_name.as_bytes() {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(0x0100_0193); // FNV-1a prime
        }
        hash
    };
    serialize(&FileFsVolumeInformation {
        volume_creation_time: FileTime::ZERO,
        volume_serial_number: serial,
        supports_objects: Boolean::from(false),
        volume_label: "".into(),
    })
}

pub fn fs_size_info(stats: &FsStats) -> Vec<u8> {
    serialize(&FileFsSizeInformation {
        total_allocation_units: stats.total_blocks,
        available_allocation_units: stats.available_blocks,
        sectors_per_allocation_unit: (stats.block_size / stats.sector_size) as u32,
        bytes_per_sector: stats.sector_size as u32,
    })
}

pub fn fs_full_size_info(stats: &FsStats) -> Vec<u8> {
    serialize(&FileFsFullSizeInformation {
        total_allocation_units: stats.total_blocks,
        caller_available_allocation_units: stats.available_blocks,
        actual_available_allocation_units: stats.free_blocks,
        sectors_per_allocation_unit: (stats.block_size / stats.sector_size) as u32,
        bytes_per_sector: stats.sector_size as u32,
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

pub fn fs_sector_size_info(stats: &FsStats) -> Vec<u8> {
    serialize(&rssmb_proto::fscc::FileFsSectorSizeInformation {
        logical_bytes_per_sector: stats.sector_size as u32,
        physical_bytes_per_sector: stats.sector_size as u32,
        physical_bytes_per_sector_for_performance: stats.sector_size as u32,
        effective_physical_bytes_per_sector_for_atomicity: stats.sector_size as u32,
        flags: rssmb_proto::fscc::SectorSizeInfoFlags::new(),
        byte_offset_for_sector_alignment: 0xFFFFFFFF,
        byte_offset_for_partition_alignment: 0xFFFFFFFF,
    })
}

// ── Security descriptor synthesis ───────────────────────────────────────

/// SECURITY_INFORMATION flags (MS-SMB2 2.2.37 AdditionalInfo).
/// We honor OWNER (1), GROUP (2), DACL (4) and ignore SACL (8), LABEL,
/// ATTRIBUTE, SCOPE, BACKUP — returning what we can.
const SECURITY_OWNER: u32 = 0x00000001;
const SECURITY_GROUP: u32 = 0x00000002;
const SECURITY_DACL: u32 = 0x00000004;
const _SECURITY_SACL: u32 = 0x00000008;

/// Build a minimal self-relative security descriptor from POSIX mode bits.
///
/// Layout (self-relative SD, MS-DTYP §2.4.6):
/// ```text
/// offset  size  field
///      0     1  Revision (1)
///      1     1  Sbz1 (0)
///      2     2  Control (SE_SELF_RELATIVE = 0x8000)
///      4     4  Offset to Owner SID (0 if none)
///      8     4  Offset to Group SID (0 if none)
///     12     4  Offset to DACL (0 if none)
///     16     4  Offset to SACL (0 if none)
/// ```
/// Followed by the SID and ACL structures.
///
/// Owner SID: `S-1-22-1-<uid>` (Samba "Unix Users" convention).
/// Group SID: `S-1-22-2-<gid>` (Samba "Unix Groups" convention).
/// DACL: ACCESS_ALLOWED_ACE for owner, group, and Everyone, mapping the
/// POSIX rwx bits to FILE_GENERIC_READ/WRITE/EXECUTE rights.
pub fn synthesize_security_descriptor(sec_info: &SecurityInfo, additional_info: u32) -> Vec<u8> {
    let want_owner = additional_info & SECURITY_OWNER != 0;
    let want_group = additional_info & SECURITY_GROUP != 0;
    let want_dacl = additional_info & SECURITY_DACL != 0;

    // Build the SIDs.
    let owner_sid = build_sid_unix_user(sec_info.uid);
    let group_sid = build_sid_unix_group(sec_info.gid);

    // Build the DACL with ACEs mapping POSIX mode bits.
    // Use owner/group SIDs for per-class ACEs, not Everyone for all.
    let dacl = if want_dacl {
        Some(build_dacl(sec_info.mode, sec_info.uid, sec_info.gid))
    } else {
        None
    };

    // SD header is 20 bytes. Field order per MS-DTYP §2.4.6:
    // Revision(1), Sbz1(1), Control(2), OwnerOffset(4), GroupOffset(4),
    // SaclOffset(4), DaclOffset(4).
    let mut offset = 20u32;

    let owner_offset = if want_owner {
        let off = offset;
        offset += owner_sid.len() as u32;
        off
    } else {
        0
    };

    let group_offset = if want_group {
        let off = offset;
        offset += group_sid.len() as u32;
        off
    } else {
        0
    };

    // SACL is never present (offset 0).
    let sacl_offset = 0u32;

    let dacl_offset = if dacl.is_some() {
        let off = offset;
        offset += dacl.as_ref().unwrap().len() as u32;
        off
    } else {
        0
    };

    // Control flags: SE_SELF_RELATIVE (0x8000) | SE_DACL_PRESENT (0x0004).
    let control: u16 = if want_dacl { 0x8004 } else { 0x8000 };

    // Assemble the SD.
    let mut buf = Vec::with_capacity(offset as usize);

    // ── SD header (20 bytes) ──
    buf.push(1); // Revision
    buf.push(0); // Sbz1
    buf.extend_from_slice(&control.to_le_bytes()); // Control
    buf.extend_from_slice(&owner_offset.to_le_bytes()); // Owner offset
    buf.extend_from_slice(&group_offset.to_le_bytes()); // Group offset
    buf.extend_from_slice(&sacl_offset.to_le_bytes()); // SACL offset
    buf.extend_from_slice(&dacl_offset.to_le_bytes()); // DACL offset

    // ── Owner SID ──
    if want_owner {
        buf.extend_from_slice(&owner_sid);
    }
    // ── Group SID ──
    if want_group {
        buf.extend_from_slice(&group_sid);
    }
    // ── DACL ──
    if let Some(dacl_bytes) = &dacl {
        buf.extend_from_slice(dacl_bytes);
    }

    buf
}

/// Build a SID: `S-1-<id_auth>-<sub_authorities...>`.
///
/// SID layout (MS-DTYP §2.4.2):
/// - Revision (1 byte): 1
/// - SubAuthorityCount (1 byte)
/// - IdentifierAuthority (6 bytes, big-endian)
/// - SubAuthority[] (4 bytes each, LE)
fn build_sid(identifier_authority: u64, sub_authorities: &[u32]) -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1); // Revision
    sid.push(sub_authorities.len() as u8);
    sid.extend_from_slice(&identifier_authority.to_be_bytes()[2..]); // 6 bytes
    for &sa in sub_authorities {
        sid.extend_from_slice(&sa.to_le_bytes());
    }
    sid
}

/// `S-1-22-1-<uid>` — Samba "Unix Users" convention.
fn build_sid_unix_user(uid: u32) -> Vec<u8> {
    // IdentifierAuthority = 22 (Unix), SubAuthorities = [1, uid]
    build_sid(22, &[1, uid])
}

/// `S-1-22-2-<gid>` — Samba "Unix Groups" convention.
fn build_sid_unix_group(gid: u32) -> Vec<u8> {
    build_sid(22, &[2, gid])
}

/// `S-1-1-0` — Everyone (World).
fn build_sid_everyone() -> Vec<u8> {
    // S-1-1-0: IdentifierAuthority=1, SubAuthorities=[0]
    build_sid(1, &[0])
}

/// Build a minimal DACL mapping POSIX mode bits to ACCESS_ALLOWED ACEs.
///
/// POSIX rwx → Windows rights:
/// - owner r → FILE_GENERIC_READ, owner w → FILE_GENERIC_WRITE, owner x → FILE_GENERIC_EXECUTE
/// - group r/w/x → same mapping
/// - other r/w/x → same mapping (Everyone SID)
///
/// **Note:** This is a documented approximate compatibility projection,
/// not an exact POSIX-mode-to-ACL translation. Windows allow ACEs accumulate,
/// while POSIX selects the applicable permission class. The SD is metadata
/// for the client (Explorer Properties dialog); actual authorization is
/// enforced by the server layer, not by this DACL.
///
/// ACL layout (MS-DTYP §2.4.3):
/// - AclRevision (1 byte): 2
/// - Sbz1 (1 byte): 0
/// - AclSize (2 bytes): total ACL size including header
/// - AceCount (2 bytes): number of ACEs
/// - Sbz2 (2 bytes): 0
/// - ACEs...
fn build_dacl(mode: u32, uid: u32, gid: u32) -> Vec<u8> {
    let owner_rwx = (mode >> 6) & 0o7;
    let group_rwx = (mode >> 3) & 0o7;
    let other_rwx = mode & 0o7;

    let owner_sid = build_sid_unix_user(uid);
    let group_sid = build_sid_unix_group(gid);
    let everyone_sid = build_sid_everyone();

    let mut aces: Vec<Vec<u8>> = Vec::new();

    // Owner ACE
    let owner_mask = rwx_to_mask(owner_rwx);
    if owner_mask != 0 {
        aces.push(build_ace_allowed(owner_mask, &owner_sid));
    }

    // Group ACE
    let group_mask = rwx_to_mask(group_rwx);
    if group_mask != 0 {
        aces.push(build_ace_allowed(group_mask, &group_sid));
    }

    // Other (Everyone) ACE
    let other_mask = rwx_to_mask(other_rwx);
    if other_mask != 0 {
        aces.push(build_ace_allowed(other_mask, &everyone_sid));
    }

    // ACL header is 8 bytes: Revision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
    let acl_size = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
    let ace_count = aces.len() as u16;
    let mut acl = Vec::with_capacity(acl_size);
    acl.push(2); // AclRevision
    acl.push(0); // Sbz1
    acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
    acl.extend_from_slice(&ace_count.to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    for ace in &aces {
        acl.extend_from_slice(ace);
    }

    acl
}

/// Map POSIX rwx bits (3-bit) to a Windows access mask.
///
/// FILE_GENERIC_READ = 0x00120089
/// FILE_GENERIC_WRITE = 0x00120116
/// FILE_GENERIC_EXECUTE = 0x001200a0
fn rwx_to_mask(rwx: u32) -> u32 {
    let mut mask = 0u32;
    if rwx & 0o4 != 0 {
        mask |= 0x0012_0089; // FILE_GENERIC_READ
    }
    if rwx & 0o2 != 0 {
        mask |= 0x0012_0116; // FILE_GENERIC_WRITE
    }
    if rwx & 0o1 != 0 {
        mask |= 0x0012_00a0; // FILE_GENERIC_EXECUTE
    }
    mask
}

/// Build an ACCESS_ALLOWED_ACE (MS-DTYP §2.4.4.3).
fn build_ace_allowed(mask: u32, sid: &[u8]) -> Vec<u8> {
    let ace_size = 4 + 4 + sid.len(); // header + mask + sid
    let mut ace = Vec::with_capacity(ace_size);
    ace.push(0); // AceType = ACCESS_ALLOWED
    ace.push(0); // AceFlags
    ace.extend_from_slice(&(ace_size as u16).to_le_bytes()); // AceSize
    ace.extend_from_slice(&mask.to_le_bytes()); // Mask
    ace.extend_from_slice(sid); // SID
    ace
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

    // --- Golden-byte tests for QUERY_INFO file classes ---

    #[test]
    fn test_file_basic_info_golden_bytes() {
        let info = FileInfo {
            file_id: VfsFileId(42),
            attributes: rssmb_vfs::FileAttributes {
                directory: true,
                ..Default::default()
            },
            size: 0,
            allocation_size: 0,
            creation_time: 0x0102030405060708,
            last_access_time: 0x090A0B0C0D0E0F10,
            last_write_time: 0x1112131415161718,
            change_time: 0x191A1B1C1D1E1F20,
            file_name: "test".to_string(),
        };
        let buf = file_basic_info(&info);
        // FileBasicInformation: 4×FILETIME(8) + Attributes(4) + Reserved(4) = 40 bytes
        assert_eq!(buf.len(), 40);
        // Verify creation_time bytes (LE)
        assert_eq!(&buf[0..8], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(&buf[8..16], &0x090A0B0C0D0E0F10u64.to_le_bytes());
        assert_eq!(&buf[16..24], &0x1112131415161718u64.to_le_bytes());
        assert_eq!(&buf[24..32], &0x191A1B1C1D1E1F20u64.to_le_bytes());
        // Attributes at offset 32 (directory bit = 0x10 in MS-FSCC)
        let attrs = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(attrs & 0x10, 0x10, "directory bit should be set");
        // Reserved at offset 36
        assert_eq!(&buf[36..40], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_file_standard_info_golden_bytes() {
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
        // FileStandardInformation: AllocSize(8) + EOF(8) + NumLinks(4) + DelPending(1) + Dir(1) + Reserved(2) = 24
        assert_eq!(buf.len(), 24);
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 1024);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 1); // NumberOfLinks
        assert_eq!(buf[20], 0); // DeletePending = false
        assert_eq!(buf[21], 0); // Directory = false
    }

    #[test]
    fn test_file_internal_info_golden_bytes() {
        let info = FileInfo {
            file_id: VfsFileId(0xDEADBEEF),
            ..test_file_info()
        };
        let buf = file_internal_info(&info);
        // FileInternalInformation: IndexNumber(u64) = 8 bytes
        assert_eq!(buf.len(), 8);
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0xDEADBEEF);
    }

    #[test]
    fn test_file_network_open_info_golden_bytes() {
        let info = FileInfo {
            file_id: VfsFileId(1),
            attributes: rssmb_vfs::FileAttributes {
                read_only: true,
                ..Default::default()
            },
            size: 2048,
            allocation_size: 4096,
            creation_time: 100,
            last_access_time: 200,
            last_write_time: 300,
            change_time: 400,
            file_name: "test".to_string(),
        };
        let buf = file_network_open_info(&info);
        // FileNetworkOpenInformation: 4×FILETIME(8) + AllocSize(8) + EOF(8) + Attrs(4) + Reserved(4) = 56
        assert_eq!(buf.len(), 56);
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 100);
        assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), 2048);
        let attrs = u32::from_le_bytes(buf[48..52].try_into().unwrap());
        assert_eq!(attrs & 0x01, 0x01, "readonly bit should be set");
    }

    #[test]
    fn test_file_all_info_golden_bytes() {
        let info = FileInfo {
            file_id: VfsFileId(42),
            attributes: rssmb_vfs::FileAttributes {
                directory: true,
                ..Default::default()
            },
            size: 100,
            allocation_size: 512,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            file_name: "dir".to_string(),
        };
        let buf = file_all_info(&info, "dir", 0x001f_01ff);
        // Fixed 96 bytes + 4 (FileNameLength) + UTF-16LE of "\dir" (8 bytes)
        assert_eq!(buf.len(), 96 + 4 + 8);
        // FilePositionInformation at offset 80 (u64 = 0)
        assert_eq!(u64::from_le_bytes(buf[80..88].try_into().unwrap()), 0);
        // FileNameLength at offset 96 (u32 = 8)
        assert_eq!(u32::from_le_bytes(buf[96..100].try_into().unwrap()), 8);
        // FileName starts at offset 100, should be "\dir" in UTF-16LE
        let expected: Vec<u16> = "\\dir".encode_utf16().collect();
        for (i, &ch) in expected.iter().enumerate() {
            assert_eq!(
                u16::from_le_bytes(buf[100 + i * 2..102 + i * 2].try_into().unwrap()),
                ch
            );
        }
    }

    #[test]
    fn test_file_attribute_tag_info_golden_bytes() {
        let info = FileInfo {
            file_id: VfsFileId(1),
            attributes: rssmb_vfs::FileAttributes {
                archive: true,
                ..Default::default()
            },
            ..test_file_info()
        };
        let buf = file_attribute_tag_info(&info);
        // FileAttributeTagInformation: Attributes(4) + ReparseTag(4) = 8
        assert_eq!(buf.len(), 8);
        let attrs = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(attrs & 0x20, 0x20, "archive bit should be set");
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 0); // ReparseTag = 0
    }

    // --- Golden-byte tests for QUERY_DIRECTORY classes ---

    #[test]
    fn test_directory_buffer_class_37_id_both_golden() {
        let entries = vec![
            DirEntry {
                file_name: "a.txt".to_string(),
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
        ];
        let buf = build_directory_buffer(&entries, 37).expect("class 37 should work");
        assert!(!buf.is_empty());
        // First 4 bytes = next_entry_offset (0 for last entry)
        let next_off = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(next_off, 0, "single entry should have next_entry_offset=0");
        // file_index at offset 4
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn test_directory_buffer_class_38_id_full_golden() {
        let entries = vec![
            DirEntry {
                file_name: "b.txt".to_string(),
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
        let buf = build_directory_buffer(&entries, 38).expect("class 38 should work");
        assert!(!buf.is_empty());
        let next_off = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(next_off, 0, "single entry should have next_entry_offset=0");
    }

    #[test]
    fn test_directory_buffer_class_12_names_golden() {
        let entries = vec![
            DirEntry {
                file_name: "only_name.txt".to_string(),
                short_name: None,
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 0,
                allocation_size: 0,
                file_id: None,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
            },
        ];
        let buf = build_directory_buffer(&entries, 12).expect("class 12 should work");
        assert!(!buf.is_empty());
        // FileNamesInformation: next_offset(4) + file_index(4) + name_length(4) + name
        let next_off = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(next_off, 0);
        let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(name_len, "only_name.txt".encode_utf16().count() as u32 * 2);
    }

    // --- Golden-byte tests for filesystem info classes ---

    #[test]
    fn test_fs_size_info_golden_bytes() {
        let stats = FsStats {
            total_blocks: 1_000_000,
            available_blocks: 500_000,
            free_blocks: 500_000,
            block_size: 512,
            sector_size: 512,
        };
        let buf = fs_size_info(&stats);
        // FileFsSizeInformation: TotalAllocUnits(8) + AvailableAllocUnits(8) + SectorsPerAlloc(4) + BytesPerSector(4) = 24
        assert_eq!(buf.len(), 24);
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 1_000_000);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 500_000);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(buf[20..24].try_into().unwrap()), 512);
    }

    #[test]
    fn test_fs_device_info_golden_bytes() {
        let buf = fs_device_info();
        // FileFsDeviceInformation: DeviceType(4) + Characteristics(4) = 8
        assert_eq!(buf.len(), 8);
        // Disk = 0x00000007
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 0x00000007);
    }

    #[test]
    fn test_fs_full_size_info_golden_bytes() {
        let stats = FsStats {
            total_blocks: 1_000_000,
            available_blocks: 500_000,
            free_blocks: 500_000,
            block_size: 512,
            sector_size: 512,
        };
        let buf = fs_full_size_info(&stats);
        // FileFsFullSizeInformation: Total(8) + Caller(8) + Actual(8) + SectorsPerAlloc(4) + BytesPerSector(4) = 32
        assert_eq!(buf.len(), 32);
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 1_000_000);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 500_000);
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 500_000);
    }

    #[test]
    fn test_fs_volume_info_stable_serial() {
        let buf1 = fs_volume_info("testshare");
        let buf2 = fs_volume_info("testshare");
        let buf3 = fs_volume_info("othershare");
        // Serial is at offset 8 (after 8-byte creation time).
        let serial1 = u32::from_le_bytes(buf1[8..12].try_into().unwrap());
        let serial2 = u32::from_le_bytes(buf2[8..12].try_into().unwrap());
        let serial3 = u32::from_le_bytes(buf3[8..12].try_into().unwrap());
        assert_eq!(serial1, serial2, "same share → same serial");
        assert_ne!(serial1, serial3, "different share → different serial");
        assert_ne!(serial1, 0, "serial should not be zero");
    }

    // --- Security descriptor synthesis tests ---

    #[test]
    fn test_sd_synthesis_basic() {
        let sec = SecurityInfo { uid: 1000, gid: 1000, mode: 0o755 };
        let sd = synthesize_security_descriptor(&sec, SECURITY_OWNER | SECURITY_GROUP | SECURITY_DACL);
        // Header is 20 bytes, must be at least that.
        assert!(sd.len() > 20);
        // Revision = 1
        assert_eq!(sd[0], 1);
        // Control: SE_SELF_RELATIVE (0x8000) | SE_DACL_PRESENT (0x0004)
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert_eq!(control, 0x8004);
    }

    #[test]
    fn test_sd_synthesis_no_dacl() {
        let sec = SecurityInfo { uid: 0, gid: 0, mode: 0o644 };
        let sd = synthesize_security_descriptor(&sec, SECURITY_OWNER | SECURITY_GROUP);
        // Without DACL: header(20) + owner SID + group SID
        // S-1-22-1-0: revision(1) + count(1) + auth(6) + 2×subauth(4+4) = 16 bytes
        // S-1-22-2-0: same = 16 bytes
        assert_eq!(sd.len(), 20 + 16 + 16);
        // SD header: Owner(4..8), Group(8..12), SACL(12..16), DACL(16..20).
        // DACL offset at bytes 16..20 should be 0 (no DACL).
        let dacl_off = u32::from_le_bytes(sd[16..20].try_into().unwrap());
        assert_eq!(dacl_off, 0);
        // SACL offset at bytes 12..16 should be 0 (no SACL).
        let sacl_off = u32::from_le_bytes(sd[12..16].try_into().unwrap());
        assert_eq!(sacl_off, 0);
        // Control at bytes 2..4: SE_SELF_RELATIVE (0x8000) without DACL.
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert_eq!(control, 0x8000);
    }

    #[test]
    fn test_sd_synthesis_owner_offset() {
        let sec = SecurityInfo { uid: 42, gid: 42, mode: 0o700 };
        let sd = synthesize_security_descriptor(&sec, SECURITY_OWNER | SECURITY_GROUP | SECURITY_DACL);
        // Owner offset at bytes 4..8
        let owner_off = u32::from_le_bytes(sd[4..8].try_into().unwrap());
        assert_eq!(owner_off, 20); // right after header
        // Group offset at bytes 8..12
        let group_off = u32::from_le_bytes(sd[8..12].try_into().unwrap());
        // S-1-22-1-42 = 16 bytes, so group is at 20+16 = 36
        assert_eq!(group_off, 36);
        // The SID at owner_off should start with revision=1
        assert_eq!(sd[owner_off as usize], 1); // revision
        // SubAuthorityCount at offset+1
        let sub_auth_count = sd[owner_off as usize + 1];
        assert_eq!(sub_auth_count, 2); // [1, uid]
        // IdentifierAuthority is 6 bytes big-endian at offset+2
        // For authority 22: bytes are [0,0,0,0,0,22]
        let auth_byte = sd[owner_off as usize + 2 + 5]; // last byte of authority
        assert_eq!(auth_byte, 22);
        // Control: SE_SELF_RELATIVE | SE_DACL_PRESENT = 0x8004
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert_eq!(control, 0x8004);
    }
}
