//! SMB2 create and close messages, and oplock/lease types.
//!
//! MS-SMB2 2.2.13–2.2.16, 2.2.23–2.2.25.

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::dtyp::{FileTime, Guid, PosMarker, SizedStringSize, SizedWideString};
use crate::fscc::FileAttributes;

// ── FileId (MS-SMB2 2.2.14.1) ──────────────────────────────────────

/// SMB2 FileId — persistent + volatile u64 pair.
#[binrw::binrw]
#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{:x}|{:x}}}", self.persistent, self.volatile)
    }
}

impl std::fmt::Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileId({})", self)
    }
}

// ── OplockLevel (MS-SMB2 2.2.13) ──────────────────────────────────

/// Oplock level values.
///
/// The wire format allows any u8; clients send arbitrary values on
/// durable-reconnect requests that the server is expected to ignore
/// (MS-SMB2 3.3.5.9.12; Samba parses oplock_level as a plain u8). The wire
/// struct stores the raw byte; this enum is the typed view used in
/// response construction and comparisons.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum OplockLevel {
    #[default]
    None,
    II,
    Exclusive,
    Batch,
    Lease,
}

impl OplockLevel {
    pub fn from_wire(raw: u8) -> OplockLevel {
        match raw {
            0x00 => OplockLevel::None,
            0x01 => OplockLevel::II,
            0x08 => OplockLevel::Exclusive,
            0x09 => OplockLevel::Batch,
            0xFF => OplockLevel::Lease,
            // Unknown values behave as "no oplock requested" — the server
            // ignores them (they appear on reconnects that only care
            // about the durable contexts).
            _ => OplockLevel::None,
        }
    }

    pub fn to_wire(self) -> u8 {
        match self {
            OplockLevel::None => 0x00,
            OplockLevel::II => 0x01,
            OplockLevel::Exclusive => 0x08,
            OplockLevel::Batch => 0x09,
            OplockLevel::Lease => 0xFF,
        }
    }
}

impl BinRead for OplockLevel {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw = <u8 as BinRead>::read_options(reader, endian, ())?;
        Ok(Self::from_wire(raw))
    }
}

impl BinWrite for OplockLevel {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.to_wire().write_options(writer, endian, ())
    }
}

// ── ImpersonationLevel (MS-SMB2 2.2.13) ───────────────────────────

/// Impersonation level requested by the application.
///
/// MS-SMB2 2.2.13: the server MUST validate but otherwise ignore this
/// field; durable reconnects carry arbitrary values here (Samba parses
/// a plain u32). Unknown wire values are treated as `Impersonation`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    #[default]
    Impersonation,
    Delegate,
}

impl ImpersonationLevel {
    pub fn from_wire(raw: u32) -> ImpersonationLevel {
        match raw {
            0x0 => ImpersonationLevel::Anonymous,
            0x1 => ImpersonationLevel::Identification,
            0x2 => ImpersonationLevel::Impersonation,
            0x3 => ImpersonationLevel::Delegate,
            // Arbitrary values must not fail the whole request parse —
            // the field is advisory-only per MS-SMB2.
            _ => ImpersonationLevel::Impersonation,
        }
    }

    pub fn to_wire(self) -> u32 {
        match self {
            ImpersonationLevel::Anonymous => 0x0,
            ImpersonationLevel::Identification => 0x1,
            ImpersonationLevel::Impersonation => 0x2,
            ImpersonationLevel::Delegate => 0x3,
        }
    }
}

impl BinRead for ImpersonationLevel {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw = <u32 as BinRead>::read_options(reader, endian, ())?;
        Ok(Self::from_wire(raw))
    }
}

impl BinWrite for ImpersonationLevel {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.to_wire().write_options(writer, endian, ())
    }
}

// ── CreateDisposition (MS-SMB2 2.2.13) ────────────────────────────

/// Action the server must take if the file already exists.
///
/// Durable reconnect requests carry arbitrary garbage here that the
/// server ignores (MS-SMB2 3.3.5.9.12 — only the durable contexts and the
/// name are examined). Unknown wire values map to `Open` and never fail
/// the request parse; the reconnect path does not consult the disposition.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum CreateDisposition {
    Superseded,
    #[default]
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}

impl CreateDisposition {
    pub fn from_wire(raw: u32) -> CreateDisposition {
        match raw {
            0x0 => CreateDisposition::Superseded,
            0x1 => CreateDisposition::Open,
            0x2 => CreateDisposition::Create,
            0x3 => CreateDisposition::OpenIf,
            0x4 => CreateDisposition::Overwrite,
            0x5 => CreateDisposition::OverwriteIf,
            _ => CreateDisposition::Open,
        }
    }

    pub fn to_wire(self) -> u32 {
        match self {
            CreateDisposition::Superseded => 0x0,
            CreateDisposition::Open => 0x1,
            CreateDisposition::Create => 0x2,
            CreateDisposition::OpenIf => 0x3,
            CreateDisposition::Overwrite => 0x4,
            CreateDisposition::OverwriteIf => 0x5,
        }
    }
}

impl BinRead for CreateDisposition {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw = <u32 as BinRead>::read_options(reader, endian, ())?;
        Ok(Self::from_wire(raw))
    }
}

impl BinWrite for CreateDisposition {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.to_wire().write_options(writer, endian, ())
    }
}

// ── CreateOptions (MS-SMB2 2.2.13) ────────────────────────────────

/// Options to be applied when creating or opening a file.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateOptions {
    pub directory_file: bool,
    pub write_through: bool,
    pub sequential_only: bool,
    pub no_intermediate_buffering: bool,
    pub synchronous_io_alert: bool,
    pub synchronous_io_nonalert: bool,
    pub non_directory_file: bool,
    #[skip]
    __: bool,
    pub complete_if_oplocked: bool,
    pub no_ea_knowledge: bool,
    pub open_remote_instance: bool,
    pub random_access: bool,
    pub delete_on_close: bool,
    pub open_by_file_id: bool,
    pub open_for_backup_intent: bool,
    pub no_compression: bool,
    pub open_requiring_oplock: bool,
    pub disallow_exclusive: bool,
    #[skip]
    __: B2,
    pub reserve_opfilter: bool,
    pub open_reparse_point: bool,
    pub open_no_recall: bool,
    pub open_for_free_space_query: bool,
    #[skip]
    __: B8,
}

// ── ShareAccessFlags (MS-SMB2 2.2.13) ─────────────────────────────

/// Sharing mode for the open.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ShareAccessFlags {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    #[skip]
    __: B29,
}

// ── FileAccessMask (MS-SMB2 2.2.13) ──────────────────────────────

/// Access mask for file operations (desired_access field).
/// 32-bit bitfield; we model it as a u32 with accessor methods
/// matching the smb-rs interface used by our server.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileAccessMask {
    pub file_read_data: bool,        // bit 0
    pub file_write_data: bool,       // bit 1
    pub file_append_data: bool,      // bit 2
    pub file_read_ea: bool,          // bit 3
    pub file_write_ea: bool,         // bit 4
    pub file_execute: bool,          // bit 5
    pub file_delete_child: bool,     // bit 6
    pub file_read_attributes: bool,  // bit 7
    pub file_write_attributes: bool, // bit 8
    #[skip]
    __: B7,
    pub delete: bool,       // bit 16
    pub read_control: bool, // bit 17
    pub write_dacl: bool,   // bit 18
    pub write_owner: bool,  // bit 19
    pub synchronize: bool,  // bit 20
    #[skip]
    __: B3,
    pub access_system_security: bool, // bit 24
    pub maximum_allowed: bool,        // bit 25
    #[skip]
    __: B2,
    pub generic_all: bool,     // bit 28
    pub generic_execute: bool, // bit 29
    pub generic_write: bool,   // bit 30
    pub generic_read: bool,    // bit 31
}

// ── CreateRequest (MS-SMB2 2.2.13) ────────────────────────────────

/// SMB2 CREATE Request.
///
/// MS-SMB2 2.2.13
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct CreateRequest {
    #[bw(calc = 57)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u8,
    /// The requested oplock level.
    pub requested_oplock_level: OplockLevel,
    /// The impersonation level requested.
    pub impersonation_level: ImpersonationLevel,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u64,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved3: u64,
    /// The level of access required.
    pub desired_access: FileAccessMask,
    /// File attributes for create/open.
    pub file_attributes: FileAttributes,
    /// Sharing mode.
    pub share_access: ShareAccessFlags,
    /// Action if file exists.
    pub create_disposition: CreateDisposition,
    /// Options for create/open.
    pub create_options: CreateOptions,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _name_offset: PosMarker<u16>,
    #[bw(try_calc = name.size_bytes().try_into())]
    #[br(temp)]
    name_length: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _create_contexts_length: PosMarker<u32>,
    /// The Unicode file name.
    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_aoff, args(&_name_offset))]
    #[br(args { size: SizedStringSize::Bytes16(name_length) })]
    pub name: SizedWideString,
    // Create contexts are not parsed (server doesn't use them yet).
    // The raw bytes after the name are available via the outer frame.
}

// ── CreateResponse (MS-SMB2 2.2.14) ───────────────────────────────

/// SMB2 CREATE Response.
///
/// MS-SMB2 2.2.14
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct CreateResponse {
    #[bw(calc = 89)]
    structure_size: u16,
    /// Oplock level granted.
    pub oplock_level: OplockLevel,
    /// Response flags.
    pub flags: CreateResponseFlags,
    /// Action taken.
    pub create_action: CreateAction,
    /// File creation time.
    pub creation_time: FileTime,
    /// Last access time.
    pub last_access_time: FileTime,
    /// Last write time.
    pub last_write_time: FileTime,
    /// Change time.
    pub change_time: FileTime,
    /// Allocated size.
    pub allocation_size: u64,
    /// File size.
    pub endof_file: u64,
    /// File attributes.
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
    /// File identifier.
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _create_contexts_length: PosMarker<u32>,
    /// Serialized create context chain (empty if no create contexts are returned).
    #[br(if(_create_contexts_offset.value > 0 && _create_contexts_length.value > 0))]
    #[br(seek_before = std::io::SeekFrom::Start(_create_contexts_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(_create_contexts_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(if(!create_contexts.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_create_contexts_offset, &_create_contexts_length))]
    pub create_contexts: Vec<u8>,
}

/// Response flags for CREATE.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateResponseFlags {
    pub reparsepoint: bool,
    #[skip]
    __: B7,
}

/// Action taken in establishing the open.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy, Default)]
#[brw(repr(u32))]
pub enum CreateAction {
    #[default]
    Superseded = 0x0,
    Opened = 0x1,
    Created = 0x2,
    Overwritten = 0x3,
}

// ── CloseRequest/Response (MS-SMB2 2.2.15–2.2.16) ────────────────

/// SMB2 CLOSE Request.
///
/// MS-SMB2 2.2.15
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct CloseRequest {
    #[bw(calc = 24)]
    structure_size: u16,
    /// Flags for the close operation.
    pub flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
    /// File identifier.
    pub file_id: FileId,
}

/// SMB2 CLOSE Response.
///
/// MS-SMB2 2.2.16
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct CloseResponse {
    #[bw(calc = 60)]
    structure_size: u16,
    pub flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
}

/// Flags for CLOSE.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CloseFlags {
    pub postquery_attrib: bool,
    #[skip]
    __: B15,
}

// ── Oplock/Lease break types (MS-SMB2 2.2.23–2.2.25) ──────────────

/// Oplock break notification/ack/response (24 bytes).
///
/// MS-SMB2 2.2.23.1, 2.2.24.1, 2.2.25.1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct OplockBreakMsg {
    #[bw(calc = 24)]
    #[br(assert(structure_size == 24))]
    pub structure_size: u16,
    pub oplock_level: u8,
    pub reserved: u8,
    pub _reserved2: u32,
    pub file_id: FileId,
}

pub use OplockBreakMsg as OplockBreakAck;
pub use OplockBreakMsg as OplockBreakNotify;
pub use OplockBreakMsg as OplockBreakResponse;

/// Lease break notification (44 bytes).
///
/// MS-SMB2 2.2.23.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct LeaseBreakNotify {
    #[bw(calc = 44)]
    #[br(assert(structure_size == 44))]
    pub structure_size: u16,
    pub new_epoch: u16,
    pub ack_required: u32,
    pub lease_key: Guid,
    pub current_lease_state: LeaseState,
    pub new_lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(temp)]
    break_reason: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    access_mask_hint: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    share_mask_hint: u32,
}

/// Lease break ack/response (36 bytes).
///
/// MS-SMB2 2.2.24.2, 2.2.25.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct LeaseBreakAckResponse {
    #[bw(calc = 36)]
    #[br(assert(structure_size == 36))]
    pub structure_size: u16,
    pub reserved: u16,
    pub _reserved2: u32,
    pub lease_key: Guid,
    pub lease_state: LeaseState,
    pub _reserved3: u64,
}

pub use LeaseBreakAckResponse as LeaseBreakAck;
pub use LeaseBreakAckResponse as LeaseBreakResponse;

/// Lease state bitfield.
///
/// MS-SMB2 2.2.23.2
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct LeaseState {
    pub read_caching: bool,
    pub handle_caching: bool,
    pub write_caching: bool,
    #[skip]
    __: B29,
}

// ── LeaseFlags (MS-SMB2 2.2.13.2.10) ──────────────────────────────

/// Flags for lease requests.
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct LeaseFlags {
    #[skip]
    __: B2,
    pub parent_lease_key_set: bool,
    #[skip]
    __: B29,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_file_id_display() {
        let fid = FileId {
            persistent: 42,
            volatile: 99,
        };
        assert_eq!(format!("{}", fid), "{2a|63}");
    }

    #[test]
    fn test_file_id_roundtrip() {
        let fid = FileId {
            persistent: 0xDEAD_BEEF_CAFE_BABE,
            volatile: 0x1234_5678_9ABC_DEF0,
        };
        let mut buf = Cursor::new(Vec::new());
        fid.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 16);
        // Golden: persistent then volatile, LE.
        assert_eq!(&bytes[..8], &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        assert_eq!(&bytes[8..], &0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FileId = FileId::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, fid);
    }

    #[test]
    fn test_oplock_break_msg_roundtrip() {
        let msg = OplockBreakMsg {
            oplock_level: 2,
            reserved: 0,
            _reserved2: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
        };
        let mut buf = Cursor::new(Vec::new());
        msg.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 24); // StructureSize=24 per MS-SMB2 2.2.23.1
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 24);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: OplockBreakMsg = OplockBreakMsg::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.oplock_level, 2);
        assert_eq!(
            decoded.file_id,
            FileId {
                persistent: 1,
                volatile: 2
            }
        );
    }

    #[test]
    fn test_lease_break_notify_roundtrip() {
        let msg = LeaseBreakNotify {
            new_epoch: 1,
            ack_required: 1,
            lease_key: Guid::from([0xABu8; 16]),
            current_lease_state: LeaseState::new().with_read_caching(true),
            new_lease_state: LeaseState::new()
                .with_read_caching(true)
                .with_handle_caching(true),
        };
        let mut buf = Cursor::new(Vec::new());
        msg.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 44); // StructureSize=44 per MS-SMB2 2.2.23.2
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 44);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LeaseBreakNotify = LeaseBreakNotify::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.new_epoch, 1);
        assert_eq!(decoded.lease_key, Guid::from([0xABu8; 16]));
        assert!(decoded.current_lease_state.read_caching());
        assert!(decoded.new_lease_state.handle_caching());
    }

    #[test]
    fn test_lease_break_ack_response_roundtrip() {
        let msg = LeaseBreakAckResponse {
            reserved: 0,
            _reserved2: 0,
            lease_key: Guid::from([0x42u8; 16]),
            lease_state: LeaseState::new().with_write_caching(true),
            _reserved3: 0,
        };
        let mut buf = Cursor::new(Vec::new());
        msg.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 36); // StructureSize=36 per MS-SMB2 2.2.24.2
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 36);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LeaseBreakAckResponse = LeaseBreakAckResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.lease_key, Guid::from([0x42u8; 16]));
        assert!(decoded.lease_state.write_caching());
    }

    #[test]
    fn test_create_response_default() {
        let resp = CreateResponse::default();
        assert_eq!(resp.oplock_level, OplockLevel::None);
        assert_eq!(resp.create_action, CreateAction::Superseded);
    }

    #[test]
    fn test_create_response_roundtrip() {
        let resp = CreateResponse {
            oplock_level: OplockLevel::II,
            flags: CreateResponseFlags::new().with_reparsepoint(true),
            create_action: CreateAction::Created,
            creation_time: FileTime::from(132000000000000000u64),
            last_access_time: FileTime::from(132000000000000001u64),
            last_write_time: FileTime::from(132000000000000002u64),
            change_time: FileTime::from(132000000000000003u64),
            allocation_size: 4096,
            endof_file: 2048,
            file_attributes: FileAttributes::new().with_normal(true),
            file_id: FileId {
                persistent: 0xCAFE,
                volatile: 0xBABE,
            },
            create_contexts: Vec::new(),
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // CreateResponse fixed part: 2+1+1+4+8+8+8+8+8+8+4+4+8+4+4 = 88 bytes
        // (StructureSize through trailing reserved/context fields with no data)
        assert_eq!(bytes.len(), 88);
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 89);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: CreateResponse = CreateResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.oplock_level, OplockLevel::II);
        assert_eq!(decoded.create_action, CreateAction::Created);
        assert_eq!(decoded.endof_file, 2048);
        assert_eq!(
            decoded.file_id,
            FileId {
                persistent: 0xCAFE,
                volatile: 0xBABE
            }
        );
    }

    #[test]
    fn test_close_request_roundtrip() {
        let req = CloseRequest {
            flags: CloseFlags::new().with_postquery_attrib(true),
            file_id: FileId {
                persistent: 0xAAAA,
                volatile: 0xBBBB,
            },
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 24); // StructureSize=24 per MS-SMB2 2.2.15
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 24);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: CloseRequest = CloseRequest::read_le(&mut cursor).unwrap();
        assert_eq!(
            decoded.file_id,
            FileId {
                persistent: 0xAAAA,
                volatile: 0xBBBB
            }
        );
        assert!(decoded.flags.postquery_attrib());
    }

    #[test]
    fn test_close_response_roundtrip() {
        let resp = CloseResponse {
            flags: CloseFlags::new(),
            creation_time: FileTime::from(130000000000000000u64),
            last_access_time: FileTime::from(130000000000000001u64),
            last_write_time: FileTime::from(130000000000000002u64),
            change_time: FileTime::from(130000000000000003u64),
            allocation_size: 0,
            endof_file: 0,
            file_attributes: FileAttributes::new().with_directory(true),
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 60); // StructureSize=60 per MS-SMB2 2.2.16
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 60);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: CloseResponse = CloseResponse::read_le(&mut cursor).unwrap();
        assert!(decoded.file_attributes.directory());
        assert_eq!(
            decoded.last_write_time,
            FileTime::from(130000000000000002u64)
        );
    }

    #[test]
    fn test_close_flags() {
        let flags = CloseFlags::new().with_postquery_attrib(true);
        assert!(flags.postquery_attrib());
    }

    #[test]
    fn test_file_access_mask_bits() {
        let mask = FileAccessMask::new()
            .with_file_read_data(true)
            .with_generic_all(true);
        assert!(mask.file_read_data());
        assert!(mask.generic_all());
        assert!(!mask.file_write_data());
    }

    #[test]
    fn test_file_access_mask_roundtrip() {
        let mask = FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_write_data(true)
            .with_delete(true)
            .with_generic_read(true);
        let mut buf = Cursor::new(Vec::new());
        mask.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FileAccessMask = FileAccessMask::read_le(&mut cursor).unwrap();
        assert!(decoded.file_read_data());
        assert!(decoded.file_write_data());
        assert!(decoded.delete());
        assert!(decoded.generic_read());
    }

    #[test]
    fn test_create_options_roundtrip() {
        let opts = CreateOptions::new()
            .with_directory_file(true)
            .with_delete_on_close(true);
        let mut buf = Cursor::new(Vec::new());
        opts.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: CreateOptions = CreateOptions::read_le(&mut cursor).unwrap();
        assert!(decoded.directory_file());
        assert!(decoded.delete_on_close());
        assert!(!decoded.write_through());
    }

    #[test]
    fn test_share_access_flags_roundtrip() {
        let flags = ShareAccessFlags::new().with_read(true).with_delete(true);
        let mut buf = Cursor::new(Vec::new());
        flags.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: ShareAccessFlags = ShareAccessFlags::read_le(&mut cursor).unwrap();
        assert!(decoded.read());
        assert!(decoded.delete());
        assert!(!decoded.write());
    }

    #[test]
    fn test_lease_state_roundtrip() {
        let state = LeaseState::new()
            .with_read_caching(true)
            .with_write_caching(true);
        let mut buf = Cursor::new(Vec::new());
        state.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 4);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: LeaseState = LeaseState::read_le(&mut cursor).unwrap();
        assert!(decoded.read_caching());
        assert!(decoded.write_caching());
        assert!(!decoded.handle_caching());
    }

    #[test]
    fn test_create_response_with_contexts_full_message_offsets() {
        use crate::header::{Command, Header, HeaderFlags};
        use crate::plain::{PlainResponse, ResponseContent};

        let ctx_bytes = vec![0x11u8; 56]; // e.g. 16-byte header + 8-byte name + 32-byte RqLs data
        let resp = PlainResponse {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::Create,
                credit_request: 1,
                flags: HeaderFlags::new().with_server_to_redir(true),
                next_command: 0,
                message_id: 1,
                tree_id: Some(1),
                async_id: None,
                session_id: 1,
                signature: 0,
            },
            content: ResponseContent::Create(CreateResponse {
                oplock_level: OplockLevel::Lease,
                flags: CreateResponseFlags::new(),
                create_action: CreateAction::Created,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                endof_file: 0,
                file_attributes: FileAttributes::new().with_normal(true),
                file_id: FileId {
                    persistent: 1,
                    volatile: 2,
                },
                create_contexts: ctx_bytes.clone(),
            }),
        };

        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        // 64-byte SMB2 header + 88-byte fixed CreateResponse + 56-byte contexts = 208
        assert_eq!(bytes.len(), 64 + 88 + 56);
        // CreateContextsOffset at header(64) + 80 = 144..148 should be 152 (64 + 88)
        let offset = u32::from_le_bytes(bytes[144..148].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[148..152].try_into().unwrap());
        assert_eq!(offset, 152);
        assert_eq!(length, 56);

        let mut cursor = Cursor::new(&bytes[..]);
        let decoded = PlainResponse::read_le(&mut cursor).unwrap();
        match decoded.content {
            ResponseContent::Create(cr) => {
                assert_eq!(cr.oplock_level, OplockLevel::Lease);
                assert_eq!(cr.create_contexts, ctx_bytes);
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn test_oplock_and_lease_break_content_discrimination() {
        use crate::header::{Command, Header, HeaderFlags};
        use crate::plain::{PlainRequest, RequestContent};

        // 1. OplockBreakAck (24 bytes)
        let oplock_req = PlainRequest {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::OplockBreak,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 5,
                tree_id: Some(1),
                async_id: None,
                session_id: 2,
                signature: 0,
            },
            content: RequestContent::OplockBreakAck(OplockBreakMsg {
                oplock_level: 1,
                reserved: 0,
                _reserved2: 0,
                file_id: FileId {
                    persistent: 10,
                    volatile: 20,
                },
            }),
        };
        let mut buf = Cursor::new(Vec::new());
        oplock_req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded = PlainRequest::read_le(&mut cursor).unwrap();
        assert!(matches!(decoded.content, RequestContent::OplockBreakAck(_)));

        // 2. LeaseBreakAck (36 bytes)
        let lease_req = PlainRequest {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::OplockBreak,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 6,
                tree_id: Some(0),
                async_id: None,
                session_id: 2,
                signature: 0,
            },
            content: RequestContent::LeaseBreakAck(LeaseBreakAckResponse {
                reserved: 0,
                _reserved2: 0,
                lease_key: Guid::from([0x55u8; 16]),
                lease_state: LeaseState::new().with_read_caching(true),
                _reserved3: 0,
            }),
        };
        let mut buf2 = Cursor::new(Vec::new());
        lease_req.write_le(&mut buf2).unwrap();
        let bytes2 = buf2.into_inner();
        let mut cursor2 = Cursor::new(&bytes2[..]);
        let decoded2 = PlainRequest::read_le(&mut cursor2).unwrap();
        match decoded2.content {
            RequestContent::LeaseBreakAck(ack) => {
                assert_eq!(ack.lease_key, Guid::from([0x55u8; 16]));
                assert!(ack.lease_state.read_caching());
            }
            other => panic!("expected LeaseBreakAck, got {other:?}"),
        }
    }
}
