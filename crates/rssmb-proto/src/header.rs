//! SMB2 packet header, command codes, and header flags.
//!
//! Reference: MS-SMB2 2.2.1.1, 2.2.1.2.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

/// SMB2/SMB3 protocol command codes.
///
/// Reference: MS-SMB2 2.2.1.2
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum Command {
    Negotiate = 0,
    SessionSetup = 1,
    Logoff = 2,
    TreeConnect = 3,
    TreeDisconnect = 4,
    Create = 5,
    Close = 6,
    Flush = 7,
    Read = 8,
    Write = 9,
    Lock = 0xA,
    Ioctl = 0xB,
    Cancel = 0xC,
    Echo = 0xD,
    QueryDirectory = 0xE,
    ChangeNotify = 0xF,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
    ServerToClientNotification = 0x13,
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Command::Negotiate => "Negotiate",
            Command::SessionSetup => "Session Setup",
            Command::Logoff => "Logoff",
            Command::TreeConnect => "Tree Connect",
            Command::TreeDisconnect => "Tree Disconnect",
            Command::Create => "Create",
            Command::Close => "Close",
            Command::Flush => "Flush",
            Command::Read => "Read",
            Command::Write => "Write",
            Command::Lock => "Lock",
            Command::Ioctl => "Ioctl",
            Command::Cancel => "Cancel",
            Command::Echo => "Echo",
            Command::QueryDirectory => "Query Directory",
            Command::ChangeNotify => "Change Notify",
            Command::QueryInfo => "Query Info",
            Command::SetInfo => "Set Info",
            Command::OplockBreak => "Oplock Break",
            Command::ServerToClientNotification => "Server to Client Notification",
        };
        write!(f, "{} ({:#x})", s, *self as u16)
    }
}

/// SMB2 Packet Header.
///
/// Common header structure for all SMB2/SMB3 messages, supporting both
/// synchronous and asynchronous operations.
///
/// Reference: MS-SMB2 2.2.1.1
#[binrw::binrw]
#[derive(Clone, Debug)]
#[brw(magic(b"\xfeSMB"), little)]
pub struct Header {
    /// Specifies the structure size, in bytes, of the SMB2 header.
    /// Always 64 for the SMB2 packet header.
    #[bw(calc = 64)]
    #[br(temp)]
    structure_size: u16,
    /// Number of credits charged for this request.
    pub credit_charge: u16,
    /// NT status code (raw u32).
    pub status: u32,
    /// Command code identifying the request/response type.
    pub command: Command,
    /// Number of credits requested or granted.
    pub credit_request: u16,
    /// Header flags indicating message properties.
    pub flags: HeaderFlags,
    /// Offset to next message in a compounded request chain (0 if not compounded).
    pub next_command: u32,
    /// Unique message identifier.
    pub message_id: u64,

    // Sync: Reserved + TreeId (async_command MUST NOT be set).
    #[brw(if(!flags.async_command()))]
    #[bw(calc = 0)]
    _reserved: u32,
    /// Tree identifier (synchronous operations only).
    #[br(if(!flags.async_command()))]
    #[bw(assert(tree_id.is_some() != flags.async_command()))]
    pub tree_id: Option<u32>,

    // Async: AsyncId (async_command MUST be set).
    #[brw(if(flags.async_command()))]
    #[bw(assert(tree_id.is_none() == flags.async_command()))]
    pub async_id: Option<u64>,

    /// Unique session identifier.
    pub session_id: u64,
    /// Message signature for signed messages.
    pub signature: u128,
}

impl Header {
    /// Fixed size of the SMB2 header in bytes.
    pub const STRUCT_SIZE: usize = 64;

    /// Turns the current header into an async header, setting the
    /// `async_id` and clearing `tree_id`. Also sets the
    /// `HeaderFlags::async_command` flag.
    pub fn to_async(&mut self, async_id: u64) {
        self.flags.set_async_command(true);
        self.tree_id = None;
        self.async_id = Some(async_id);
    }
}

/// SMB2 header flags.
///
/// Reference: MS-SMB2 2.2.1.2
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct HeaderFlags {
    /// Message is a server response (set in responses).
    pub server_to_redir: bool,
    /// Message is part of an asynchronous operation.
    pub async_command: bool,
    /// Request is a related operation in a compounded chain.
    pub related_operations: bool,
    /// Message is signed.
    pub signed: bool,
    /// Priority mask for quality of service.
    pub priority_mask: B3,
    #[skip]
    __: B21,
    /// Request is a DFS operation.
    pub dfs_operation: bool,
    /// Request is a replay operation for resilient handles.
    pub replay_operation: bool,
    #[skip]
    __: B2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_header_roundtrip_sync() {
        let header = Header {
            credit_charge: 1,
            status: 0,
            command: Command::Echo,
            credit_request: 1,
            flags: HeaderFlags::new().with_server_to_redir(true),
            next_command: 0,
            message_id: 42,
            tree_id: Some(7),
            async_id: None,
            session_id: 99,
            signature: 0,
        };
        let mut buf = Cursor::new(Vec::new());
        header.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 64);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: Header = Header::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.command, Command::Echo);
        assert_eq!(decoded.message_id, 42);
        assert_eq!(decoded.tree_id, Some(7));
        assert_eq!(decoded.session_id, 99);
    }

    #[test]
    fn test_header_roundtrip_async() {
        let mut header = Header {
            credit_charge: 0,
            status: 0x0000_0103, // Pending
            command: Command::ChangeNotify,
            credit_request: 1,
            flags: HeaderFlags::new(),
            next_command: 0,
            message_id: 8,
            tree_id: Some(0),
            async_id: None,
            session_id: 0x0000_0000_0853_27d7,
            signature: 0,
        };
        header.to_async(8);
        assert!(header.flags.async_command());
        assert!(header.tree_id.is_none());
        assert_eq!(header.async_id, Some(8));

        let mut buf = Cursor::new(Vec::new());
        header.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 64);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: Header = Header::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.command, Command::ChangeNotify);
        assert!(decoded.flags.async_command());
        assert_eq!(decoded.async_id, Some(8));
    }

    #[test]
    fn test_command_display() {
        assert_eq!(format!("{}", Command::Negotiate), "Negotiate (0x0)");
        assert_eq!(format!("{}", Command::Echo), "Echo (0xd)");
    }
}
