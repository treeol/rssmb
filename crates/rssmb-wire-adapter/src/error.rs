//! Error types and NTSTATUS codes for the wire layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("incomplete frame — not enough bytes")]
    IncompleteFrame,
    #[error("oversized frame: {0} bytes exceeds max")]
    OversizedFrame(usize),
    #[error("unknown NetBIOS message type: 0x{0:02x}")]
    UnknownNetbiosType(u8),
    #[error("unknown magic bytes: {0:?}")]
    UnknownMagic(Vec<u8>),
    #[error("decode error: {0}")]
    DecodeError(String),
    #[error("io error: {0}")]
    Io(String),
}

/// NTSTATUS codes used by SMB2.
/// Reference: MS-SMB2 §2.2.2 and Windows NTSTATUS definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtStatus {
    /// Success (0x00000000)
    Success,
    /// More processing required (0xC0000016) — for multi-round auth
    MoreProcessingRequired,
    /// Pending (0x00000103) — async response
    Pending,
    /// End of file (0xC0000011)
    EndOfFile,
    /// Invalid parameter (0xC000000D)
    InvalidParameter,
    /// Invalid handle (0xC0000008)
    InvalidHandle,
    /// Access denied (0xC0000022)
    AccessDenied,
    /// Object name not found (0xC0000034)
    ObjectNameNotFound,
    /// Object name collision (0xC0000035)
    ObjectNameCollision,
    /// Duplicate object ID (0xC000022A) — e.g. a non-replay DH2Q reusing a
    /// CreateGuid that is still held by a live durable open (MS-SMB2
    /// 3.3.5.9.10). Value per MS-ERREF §2.3.1; 0xC0000042 is
    /// STATUS_INVALID_PORT_HANDLE, not this code.
    DuplicateObjectId,
    /// Lock not granted (0xC0000055) — an overlapping conflicting lock is
    /// held (MS-SMB2 2.2.21; MS-ERREF §2.3.1).
    LockNotGranted,
    /// File lock conflict (0xC0000054) — a byte-range lock conflicts with
    /// the attempted READ/WRITE (MS-ERREF §2.3.1). 0xC0000070 is
    /// STATUS_INVALID_WORKSTATION, not this code.
    FileLockConflict,
    /// Named pipe empty (0xC00000D9) — read on a pipe with no data
    /// available (MS-ERREF §2.3.1). 0xC0000050 is STATUS_EA_TOO_LARGE.
    PipeEmpty,
    /// Object name invalid (0xC0000033) — invalid path/name
    ObjectNameInvalid,
    /// Sharing violation (0xC0000043)
    SharingViolation,
    /// File is a directory (0xC00000BA)
    FileIsADirectory,
    /// Not a directory (0xC0000103)
    NotADirectory,
    /// Logon failure (0xC000006D)
    LogonFailure,
    /// Wrong password (0xC000006A)
    WrongPassword,
    /// User does not exist (0xC0000064)
    NoSuchUser,
    /// Account disabled (0xC0000072)
    AccountDisabled,
    /// Not supported (0xC00000BB)
    NotSupported,
    /// Directory not empty (0xC0000101)
    DirectoryNotEmpty,
    /// Disk full (0xC000007F)
    DiskFull,
    /// Insufficient server resources (0xC0000205)
    InsufficientServerResources,
    /// Buffer too small (0xC0000023)
    BufferTooSmall,
    /// No more files (0x80000006) — STATUS_NO_MORE_FILES
    NoMoreFiles,
    /// No more entries (0x8000001A) — STATUS_NO_MORE_ENTRIES
    NoMoreEntries,
    /// No such file (0xC000000F)
    NoSuchFile,
    /// Buffer overflow (0x80000005) — STATUS_BUFFER_OVERFLOW
    BufferOverflow,
    /// Info length mismatch (0xC0000004)
    InfoLengthMismatch,
    /// Invalid info class (0xC0000003)
    InvalidInfoClass,
    /// Network name deleted (0xC00000C9)
    NetworkNameDeleted,
    /// User session deleted (0xC0000203)
    UserSessionDeleted,
    /// SMB no preauth integrity hash overlap (0xC05D0000)
    SmbNoPreauthIntegrityHashOverlap,
    /// Custom NTSTATUS value
    Other(u32),
}

impl NtStatus {
    pub fn to_u32(self) -> u32 {
        match self {
            NtStatus::Success => 0x00000000,
            NtStatus::MoreProcessingRequired => 0xC0000016,
            NtStatus::Pending => 0x00000103,
            NtStatus::EndOfFile => 0xC0000011,
            NtStatus::InvalidParameter => 0xC000000D,
            NtStatus::InvalidHandle => 0xC0000008,
            NtStatus::AccessDenied => 0xC0000022,
            NtStatus::ObjectNameNotFound => 0xC0000034,
            NtStatus::ObjectNameCollision => 0xC0000035,
            NtStatus::DuplicateObjectId => 0xC000022A,
            NtStatus::LockNotGranted => 0xC0000055,
            NtStatus::FileLockConflict => 0xC0000054,
            NtStatus::PipeEmpty => 0xC00000D9,
            NtStatus::ObjectNameInvalid => 0xC0000033,
            NtStatus::SharingViolation => 0xC0000043,
            NtStatus::FileIsADirectory => 0xC00000BA,
            NtStatus::NotADirectory => 0xC0000103,
            NtStatus::LogonFailure => 0xC000006D,
            NtStatus::WrongPassword => 0xC000006A,
            NtStatus::NoSuchUser => 0xC0000064,
            NtStatus::AccountDisabled => 0xC0000072,
            NtStatus::NotSupported => 0xC00000BB,
            NtStatus::DirectoryNotEmpty => 0xC0000101,
            NtStatus::DiskFull => 0xC000007F,
            NtStatus::InsufficientServerResources => 0xC0000205,
            NtStatus::BufferTooSmall => 0xC0000023,
            NtStatus::NoMoreFiles => 0x80000006,
            NtStatus::NoMoreEntries => 0x8000001A,
            NtStatus::NoSuchFile => 0xC000000F,
            NtStatus::BufferOverflow => 0x80000005,
            NtStatus::InfoLengthMismatch => 0xC0000004,
            NtStatus::InvalidInfoClass => 0xC0000003,
            NtStatus::NetworkNameDeleted => 0xC00000C9,
            NtStatus::UserSessionDeleted => 0xC0000203,
            NtStatus::SmbNoPreauthIntegrityHashOverlap => 0xC05D0000,
            NtStatus::Other(v) => v,
        }
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            0x00000000 => NtStatus::Success,
            0xC0000016 => NtStatus::MoreProcessingRequired,
            0x00000103 => NtStatus::Pending,
            0xC0000011 => NtStatus::EndOfFile,
            0xC000000D => NtStatus::InvalidParameter,
            0xC0000008 => NtStatus::InvalidHandle,
            0xC0000022 => NtStatus::AccessDenied,
            0xC0000034 => NtStatus::ObjectNameNotFound,
            0xC0000035 => NtStatus::ObjectNameCollision,
            0xC0000033 => NtStatus::ObjectNameInvalid,
            0xC0000043 => NtStatus::SharingViolation,
            0xC00000BA => NtStatus::FileIsADirectory,
            0xC0000103 => NtStatus::NotADirectory,
            0xC000006D => NtStatus::LogonFailure,
            0xC000006A => NtStatus::WrongPassword,
            0xC0000064 => NtStatus::NoSuchUser,
            0xC0000072 => NtStatus::AccountDisabled,
            0xC00000BB => NtStatus::NotSupported,
            0xC0000101 => NtStatus::DirectoryNotEmpty,
            0xC000007F => NtStatus::DiskFull,
            0xC0000205 => NtStatus::InsufficientServerResources,
            0xC0000023 => NtStatus::BufferTooSmall,
            0x80000006 => NtStatus::NoMoreFiles,
            0x8000001A => NtStatus::NoMoreEntries,
            0xC000000F => NtStatus::NoSuchFile,
            0x80000005 => NtStatus::BufferOverflow,
            0xC0000004 => NtStatus::InfoLengthMismatch,
            0xC0000003 => NtStatus::InvalidInfoClass,
            0xC00000C9 => NtStatus::NetworkNameDeleted,
            0xC0000203 => NtStatus::UserSessionDeleted,
            0xC000022A => NtStatus::DuplicateObjectId,
            0xC0000055 => NtStatus::LockNotGranted,
            0xC0000054 => NtStatus::FileLockConflict,
            0xC00000D9 => NtStatus::PipeEmpty,
            0xC05D0000 => NtStatus::SmbNoPreauthIntegrityHashOverlap,
            _ => NtStatus::Other(val),
        }
    }

    pub fn is_error(self) -> bool {
        (self.to_u32() & 0xC0000000) == 0xC0000000
    }

    pub fn is_warning(self) -> bool {
        (self.to_u32() & 0xC0000000) == 0x80000000
    }

    pub fn is_success(self) -> bool {
        (self.to_u32() & 0xC0000000) == 0x00000000
    }
}

impl std::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NTSTATUS 0x{:08X} ({:?})", self.to_u32(), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntstatus_roundtrip() {
        let codes = [
            NtStatus::Success,
            NtStatus::MoreProcessingRequired,
            NtStatus::AccessDenied,
            NtStatus::SharingViolation,
            NtStatus::LogonFailure,
            NtStatus::EndOfFile,
            NtStatus::NoMoreEntries,
            NtStatus::DuplicateObjectId,
            NtStatus::LockNotGranted,
            NtStatus::FileLockConflict,
            NtStatus::PipeEmpty,
        ];
        for code in codes {
            let raw = code.to_u32();
            let back = NtStatus::from_u32(raw);
            assert_eq!(code, back, "roundtrip failed for {:?}", code);
        }
    }

    #[test]
    fn test_ntstatus_classification() {
        assert!(NtStatus::Success.is_success());
        assert!(NtStatus::AccessDenied.is_error());
        assert!(NtStatus::NoMoreEntries.is_warning());
        // MoreProcessingRequired is 0xC0000016 — error severity, used during multi-round auth
        assert!(NtStatus::MoreProcessingRequired.is_error());
        // Pending is 0x00000103 — informational (not error, not warning)
        assert!(!NtStatus::Pending.is_error());
        assert!(!NtStatus::Pending.is_warning());
    }

    #[test]
    fn test_other_status() {
        let custom = NtStatus::Other(0xC0000133);
        assert!(custom.is_error());
        assert_eq!(custom.to_u32(), 0xC0000133);
    }
}
