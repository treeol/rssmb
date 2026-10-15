//! RSSMB VFS — Virtual filesystem trait and backends for SMB file serving.
//!
//! The VFS trait is **handle-centric** (not path-centric) to match SMB's
//! file-handle model. All operations work on opaque `OpenId` handles returned
//! by `create()`. The server layer handles path normalization, case policy,
//! and authorization before calling the VFS.

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

pub mod localfs;
pub mod memoryfs;
pub mod path;

pub use path::NormalizedPath;

/// Symlink policy for a share's local filesystem backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FollowSymlinks {
    /// Never follow symlinks. Report them as reparse points
    /// (`FILE_ATTRIBUTE_REPARSE_POINT`). Opening through a symlink returns
    /// `AccessDenied` / `STATUS_STOPPED_ON_SYMLINK`.
    #[default]
    Never,
    /// Follow symlinks only if the resolved target is within the share root.
    /// Out-of-share symlink targets are refused.
    WithinShare,
}

/// Opaque handle to an open file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenId(pub u64);

/// Opaque file identity for cross-session open tracking.
/// Must be stable across rename and hard links within a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u64);

/// Create disposition (MS-SMB2 §2.2.13 CREATE disposition values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDisposition {
    /// FILE_SUPERSEDE (0) — replace existing or create new
    Supersede,
    /// FILE_OPEN (1) — open existing, fail if not exists
    Open,
    /// FILE_CREATE (2) — create new, fail if exists
    Create,
    /// FILE_OPEN_IF (3) — open existing or create new
    OpenIf,
    /// FILE_OVERWRITE (4) — open and overwrite, fail if not exists
    Overwrite,
    /// FILE_OVERWRITE_IF (5) — open and overwrite, or create new
    OverwriteIf,
}

/// Share access flags (what operations other opens are allowed while this open is active).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareAccess {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

impl ShareAccess {
    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            delete: true,
        }
    }
    pub fn none() -> Self {
        Self {
            read: false,
            write: false,
            delete: false,
        }
    }
}

/// Desired access mask (subset of FILE_ACCESS_MASK).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DesiredAccess {
    pub read: bool,
    pub write: bool,
    pub read_attributes: bool,
    pub delete: bool,
    pub generic_read: bool,
    pub generic_write: bool,
    pub generic_execute: bool,
    pub generic_all: bool,
}

/// Create options flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateOptions {
    pub directory: bool,
    pub non_directory_file: bool,
    pub write_through: bool,
    pub delete_on_close: bool,
    pub random_access: bool,
    pub sequential_only: bool,
    pub no_intermediate_buffering: bool,
    pub synchronous_io_non_alert: bool,
}

/// Arguments for creating/opening a file.
#[derive(Debug, Clone)]
pub struct CreateArgs {
    pub disposition: CreateDisposition,
    pub share_access: ShareAccess,
    pub desired_access: DesiredAccess,
    pub create_options: CreateOptions,
}

impl CreateArgs {
    pub fn open_readonly() -> Self {
        Self {
            disposition: CreateDisposition::Open,
            share_access: ShareAccess::all(),
            desired_access: DesiredAccess {
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            create_options: CreateOptions::default(),
        }
    }
}

/// File attributes returned by create/query_info.
#[derive(Debug, Clone, Default)]
pub struct FileAttributes {
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
}

/// Information about an open file or directory.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub file_id: FileId,
    pub attributes: FileAttributes,
    pub size: u64,
    pub allocation_size: u64,
    pub creation_time: u64, // Windows FILETIME (100ns intervals since 1601-01-01)
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_name: String,
}

/// A directory entry returned by query_dir.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub file_name: String,
    pub short_name: Option<String>,
    pub attributes: FileAttributes,
    pub size: u64,
    pub allocation_size: u64,
    pub file_id: Option<FileId>,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
}

/// Lock range for byte-range locks.
#[derive(Debug, Clone, Copy)]
pub struct LockRange {
    pub offset: u64,
    pub length: u64,
}

/// Filesystem statistics (from statvfs/fstatvfs).
#[derive(Debug, Clone, Copy, Default)]
pub struct FsStats {
    /// Total blocks in the filesystem.
    pub total_blocks: u64,
    /// Available blocks (free, not reserved for root).
    pub available_blocks: u64,
    /// Free blocks (including reserved).
    pub free_blocks: u64,
    /// Block size (allocation unit).
    pub block_size: u64,
    /// Logical sector size.
    pub sector_size: u64,
}

/// Security descriptor info synthesized from POSIX mode bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityInfo {
    /// Unix UID of the file owner.
    pub uid: u32,
    /// Unix GID of the file group.
    pub gid: u32,
    /// Unix mode bits (st_mode).
    pub mode: u32,
}

/// Directory information class for QUERY_DIRECTORY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirInfoClass {
    DirectoryInfo,
    FullDirectoryInfo,
    BothDirectoryInfo,
    IdBothDirectoryInfo,
    NamesInfo,
    IdFullDirectoryInfo,
}

/// File information class for QUERY_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoClass {
    FileBasicInfo,
    FileStandardInfo,
    FileInternalInfo,
    FileEaInfo,
    FileAccessInfo,
    FileNameInfo,
    FileRenameInfo,
    FileDispositionInfo,
    FileAllocationInfo,
    FileEndOfFileInfo,
    FileNetworkOpenInfo,
    FileAttributeTagInfo,
    FileFsAttributeInfo,
    FileFsVolumeInfo,
    FileFsSizeInfo,
    FileFsDeviceInfo,
    FileFsControlInfo,
    FileFsFullSizeInfo,
    FileFsSectorSizeInfo,
}

/// Notify filter for CHANGE_NOTIFY.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,
    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,
    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,
}

/// FSCTL codes for IOCTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsCtlCode {
    DfsGetReferrals,
    SrvCopyChunk,
    SrvCopyChunkRead,
    SrvEnumerateSnapshots,
    QueryAllocatedRanges,
    SetSparse,
    SetZeroData,
    QueryOnDiskVolumeInfo,
    FileLevelTrim,
    ValidateNegotiateInfo,
    Other(u32),
}

/// VFS error type.
#[derive(Debug, Error)]
pub enum VfsError {
    #[error("file not found")]
    NotFound,
    #[error("file already exists")]
    AlreadyExists,
    #[error("access denied")]
    AccessDenied,
    #[error("sharing violation")]
    SharingViolation,
    #[error("file is a directory")]
    IsDirectory,
    #[error("not a directory")]
    NotDirectory,
    #[error("end of file")]
    EndOfFile,
    #[error("not supported")]
    NotSupported,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("path traversal detected")]
    PathTraversal,
    #[error("invalid path name")]
    InvalidName,
    #[error("directory not empty")]
    DirectoryNotEmpty,
    #[error("io error: {0}")]
    Io(String),
}

/// The VFS trait. All operations are handle-centric.
///
/// Security: the server layer performs authorization (access mask checks)
/// before calling any VFS method. VFS backends do not re-authorize.
/// The server layer also enforces share-mode conflicts and byte-range locks
/// using a global open table (not the VFS).
#[async_trait]
pub trait Vfs: Send + Sync {
    /// Open or create a file/directory.
    /// Returns an `OpenId` for subsequent operations.
    async fn create(
        &self,
        share_root: &str,
        path: &str,
        args: &CreateArgs,
    ) -> Result<OpenId, VfsError>;

    /// Read data from an open file at the given offset.
    /// Returns the bytes read (may be fewer than requested at EOF).
    async fn read_at(&self, open: OpenId, offset: u64, len: u32) -> Result<Bytes, VfsError>;

    /// Write data to an open file at the given offset.
    /// Returns the number of bytes written.
    async fn write_at(&self, open: OpenId, offset: u64, data: &[u8]) -> Result<u32, VfsError>;

    /// Close an open handle. Performs delete-on-close if flag is set.
    async fn close(&self, open: OpenId) -> Result<(), VfsError>;

    /// Flush buffered data to storage.
    async fn flush(&self, open: OpenId) -> Result<(), VfsError>;

    /// Acquire a byte-range lock.
    async fn lock(&self, open: OpenId, range: LockRange, exclusive: bool) -> Result<(), VfsError>;

    /// Release a byte-range lock.
    async fn unlock(&self, open: OpenId, range: LockRange) -> Result<(), VfsError>;

    /// Query file/directory information.
    async fn query_info(&self, open: OpenId, class: InfoClass) -> Result<FileInfo, VfsError>;

    /// Set file/directory information.
    async fn set_info(
        &self,
        open: OpenId,
        class: InfoClass,
        info: &FileInfo,
    ) -> Result<(), VfsError>;

    /// Query directory entries (handle-based, stateful).
    /// `restart` resets the enumeration to the beginning.
    /// Returns at most `max_results` entries; caller requests more.
    /// Empty vec means no more entries.
    async fn query_dir(
        &self,
        open: OpenId,
        pattern: &str,
        class: DirInfoClass,
        restart: bool,
        max_results: usize,
    ) -> Result<Vec<DirEntry>, VfsError>;

    /// Get the stable file identity for an open handle.
    async fn file_id(&self, open: OpenId) -> Result<FileId, VfsError>;

    /// Delete a file (via delete-on-close flag, or direct).
    async fn delete(&self, open: OpenId) -> Result<(), VfsError>;

    /// Set or clear delete-on-close for an open (FileDispositionInformation).
    /// The delete happens when the handle is closed. Backends that cannot
    /// defer return `NotSupported`.
    async fn set_delete_on_close(&self, _open: OpenId, _delete: bool) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    /// Rename a file.
    async fn rename(&self, open: OpenId, new_path: &str, replace: bool) -> Result<(), VfsError>;

    /// IOCTL / FSCTL handler.
    async fn ioctl(&self, open: OpenId, ctl: FsCtlCode, input: &[u8]) -> Result<Vec<u8>, VfsError>;

    /// Query filesystem statistics for the share backing this handle.
    /// Used for FileFsSizeInformation / FileFsFullSizeInformation.
    async fn fs_stats(&self, open: OpenId) -> Result<FsStats, VfsError>;

    /// Query security info (POSIX uid/gid/mode) for an open handle.
    /// Used to synthesize a minimal self-relative security descriptor.
    async fn query_security(&self, open: OpenId) -> Result<SecurityInfo, VfsError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_access() {
        let sa = ShareAccess::all();
        assert!(sa.read && sa.write && sa.delete);

        let sa = ShareAccess::none();
        assert!(!sa.read && !sa.write && !sa.delete);
    }

    #[test]
    fn test_create_args_readonly() {
        let args = CreateArgs::open_readonly();
        assert_eq!(args.disposition, CreateDisposition::Open);
        assert!(args.desired_access.read);
        assert!(args.share_access.read);
    }
}
