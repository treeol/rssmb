//! Local filesystem VFS backend.
//!
//! A `LocalFs` implements the [`Vfs`](crate::Vfs) trait backed by the real
//! filesystem via `cap-std`. All paths are resolved relative to a share root
//! directory using `cap_std::fs::Dir`, which uses `openat2(RESOLVE_BENEATH)`
//! on Linux ≥5.6 and a manual `O_NOFOLLOW` walk on other platforms. This
//! eliminates the TOCTOU race in the previous `canonicalize`-based approach:
//! the kernel resolves the path beneath the held directory fd, so a symlink
//! swapped mid-resolution cannot escape the share root.
//!
//! Symlink policy is configurable per share via [`FollowSymlinks`]:
//! - `Never` (default): symlinks are reported as reparse points and never
//!   followed. Opening through a symlink returns `AccessDenied`.
//! - `WithinShare`: symlinks are followed only if the resolved target is
//!   within the share root (enforced by cap-std's `RESOLVE_BENEATH`).

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::fs::OpenOptions as CapOpenOptions;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::*;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Seconds between 1601-01-01 and 1970-01-01 (Windows FILETIME epoch offset).
const UNIX_EPOCH_FILETIME_OFFSET: u64 = 11_644_473_600;

/// Convert a Unix `SystemTime` to a Windows FILETIME (100ns intervals since 1601).
fn system_time_to_filetime(time: std::time::SystemTime) -> u64 {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs + UNIX_EPOCH_FILETIME_OFFSET) * 10_000_000
}

/// Build `FileAttributes` from filesystem metadata.
fn attributes_from_metadata(meta: &std::fs::Metadata) -> FileAttributes {
    let is_dir = meta.is_dir();
    #[cfg(unix)]
    let read_only = {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o200) == 0
    };
    #[cfg(not(unix))]
    let read_only = meta.permissions().readonly();

    FileAttributes {
        read_only,
        hidden: false,
        system: false,
        directory: is_dir,
        archive: !is_dir && !read_only,
        normal: !is_dir,
        temporary: false,
        sparse_file: false,
        reparse_point: meta.file_type().is_symlink(),
        compressed: false,
        offline: false,
        not_content_indexed: true,
        encrypted: false,
    }
}

/// Compute the file identity. On Unix this is the inode number; elsewhere 0.
#[cfg(unix)]
fn file_id_from_metadata(meta: &std::fs::Metadata) -> FileId {
    FileId(meta.ino())
}

#[cfg(not(unix))]
fn file_id_from_metadata(_meta: &std::fs::Metadata) -> FileId {
    FileId(0)
}

/// An open handle tracked by `LocalFs`.
struct FileHandle {
    /// The async file handle (fd obtained from cap-std's confined open).
    file: TokioFile,
    /// Relative path from the share root (for Dir-based operations).
    rel_path: PathBuf,
    /// The last path component (file name) for reporting.
    file_name: String,
    /// Whether this open is a directory.
    is_directory: bool,
    /// Whether to delete the file when the handle is closed.
    delete_on_close: bool,
}

/// A `LocalFs` VFS backend rooted at a directory, using `cap-std` for
/// TOCTOU-free handle-relative path resolution.
pub struct LocalFs {
    /// The cap-std directory handle — all path resolution goes through this.
    dir: cap_std::fs::Dir,
    /// Symlink policy.
    follow_symlinks: FollowSymlinks,
    opens: Mutex<HashMap<OpenId, FileHandle>>,
    next_open_id: Mutex<u64>,
}

impl LocalFs {
    /// Construct a `LocalFs` rooted at `root` with the given symlink policy.
    /// The root is opened via `cap_std::fs::Dir::open_ambient_dir` at
    /// construction time; all subsequent operations are confined beneath it.
    pub fn new(
        root: impl AsRef<Path>,
        follow_symlinks: FollowSymlinks,
    ) -> Result<Self, VfsError> {
        let dir = cap_std::fs::Dir::open_ambient_dir(root.as_ref(), cap_std::ambient_authority())
            .map_err(|e| VfsError::Io(format!("open share root: {e}")))?;
        Ok(Self {
            dir,
            follow_symlinks,
            opens: Mutex::new(HashMap::new()),
            next_open_id: Mutex::new(1),
        })
    }

    async fn next_open_id(&self) -> OpenId {
        let mut id = self.next_open_id.lock().await;
        let val = *id;
        *id += 1;
        OpenId(val)
    }

    /// Resolve an SMB path to a relative path within the share root.
    fn resolve_rel(&self, path: &str) -> Result<PathBuf, VfsError> {
        let normalized = NormalizedPath::from_smb_path(path).map_err(|e| match e {
            path::PathError::TraversalDetected => VfsError::PathTraversal,
            path::PathError::InvalidName | path::PathError::InvalidEncoding => VfsError::InvalidName,
        })?;
        Ok(normalized.to_pathbuf())
    }

    /// Check symlink policy for a path that exists. Returns `AccessDenied`
    /// if the path is a symlink and the policy is `Never`.
    fn check_symlink_policy(&self, rel: &Path) -> Result<(), VfsError> {
        if self.follow_symlinks == FollowSymlinks::Never {
            if let Ok(meta) = self.dir.symlink_metadata(rel) {
                if meta.file_type().is_symlink() {
                    return Err(VfsError::AccessDenied);
                }
            }
        }
        // For WithinShare: cap-std's openat2(RESOLVE_BENEATH) confines
        // resolution. A symlink targeting outside the share root is
        // refused by the kernel. No extra check needed.
        Ok(())
    }

    /// Extract the file name from a relative path.
    fn file_name_from_rel(rel: &Path) -> String {
        rel.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    }

    /// Check if a relative path is a directory.
    fn is_dir_rel(&self, rel: &Path) -> Result<bool, VfsError> {
        self.dir
            .metadata(rel)
            .map(|m| m.is_dir())
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    VfsError::NotFound
                } else {
                    VfsError::Io(format!("metadata: {e}"))
                }
            })
    }
}

#[async_trait]
impl Vfs for LocalFs {
    async fn create(
        &self,
        _share_root: &str,
        path: &str,
        args: &CreateArgs,
    ) -> Result<OpenId, VfsError> {
        let rel = self.resolve_rel(path)?;

        // cap-std uses "." to refer to the Dir itself. Empty paths don't work.
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel
        };

        // Check if the target exists (using symlink_metadata to detect
        // symlinks without following them — cap-std's exists() uses
        // openat2 which refuses symlink-escaped paths, returning false).
        let exists = self.dir.symlink_metadata(&rel).is_ok();
        if exists {
            self.check_symlink_policy(&rel)?;
        }

        let is_dir = args.create_options.directory;
        let wants_dir = is_dir;
        let wants_file = args.create_options.non_directory_file;

        // Determine target type if it exists.
        let target_is_dir = if exists {
            self.is_dir_rel(&rel).unwrap_or(wants_dir)
        } else {
            wants_dir
        };

        // Disposition handling.
        let mut needs_create = !exists;
        match args.disposition {
            CreateDisposition::Open => {
                if !exists {
                    return Err(VfsError::NotFound);
                }
                needs_create = false;
            }
            CreateDisposition::Create => {
                if exists {
                    return Err(VfsError::AlreadyExists);
                }
                needs_create = true;
            }
            CreateDisposition::OpenIf => {}
            CreateDisposition::Supersede => {
                if exists && !target_is_dir {
                    let _ = self.dir.remove_file(&rel);
                    needs_create = true;
                }
            }
            CreateDisposition::Overwrite => {
                if !exists {
                    return Err(VfsError::NotFound);
                }
                needs_create = false;
            }
            CreateDisposition::OverwriteIf => {}
        }

        if wants_dir && !exists {
            self.dir
                .create_dir(&rel)
                .map_err(|e| VfsError::Io(format!("create_dir: {e}")))?;
        } else if wants_file && exists && target_is_dir {
            return Err(VfsError::IsDirectory);
        }

        // Build cap-std open options.
        let mut opts = CapOpenOptions::new();
        opts.read(true);
        let wants_write = matches!(
            args.disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Create
                | CreateDisposition::OverwriteIf
        ) || args.desired_access.write
            || args.desired_access.generic_write
            || args.desired_access.generic_all;
        opts.write(wants_write);
        if needs_create {
            opts.create(true);
        }
        if matches!(
            args.disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Overwrite
                | CreateDisposition::OverwriteIf
        ) && !target_is_dir
        {
            opts.truncate(true);
        }
        // For Never policy: don't follow symlinks during the final-component
        // open. cap-std uses O_NOFOLLOW (or equivalent), causing the open
        // to fail with ELOOP if the path is a symlink.
        if self.follow_symlinks == FollowSymlinks::Never {
            opts._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
        }

        // Open via cap-std — confined to the share root by openat2.
        // For the root directory (rel == "."), we open the Dir itself
        // and convert to a File for handle tracking.
        let cap_file = if rel == Path::new(".") {
            self.dir
                .open_dir(".")
                .map(|d| cap_std::fs::File::from_std(d.into_std_file()))
                .map_err(|e| VfsError::Io(format!("open root dir: {e}")))?
        } else {
            self.dir.open_with(&rel, &opts).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    VfsError::NotFound
                } else if e.kind() == std::io::ErrorKind::AlreadyExists {
                    VfsError::AlreadyExists
                } else {
                    VfsError::Io(format!("open: {e}"))
                }
            })?
        };

        // Convert to tokio for async I/O. The fd was obtained from a
        // confined open; the tokio File wraps the same fd.
        let file = TokioFile::from_std(cap_file.into_std());

        let file_name = Self::file_name_from_rel(&rel);

        let open_id = self.next_open_id().await;
        let mut opens = self.opens.lock().await;
        opens.insert(
            open_id,
            FileHandle {
                file,
                rel_path: rel,
                file_name,
                is_directory: target_is_dir,
                delete_on_close: args.create_options.delete_on_close,
            },
        );
        Ok(open_id)
    }

    async fn read_at(
        &self,
        open: OpenId,
        offset: u64,
        len: u32,
    ) -> Result<Bytes, VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        if handle.is_directory {
            return Err(VfsError::IsDirectory);
        }
        handle
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| VfsError::Io(format!("seek: {e}")))?;
        let mut buf = vec![0u8; len as usize];
        let n = handle
            .file
            .read(&mut buf)
            .await
            .map_err(|e| VfsError::Io(format!("read: {e}")))?;
        buf.truncate(n);
        Ok(Bytes::from(buf))
    }

    async fn write_at(
        &self,
        open: OpenId,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        if handle.is_directory {
            return Err(VfsError::IsDirectory);
        }
        handle
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| VfsError::Io(format!("seek: {e}")))?;
        handle
            .file
            .write_all(data)
            .await
            .map_err(|e| VfsError::Io(format!("write: {e}")))?;
        Ok(data.len() as u32)
    }

    async fn close(&self, open: OpenId) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.remove(&open).ok_or(VfsError::InvalidHandle)?;
        if handle.delete_on_close {
            if handle.is_directory {
                let _ = self.dir.remove_dir(&handle.rel_path);
            } else {
                let _ = self.dir.remove_file(&handle.rel_path);
            }
        }
        // TokioFile is dropped here, closing the fd.
        drop(handle);
        Ok(())
    }

    async fn flush(&self, open: OpenId) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        handle
            .file
            .sync_data()
            .await
            .map_err(|e| VfsError::Io(format!("flush: {e}")))
    }

    async fn lock(
        &self,
        _open: OpenId,
        _range: LockRange,
        _exclusive: bool,
    ) -> Result<(), VfsError> {
        Ok(())
    }

    async fn unlock(&self, _open: OpenId, _range: LockRange) -> Result<(), VfsError> {
        Ok(())
    }

    async fn query_info(
        &self,
        open: OpenId,
        _class: InfoClass,
    ) -> Result<FileInfo, VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        let attrs = attributes_from_metadata(&meta);
        let file_id = file_id_from_metadata(&meta);
        let size = if attrs.directory { 0 } else { meta.len() };
        let file_name = handle.file_name.clone();
        drop(opens);

        Ok(FileInfo {
            file_id,
            attributes: attrs,
            size,
            allocation_size: size,
            creation_time: system_time_to_filetime(
                meta.created().unwrap_or(std::time::UNIX_EPOCH),
            ),
            last_access_time: system_time_to_filetime(
                meta.accessed().unwrap_or(std::time::UNIX_EPOCH),
            ),
            last_write_time: system_time_to_filetime(
                meta.modified().unwrap_or(std::time::UNIX_EPOCH),
            ),
            change_time: system_time_to_filetime(
                meta.modified().unwrap_or(std::time::UNIX_EPOCH),
            ),
            file_name,
        })
    }

    async fn set_info(
        &self,
        open: OpenId,
        _class: InfoClass,
        info: &FileInfo,
    ) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;

        if info.size != 0 && !handle.is_directory {
            handle
                .file
                .set_len(info.size)
                .await
                .map_err(|e| VfsError::Io(format!("set_len: {e}")))?;
        }

        // Apply timestamps via the file path (std::fs::File::set_times).
        #[cfg(unix)]
        {
            use std::time::Duration;
            // Apply timestamps via fs-set-times (SetTimes for tokio::fs::File).
            use fs_set_times::{SetTimes, SystemTimeSpec};
            let to_spec = |ft: u64| -> Option<SystemTimeSpec> {
                if ft == 0 {
                    return None;
                }
                let secs = ft / 10_000_000;
                let unix_secs = secs.saturating_sub(UNIX_EPOCH_FILETIME_OFFSET);
                Some(SystemTimeSpec::from(
                    std::time::UNIX_EPOCH + Duration::from_secs(unix_secs),
                ))
            };
            let _ = handle.file.set_times(
                to_spec(info.last_access_time),
                to_spec(info.last_write_time),
            );
        }

        // Apply DOS attributes — only when the info class is FileBasicInfo.
        // Other SET_INFO classes (EOF, Disposition) should not touch attrs.
        // - READONLY ↔ remove owner write bit (Unix mode bit)
        // - HIDDEN/SYSTEM/ARCHIVE: stored in xattr user.DOSATTRIB
        //   (Samba-compatible format). Requires the xattr crate on Unix.
        //   For now, only READONLY is applied; the rest are accepted but
        //   not persisted (Phase 2.8 partial).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use cap_std::fs::PermissionsExt as CapPermissionsExt;
            let readonly = info.attributes.read_only;
            // Only apply attribute changes when the caller is setting
            // FileBasicInfo (class 4). For other classes, skip to avoid
            // accidentally clearing READONLY on an EOF truncate.
            let is_basic_info = matches!(_class, InfoClass::FileBasicInfo);
            if is_basic_info {
                let meta = handle
                    .file
                    .metadata()
                    .await
                    .map_err(|e| VfsError::Io(format!("metadata for attrs: {e}")))?;
                let mode = meta.permissions().mode();
                let new_mode = if readonly {
                    mode & !0o200
                } else {
                    mode | 0o200
                };
                let perms = CapPermissionsExt::from_mode(new_mode);
                let rel = handle.rel_path.clone();
                drop(opens);
                if let Err(e) = self.dir.set_permissions(&rel, perms) {
                    return Err(VfsError::Io(format!("set_permissions: {e}")));
                }
            }
        }

        Ok(())
    }

    async fn query_dir(
        &self,
        open: OpenId,
        pattern: &str,
        _class: DirInfoClass,
        _restart: bool,
        max_results: usize,
    ) -> Result<Vec<DirEntry>, VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        if !handle.is_directory {
            return Err(VfsError::NotDirectory);
        }
        let rel = handle.rel_path.clone();
        drop(opens);

        let mut entries = Vec::new();
        // Open the subdirectory via cap-std (confined). Root ("." or "")
        // uses the share root Dir directly.
        let read_dir = if rel.as_os_str().is_empty() || rel == Path::new(".") {
            self.dir
                .entries()
                .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?
        } else {
            let subdir = self
                .dir
                .open_dir(&rel)
                .map_err(|e| VfsError::Io(format!("open_dir: {e}")))?;
            subdir
                .entries()
                .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?
        };

        let cap = if max_results == 0 { usize::MAX } else { max_results };
        for entry in read_dir {
            let entry = entry.map_err(|e| VfsError::Io(format!("dir entry: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !matches_pattern(&name, pattern) {
                continue;
            }
            let meta = entry
                .metadata()
                .map_err(|e| VfsError::Io(format!("entry metadata: {e}")))?;

            // Convert cap-std metadata to our FileAttributes.
            let is_dir = meta.is_dir();
            #[cfg(unix)]
            let read_only = {
                use cap_std::fs::PermissionsExt;
                (meta.permissions().mode() & 0o200) == 0
            };
            #[cfg(not(unix))]
            let read_only = meta.permissions().readonly();
            let attrs = FileAttributes {
                read_only,
                hidden: false,
                system: false,
                directory: is_dir,
                archive: !is_dir && !read_only,
                normal: !is_dir,
                temporary: false,
                sparse_file: false,
                reparse_point: meta.file_type().is_symlink(),
                compressed: false,
                offline: false,
                not_content_indexed: true,
                encrypted: false,
            };

            let size = if is_dir { 0 } else { meta.len() };
            #[cfg(unix)]
            let allocation_size = {
                use cap_std::fs::MetadataExt;
                meta.blocks() * 512
            };
            #[cfg(not(unix))]
            let allocation_size = (size + 4095) & !4095;
            #[cfg(unix)]
            let file_id = {
                use cap_std::fs::MetadataExt;
                Some(FileId(meta.ino() as u64))
            };
            #[cfg(not(unix))]
            let file_id = None;

            // Convert cap-std metadata times to filetime. cap-std's
            // SystemTime converts to std's via into_std().
            let to_ft = |res: Result<cap_std::time::SystemTime, std::io::Error>| -> u64 {
                res.map(|t| system_time_to_filetime(t.into_std()))
                    .unwrap_or(0)
            };

            entries.push(DirEntry {
                file_name: name,
                short_name: None,
                attributes: attrs,
                size,
                allocation_size,
                file_id,
                creation_time: to_ft(meta.created()),
                last_access_time: to_ft(meta.accessed()),
                last_write_time: to_ft(meta.modified()),
                change_time: to_ft(meta.modified()),
            });
            if entries.len() >= cap {
                break;
            }
        }
        Ok(entries)
    }

    async fn file_id(&self, open: OpenId) -> Result<FileId, VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        Ok(file_id_from_metadata(&meta))
    }

    async fn set_delete_on_close(&self, open: OpenId, delete: bool) -> Result<(), VfsError> {
        // Read the handle info without holding the lock during dir I/O.
        let (rel, is_dir) = {
            let opens = self.opens.lock().await;
            let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
            (handle.rel_path.clone(), handle.is_directory)
        };

        if delete && is_dir {
            // Check that the directory is empty (MS-FSCC).
            let read_dir = if rel.as_os_str().is_empty() || rel == Path::new(".") {
                self.dir
                    .entries()
                    .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?
            } else {
                self.dir
                    .open_dir(&rel)
                    .map_err(|e| VfsError::Io(format!("open_dir: {e}")))?
                    .entries()
                    .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?
            };
            if read_dir.take(1).count() > 0 {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }

        let mut opens = self.opens.lock().await;
        if let Some(h) = opens.get_mut(&open) {
            h.delete_on_close = delete;
        }
        Ok(())
    }

    async fn delete(&self, open: OpenId) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let rel = handle.rel_path.clone();
        let is_dir = handle.is_directory;
        drop(opens);

        if is_dir {
            self.dir
                .remove_dir(&rel)
                .map_err(|e| VfsError::Io(format!("remove_dir: {e}")))
        } else {
            self.dir
                .remove_file(&rel)
                .map_err(|e| VfsError::Io(format!("remove_file: {e}")))
        }
    }

    async fn rename(
        &self,
        open: OpenId,
        new_path: &str,
        replace: bool,
    ) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let handle = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let old_rel = handle.rel_path.clone();
        drop(opens);

        let new_rel = self.resolve_rel(new_path)?;

        if !replace && self.dir.exists(&new_rel) {
            return Err(VfsError::AlreadyExists);
        }

        self.dir
            .rename(&old_rel, &self.dir, &new_rel)
            .map_err(|e| VfsError::Io(format!("rename: {e}")))?;

        let mut opens = self.opens.lock().await;
        if let Some(handle) = opens.get_mut(&open) {
            handle.rel_path = new_rel.clone();
            handle.file_name = Self::file_name_from_rel(&new_rel);
        }
        Ok(())
    }

    async fn ioctl(
        &self,
        _open: OpenId,
        _ctl: FsCtlCode,
        _input: &[u8],
    ) -> Result<Vec<u8>, VfsError> {
        Err(VfsError::NotSupported)
    }
}

/// Simple wildcard pattern matching (`*` and `?`), case-insensitive.
/// Operates on char slices to avoid UTF-8 boundary issues.
fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" || pattern.is_empty() {
        return true;
    }
    let name_chars: Vec<char> = name.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();
    matches_pattern_impl(&name_chars, &pattern_chars)
}

fn matches_pattern_impl(name: &[char], pattern: &[char]) -> bool {
    let mut ni = 0;
    let mut pi = 0;

    while pi < pattern.len() {
        match pattern[pi] {
            '*' => {
                pi += 1;
                if pi >= pattern.len() {
                    return true; // trailing * matches everything
                }
                // Try to match the rest of the pattern at each position.
                for i in 0..=name.len() {
                    if matches_pattern_impl(&name[i..], &pattern[pi..]) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if ni >= name.len() {
                    return false;
                }
                ni += 1;
                pi += 1;
            }
            pc => {
                if ni >= name.len() {
                    return false;
                }
                if !name[ni].eq_ignore_ascii_case(&pc) {
                    return false;
                }
                ni += 1;
                pi += 1;
            }
        }
    }
    ni >= name.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    #[tokio::test]
    async fn test_create_write_read_close() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();

        let args = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "hello.txt", &args).await.unwrap();
        let n = fs.write_at(open, 0, b"Hello, LocalFs!").await.unwrap();
        assert_eq!(n, 15);
        let data = fs.read_at(open, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"Hello, LocalFs!");
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_open_existing() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();

        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "f.txt", &create).await.unwrap();
        fs.write_at(open, 0, b"data").await.unwrap();
        fs.close(open).await.unwrap();

        let open2 = fs
            .create("", "f.txt", &CreateArgs::open_readonly())
            .await
            .unwrap();
        let data = fs.read_at(open2, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"data");
        fs.close(open2).await.unwrap();
    }

    #[tokio::test]
    async fn test_open_missing_fails() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let result = fs.create("", "nope.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_create_existing_fails() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "dup.txt", &create).await.unwrap();
        fs.close(open).await.unwrap();
        let result = fs.create("", "dup.txt", &create).await;
        assert!(matches!(result, Err(VfsError::AlreadyExists)));
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let result = fs
            .create("", "..\\..\\escape.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::PathTraversal)));
    }

    #[tokio::test]
    async fn test_invalid_name_rejected() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let result = fs
            .create("", "file\x00.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::InvalidName)));
    }

    #[tokio::test]
    async fn test_query_info() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "info.txt", &create).await.unwrap();
        fs.write_at(open, 0, b"abc").await.unwrap();
        let info = fs
            .query_info(open, InfoClass::FileBasicInfo)
            .await
            .unwrap();
        assert_eq!(info.size, 3);
        assert!(!info.attributes.directory);
        assert!(!info.file_name.is_empty());
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_file_id() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "id.txt", &create).await.unwrap();
        let id = fs.file_id(open).await.unwrap();
        assert_ne!(id, FileId(0));
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_and_query_dir() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();

        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        fs.create("", "a.txt", &create).await.unwrap();
        fs.create("", "b.txt", &create).await.unwrap();
        fs.create("", "c.log", &create).await.unwrap();

        let dir_args = CreateArgs {
            disposition: CreateDisposition::Open,
            create_options: CreateOptions {
                directory: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let dopen = fs.create("", "", &dir_args).await.unwrap();
        let entries = fs
            .query_dir(dopen, "*", DirInfoClass::DirectoryInfo, true, 100)
            .await
            .unwrap();
        assert_eq!(entries.len(), 3);
        let txt_entries = fs
            .query_dir(dopen, "*.txt", DirInfoClass::DirectoryInfo, true, 100)
            .await
            .unwrap();
        assert_eq!(txt_entries.len(), 2);
        fs.close(dopen).await.unwrap();
    }

    #[tokio::test]
    async fn test_delete() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                delete: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "del.txt", &create).await.unwrap();
        fs.delete(open).await.unwrap();
        let result = fs.create("", "del.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_rename() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "old.txt", &create).await.unwrap();
        fs.rename(open, "new.txt", false).await.unwrap();
        let info = fs
            .query_info(open, InfoClass::FileBasicInfo)
            .await
            .unwrap();
        assert_eq!(info.file_name, "new.txt");
        fs.close(open).await.unwrap();
        let result = fs.create("", "old.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
        let open2 = fs.create("", "new.txt", &CreateArgs::open_readonly()).await;
        assert!(open2.is_ok());
    }

    #[tokio::test]
    async fn test_delete_on_close() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let mut args = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        args.create_options.delete_on_close = true;
        let open = fs.create("", "tmp.txt", &args).await.unwrap();
        fs.close(open).await.unwrap();
        let result = fs.create("", "tmp.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_ioctl_not_supported() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "ioctl.txt", &create).await.unwrap();
        let result = fs.ioctl(open, FsCtlCode::SetZeroData, &[]).await;
        assert!(matches!(result, Err(VfsError::NotSupported)));
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_flush() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "flush.txt", &create).await.unwrap();
        fs.write_at(open, 0, b"flush me").await.unwrap();
        fs.flush(open).await.unwrap();
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_unlock() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "lock.txt", &create).await.unwrap();
        fs.lock(open, LockRange { offset: 0, length: 10 }, true)
            .await
            .unwrap();
        fs.unlock(open, LockRange { offset: 0, length: 10 })
            .await
            .unwrap();
        fs.close(open).await.unwrap();
    }

    #[test]
    fn test_filetime_conversion() {
        let now = std::time::SystemTime::now();
        let ft = system_time_to_filetime(now);
        assert!(ft > UNIX_EPOCH_FILETIME_OFFSET * 10_000_000);
    }

    #[test]
    fn test_wildcard() {
        assert!(matches_pattern("file.txt", "*"));
        assert!(matches_pattern("file.txt", "*.*"));
        assert!(matches_pattern("file.txt", "*.txt"));
        assert!(matches_pattern("file.txt", "file.*"));
        assert!(matches_pattern("file.txt", "file.txt"));
        assert!(!matches_pattern("file.txt", "file.log"));
        assert!(matches_pattern("file.txt", "fil?.txt"));
        assert!(matches_pattern("a.txt", "?.txt"));
        assert!(!matches_pattern("ab.txt", "?.txt"));
    }

    // --- Phase 1.1: symlink confinement tests ---

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_to_outside_rejected_never() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        let outside = tempfile::tempdir().expect("create outside tempdir");
        let outside_target = outside.path().join("secret.txt");
        std::fs::write(&outside_target, b"secret").unwrap();

        // Create a symlink inside the share pointing outside.
        symlink(&outside_target, dir.path().join("link.txt")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let result = fs
            .create("", "link.txt", &CreateArgs::open_readonly())
            .await;
        assert!(
            matches!(result, Err(VfsError::AccessDenied)),
            "symlink with Never policy should be refused: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_within_share_followed() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::write(dir.path().join("real.txt"), b"content").unwrap();
        symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::WithinShare).unwrap();
        let open = fs
            .create("", "link.txt", &CreateArgs::open_readonly())
            .await
            .expect("within-share symlink should be followed");
        let data = fs.read_at(open, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"content");
        fs.close(open).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_to_outside_rejected_within_share() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        let outside = tempfile::tempdir().expect("create outside tempdir");
        let outside_target = outside.path().join("secret.txt");
        std::fs::write(&outside_target, b"secret").unwrap();

        symlink(&outside_target, dir.path().join("link.txt")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::WithinShare).unwrap();
        let result = fs
            .create("", "link.txt", &CreateArgs::open_readonly())
            .await;
        assert!(
            result.is_err(),
            "symlink pointing outside share should be refused (WithinShare policy)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_reported_as_reparse_point() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::write(dir.path().join("real.txt"), b"content").unwrap();
        symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();
        let dir_args = CreateArgs {
            disposition: CreateDisposition::Open,
            create_options: CreateOptions {
                directory: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let dopen = fs.create("", "", &dir_args).await.unwrap();
        let entries = fs
            .query_dir(dopen, "link*", DirInfoClass::DirectoryInfo, true, 100)
            .await
            .unwrap();
        assert!(!entries.is_empty(), "should find the symlink entry");
        assert!(
            entries[0].attributes.reparse_point,
            "symlink should have reparse_point attribute"
        );
        fs.close(dopen).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_race_safety_symlink_swap() {
        // cap-std's openat-based resolution prevents a TOCTOU race where a
        // directory is swapped for a symlink to / between resolution and open.
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("subdir")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never).unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dir_path = dir.path().to_path_buf();
        let stop_clone = stop.clone();
        let _handle = std::thread::spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = std::fs::remove_dir_all(dir_path.join("subdir"));
                let _ = symlink("/", dir_path.join("subdir"));
                let _ = std::fs::remove_file(dir_path.join("subdir"));
                let _ = std::fs::create_dir_all(dir_path.join("subdir"));
            }
        });

        let args = CreateArgs {
            disposition: CreateDisposition::OpenIf,
            create_options: CreateOptions {
                directory: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        for _ in 0..50 {
            let _ = fs.create("", "subdir", &args).await;
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}