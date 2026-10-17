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
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};

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
    FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

#[cfg(not(unix))]
fn file_id_from_metadata(_meta: &std::fs::Metadata) -> FileId {
    FileId { dev: 0, ino: 0 }
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
    /// Whether file name lookup is case-sensitive.
    case_sensitive: bool,
    opens: RwLock<HashMap<OpenId, Arc<Mutex<FileHandle>>>>,
    next_open_id: Mutex<u64>,
}

impl LocalFs {
    /// Construct a `LocalFs` rooted at `root` with the given symlink and
    /// case-sensitivity policies. The root is opened via
    /// `cap_std::fs::Dir::open_ambient_dir` at construction time; all
    /// subsequent operations are confined beneath it.
    pub fn new(
        root: impl AsRef<Path>,
        follow_symlinks: FollowSymlinks,
        case_sensitive: bool,
    ) -> Result<Self, VfsError> {
        let dir = cap_std::fs::Dir::open_ambient_dir(root.as_ref(), cap_std::ambient_authority())
            .map_err(|e| VfsError::Io(format!("open share root: {e}")))?;
        Ok(Self {
            dir,
            follow_symlinks,
            case_sensitive,
            opens: RwLock::new(HashMap::new()),
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
            path::PathError::InvalidName | path::PathError::InvalidEncoding => {
                VfsError::InvalidName
            }
        })?;
        Ok(normalized.to_pathbuf())
    }

    /// Check symlink policy for a path. Returns `AccessDenied` if any
    /// component of the path is a symlink and the policy is `Never`.
    ///
    /// Walks every path component via `symlink_metadata` (lstat) anchored
    /// at the share root dir. This catches intermediate-directory symlinks
    /// that `check_symlink_policy` (final-component-only) missed.
    ///
    /// For `WithinShare`: cap-std's `openat2(RESOLVE_BENEATH)` confines
    /// resolution to the share root; a symlink targeting outside is
    /// refused by the kernel. No extra check needed.
    fn check_no_symlinks(&self, rel: &Path) -> Result<(), VfsError> {
        // "." and empty paths refer to the root dir itself — no symlink.
        if rel == Path::new(".") || rel.as_os_str().is_empty() {
            return Ok(());
        }

        if self.follow_symlinks == FollowSymlinks::Never {
            // Never: reject any symlink in any path component. Walk every
            // component via symlink_metadata (lstat) anchored at the share
            // root dir. This catches intermediate-directory symlinks that
            // a final-component-only check would miss.
            let mut accum = PathBuf::new();
            for component in rel.components() {
                match component {
                    std::path::Component::Normal(name) => {
                        accum.push(name);
                        match self.dir.symlink_metadata(&accum) {
                            Ok(meta) => {
                                if meta.file_type().is_symlink() {
                                    return Err(VfsError::AccessDenied);
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                // Component doesn't exist — not a symlink. The
                                // actual file operation will fail with NotFound
                                // if needed; we only reject symlinks here.
                            }
                            Err(e) => {
                                // Unexpected error (permissions, I/O) — propagate.
                                return Err(VfsError::Io(format!("symlink_metadata: {e}")));
                            }
                        }
                    }
                    std::path::Component::CurDir => {}
                    _ => {} // RootDir/ParentDir shouldn't appear after resolve_rel
                }
            }
            return Ok(());
        }

        // WithinShare: cap-std's open operations use openat2(RESOLVE_BENEATH)
        // on Linux ≥5.6, but unlinkat(2), renameat(2), and other path-based
        // operations do not. Verify the parent directory is accessible via
        // cap-std (confined by RESOLVE_BENEATH) to ensure intermediate
        // symlinks don't escape the share.
        let parent = match rel.parent() {
            None => return Ok(()),
            Some(p) if p == Path::new("") || p == Path::new(".") => return Ok(()),
            Some(p) => p,
        };
        self.dir
            .open_dir(parent)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    VfsError::NotFound
                } else {
                    // RESOLVE_BENEATH rejected a symlink escape, or other
                    // I/O error — deny access.
                    VfsError::AccessDenied
                }
            })
            .map(|_| ())
    }

    /// On a case-insensitive share, resolve a path that doesn't exist exactly
    /// to a case-insensitive match by walking each component from the share
    /// root down.
    ///
    /// Returns `Some(resolved_path)` if a case-insensitive resolution succeeds
    /// for existing components (even if the final leaf component is a new file
    /// to be created inside a case-matched parent directory), or `None` if no
    /// match or the share is case-sensitive.
    ///
    /// If multiple names in any directory match case-insensitively without an
    /// exact match (ambiguity), returns `None`.
    fn resolve_case_insensitive(&self, rel: &Path) -> Option<PathBuf> {
        if self.case_sensitive {
            return None;
        }

        let components: Vec<OsString> = rel
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_os_string()),
                _ => None,
            })
            .collect();

        if components.is_empty() {
            return None;
        }

        let mut resolved = PathBuf::new();
        let mut changed = false;

        for (idx, comp) in components.iter().enumerate() {
            let is_last = idx + 1 == components.len();
            let comp_str = comp.to_str()?;

            // Open the directory accumulated so far (or share root).
            let entries = if resolved.as_os_str().is_empty() {
                self.dir.entries().ok()?
            } else {
                self.dir.open_dir(&resolved).ok()?.entries().ok()?
            };

            let mut exact_match: Option<OsString> = None;
            let mut ci_match: Option<OsString> = None;
            let mut ambiguous = false;
            let lower = comp_str.to_lowercase();

            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                if name_str == comp_str {
                    exact_match = Some(name);
                    break;
                }
                if name_str.to_lowercase() == lower {
                    if ci_match.is_some() {
                        ambiguous = true;
                    } else {
                        ci_match = Some(name);
                    }
                }
            }

            if let Some(exact) = exact_match {
                resolved.push(exact);
            } else if ambiguous {
                return None;
            } else if let Some(matched) = ci_match {
                resolved.push(matched);
                changed = true;
            } else if is_last {
                // Final component does not exist (e.g. creating a new file inside
                // a case-resolved parent directory). Keep the requested leaf name.
                resolved.push(comp);
            } else {
                // Intermediate directory does not exist at all.
                return None;
            }
        }

        if changed {
            Some(resolved)
        } else {
            None
        }
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
        self.dir.metadata(rel).map(|m| m.is_dir()).map_err(|e| {
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
        let mut exists = self.dir.symlink_metadata(&rel).is_ok();

        // Case-insensitive lookup: if the exact path doesn't exist and the
        // share is case-insensitive, scan from the share root down for a
        // match. Resolve before running `check_no_symlinks` so that under
        // `FollowSymlinks::WithinShare` (which opens the parent dir) a
        // case-mismatched parent directory is resolved to its on-disk case
        // before `open_dir(parent)` checks confinement.
        let mut effective_rel = rel.clone();
        if !exists && !self.case_sensitive {
            if let Some(ci_rel) = self.resolve_case_insensitive(&rel) {
                if self.dir.symlink_metadata(&ci_rel).is_ok() {
                    effective_rel = ci_rel;
                    exists = true;
                } else {
                    // The parent directory matched case-insensitively even
                    // though the final component does not exist yet (e.g.
                    // creating a new file inside a case-mismatched parent dir).
                    effective_rel = ci_rel;
                }
            }
        }

        // Check symlink policy on all components of the effective path
        // (existing or parent components of a new file/dir). For
        // FollowSymlinks::Never this rejects any intermediate symlink
        // traversal even when the final target doesn't exist yet; for
        // WithinShare it verifies the resolved parent is confined.
        self.check_no_symlinks(&effective_rel)?;

        let is_dir = args.create_options.directory;
        let wants_dir = is_dir;
        let wants_file = args.create_options.non_directory_file;

        // Determine target type if it exists.
        let target_is_dir = if exists {
            self.is_dir_rel(&effective_rel).unwrap_or(wants_dir)
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
                    let _ = self.dir.remove_file(&effective_rel);
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
                .create_dir(&effective_rel)
                .map_err(|e| VfsError::from_io("create_dir", e))?;
            // The directory now exists; the open below must not try to
            // create it again.
            needs_create = false;
        } else if wants_file && exists && target_is_dir {
            return Err(VfsError::IsDirectory);
        }

        // Build cap-std open options.
        let mut opts = CapOpenOptions::new();
        opts.read(true);
        // Directories are always opened read-only and without O_CREAT:
        // Linux rejects O_WRONLY/O_RDWR/O_CREAT on a directory with EISDIR,
        // which surfaced as STATUS_INVALID_PARAMETER on every mkdir.
        // Directory "writes" (creating children, rename, delete) go through
        // the share Dir, not this fd.
        let wants_write = !target_is_dir
            && (matches!(
                args.disposition,
                CreateDisposition::Supersede
                    | CreateDisposition::Create
                    | CreateDisposition::OverwriteIf
            ) || args.desired_access.write
                || args.desired_access.generic_write
                || args.desired_access.generic_all);
        opts.write(wants_write);
        if needs_create && !target_is_dir {
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
        // For the root directory (effective_rel == "."), we open the Dir
        // itself and convert to a File for handle tracking.
        let cap_file = if effective_rel == Path::new(".") {
            self.dir
                .open_dir(".")
                .map(|d| cap_std::fs::File::from_std(d.into_std_file()))
                .map_err(|e| VfsError::from_io("open root dir", e))?
        } else {
            self.dir
                .open_with(&effective_rel, &opts)
                .map_err(|e| VfsError::from_io("open", e))?
        };

        // Convert to tokio for async I/O. The fd was obtained from a
        // confined open; the tokio File wraps the same fd.
        let file = TokioFile::from_std(cap_file.into_std());

        let file_name = Self::file_name_from_rel(&effective_rel);

        let open_id = self.next_open_id().await;
        let mut opens = self.opens.write().await;
        opens.insert(
            open_id,
            Arc::new(Mutex::new(FileHandle {
                file,
                rel_path: effective_rel,
                file_name,
                is_directory: target_is_dir,
                delete_on_close: args.create_options.delete_on_close,
            })),
        );
        Ok(open_id)
    }

    async fn read_at(&self, open: OpenId, offset: u64, len: u32) -> Result<Bytes, VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let mut handle = handle.lock().await;
        if handle.is_directory {
            return Err(VfsError::IsDirectory);
        }
        handle
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| VfsError::from_io("seek", e))?;
        let mut buf = vec![0u8; len as usize];
        let n = handle
            .file
            .read(&mut buf)
            .await
            .map_err(|e| VfsError::from_io("read", e))?;
        buf.truncate(n);
        Ok(Bytes::from(buf))
    }

    async fn write_at(&self, open: OpenId, offset: u64, data: &[u8]) -> Result<u32, VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let mut handle = handle.lock().await;
        if handle.is_directory {
            return Err(VfsError::IsDirectory);
        }
        handle
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| VfsError::from_io("seek", e))?;
        handle
            .file
            .write_all(data)
            .await
            .map_err(|e| VfsError::from_io("write", e))?;
        // tokio::fs::File::write_all only copies into an internal buffer and
        // performs the write(2) on the blocking pool in the background. Wait
        // for it here (flush does NOT fsync) so that (a) write errors are
        // reported on this WRITE, not a later op, and (b) the data is visible
        // to metadata()/other opens/close before we acknowledge the WRITE.
        handle
            .file
            .flush()
            .await
            .map_err(|e| VfsError::from_io("write", e))?;
        Ok(data.len() as u32)
    }

    async fn close(&self, open: OpenId) -> Result<(), VfsError> {
        let handle_arc = {
            let mut opens = self.opens.write().await;
            opens.remove(&open).ok_or(VfsError::InvalidHandle)?
        };
        // Lock the handle to read delete_on_close and rel_path, then drop
        // the lock (and the Arc, which closes the fd) before doing I/O.
        let (rel, is_dir, delete_on_close) = {
            let handle = handle_arc.lock().await;
            (
                handle.rel_path.clone(),
                handle.is_directory,
                handle.delete_on_close,
            )
        };
        // handle_arc is dropped here, closing the fd.
        drop(handle_arc);
        if delete_on_close {
            self.check_no_symlinks(&rel)?;
            if is_dir {
                self.dir
                    .remove_dir(&rel)
                    .map_err(|e| VfsError::from_io("close delete_on_close remove_dir", e))?;
            } else {
                self.dir
                    .remove_file(&rel)
                    .map_err(|e| VfsError::from_io("close delete_on_close remove_file", e))?;
            }
        }
        Ok(())
    }

    async fn flush(&self, open: OpenId) -> Result<(), VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;
        handle
            .file
            .sync_data()
            .await
            .map_err(|e| VfsError::from_io("flush", e))
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

    async fn query_info(&self, open: OpenId, _class: InfoClass) -> Result<FileInfo, VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        let attrs = attributes_from_metadata(&meta);
        let file_id = file_id_from_metadata(&meta);
        let size = if attrs.directory { 0 } else { meta.len() };
        let file_name = handle.file_name.clone();
        drop(handle);

        Ok(FileInfo {
            file_id,
            attributes: attrs,
            size,
            allocation_size: size,
            creation_time: system_time_to_filetime(meta.created().unwrap_or(std::time::UNIX_EPOCH)),
            last_access_time: system_time_to_filetime(
                meta.accessed().unwrap_or(std::time::UNIX_EPOCH),
            ),
            last_write_time: system_time_to_filetime(
                meta.modified().unwrap_or(std::time::UNIX_EPOCH),
            ),
            change_time: system_time_to_filetime(meta.modified().unwrap_or(std::time::UNIX_EPOCH)),
            file_name,
        })
    }

    async fn set_info(
        &self,
        open: OpenId,
        _class: InfoClass,
        info: &FileInfo,
    ) -> Result<(), VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;

        let is_size_info = matches!(
            _class,
            InfoClass::FileEndOfFileInfo | InfoClass::FileAllocationInfo
        );
        if is_size_info && !handle.is_directory {
            handle
                .file
                .set_len(info.size)
                .await
                .map_err(|e| VfsError::from_io("set_len", e))?;
        }

        // Apply timestamps via the file path (std::fs::File::set_times) when
        // setting FileBasicInfo.
        #[cfg(unix)]
        if matches!(_class, InfoClass::FileBasicInfo) {
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
            use cap_std::fs::PermissionsExt as CapPermissionsExt;
            use std::os::unix::fs::PermissionsExt;
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
                drop(handle);
                self.check_no_symlinks(&rel)?;
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
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;
        if !handle.is_directory {
            return Err(VfsError::NotDirectory);
        }
        let rel = handle.rel_path.clone();
        drop(handle);

        self.check_no_symlinks(&rel)?;

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

        let cap = if max_results == 0 {
            usize::MAX
        } else {
            max_results
        };
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
                Some(FileId {
                    dev: meta.dev(),
                    ino: meta.ino(),
                })
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
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        Ok(file_id_from_metadata(&meta))
    }

    async fn set_delete_on_close(&self, open: OpenId, delete: bool) -> Result<(), VfsError> {
        // Clone the Arc to avoid holding the map lock across the handle lock.
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let (rel, is_dir) = {
            let h = handle.lock().await;
            (h.rel_path.clone(), h.is_directory)
        };

        self.check_no_symlinks(&rel)?;

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

        // Re-acquire from the map to verify the handle is still open.
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let mut h = handle.lock().await;
        h.delete_on_close = delete;
        Ok(())
    }

    async fn delete(&self, open: OpenId) -> Result<(), VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let h = handle.lock().await;
        let rel = h.rel_path.clone();
        let is_dir = h.is_directory;
        drop(h);

        self.check_no_symlinks(&rel)?;

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

    async fn rename(&self, open: OpenId, new_path: &str, replace: bool) -> Result<(), VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle_guard = handle.lock().await;
        let old_rel = handle_guard.rel_path.clone();
        drop(handle_guard);

        let new_rel = self.resolve_rel(new_path)?;

        // Check symlink policy on both old and new paths — prevents
        // acting through intermediate symlinks (finding 1 & 2).
        self.check_no_symlinks(&old_rel)?;
        self.check_no_symlinks(&new_rel)?;

        // Open parent directories via cap-std (confined by RESOLVE_BENEATH
        // on Linux ≥5.6). Renaming using only the final component name
        // relative to the parent dir fd prevents intermediate symlinks
        // from redirecting the rename outside the share — the parent
        // path is resolved by the kernel with RESOLVE_BENEATH, and the
        // rename operates on a basename within the already-resolved
        // directory (finding 4).
        let old_parent = old_rel
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("."));
        let old_name = old_rel
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("."));
        let new_parent = new_rel
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("."));
        let new_name = new_rel
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("."));

        let open_parent = |parent: Option<&Path>| -> Result<Option<cap_std::fs::Dir>, VfsError> {
            match parent {
                Some(p) => Ok(Some(self.dir.open_dir(p).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        VfsError::NotFound
                    } else {
                        VfsError::AccessDenied
                    }
                })?)),
                None => Ok(None),
            }
        };
        let old_parent_dir = open_parent(old_parent)?;
        let new_parent_dir = open_parent(new_parent)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            if !replace {
                use rustix::fs::{renameat_with, RenameFlags};
                let old_fd = old_parent_dir
                    .as_ref()
                    .map(|d| d.as_fd())
                    .unwrap_or_else(|| self.dir.as_fd());
                let new_fd = new_parent_dir
                    .as_ref()
                    .map(|d| d.as_fd())
                    .unwrap_or_else(|| self.dir.as_fd());
                match renameat_with(old_fd, old_name, new_fd, new_name, RenameFlags::NOREPLACE) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => return Err(VfsError::AlreadyExists),
                    Err(e) => {
                        return Err(VfsError::from_io(
                            "renameat2(NOREPLACE)",
                            std::io::Error::from_raw_os_error(e.raw_os_error()),
                        ))
                    }
                }
            } else {
                // Use cap-std's Dir::rename from the parent dir with a
                // basename — no intermediate symlinks are traversed.
                match (&old_parent_dir, &new_parent_dir) {
                    (Some(od), Some(nd)) => od
                        .rename(old_name, nd, new_name)
                        .map_err(|e| VfsError::from_io("rename", e)),
                    (Some(od), None) => od
                        .rename(old_name, &self.dir, new_name)
                        .map_err(|e| VfsError::from_io("rename", e)),
                    (None, Some(nd)) => self
                        .dir
                        .rename(old_name, nd, new_name)
                        .map_err(|e| VfsError::from_io("rename", e)),
                    (None, None) => self
                        .dir
                        .rename(old_name, &self.dir, new_name)
                        .map_err(|e| VfsError::from_io("rename", e)),
                }?;
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            if !replace && self.dir.exists(&new_rel) {
                return Err(VfsError::AlreadyExists);
            }
            self.dir
                .rename(&old_rel, &self.dir, &new_rel)
                .map_err(|e| VfsError::from_io("rename", e))?;
        }

        // Update rel_path on all open handles affected by this rename (the
        // renamed handle itself, duplicate opens to the same path, and any
        // child handles when a directory is renamed).
        let all_handles: Vec<Arc<Mutex<FileHandle>>> = {
            let opens = self.opens.read().await;
            opens.values().cloned().collect()
        };
        for h_arc in all_handles {
            let mut h = h_arc.lock().await;
            if h.rel_path == old_rel {
                h.rel_path = new_rel.clone();
                h.file_name = Self::file_name_from_rel(&new_rel);
            } else if let Ok(suffix) = h.rel_path.strip_prefix(&old_rel) {
                let mut updated = new_rel.clone();
                updated.push(suffix);
                h.file_name = Self::file_name_from_rel(&updated);
                h.rel_path = updated;
            }
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

    async fn fs_stats(&self, _open: OpenId) -> Result<FsStats, VfsError> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.dir.as_raw_fd();
            let mut statvfs_buf: libc::statvfs = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::fstatvfs(fd, &mut statvfs_buf) };
            if ret != 0 {
                return Err(VfsError::from_io(
                    "fstatvfs",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(FsStats {
                total_blocks: statvfs_buf.f_blocks as u64,
                available_blocks: statvfs_buf.f_bavail as u64,
                free_blocks: statvfs_buf.f_bfree as u64,
                block_size: statvfs_buf.f_bsize as u64,
                sector_size: statvfs_buf.f_bsize as u64,
            })
        }
        #[cfg(not(unix))]
        {
            Err(VfsError::NotSupported)
        }
    }

    async fn query_security(&self, open: OpenId) -> Result<SecurityInfo, VfsError> {
        let handle = {
            let opens = self.opens.read().await;
            opens.get(&open).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let handle = handle.lock().await;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata for security: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(SecurityInfo {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(SecurityInfo {
                uid: 0,
                gid: 0,
                mode: 0o644,
            })
        }
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
    let mut ni = 0usize;
    let mut pi = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || name[ni].eq_ignore_ascii_case(&pattern[pi]))
        {
            ni += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ni;
            pi += 1;
        } else if let Some(s) = star_idx {
            pi = s + 1;
            match_idx += 1;
            ni = match_idx;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();

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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();

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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let result = fs
            .create("", "nope.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_case_insensitive_open() {
        let dir = tmp_root();
        // case_sensitive = false → case-insensitive lookup
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();

        // Create a file with exact case.
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
        let open = fs.create("", "MyFile.txt", &create).await.unwrap();
        fs.close(open).await.unwrap();

        // Open with different case — should succeed.
        let open2 = fs
            .create("", "myfile.txt", &CreateArgs::open_readonly())
            .await
            .expect("case-insensitive open should succeed");
        fs.close(open2).await.unwrap();
    }

    #[tokio::test]
    async fn test_case_sensitive_open_misses() {
        let dir = tmp_root();
        // case_sensitive = true → exact match only
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, true).unwrap();

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
        let open = fs.create("", "MyFile.txt", &create).await.unwrap();
        fs.close(open).await.unwrap();

        // Open with different case — should fail with NotFound.
        let result = fs
            .create("", "myfile.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_create_existing_fails() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let result = fs
            .create("", "..\\..\\escape.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::PathTraversal)));
    }

    #[tokio::test]
    async fn test_invalid_name_rejected() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let result = fs
            .create("", "file\x00.txt", &CreateArgs::open_readonly())
            .await;
        assert!(matches!(result, Err(VfsError::InvalidName)));
    }

    #[tokio::test]
    async fn test_query_info() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let info = fs.query_info(open, InfoClass::FileBasicInfo).await.unwrap();
        assert_eq!(info.size, 3);
        assert!(!info.attributes.directory);
        assert!(!info.file_name.is_empty());
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_file_id() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "id.txt", &create).await.unwrap();
        let id = fs.file_id(open).await.unwrap();
        assert_ne!(id, FileId { dev: 0, ino: 0 });
        fs.close(open).await.unwrap();
    }

    /// mkdir as sent by libsmbclient/GVFS and Windows: disposition Create
    /// (or OpenIf) with FILE_DIRECTORY_FILE on a path that does not exist.
    /// Regression: the open after create_dir used O_CREAT|O_WRONLY on the
    /// new directory → EISDIR → STATUS_INVALID_PARAMETER ("Invalid argument").
    #[tokio::test]
    async fn test_mkdir_new_directory() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        for (name, disposition) in [
            ("made_by_create", CreateDisposition::Create),
            ("made_by_openif", CreateDisposition::OpenIf),
        ] {
            let args = CreateArgs {
                disposition,
                desired_access: DesiredAccess {
                    read_attributes: true,
                    ..Default::default()
                },
                create_options: CreateOptions {
                    directory: true,
                    ..Default::default()
                },
                ..CreateArgs::open_readonly()
            };
            let open = fs
                .create("", name, &args)
                .await
                .unwrap_or_else(|e| panic!("mkdir {name} ({disposition:?}) failed: {e}"));
            fs.close(open).await.unwrap();
            assert!(
                dir.path().join(name).is_dir(),
                "{name} should be a directory"
            );
        }
        // Nested mkdir inside a freshly created directory.
        let args = CreateArgs {
            disposition: CreateDisposition::Create,
            create_options: CreateOptions {
                directory: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "made_by_create/child", &args).await.unwrap();
        fs.close(open).await.unwrap();
        assert!(dir.path().join("made_by_create/child").is_dir());
        // Create on an existing directory must collide, not succeed.
        assert!(matches!(
            fs.create("", "made_by_create", &args).await,
            Err(VfsError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn test_create_and_query_dir() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();

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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let info = fs.query_info(open, InfoClass::FileBasicInfo).await.unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "lock.txt", &create).await.unwrap();
        fs.lock(
            open,
            LockRange {
                offset: 0,
                length: 10,
            },
            true,
        )
        .await
        .unwrap();
        fs.unlock(
            open,
            LockRange {
                offset: 0,
                length: 10,
            },
        )
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

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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

        let fs = LocalFs::new(dir.path(), FollowSymlinks::WithinShare, false).unwrap();
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

        let fs = LocalFs::new(dir.path(), FollowSymlinks::WithinShare, false).unwrap();
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

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
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

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();

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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_intermediate_symlink_rejected_delete() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("realdir")).unwrap();
        std::fs::write(dir.path().join("realdir").join("file.txt"), b"content").unwrap();
        // Create a symlink "linkdir" → "realdir"
        symlink("realdir", dir.path().join("linkdir")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        // Open the file through the symlink directory
        let create = CreateArgs {
            disposition: CreateDisposition::Open,
            desired_access: DesiredAccess {
                read: true,
                delete: true,
                read_attributes: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        // Open "linkdir/file.txt" — create should reject due to intermediate symlink
        let result = fs.create("", "linkdir\\file.txt", &create).await;
        assert!(
            matches!(result, Err(VfsError::AccessDenied)),
            "opening through intermediate symlink with Never policy should be refused: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_intermediate_symlink_rejected_rename() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("realdir")).unwrap();
        symlink("realdir", dir.path().join("linkdir")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        // Create a file directly in realdir
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
        let open = fs.create("", "realdir\\file.txt", &create).await.unwrap();
        // Try to rename to a path through the symlink dir
        let result = fs.rename(open, "linkdir\\moved.txt", false).await;
        assert!(
            matches!(result, Err(VfsError::AccessDenied)),
            "rename through intermediate symlink should be refused: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_intermediate_symlink_allowed_within_share() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("realdir")).unwrap();
        std::fs::write(dir.path().join("realdir").join("file.txt"), b"content").unwrap();
        symlink("realdir", dir.path().join("linkdir")).unwrap();

        // WithinShare: intermediate symlinks within the share are followed.
        let fs = LocalFs::new(dir.path(), FollowSymlinks::WithinShare, false).unwrap();
        let open = fs
            .create("", "linkdir\\file.txt", &CreateArgs::open_readonly())
            .await
            .expect("within-share intermediate symlink should be followed");
        let data = fs.read_at(open, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"content");
        fs.close(open).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_intermediate_symlink_rejected_on_new_create() {
        use std::os::unix::fs::symlink;
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("realdir")).unwrap();
        symlink("realdir", dir.path().join("linkdir")).unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let result = fs.create("", "linkdir\\brand_new.txt", &create).await;
        assert!(
            matches!(result, Err(VfsError::AccessDenied)),
            "creating new file through intermediate symlink under Never must fail: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_set_info_eof_zero_truncates() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "nonempty.txt", &create).await.unwrap();
        fs.write_at(open, 0, b"hello world").await.unwrap();
        let mut info = fs
            .query_info(open, InfoClass::FileStandardInfo)
            .await
            .unwrap();
        assert_eq!(info.size, 11);

        // Truncate to 0 bytes via FileEndOfFileInfo.
        info.size = 0;
        fs.set_info(open, InfoClass::FileEndOfFileInfo, &info)
            .await
            .unwrap();
        let after = fs
            .query_info(open, InfoClass::FileStandardInfo)
            .await
            .unwrap();
        assert_eq!(after.size, 0, "FileEndOfFileInfo with size=0 must truncate");
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_case_insensitive_nested_dirs_and_new_file() {
        let dir = tmp_root();
        std::fs::create_dir_all(dir.path().join("SubDir/Inner")).unwrap();
        std::fs::write(dir.path().join("SubDir/Inner/Report.TXT"), b"ok").unwrap();

        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        // Open existing file with mismatched intermediate and leaf case.
        let open = fs
            .create(
                "",
                "subdir\\INNER\\report.txt",
                &CreateArgs::open_readonly(),
            )
            .await
            .expect("nested case-insensitive open should succeed");
        let data = fs.read_at(open, 0, 10).await.unwrap();
        assert_eq!(data.as_ref(), b"ok");
        fs.close(open).await.unwrap();

        // Create a new file inside case-mismatched parent directory.
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open2 = fs
            .create("", "SUBDIR\\inner\\Created.txt", &create)
            .await
            .expect("creating new file in case-mismatched dir should succeed");
        fs.close(open2).await.unwrap();
        assert!(dir.path().join("SubDir/Inner/Created.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_updates_other_open_handles() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path(), FollowSymlinks::Never, false).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            desired_access: DesiredAccess {
                write: true,
                read: true,
                delete: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let open1 = fs.create("", "orig.txt", &create).await.unwrap();
        let open2 = fs
            .create("", "orig.txt", &CreateArgs::open_readonly())
            .await
            .unwrap();

        // Rename via open1, then set delete_on_close and close via open2.
        fs.rename(open1, "renamed.txt", false).await.unwrap();
        fs.close(open1).await.unwrap();
        fs.set_delete_on_close(open2, true).await.unwrap();
        fs.close(open2).await.unwrap();
        assert!(!dir.path().join("renamed.txt").exists());
    }

    #[test]
    fn test_wildcard_no_exponential_backtracking() {
        let long_name = "a".repeat(60) + "c";
        let pat = "a*a*a*a*a*a*a*a*a*a*a*a*b";
        assert!(!matches_pattern(&long_name, pat));
        assert!(matches_pattern(&("a".repeat(60) + "b"), pat));
    }
}
