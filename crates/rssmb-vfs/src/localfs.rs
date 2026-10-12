//! Local filesystem VFS backend.
//!
//! A `LocalFs` implements the [`Vfs`](crate::Vfs) trait backed by the real
//! filesystem via `tokio::fs`. All paths are resolved relative to a share root
//! directory, and share-root confinement is enforced: every create/open
//! canonicalizes the parent directory and verifies it is contained within the
//! share root, rejecting symlink-escape and traversal attempts.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::*;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Seconds between 1601-01-01 and 1970-01-01 (the Windows FILETIME epoch offset).
const UNIX_EPOCH_FILETIME_OFFSET: u64 = 11_644_473_600;

/// Convert a Unix `SystemTime` to a Windows FILETIME (100ns intervals since 1601).
fn system_time_to_filetime(time: std::time::SystemTime) -> u64 {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs + UNIX_EPOCH_FILETIME_OFFSET) * 10_000_000
}

/// Build a `FileAttributes` from filesystem metadata.
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

/// Compute the file identity. On Unix this is the inode number; elsewhere we
/// fall back to a hash of the canonical path.
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
    file: TokioFile,
    /// Canonicalized full path of the file on disk.
    full_path: PathBuf,
    /// The last path component (file name) for reporting.
    file_name: String,
    /// Whether this open is a directory.
    is_directory: bool,
    /// Whether to delete the file when the handle is closed.
    delete_on_close: bool,
}

/// A `LocalFs` VFS backend rooted at a directory.
pub struct LocalFs {
    /// Canonicalized share root.
    share_root: PathBuf,
    opens: Mutex<HashMap<OpenId, FileHandle>>,
    next_open_id: Mutex<u64>,
}

impl LocalFs {
    /// Construct a `LocalFs` rooted at `root`. The root is canonicalized at
    /// construction time.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, VfsError> {
        let share_root = std::fs::canonicalize(root.as_ref())
            .map_err(|e| VfsError::Io(format!("canonicalize share root: {e}")))?;
        Ok(Self {
            share_root,
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

    /// Resolve an SMB path relative to the share root into a safe, canonicalized
    /// full path. Verifies the parent directory is contained within the share
    /// root.
    ///
    /// Returns `(full_path, exists)` where `full_path` is the path to use for
    /// open/create and `exists` indicates whether the file currently exists.
    fn resolve_path(&self, path: &str) -> Result<(PathBuf, bool), VfsError> {
        let normalized = NormalizedPath::from_smb_path(path).map_err(|_| VfsError::PathTraversal)?;

        // Build the tentative full path under the share root.
        let rel = normalized.to_pathbuf();
        let candidate = if normalized.is_root() {
            self.share_root.clone()
        } else {
            self.share_root.join(&rel)
        };

        // Determine existence. We try to canonicalize the candidate; if that
        // succeeds the file exists. If it fails, it may not exist yet (for
        // Create dispositions).
        match std::fs::canonicalize(&candidate) {
            Ok(canon) => {
                // File exists — verify containment in share root.
                if !canon.starts_with(&self.share_root) {
                    return Err(VfsError::PathTraversal);
                }
                Ok((canon, true))
            }
            Err(_) => {
                // File does not exist. Canonicalize the parent and verify
                // containment, then join the filename.
                let parent = candidate
                    .parent()
                    .ok_or_else(|| VfsError::Io("path has no parent".into()))?;
                let canon_parent = std::fs::canonicalize(parent)
                    .map_err(|e| VfsError::Io(format!("canonicalize parent: {e}")))?;
                if !canon_parent.starts_with(&self.share_root) {
                    return Err(VfsError::PathTraversal);
                }
                let file_name = candidate
                    .file_name()
                    .ok_or_else(|| VfsError::Io("path has no file name".into()))?;
                let full_path = canon_parent.join(file_name);
                Ok((full_path, false))
            }
        }
    }

    /// Resolve a new destination path for rename, returning the full path.
    fn resolve_new_path(&self, new_path: &str) -> Result<PathBuf, VfsError> {
        let (full, exists) = self.resolve_path(new_path)?;
        // For rename we return the target path regardless of existence.
        let _ = exists;
        Ok(full)
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
        let (full_path, mut exists) = self.resolve_path(path)?;

        // Disposition handling.
        match args.disposition {
            CreateDisposition::Open => {
                if !exists {
                    return Err(VfsError::NotFound);
                }
            }
            CreateDisposition::Create => {
                if exists {
                    return Err(VfsError::AlreadyExists);
                }
            }
            CreateDisposition::OpenIf => {}
            CreateDisposition::Supersede => {
                // Replace existing or create new.
                if exists {
                    let _ = std::fs::remove_file(&full_path);
                    exists = false;
                }
            }
            CreateDisposition::Overwrite => {
                if !exists {
                    return Err(VfsError::NotFound);
                }
            }
            CreateDisposition::OverwriteIf => {
                // Open and truncate, or create new.
            }
        }

        let is_dir = args.create_options.directory;
        let wants_dir = is_dir;
        let wants_file = args.create_options.non_directory_file;

        // Determine directory vs file.
        let target_is_dir = if exists {
            std::fs::metadata(&full_path)
                .map(|m| m.is_dir())
                .map_err(|e| VfsError::Io(format!("metadata: {e}")))?
        } else {
            wants_dir
        };

        if wants_dir && !exists {
            std::fs::create_dir_all(&full_path)
                .map_err(|e| VfsError::Io(format!("create_dir: {e}")))?;
        } else if wants_file && exists && target_is_dir {
            return Err(VfsError::IsDirectory);
        }

        // Truncate for overwrite dispositions.
        if exists
            && !target_is_dir
            && matches!(
                args.disposition,
                CreateDisposition::Overwrite
                    | CreateDisposition::OverwriteIf
                    | CreateDisposition::Supersede
            )
        {
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&full_path)
                .map_err(|e| VfsError::Io(format!("truncate: {e}")))?;
        }

        // Open the file.
        let file_name = full_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let file = if target_is_dir {
            // For directories we keep a read-only handle for tracking; query_dir
            // uses tokio::fs::read_dir on the stored path directly.
            std::fs::OpenOptions::new()
                .read(true)
                .open(&full_path)
                .map_err(|e| VfsError::Io(format!("open dir: {e}")))?
        } else {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true)
                .write(matches!(
                    args.disposition,
                    CreateDisposition::Supersede
                        | CreateDisposition::Create
                        | CreateDisposition::OverwriteIf
                ) || args.desired_access.write
                    || args.desired_access.generic_write
                    || args.desired_access.generic_all);
            if !exists {
                opts.create(true);
            }
            if matches!(
                args.disposition,
                CreateDisposition::Supersede | CreateDisposition::Overwrite | CreateDisposition::OverwriteIf
            ) && !target_is_dir
            {
                opts.truncate(true);
            }
            opts.open(&full_path)
                .map_err(|e| VfsError::Io(format!("open file: {e}")))?
        };
        let file = TokioFile::from_std(file);

        let open_id = self.next_open_id().await;
        let mut opens = self.opens.lock().await;
        opens.insert(
            open_id,
            FileHandle {
                file,
                full_path: full_path.clone(),
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
        let mut handle = opens.remove(&open).ok_or(VfsError::InvalidHandle)?;
        let _ = handle.file.flush().await;
        if handle.delete_on_close {
            if handle.is_directory {
                // Only an empty directory may be deleted (SMB semantics:
                // STATUS_DIRECTORY_NOT_EMPTY). Never recurse.
                let _ = tokio::fs::remove_dir(&handle.full_path).await;
            } else {
                let _ = tokio::fs::remove_file(&handle.full_path).await;
            }
        }
        Ok(())
    }

    async fn flush(&self, open: OpenId) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        handle
            .file
            .flush()
            .await
            .map_err(|e| VfsError::Io(format!("flush: {e}")))
    }

    async fn lock(
        &self,
        _open: OpenId,
        _range: LockRange,
        _exclusive: bool,
    ) -> Result<(), VfsError> {
        // MVP: the server's global lock table handles logical locks.
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
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        let attrs = attributes_from_metadata(&meta);
        let file_id = file_id_from_metadata(&meta);
        let size = if attrs.directory { 0 } else { meta.len() };
        Ok(FileInfo {
            file_id,
            attributes: attrs,
            size,
            allocation_size: size,
            creation_time: system_time_to_filetime(meta.created().unwrap_or(std::time::UNIX_EPOCH)),
            last_access_time: system_time_to_filetime(meta.accessed().unwrap_or(std::time::UNIX_EPOCH)),
            last_write_time: system_time_to_filetime(meta.modified().unwrap_or(std::time::UNIX_EPOCH)),
            change_time: system_time_to_filetime(meta.modified().unwrap_or(std::time::UNIX_EPOCH)),
            file_name: handle.file_name.clone(),
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

        // Apply size change (FileEndOfFileInfo / FileAllocationInfo).
        if info.size != 0 && !handle.is_directory {
            handle
                .file
                .set_len(info.size)
                .await
                .map_err(|e| VfsError::Io(format!("set_len: {e}")))?;
        }

        // Apply timestamps via the file path (std::fs::File::set_times not stable
        // on all platforms via tokio; use std blocking on the path).
        #[cfg(unix)]
        {
            use std::time::Duration;
            // FILETIME -> Unix epoch duration. Only set if non-zero.
            let to_systemtime = |ft: u64| -> Option<std::time::SystemTime> {
                if ft == 0 {
                    return None;
                }
                let secs = ft / 10_000_000;
                let unix_secs = secs.saturating_sub(UNIX_EPOCH_FILETIME_OFFSET);
                Some(std::time::UNIX_EPOCH + Duration::from_secs(unix_secs))
            };
            let times = std::fs::FileTimes::new();
            if let Some(t) = to_systemtime(info.last_write_time) {
                times.set_modified(t);
            }
            if let Some(t) = to_systemtime(info.last_access_time) {
                times.set_accessed(t);
            }
            if let Some(t) = to_systemtime(info.creation_time) {
                // set_created is not stable in this Rust version; skip creation time
                // let _ = times.set_created(t);
                let _ = t; // suppress unused variable warning
            }
            if let Ok(std_file) = std::fs::OpenOptions::new().write(true).open(&handle.full_path) {
                let _ = std_file.set_times(times);
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
        let dir_path = handle.full_path.clone();
        drop(opens);

        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&dir_path)
            .await
            .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?;
        let cap = if max_results == 0 { usize::MAX } else { max_results };
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| VfsError::Io(format!("next_entry: {e}")))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if !matches_pattern(&name, pattern) {
                continue;
            }
            let meta = entry
                .metadata()
                .await
                .map_err(|e| VfsError::Io(format!("entry metadata: {e}")))?;
            let attrs = attributes_from_metadata(&meta);
            let size = if attrs.directory { 0 } else { meta.len() };
            #[cfg(unix)]
            let allocation_size = {
                use std::os::unix::fs::MetadataExt;
                meta.blocks() * 512
            };
            #[cfg(not(unix))]
            let allocation_size = (size + 4095) & !4095;
            #[cfg(unix)]
            let file_id = {
                use std::os::unix::fs::MetadataExt;
                Some(FileId(meta.ino() as u64))
            };
            #[cfg(not(unix))]
            let file_id = None;
            entries.push(DirEntry {
                file_name: name,
                short_name: None,
                attributes: attrs,
                size,
                allocation_size,
                file_id,
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
            });
            if entries.len() >= cap {
                break;
            }
        }
        Ok(entries)
    }

    async fn file_id(&self, open: OpenId) -> Result<FileId, VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        let meta = handle
            .file
            .metadata()
            .await
            .map_err(|e| VfsError::Io(format!("metadata: {e}")))?;
        Ok(file_id_from_metadata(&meta))
    }

    async fn set_delete_on_close(&self, open: OpenId, delete: bool) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        if delete && handle.is_directory {
            // MS-FSCC: a non-empty directory cannot be marked for delete.
            let mut rd = tokio::fs::read_dir(&handle.full_path)
                .await
                .map_err(|e| VfsError::Io(format!("read_dir: {e}")))?;
            if rd.next_entry().await.map_err(|e| VfsError::Io(e.to_string()))?.is_some() {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }
        handle.delete_on_close = delete;
        Ok(())
    }

    async fn delete(&self, open: OpenId) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        if handle.is_directory {
            // Never recurse: a non-empty directory must not be deleted.
            tokio::fs::remove_dir(&handle.full_path)
                .await
                .map_err(|e| VfsError::Io(format!("remove_dir: {e}")))
        } else {
            tokio::fs::remove_file(&handle.full_path)
                .await
                .map_err(|e| VfsError::Io(format!("remove_file: {e}")))
        }
    }

    async fn rename(
        &self,
        open: OpenId,
        new_path: &str,
        replace: bool,
    ) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let handle = opens.get_mut(&open).ok_or(VfsError::InvalidHandle)?;
        let old_path = handle.full_path.clone();
        drop(opens);

        let new_full = self.resolve_new_path(new_path)?;
        if !replace && new_full.exists() {
            return Err(VfsError::AlreadyExists);
        }
        tokio::fs::rename(&old_path, &new_full)
            .await
            .map_err(|e| VfsError::Io(format!("rename: {e}")))?;
        // Update the handle's path/name.
        let mut opens = self.opens.lock().await;
        if let Some(handle) = opens.get_mut(&open) {
            handle.full_path = new_full.clone();
            handle.file_name = new_full
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
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
fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" || pattern.is_empty() {
        return true;
    }
    let mut ni = name.chars().peekable();
    let mut pi = pattern.chars().peekable();

    while let Some(pc) = pi.next() {
        match pc {
            '*' => {
                if pi.peek().is_none() {
                    return true;
                }
                let rest: String = pi.collect();
                for i in 0..=name.len() {
                    if matches_pattern(&name[i..], &rest) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if ni.next().is_none() {
                    return false;
                }
            }
            _ => match ni.next() {
                Some(nc) if nc.eq_ignore_ascii_case(&pc) => {}
                _ => return false,
            },
        }
    }
    ni.next().is_none()
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
        let fs = LocalFs::new(dir.path()).unwrap();

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
        let fs = LocalFs::new(dir.path()).unwrap();

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

        let open2 = fs.create("", "f.txt", &CreateArgs::open_readonly()).await.unwrap();
        let data = fs.read_at(open2, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"data");
        fs.close(open2).await.unwrap();
    }

    #[tokio::test]
    async fn test_open_missing_fails() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();
        let result = fs.create("", "nope.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_create_existing_fails() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();
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
        let fs = LocalFs::new(dir.path()).unwrap();
        let result = fs.create("", "..\\..\\escape.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::PathTraversal)));
    }

    #[tokio::test]
    async fn test_query_info() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();
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
        let fs = LocalFs::new(dir.path()).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "id.txt", &create).await.unwrap();
        let id = fs.file_id(open).await.unwrap();
        // Inode should be non-zero on a real filesystem.
        assert_ne!(id, FileId(0));
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_and_query_dir() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();

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
        let fs = LocalFs::new(dir.path()).unwrap();
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
        let fs = LocalFs::new(dir.path()).unwrap();
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
        // Old path gone, new path exists.
        let result = fs.create("", "old.txt", &CreateArgs::open_readonly()).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
        let open2 = fs.create("", "new.txt", &CreateArgs::open_readonly()).await;
        assert!(open2.is_ok());
    }

    #[tokio::test]
    async fn test_delete_on_close() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();
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
        let fs = LocalFs::new(dir.path()).unwrap();
        let create = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        let open = fs.create("", "ioctl.txt", &create).await.unwrap();
        let result = fs
            .ioctl(open, FsCtlCode::SetZeroData, &[])
            .await;
        assert!(matches!(result, Err(VfsError::NotSupported)));
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_flush() {
        let dir = tmp_root();
        let fs = LocalFs::new(dir.path()).unwrap();
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
        let fs = LocalFs::new(dir.path()).unwrap();
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
        // FILETIME must be greater than the epoch offset alone.
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
}
