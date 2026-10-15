//! In-memory VFS backend — for testing.
//!
//! A simple in-memory filesystem that implements the Vfs trait.
//! Useful for unit tests where filesystem I/O is not desired.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::*;

struct InMemoryFile {
    data: Vec<u8>,
    attributes: FileAttributes,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    is_directory: bool,
    #[allow(dead_code)]
    delete_on_close: bool,
    file_id: Option<FileId>,
}

struct InMemoryOpen {
    file_key: String,
    file_id: FileId,
    #[allow(dead_code)]
    share_access: ShareAccess,
    #[allow(dead_code)]
    delete_on_close: bool,
}

pub struct MemoryFs {
    files: Arc<Mutex<HashMap<String, InMemoryFile>>>,
    opens: Arc<Mutex<HashMap<OpenId, InMemoryOpen>>>,
    next_open_id: Arc<Mutex<u64>>,
    next_file_id: Arc<Mutex<u64>>,
}

impl MemoryFs {
    pub fn new() -> Self {
        let mut files = HashMap::new();
        // Create root directory
        files.insert(
            "".to_string(),
            InMemoryFile {
                data: vec![],
                attributes: FileAttributes {
                    directory: true,
                    normal: false,
                    ..Default::default()
                },
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                is_directory: true,
                delete_on_close: false,
                file_id: Some(FileId(0)),
            },
        );

        Self {
            files: Arc::new(Mutex::new(files)),
            opens: Arc::new(Mutex::new(HashMap::new())),
            next_open_id: Arc::new(Mutex::new(1)),
            next_file_id: Arc::new(Mutex::new(1)),
        }
    }

    fn now_filetime() -> u64 {
        // Approximate: seconds since epoch as 100ns intervals since 1601
        // 11644473600 = seconds between 1601-01-01 and 1970-01-01
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (secs + 11644473600) * 10_000_000
    }

    async fn next_open_id(&self) -> OpenId {
        let mut id = self.next_open_id.lock().await;
        let val = *id;
        *id += 1;
        OpenId(val)
    }

    async fn next_file_id(&self) -> FileId {
        let mut id = self.next_file_id.lock().await;
        let val = *id;
        *id += 1;
        FileId(val)
    }
}

impl Default for MemoryFs {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Vfs for MemoryFs {
    async fn create(
        &self,
        _share_root: &str,
        path: &str,
        args: &CreateArgs,
    ) -> Result<OpenId, VfsError> {
        let normalized =
            NormalizedPath::from_smb_path(path).map_err(|_| VfsError::PathTraversal)?;
        let key = normalized.to_smb_string();

        let mut files = self.files.lock().await;

        let file_id = self.next_file_id().await;
        let is_dir = args.create_options.directory;

        let exists = files.contains_key(&key);

        // Check disposition
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
                // Replace existing or create new
            }
            CreateDisposition::Overwrite => {
                if !exists {
                    return Err(VfsError::NotFound);
                }
            }
            CreateDisposition::OverwriteIf => {}
        }

        if !exists {
            let now = Self::now_filetime();
            let new_id = FileId(files.len() as u64);
            files.insert(
                key.clone(),
                InMemoryFile {
                    data: vec![],
                    attributes: FileAttributes {
                        directory: is_dir,
                        normal: !is_dir,
                        ..Default::default()
                    },
                    creation_time: now,
                    last_access_time: now,
                    last_write_time: now,
                    change_time: now,
                    is_directory: is_dir,
                    delete_on_close: false,
                    file_id: Some(new_id),
                },
            );
        } else if matches!(
            args.disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Overwrite
                | CreateDisposition::OverwriteIf
        ) {
            // Truncate
            if let Some(f) = files.get_mut(&key) {
                f.data.clear();
                f.last_write_time = Self::now_filetime();
            }
        }

        let open_id = self.next_open_id().await;
        let mut opens = self.opens.lock().await;
        opens.insert(
            open_id,
            InMemoryOpen {
                file_key: key,
                file_id,
                share_access: args.share_access,
                delete_on_close: args.create_options.delete_on_close,
            },
        );

        Ok(open_id)
    }

    async fn read_at(&self, open: OpenId, offset: u64, len: u32) -> Result<Bytes, VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let key = open_info.file_key.clone();
        drop(opens);

        let files = self.files.lock().await;
        let file = files.get(&key).ok_or(VfsError::NotFound)?;

        if file.is_directory {
            return Err(VfsError::IsDirectory);
        }

        let offset = offset as usize;
        if offset >= file.data.len() {
            return Ok(Bytes::new());
        }

        let end = (offset + len as usize).min(file.data.len());
        Ok(Bytes::copy_from_slice(&file.data[offset..end]))
    }

    async fn write_at(&self, open: OpenId, offset: u64, data: &[u8]) -> Result<u32, VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let key = open_info.file_key.clone();
        drop(opens);

        let mut files = self.files.lock().await;
        let file = files.get_mut(&key).ok_or(VfsError::NotFound)?;

        if file.is_directory {
            return Err(VfsError::IsDirectory);
        }

        let offset = offset as usize;
        let end = offset + data.len();
        if end > file.data.len() {
            file.data.resize(end, 0);
        }
        file.data[offset..end].copy_from_slice(data);
        file.last_write_time = Self::now_filetime();
        file.change_time = file.last_write_time;

        Ok(data.len() as u32)
    }

    async fn close(&self, open: OpenId) -> Result<(), VfsError> {
        let mut opens = self.opens.lock().await;
        let open_info = opens.remove(&open).ok_or(VfsError::InvalidHandle)?;

        if open_info.delete_on_close {
            let mut files = self.files.lock().await;
            files.remove(&open_info.file_key);
        }

        Ok(())
    }

    async fn flush(&self, _open: OpenId) -> Result<(), VfsError> {
        // In-memory — nothing to flush
        Ok(())
    }

    async fn lock(
        &self,
        _open: OpenId,
        _range: LockRange,
        _exclusive: bool,
    ) -> Result<(), VfsError> {
        // In-memory — locks are tracked by the server's global table
        Ok(())
    }

    async fn unlock(&self, _open: OpenId, _range: LockRange) -> Result<(), VfsError> {
        Ok(())
    }

    async fn query_info(&self, open: OpenId, _class: InfoClass) -> Result<FileInfo, VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let key = open_info.file_key.clone();
        let file_id = open_info.file_id;
        drop(opens);

        let files = self.files.lock().await;
        let file = files.get(&key).ok_or(VfsError::NotFound)?;

        Ok(FileInfo {
            file_id,
            attributes: file.attributes.clone(),
            size: file.data.len() as u64,
            allocation_size: file.data.len() as u64,
            creation_time: file.creation_time,
            last_access_time: file.last_access_time,
            last_write_time: file.last_write_time,
            change_time: file.change_time,
            file_name: key,
        })
    }

    async fn set_info(
        &self,
        open: OpenId,
        _class: InfoClass,
        info: &FileInfo,
    ) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let key = open_info.file_key.clone();
        drop(opens);

        let mut files = self.files.lock().await;
        let file = files.get_mut(&key).ok_or(VfsError::NotFound)?;
        file.attributes = info.attributes.clone();
        file.creation_time = info.creation_time;
        file.last_access_time = info.last_access_time;
        file.last_write_time = info.last_write_time;
        file.change_time = info.change_time;
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
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let dir_key = open_info.file_key.clone();
        drop(opens);

        let files = self.files.lock().await;

        // Find all children of dir_key
        let prefix = if dir_key.is_empty() {
            String::new()
        } else {
            format!("{}\\", dir_key)
        };

        let mut entries = Vec::new();
        for (key, file) in files.iter() {
            // Skip the directory itself
            if key == &dir_key {
                continue;
            }
            // Check if this is a direct child
            if let Some(rest) = key.strip_prefix(&prefix) {
                // Only direct children (no more separators)
                if !rest.contains('\\') {
                    let name = rest.to_string();
                    // Simple wildcard matching (* and ?)
                    if matches_pattern(&name, pattern) {
                        entries.push(DirEntry {
                            file_name: name,
                            short_name: None,
                            attributes: file.attributes.clone(),
                            size: file.data.len() as u64,
                            allocation_size: file.data.len() as u64,
                            file_id: file.file_id,
                            creation_time: file.creation_time,
                            last_access_time: file.last_access_time,
                            last_write_time: file.last_write_time,
                            change_time: file.change_time,
                        });
                        if entries.len() >= max_results {
                            break;
                        }
                    }
                }
            }
        }
        Ok(entries)
    }

    async fn file_id(&self, open: OpenId) -> Result<FileId, VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        Ok(open_info.file_id)
    }

    async fn delete(&self, open: OpenId) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let key = open_info.file_key.clone();
        drop(opens);

        let mut files = self.files.lock().await;
        files.remove(&key);
        Ok(())
    }

    async fn rename(&self, open: OpenId, new_path: &str, _replace: bool) -> Result<(), VfsError> {
        let opens = self.opens.lock().await;
        let open_info = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let old_key = open_info.file_key.clone();
        drop(opens);

        let normalized =
            NormalizedPath::from_smb_path(new_path).map_err(|_| VfsError::PathTraversal)?;
        let new_key = normalized.to_smb_string();

        let mut files = self.files.lock().await;
        if let Some(mut file) = files.remove(&old_key) {
            file.last_write_time = Self::now_filetime();
            file.change_time = file.last_write_time;
            files.insert(new_key, file);
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }

    async fn ioctl(
        &self,
        _open: OpenId,
        ctl: FsCtlCode,
        _input: &[u8],
    ) -> Result<Vec<u8>, VfsError> {
        match ctl {
            FsCtlCode::Other(_) => Err(VfsError::NotSupported),
            _ => Err(VfsError::NotSupported),
        }
    }

    async fn fs_stats(&self, _open: OpenId) -> Result<FsStats, VfsError> {
        // In-memory filesystem: report a small fixed capacity.
        Ok(FsStats {
            total_blocks: 1_000_000,
            available_blocks: 500_000,
            free_blocks: 500_000,
            block_size: 512,
            sector_size: 512,
        })
    }

    async fn query_security(&self, open: OpenId) -> Result<SecurityInfo, VfsError> {
        let opens = self.opens.lock().await;
        let file_open = opens.get(&open).ok_or(VfsError::InvalidHandle)?;
        let files = self.files.lock().await;
        let file = files.get(&file_open.file_key).ok_or(VfsError::NotFound)?;
        Ok(SecurityInfo {
            uid: 0,
            gid: 0,
            mode: if file.attributes.read_only {
                0o444
            } else {
                0o644
            },
        })
    }
}

/// Simple wildcard pattern matching (* and ?).
/// Unicode-safe: uses char indices, not byte indices.
fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
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
                // Try to match the rest of the pattern at each position
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

    #[tokio::test]
    async fn test_create_read_write_close() {
        let fs = MemoryFs::new();
        let _args = CreateArgs::open_readonly();

        // Create a file
        let mut create_args = CreateArgs::open_readonly();
        create_args.disposition = CreateDisposition::Create;
        let open = fs.create("", "test.txt", &create_args).await.unwrap();

        // Write
        let written = fs.write_at(open, 0, b"Hello, World!").await.unwrap();
        assert_eq!(written, 13);

        // Read back
        let data = fs.read_at(open, 0, 100).await.unwrap();
        assert_eq!(data.as_ref(), b"Hello, World!");

        // Close
        fs.close(open).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_existing_fails() {
        let fs = MemoryFs::new();
        let args = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };

        fs.create("", "file.txt", &args).await.unwrap();
        let result = fs.create("", "file.txt", &args).await;
        assert!(matches!(result, Err(VfsError::AlreadyExists)));
    }

    #[tokio::test]
    async fn test_open_missing_fails() {
        let fs = MemoryFs::new();
        let args = CreateArgs::open_readonly();
        let result = fs.create("", "nonexistent.txt", &args).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let fs = MemoryFs::new();
        let args = CreateArgs::open_readonly();
        let result = fs.create("", "..\\..\\escape.txt", &args).await;
        assert!(matches!(result, Err(VfsError::PathTraversal)));
    }

    #[tokio::test]
    async fn test_delete_on_close() {
        let fs = MemoryFs::new();
        let mut args = CreateArgs::open_readonly();
        args.disposition = CreateDisposition::Create;
        args.create_options.delete_on_close = true;

        let open = fs.create("", "temp.txt", &args).await.unwrap();
        fs.close(open).await.unwrap();

        // File should be gone
        let args2 = CreateArgs::open_readonly();
        let result = fs.create("", "temp.txt", &args2).await;
        assert!(matches!(result, Err(VfsError::NotFound)));
    }

    #[tokio::test]
    async fn test_query_dir() {
        let fs = MemoryFs::new();

        // Create some files
        let args = CreateArgs {
            disposition: CreateDisposition::Create,
            ..CreateArgs::open_readonly()
        };
        fs.create("", "file1.txt", &args).await.unwrap();
        fs.create("", "file2.txt", &args).await.unwrap();
        fs.create("", "file3.log", &args).await.unwrap();

        // Open root directory
        let dir_args = CreateArgs {
            disposition: CreateDisposition::Open,
            create_options: CreateOptions {
                directory: true,
                ..Default::default()
            },
            ..CreateArgs::open_readonly()
        };
        let dir_open = fs.create("", "", &dir_args).await.unwrap();

        // List all
        let entries = fs
            .query_dir(dir_open, "*", DirInfoClass::DirectoryInfo, true, 100)
            .await
            .unwrap();
        assert_eq!(entries.len(), 3);

        // List *.txt
        let entries = fs
            .query_dir(dir_open, "*.txt", DirInfoClass::DirectoryInfo, true, 100)
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_wildcard_pattern() {
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
