//! Tree connection — a share mount point within a session.
//!
//! A `Tree` represents a successful TREE_CONNECT to a share. It owns the
//! per-share VFS backend and tracks all open handles created under this tree
//! so they can be force-closed when the tree is disconnected (TREE_DISCONNECT)
//! or the owning session logs off.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::ShareConfig;

/// A tree connection (share mount point) within a session.
///
/// Each `Tree` binds a `ShareConfig` to its live VFS backend instance and
/// tracks the open handles issued against it. On disconnect, all tracked
/// handles are closed through the VFS so that delete-on-close and resource
/// cleanup propagate to the backend.
pub struct Tree {
    /// Tree ID assigned by the server for this connection.
    pub id: u32,
    /// Owning session ID.
    pub session_id: u64,
    /// Name of the share this tree is connected to.
    pub share_name: String,
    /// Configuration for the share backing this tree.
    pub share_config: ShareConfig,
    /// VFS backend for this share.
    pub vfs: Arc<dyn rssmb_vfs::Vfs>,
    /// Open handles created under this tree, tracked for cleanup.
    open_handles: Mutex<HashSet<rssmb_vfs::OpenId>>,
}

impl Tree {
    /// Create a new tree connection.
    pub fn new(
        id: u32,
        session_id: u64,
        share_name: String,
        share_config: ShareConfig,
        vfs: Arc<dyn rssmb_vfs::Vfs>,
    ) -> Self {
        Self {
            id,
            session_id,
            share_name,
            share_config,
            vfs,
            open_handles: Mutex::new(HashSet::new()),
        }
    }

    /// Record a handle as belonging to this tree.
    pub async fn add_handle(&self, open_id: rssmb_vfs::OpenId) {
        self.open_handles.lock().await.insert(open_id);
    }

    /// Remove a handle from this tree's tracking set.
    ///
    /// Returns `true` if the handle was present and removed.
    pub async fn remove_handle(&self, open_id: rssmb_vfs::OpenId) -> bool {
        self.open_handles.lock().await.remove(&open_id)
    }

    /// Close all outstanding handles via the VFS and clear the tracking set.
    ///
    /// Errors closing individual handles are logged and ignored so that one
    /// failing close does not prevent cleanup of the remaining handles.
    pub async fn close_all(&self) {
        let handles: Vec<rssmb_vfs::OpenId> = self.open_handles.lock().await.drain().collect();
        for open_id in handles {
            if let Err(e) = self.vfs.close(open_id).await {
                tracing::warn!(
                    tree_id = self.id,
                    session_id = self.session_id,
                    open_id = open_id.0,
                    error = %e,
                    "failed to close handle during tree teardown"
                );
            }
        }
    }

    /// Borrow the share name for this tree.
    pub fn share_name(&self) -> &str {
        &self.share_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use rssmb_vfs::{
        CreateArgs, DirEntry, DirInfoClass, FileId, FileInfo, FsCtlCode, FsStats, InfoClass,
        LockRange, OpenId, SecurityInfo, Vfs, VfsError,
    };

    /// A no-op VFS stub that only records close calls so tests can observe
    /// handle cleanup without exercising a real filesystem.
    struct StubVfs {
        closed: Mutex<Vec<OpenId>>,
    }

    impl StubVfs {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                closed: Mutex::new(Vec::new()),
            })
        }

        async fn closed_ids(&self) -> Vec<OpenId> {
            self.closed.lock().await.clone()
        }
    }

    #[async_trait]
    impl Vfs for StubVfs {
        async fn create(
            &self,
            _share_root: &str,
            _path: &str,
            _args: &CreateArgs,
        ) -> Result<rssmb_vfs::CreateResult, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn read_at(&self, _open: OpenId, _offset: u64, _len: u32) -> Result<Bytes, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn write_at(
            &self,
            _open: OpenId,
            _offset: u64,
            _data: &[u8],
        ) -> Result<u32, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn close(&self, open: OpenId) -> Result<(), VfsError> {
            self.closed.lock().await.push(open);
            Ok(())
        }
        async fn flush(&self, _open: OpenId) -> Result<(), VfsError> {
            Ok(())
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
        async fn query_info(&self, _open: OpenId, _class: InfoClass) -> Result<FileInfo, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn set_info(
            &self,
            _open: OpenId,
            _class: InfoClass,
            _info: &FileInfo,
        ) -> Result<(), VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn query_dir(
            &self,
            _open: OpenId,
            _pattern: &str,
            _class: DirInfoClass,
            _restart: bool,
            _max_results: usize,
        ) -> Result<Vec<DirEntry>, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn file_id(&self, _open: OpenId) -> Result<FileId, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn delete(&self, _open: OpenId) -> Result<(), VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn rename(
            &self,
            _open: OpenId,
            _new_path: &str,
            _replace: bool,
        ) -> Result<(), VfsError> {
            Err(VfsError::NotSupported)
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
            Err(VfsError::NotSupported)
        }
        async fn query_security(&self, _open: OpenId) -> Result<SecurityInfo, VfsError> {
            Err(VfsError::NotSupported)
        }
    }

    fn test_share_config() -> ShareConfig {
        ShareConfig {
            name: "test".to_string(),
            path: "/tmp/rssmb-test".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            read_users: vec![],
            write_users: vec![],
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
            strict_sync: true,
            case_sensitive: false,
        }
    }

    #[tokio::test]
    async fn add_and_remove_handle() {
        let vfs = StubVfs::new();
        let tree = Tree::new(1, 42, "test".to_string(), test_share_config(), vfs.clone());

        let id_a = OpenId(10);
        let id_b = OpenId(20);

        tree.add_handle(id_a).await;
        tree.add_handle(id_b).await;

        // remove returns true for present handles
        assert!(tree.remove_handle(id_a).await);
        // removing again returns false
        assert!(!tree.remove_handle(id_a).await);
        // unknown handle returns false
        assert!(!tree.remove_handle(OpenId(999)).await);
    }

    #[tokio::test]
    async fn share_name_accessor() {
        let vfs = StubVfs::new();
        let tree = Tree::new(7, 1, "docs".to_string(), test_share_config(), vfs.clone());
        assert_eq!(tree.share_name(), "docs");
    }

    #[tokio::test]
    async fn close_all_closes_every_handle_and_clears_set() {
        let vfs = StubVfs::new();
        let tree = Tree::new(2, 99, "test".to_string(), test_share_config(), vfs.clone());

        let ids = [OpenId(1), OpenId(2), OpenId(3)];
        for id in ids {
            tree.add_handle(id).await;
        }

        tree.close_all().await;

        let closed = vfs.closed_ids().await;
        // all three handles were closed through the VFS
        assert_eq!(closed.len(), 3);
        for id in ids {
            assert!(closed.contains(&id));
        }
        // the tracking set is drained
        assert!(!tree.remove_handle(OpenId(1)).await);
        assert!(!tree.remove_handle(OpenId(2)).await);
        assert!(!tree.remove_handle(OpenId(3)).await);
    }

    #[tokio::test]
    async fn close_all_on_empty_tree_is_noop() {
        let vfs = StubVfs::new();
        let tree = Tree::new(3, 7, "test".to_string(), test_share_config(), vfs.clone());
        // no handles added; close_all should not panic or close anything
        tree.close_all().await;
        assert!(vfs.closed_ids().await.is_empty());
    }

    #[tokio::test]
    async fn duplicate_add_handle_is_idempotent() {
        let vfs = StubVfs::new();
        let tree = Tree::new(4, 5, "test".to_string(), test_share_config(), vfs.clone());

        let id = OpenId(77);
        tree.add_handle(id).await;
        tree.add_handle(id).await; // duplicate insert is a no-op for a set

        assert!(tree.remove_handle(id).await);
        assert!(!tree.remove_handle(id).await);
    }
}
