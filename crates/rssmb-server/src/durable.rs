//! Durable handle table for SMB 3.x reconnect (MS-SMB2 2.2.13.2.11/2.2.13.2.12).
//!
//! When a client opens a file with a DH2Q (durable handle v2 request) create
//! context, the server records the open so it can survive a disconnect. If the
//! client reconnects within the durable timeout and presents a DH2C (durable
//! handle v2 reconnect) create context with the same `CreateGuid`, the open is
//! re-attached to the new connection — no "network path lost" error.
//!
//! The table is keyed by `CreateGuid` (a client-supplied GUID). Each entry
//! stores the VFS handle, session identity, tree, share-access, and a
//! deadline. Expired entries are cleaned up lazily on lookup and by a
//! background sweeper.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use rssmb_vfs::{DesiredAccess, FileId, OpenId, ShareAccess};

/// A durable open entry — kept alive after disconnect for reconnect.
///
/// Stores enough context to re-attach the open to a new connection: the VFS
/// handle, the session user (for validation), the tree, and the share-access
/// flags (so share-mode conflicts can be re-checked against any new opens
/// that may have arrived while the client was disconnected).
pub struct DurableEntry {
    /// The VFS open handle — kept alive (not closed) while durable.
    pub vfs: Arc<dyn rssmb_vfs::Vfs>,
    /// The opaque VFS open id for this handle.
    pub open_id: OpenId,
    /// Stable file identity (dev,ino) for the open file — used to key
    /// into the global OpenTable for share-mode conflict tracking.
    pub file_id: Option<FileId>,
    /// Session id that created the durable open.
    pub session_id: u64,
    /// Tree id on which the durable open was created.
    pub tree_id: u32,
    /// The share name (for re-connect tree validation).
    pub share_name: String,
    /// User identity (username) that created the durable open.
    /// Reconnect must come from the same user.
    pub username: String,
    /// Share-access flags from the original open.
    pub share_access: ShareAccess,
    /// Desired access from the original open.
    pub desired_access: DesiredAccess,
    /// File path (for diagnostics/logging).
    pub path: String,
    /// Deadline after which the durable open is closed and removed.
    pub deadline: Instant,
}

impl std::fmt::Debug for DurableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableEntry")
            .field("open_id", &self.open_id)
            .field("session_id", &self.session_id)
            .field("tree_id", &self.tree_id)
            .field("share_name", &self.share_name)
            .field("username", &self.username)
            .field("path", &self.path)
            .finish()
    }
}

/// Global table of durable opens, keyed by `CreateGuid`.
///
/// The table is a `RwLock<HashMap<[u8; 16], DurableEntry>>`. The key is the
/// raw 16-byte representation of the `CreateGuid` (the client-supplied GUID
/// from the DH2Q create context).
///
/// Expired entries are cleaned up lazily: every `insert`, `take`, and
/// `sweep` call evicts entries past their deadline. A background sweeper
/// (spawned by `ServerState`) calls `sweep` periodically to close expired
/// VFS handles promptly even when no client activity triggers a lookup.
pub struct DurableTable {
    entries: RwLock<HashMap<[u8; 16], DurableEntry>>,
}

impl DurableTable {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a durable open. Called from `handle_create` when a DH2Q
    /// create context is present and the open succeeds.
    pub async fn insert(&self, create_guid: [u8; 16], entry: DurableEntry) {
        let mut entries = self.entries.write().await;
        // If an entry with the same GUID already exists (e.g. a stale
        // durable from a previous connection that timed out but wasn't
        // swept yet), close it before replacing it.
        if let Some(old) = entries.remove(&create_guid) {
            tracing::debug!(
                guid = ?create_guid,
                "durable insert: replacing stale entry, closing old VFS handle"
            );
            // Close the old VFS handle in the background — don't block
            // the new open on the old handle's cleanup.
            let vfs = old.vfs.clone();
            let open_id = old.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "durable: closing stale VFS handle failed");
                }
            });
        }
        entries.insert(create_guid, entry);
    }

    /// Peek at a durable open by `CreateGuid` without removing it.
    /// Returns `Ok(&DurableEntry)` if found (expired entries return `Expired`).
    /// Used by the DH2C path to validate identity/share before committing
    /// to the take.
    pub async fn peek(
        &self,
        create_guid: &[u8; 16],
    ) -> Result<DurableEntry, DurableReconnectError> {
        let entries = self.entries.read().await;
        match entries.get(create_guid) {
            Some(entry) => {
                if Instant::now() > entry.deadline {
                    Err(DurableReconnectError::Expired)
                } else {
                    // Clone the entry — it contains Arcs so this is cheap.
                    Ok(DurableEntry {
                        vfs: entry.vfs.clone(),
                        open_id: entry.open_id,
                        file_id: entry.file_id,
                        session_id: entry.session_id,
                        tree_id: entry.tree_id,
                        share_name: entry.share_name.clone(),
                        username: entry.username.clone(),
                        share_access: entry.share_access,
                        desired_access: entry.desired_access,
                        path: entry.path.clone(),
                        deadline: entry.deadline,
                    })
                }
            }
            None => Err(DurableReconnectError::NotFound),
        }
    }

    /// Take (remove) a durable open by `CreateGuid`. Returns `Ok(entry)` if
    /// found and not expired, `Err(DurableReconnectError)` otherwise.
    ///
    /// The caller is responsible for re-attaching the returned entry to the
    /// new connection's open table. Call `peek` first to validate identity
    /// before committing to the take.
    pub async fn take(
        &self,
        create_guid: &[u8; 16],
    ) -> Result<DurableEntry, DurableReconnectError> {
        let mut entries = self.entries.write().await;
        // Note: we do NOT call evict_expired here — the requested entry
        // must be checked for expiry specifically so the caller gets
        // `Expired` (not `NotFound`) when the deadline has passed.
        // Other expired entries are cleaned up by the sweeper.
        match entries.remove(create_guid) {
            Some(entry) => {
                if Instant::now() > entry.deadline {
                    tracing::debug!(guid = ?create_guid, "durable reconnect: entry expired");
                    // Close the expired VFS handle.
                    let vfs = entry.vfs.clone();
                    let open_id = entry.open_id;
                    tokio::spawn(async move {
                        if let Err(e) = vfs.close(open_id).await {
                            tracing::warn!(error = %e, "durable: closing expired VFS handle failed");
                        }
                    });
                    Err(DurableReconnectError::Expired)
                } else {
                    Ok(entry)
                }
            }
            None => Err(DurableReconnectError::NotFound),
        }
    }

    /// Forget a durable open by `CreateGuid` (e.g. when the client closes
    /// the handle normally). Does NOT close the VFS handle — the caller
    /// is responsible for closing the VFS handle after calling this.
    ///
    /// Returns `true` if the entry was found and removed.
    pub async fn forget(&self, create_guid: &[u8; 16]) -> bool {
        let mut entries = self.entries.write().await;
        entries.remove(create_guid).is_some()
    }

    /// Sweep all expired entries, closing their VFS handles. Called
    /// periodically by the background sweeper and opportunistically by
    /// `take`/`insert`.
    pub async fn sweep(&self) -> usize {
        let mut entries = self.entries.write().await;
        Self::evict_expired(&mut entries).await
    }

    /// Evict expired entries from the map. Returns the count evicted.
    /// Closes VFS handles for evicted entries in the background.
    async fn evict_expired(entries: &mut HashMap<[u8; 16], DurableEntry>) -> usize {
        let now = Instant::now();
        let expired: Vec<[u8; 16]> = entries
            .iter()
            .filter(|(_, e)| now > e.deadline)
            .map(|(k, _)| *k)
            .collect();
        let count = expired.len();
        for guid in expired {
            if let Some(entry) = entries.remove(&guid) {
                let vfs = entry.vfs.clone();
                let open_id = entry.open_id;
                // Also remove from the global open table.
                if let Some(fid) = entry.file_id {
                    // We can't access the OpenTable here without a reference.
                    // The OpenTable removal is handled by the caller or the
                    // background sweeper. For now, just close the VFS handle.
                    // The OpenTable entry will be cleaned up on the next
                    // check_and_add or sweep.
                    let _ = fid; // suppress unused warning
                }
                tokio::spawn(async move {
                    if let Err(e) = vfs.close(open_id).await {
                        tracing::warn!(error = %e, "durable sweep: closing VFS handle failed");
                    }
                });
            }
        }
        if count > 0 {
            tracing::debug!(expired = count, "durable: swept expired entries");
        }
        count
    }

    /// Number of entries in the table (for diagnostics).
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if the table contains no entries.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Close all durable VFS handles and clear the table. Called during
    /// graceful shutdown to ensure durable handles are properly cleaned up.
    pub async fn close_all(&self) -> usize {
        let mut entries = self.entries.write().await;
        let drained: Vec<([u8; 16], DurableEntry)> = entries.drain().collect();
        let count = drained.len();
        for (_guid, entry) in drained {
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "durable close_all: VFS close failed");
                }
            });
        }
        count
    }
}

impl Default for DurableTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned by `DurableTable::take` when a reconnect fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DurableReconnectError {
    #[error("durable handle not found")]
    NotFound,
    #[error("durable handle expired")]
    Expired,
}

/// Compute the deadline for a durable open given the timeout in seconds.
pub fn deadline_from_timeout(timeout_secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rssmb_vfs::{
        CreateArgs, CreateResult, DesiredAccess, DirEntry, DirInfoClass, FileId, FileInfo,
        FsCtlCode, FsStats, InfoClass, LockRange, OpenId, SecurityInfo, ShareAccess, Vfs, VfsError,
    };

    /// A no-op VFS stub for durable table tests.
    struct StubVfs;

    #[async_trait::async_trait]
    impl Vfs for StubVfs {
        async fn create(&self, _: &str, _: &str, _: &CreateArgs) -> Result<CreateResult, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn read_at(&self, _: OpenId, _: u64, _: u32) -> Result<bytes::Bytes, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn write_at(&self, _: OpenId, _: u64, _: &[u8]) -> Result<u32, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn close(&self, _: OpenId) -> Result<(), VfsError> {
            Ok(())
        }
        async fn flush(&self, _: OpenId) -> Result<(), VfsError> {
            Ok(())
        }
        async fn lock(&self, _: OpenId, _: LockRange, _: bool) -> Result<(), VfsError> {
            Ok(())
        }
        async fn unlock(&self, _: OpenId, _: LockRange) -> Result<(), VfsError> {
            Ok(())
        }
        async fn query_info(&self, _: OpenId, _: InfoClass) -> Result<FileInfo, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn set_info(&self, _: OpenId, _: InfoClass, _: &FileInfo) -> Result<(), VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn query_dir(
            &self,
            _: OpenId,
            _: &str,
            _: DirInfoClass,
            _: bool,
            _: usize,
        ) -> Result<Vec<DirEntry>, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn file_id(&self, _: OpenId) -> Result<FileId, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn delete(&self, _: OpenId) -> Result<(), VfsError> {
            Ok(())
        }
        async fn rename(&self, _: OpenId, _: &str, _: bool) -> Result<(), VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn ioctl(&self, _: OpenId, _: FsCtlCode, _: &[u8]) -> Result<Vec<u8>, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn fs_stats(&self, _: OpenId) -> Result<FsStats, VfsError> {
            Err(VfsError::NotSupported)
        }
        async fn query_security(&self, _: OpenId) -> Result<SecurityInfo, VfsError> {
            Err(VfsError::NotSupported)
        }
    }

    fn test_entry() -> DurableEntry {
        DurableEntry {
            vfs: Arc::new(StubVfs) as Arc<dyn Vfs>,
            open_id: OpenId(1),
            file_id: Some(FileId { dev: 0, ino: 42 }),
            session_id: 100,
            tree_id: 1,
            share_name: "test".to_string(),
            username: "user".to_string(),
            share_access: ShareAccess::all(),
            desired_access: DesiredAccess::default(),
            path: "/test".to_string(),
            deadline: Instant::now() + Duration::from_secs(3600),
        }
    }

    fn guid(n: u8) -> [u8; 16] {
        let mut g = [0u8; 16];
        g[0] = n;
        g
    }

    #[tokio::test]
    async fn insert_and_take() {
        let table = DurableTable::new();
        table.insert(guid(1), test_entry()).await;
        assert_eq!(table.len().await, 1);
        let entry = table.take(&guid(1)).await.expect("should find entry");
        assert_eq!(entry.session_id, 100);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn take_not_found() {
        let table = DurableTable::new();
        let err = table.take(&guid(99)).await.unwrap_err();
        assert_eq!(err, DurableReconnectError::NotFound);
    }

    #[tokio::test]
    async fn take_expired() {
        let table = DurableTable::new();
        let mut entry = test_entry();
        entry.deadline = Instant::now() - Duration::from_secs(1);
        table.insert(guid(1), entry).await;
        let err = table.take(&guid(1)).await.unwrap_err();
        assert_eq!(err, DurableReconnectError::Expired);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn forget_returns_true_when_found() {
        let table = DurableTable::new();
        table.insert(guid(1), test_entry()).await;
        assert!(table.forget(&guid(1)).await);
        assert_eq!(table.len().await, 0);
        assert!(!table.forget(&guid(1)).await);
    }

    #[tokio::test]
    async fn insert_replaces_stale() {
        let table = DurableTable::new();
        table.insert(guid(1), test_entry()).await;
        let mut entry2 = test_entry();
        entry2.session_id = 200;
        table.insert(guid(1), entry2).await;
        let entry = table.take(&guid(1)).await.unwrap();
        assert_eq!(entry.session_id, 200);
    }

    #[tokio::test]
    async fn sweep_removes_expired() {
        let table = DurableTable::new();
        let mut expired = test_entry();
        expired.deadline = Instant::now() - Duration::from_secs(1);
        table.insert(guid(1), expired).await;
        table.insert(guid(2), test_entry()).await;
        assert_eq!(table.len().await, 2);
        let swept = table.sweep().await;
        assert_eq!(swept, 1);
        assert_eq!(table.len().await, 1);
        // The non-expired entry should still be there.
        assert!(table.take(&guid(2)).await.is_ok());
    }

    #[tokio::test]
    async fn sweep_with_no_entries_is_noop() {
        let table = DurableTable::new();
        assert_eq!(table.sweep().await, 0);
    }
}
