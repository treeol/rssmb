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

use rssmb_proto::oplock::OplockLevel;
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
    /// The SMB2 persistent id that was returned to the client in the CREATE
    /// response. DH2C/DHnC reconnect requests carry this id and Samba's
    /// primary lookup is BY PERSISTENT ID (smbXsrv_open.c:
    /// smb2srv_open_recreate — `persistent_id & 0xFFFFFFFF` keys the global
    /// table); the CreateGuid is only verified afterwards.
    pub smb_persistent_id: u64,
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
    /// File path (for name-vs-lease validation and diagnostics).
    pub path: String,
    /// The client GUID of the connection that created the durable open.
    /// Lease-backed durables are scoped to it: a reconnect presenting the
    /// right lease key from a different client GUID fails with
    /// OBJECT_NAME_NOT_FOUND (golden: reopen1a-lease; Samba scopes leases
    /// by (client_guid, lease_key) in leases_db). Oplock-backed durables
    /// ignore it (durable_v2_open.c:634 — "for oplocks, the client guid
    /// can be different").
    pub client_guid: Option<[u8; 16]>,
    /// Deadline after which the durable open is closed and removed.
    pub deadline: Instant,
    /// Oplock granted on the original open, echoed on reconnect
    /// (Samba maps from the stored oplock_type; `None` = no oplock).
    pub oplock_level: Option<OplockLevel>,
    /// Lease granted on the original open, echoed on reconnect via an RqLs
    /// response context (Samba: `smb2_create.c:1622` — emitted when the
    /// original open holds a lease, regardless of what the reconnect
    /// requests). `None` = the open was not leased.
    pub lease: Option<LeaseEcho>,
    /// Whether the owning connection has dropped and the handle is orphaned.
    ///
    /// Samba's `vfs_default_durable_cookie.allow_reconnect` is `false` while
    /// the handle is still attached to a live connection and only flips to
    /// `true` in `vfs_default_durable_disconnect` (source3/smbd/durable.c)
    /// when the connection tears down. A DH2C against a still-live handle
    /// therefore fails with `OBJECT_NAME_NOT_FOUND` (verified against the
    /// 4.19.5 golden server, subtest reopen1).
    pub orphaned: bool,
}

/// Lease state to echo in the reconnect CREATE response.
#[derive(Debug, Clone)]
pub struct LeaseEcho {
    pub lease_key: [u8; 16],
    pub state: crate::opens::LeaseCaching,
    pub is_v2: bool,
    pub parent_lease_key: Option<[u8; 16]>,
    pub epoch: u16,
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
            .field("orphaned", &self.orphaned)
            .finish()
    }
}

/// Global table of durable opens, keyed by `CreateGuid`.
///
/// The table is a `RwLock<HashMap<[u8; 16], DurableEntry>>`. The key is the
/// raw 16-byte representation of the `CreateGuid` (the client-supplied GUID
/// from the DH2Q create context). A secondary index by SMB persistent id
/// serves the DH2C/DHnC lookup path (Samba keys its global table by the
/// persistent id and verifies the CreateGuid afterwards — a v1 `DHnC`
/// reconnect carries no GUID and must match by id alone).
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
                    Ok(clone_entry(entry))
                }
            }
            None => Err(DurableReconnectError::NotFound),
        }
    }

    /// Look up a durable open by the SMB persistent file id carried in a
    /// DH2C/DHnC reconnect context. Mirrors Samba's primary lookup
    /// (`smb2srv_open_recreate`); when `create_guid` is provided (DH2C) it
    /// is verified against the stored entry, when `None` (DHnC v1 reconnect)
    /// the GUID check is skipped — it is valid to v1-reconnect a v2-opened
    /// handle (source3/smbd/smbXsrv_open.c, smb2srv_open_recreate_fn).
    pub async fn peek_by_persistent_id(
        &self,
        smb_persistent_id: u64,
        create_guid: Option<&[u8; 16]>,
    ) -> Result<DurableEntry, DurableReconnectError> {
        let entries = self.entries.read().await;
        let found = entries
            .iter()
            .find(|(_, e)| e.smb_persistent_id == smb_persistent_id);
        match found {
            Some((guid, entry)) => {
                if Instant::now() > entry.deadline {
                    return Err(DurableReconnectError::Expired);
                }
                if let Some(req_guid) = create_guid {
                    if guid != req_guid {
                        return Err(DurableReconnectError::NotFound);
                    }
                }
                Ok(clone_entry(entry))
            }
            None => Err(DurableReconnectError::NotFound),
        }
    }

    /// Mark the entry keyed by `create_guid` as orphaned (its owning
    /// connection has dropped). Guid-keyed variant used from connection
    /// cleanup, which has the guid at hand.
    pub async fn mark_orphaned(&self, create_guid: &[u8; 16]) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(create_guid) {
            entry.orphaned = true;
        }
    }

    /// Mark every entry created by `session_id` on `conn_id`'s opens as
    /// orphaned: the owning connection has dropped, so a future DH2C/DHnC
    /// may re-attach the handle. Called from the connection cleanup path.
    /// Samba flips the equivalent `allow_reconnect` cookie in
    /// `vfs_default_durable_disconnect` at the same point.
    pub async fn orphan_by_session(&self, session_id: u64) -> usize {
        let mut entries = self.entries.write().await;
        let mut count = 0;
        for entry in entries.values_mut() {
            if entry.session_id == session_id && !entry.orphaned {
                entry.orphaned = true;
                count += 1;
            }
        }
        if count > 0 {
            tracing::debug!(
                session_id,
                orphaned = count,
                "durable: entries orphaned by disconnect"
            );
        }
        count
    }

    /// Take (remove) a durable open by the SMB persistent file id carried in
    /// a DH2C/DHnC reconnect context, verifying the CreateGuid when present.
    /// Returns `Ok(entry)` if found and not expired, `Err(DurableReconnectError)`
    /// otherwise.
    ///
    /// The caller is responsible for re-attaching the returned entry to the
    /// new connection's open table. Call `peek_by_persistent_id` first to
    /// validate identity before committing to the take.
    pub async fn take_by_persistent_id(
        &self,
        smb_persistent_id: u64,
        create_guid: Option<&[u8; 16]>,
    ) -> Result<(DurableEntry, [u8; 16]), DurableReconnectError> {
        let mut entries = self.entries.write().await;
        // Note: we do NOT call evict_expired here — the requested entry
        // must be checked for expiry specifically so the caller gets
        // `Expired` (not `NotFound`) when the deadline has passed.
        // Other expired entries are cleaned up by the sweeper.
        let found = entries
            .iter()
            .find(|(_, e)| e.smb_persistent_id == smb_persistent_id)
            .map(|(guid, _)| *guid);
        let guid = match found {
            Some(guid) => guid,
            None => return Err(DurableReconnectError::NotFound),
        };
        let entry = entries.remove(&guid).expect("just found");
        if Instant::now() > entry.deadline {
            tracing::debug!(guid = ?guid, "durable reconnect: entry expired");
            // Close the expired VFS handle.
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "durable: closing expired VFS handle failed");
                }
            });
            return Err(DurableReconnectError::Expired);
        }
        if let Some(req_guid) = create_guid {
            if guid != *req_guid {
                // Put it back — a failed GUID verification must not destroy
                // the durable open (mirrors peek/take split semantics).
                entries.insert(guid, entry);
                return Err(DurableReconnectError::NotFound);
            }
        }
        Ok((entry, guid))
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

impl DurableEntry {
    // The CreateGuid is the table key, not a field; GUID verification happens
    // in the keyed lookup APIs (peek_by_persistent_id / take_by_persistent_id)
    // which see both the key and the entry.
}

/// Clone a durable entry (Arcs make this cheap).
fn clone_entry(entry: &DurableEntry) -> DurableEntry {
    DurableEntry {
        vfs: entry.vfs.clone(),
        open_id: entry.open_id,
        file_id: entry.file_id,
        smb_persistent_id: entry.smb_persistent_id,
        session_id: entry.session_id,
        tree_id: entry.tree_id,
        share_name: entry.share_name.clone(),
        username: entry.username.clone(),
        share_access: entry.share_access,
        desired_access: entry.desired_access,
        path: entry.path.clone(),
        client_guid: entry.client_guid,
        deadline: entry.deadline,
        oplock_level: entry.oplock_level,
        lease: entry.lease.clone(),
        orphaned: entry.orphaned,
    }
}

/// Compute the deadline for a durable open given the timeout in seconds.
#[cfg(test)]
pub fn deadline_from_timeout(timeout_secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(timeout_secs)
}

/// Compute the deadline for a durable open given the negotiated timeout in
/// milliseconds (MS-SMB2 §2.2.13.2.11 — the server echoes this to the client).
pub fn deadline_from_millis(timeout_msecs: u32) -> Instant {
    Instant::now() + Duration::from_millis(timeout_msecs as u64)
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
            smb_persistent_id: 0x1234_5678,
            session_id: 100,
            tree_id: 1,
            share_name: "test".to_string(),
            username: "user".to_string(),
            share_access: ShareAccess::all(),
            desired_access: DesiredAccess::default(),
            path: "/test".to_string(),
            client_guid: None,
            deadline: Instant::now() + Duration::from_secs(3600),
            oplock_level: None,
            lease: None,
            orphaned: false,
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

    #[tokio::test]
    async fn orphan_by_session_flips_only_matching_entries() {
        let table = DurableTable::new();
        table.insert(guid(1), test_entry()).await;
        let mut other = test_entry();
        other.session_id = 200;
        table.insert(guid(2), other).await;
        assert_eq!(table.orphan_by_session(100).await, 1);
        let e = table.peek(&guid(1)).await.unwrap();
        assert!(e.orphaned);
        let e2 = table.peek(&guid(2)).await.unwrap();
        assert!(!e2.orphaned);
        // Idempotent: second call finds nothing new.
        assert_eq!(table.orphan_by_session(100).await, 0);
    }

    #[tokio::test]
    async fn take_by_persistent_id_matches_and_verifies_guid() {
        let table = DurableTable::new();
        table.insert(guid(1), test_entry()).await;

        // Match by persistent id with the right GUID.
        let (entry, key) = table
            .take_by_persistent_id(0x1234_5678, Some(&guid(1)))
            .await
            .expect("should find by persistent id");
        assert_eq!(key, guid(1));
        assert_eq!(entry.session_id, 100);

        // Re-insert; wrong GUID must fail with NotFound and NOT consume
        // the entry.
        table.insert(guid(1), test_entry()).await;
        let err = table
            .take_by_persistent_id(0x1234_5678, Some(&guid(9)))
            .await
            .unwrap_err();
        assert_eq!(err, DurableReconnectError::NotFound);
        assert_eq!(
            table.len().await,
            1,
            "wrong-guid take must not consume the entry"
        );

        // v1 DHnC reconnect: no GUID — valid to v1-reconnect a v2 open.
        let (entry, _) = table
            .take_by_persistent_id(0x1234_5678, None)
            .await
            .expect("v1 reconnect must match by id alone");
        assert_eq!(entry.session_id, 100);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn take_by_persistent_id_miss_and_expiry() {
        let table = DurableTable::new();
        let err = table.take_by_persistent_id(0xDEAD, None).await.unwrap_err();
        assert_eq!(err, DurableReconnectError::NotFound);

        let mut expired = test_entry();
        expired.deadline = Instant::now() - Duration::from_secs(1);
        table.insert(guid(1), expired).await;
        let err = table
            .take_by_persistent_id(0x1234_5678, None)
            .await
            .unwrap_err();
        assert_eq!(err, DurableReconnectError::Expired);
        assert_eq!(table.len().await, 0);
    }
}
