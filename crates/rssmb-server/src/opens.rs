//! Global open table for cross-session share-mode conflict tracking.
//!
//! SMB mandates that the server enforce **share-mode** conflicts across all
//! opens of the same underlying file, regardless of which session or tree
//! connection they originate from. This module implements that global table.
//!
//! The table is keyed by [`FileId`] — a stable identity that survives rename
//! and is identical for hard links pointing at the same file system object.
//! Each file identity maps to a list of [`OpenEntry`] records, one per
//! outstanding open handle.
//!
//! Conflict rules follow MS-SMB2 / Windows semantics. A new open declares a
//! [`ShareAccess`] describing the access it requires (read/write/delete). For
//! the new open to succeed, **every** existing open of that file must have
//! granted the corresponding share-access flag. If any existing open did not
//! share the requested access, the new open is denied with [`OpenConflict`].

use std::collections::HashMap;
use std::fmt;
use tokio::sync::RwLock;

use rssmb_vfs::{FileId, OpenId, ShareAccess};

use thiserror::Error;
use tracing::{debug, instrument};

/// Error describing a sharing-mode conflict between a new open and an
/// existing open of the same file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenConflict {
    /// An existing open does not share read access with the new open.
    #[error("sharing violation: existing open {} (session {}) does not share READ", existing_open_id.0, existing_session_id)]
    ReadNotShared {
        file_id: FileId,
        existing_open_id: OpenId,
        existing_session_id: u64,
    },
    /// An existing open does not share write access with the new open.
    #[error("sharing violation: existing open {} (session {}) does not share WRITE", existing_open_id.0, existing_session_id)]
    WriteNotShared {
        file_id: FileId,
        existing_open_id: OpenId,
        existing_session_id: u64,
    },
    /// An existing open does not share delete access with the new open.
    #[error("sharing violation: existing open {} (session {}) does not share DELETE", existing_open_id.0, existing_session_id)]
    DeleteNotShared {
        file_id: FileId,
        existing_open_id: OpenId,
        existing_session_id: u64,
    },
}

impl OpenConflict {
    /// The file identity involved in the conflict.
    pub fn file_id(&self) -> FileId {
        match self {
            OpenConflict::ReadNotShared { file_id, .. }
            | OpenConflict::WriteNotShared { file_id, .. }
            | OpenConflict::DeleteNotShared { file_id, .. } => *file_id,
        }
    }
}

/// A single open handle recorded in the global open table.
///
/// Each entry records enough context to attribute a conflict (for logging and
/// diagnostics) and to enforce the share-mode contract: the share-access flags
/// declared when the open was created, and the delete-on-close disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenEntry {
    /// The opaque open handle returned to the client / tracked by the VFS.
    pub open_id: OpenId,
    /// Owning session id (for cross-session conflict attribution).
    pub session_id: u64,
    /// Tree id on which the open was issued.
    pub tree_id: u32,
    /// Share-access flags declared by this open — what it requires and shares.
    pub share_access: ShareAccess,
    /// Whether this open requested delete-on-close disposition.
    pub delete_on_close: bool,
}

impl fmt::Display for OpenEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "open {:?} (session {}, tree {}, share r{}w{}d{}, doc {})",
            self.open_id,
            self.session_id,
            self.tree_id,
            self.share_access.read as u8,
            self.share_access.write as u8,
            self.share_access.delete as u8,
            self.delete_on_close,
        )
    }
}

/// Global open table tracking every outstanding file open keyed by file
/// identity, used to enforce share-mode conflicts across sessions.
///
/// All mutating and querying methods take an async lock on the inner map.
/// The write lock is held for the duration of a `check_and_add` so that the
/// check-then-add step is atomic with respect to concurrent openers.
#[derive(Debug)]
pub struct OpenTable {
    opens: RwLock<HashMap<FileId, Vec<OpenEntry>>>,
}

impl OpenTable {
    /// Create an empty open table.
    pub fn new() -> Self {
        Self {
            opens: RwLock::new(HashMap::new()),
        }
    }

    /// Check whether `entry` conflicts with existing opens of the same file,
    /// and if not, atomically add it to the table.
    ///
    /// The new open's requested access is taken from `entry.share_access`:
    /// each set flag (read/write/delete) is an access the new open requires.
    /// For the open to succeed, **every** existing open of the file must have
    /// granted the corresponding share-access flag. If any existing open did
    /// not share a requested access, an [`OpenConflict`] is returned and the
    /// open is **not** added.
    #[instrument(skip(self, file_id, entry), fields(file_id = ?file_id, open_id = ?entry.open_id, session = entry.session_id))]
    pub async fn check_and_add(
        &self,
        file_id: FileId,
        entry: OpenEntry,
    ) -> Result<(), OpenConflict> {
        let mut map = self.opens.write().await;
        if let Some(existing) = map.get(&file_id) {
            for ex in existing {
                // New open wants READ: all existing opens must share read.
                if entry.share_access.read && !ex.share_access.read {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: READ not shared by existing open"
                    );
                    return Err(OpenConflict::ReadNotShared {
                        file_id,
                        existing_open_id: ex.open_id,
                        existing_session_id: ex.session_id,
                    });
                }
                // New open wants WRITE: all existing opens must share write.
                if entry.share_access.write && !ex.share_access.write {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: WRITE not shared by existing open"
                    );
                    return Err(OpenConflict::WriteNotShared {
                        file_id,
                        existing_open_id: ex.open_id,
                        existing_session_id: ex.session_id,
                    });
                }
                // New open wants DELETE: all existing opens must share delete.
                if entry.share_access.delete && !ex.share_access.delete {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: DELETE not shared by existing open"
                    );
                    return Err(OpenConflict::DeleteNotShared {
                        file_id,
                        existing_open_id: ex.open_id,
                        existing_session_id: ex.session_id,
                    });
                }
            }
        }
        // No conflict: insert the new open.
        map.entry(file_id).or_default().push(entry);
        Ok(())
    }

    /// Remove an open (by `open_id`) from the file's open list.
    ///
    /// If the removed entry was the last for a file, the file key is pruned
    /// from the map to keep the table compact.
    #[instrument(skip(self, file_id))]
    pub async fn remove(&self, file_id: FileId, open_id: OpenId) {
        let mut map = self.opens.write().await;
        if let Some(vec) = map.get_mut(&file_id) {
            vec.retain(|e| e.open_id != open_id);
            if vec.is_empty() {
                map.remove(&file_id);
            }
        }
    }

    /// Returns `true` if any open of the file has `delete_on_close` set.
    ///
    /// A delete-pending file must reject new opens that would prevent the
    /// delete (and is used by the create path to honor the disposition).
    #[instrument(skip(self, file_id))]
    pub async fn is_delete_pending(&self, file_id: FileId) -> bool {
        let map = self.opens.read().await;
        map.get(&file_id)
            .map(|vec| vec.iter().any(|e| e.delete_on_close))
            .unwrap_or(false)
    }

    /// Number of outstanding opens for a file identity.
    #[instrument(skip(self, file_id))]
    pub async fn count(&self, file_id: FileId) -> usize {
        let map = self.opens.read().await;
        map.get(&file_id).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for OpenTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rssmb_vfs::{FileId, OpenId, ShareAccess};

    fn fid(n: u64) -> FileId {
        FileId(n)
    }
    fn oid(n: u64) -> OpenId {
        OpenId(n)
    }
    fn entry(open_id: u64, session_id: u64, share: ShareAccess) -> OpenEntry {
        OpenEntry {
            open_id: oid(open_id),
            session_id,
            tree_id: 1,
            share_access: share,
            delete_on_close: false,
        }
    }

    #[tokio::test]
    async fn add_first_open_succeeds() {
        let table = OpenTable::new();
        let e = entry(1, 100, ShareAccess::all());
        table.check_and_add(fid(1), e).await.expect("first open always succeeds");
        assert_eq!(table.count(fid(1)).await, 1);
    }

    #[tokio::test]
    async fn compatible_opens_succeed() {
        let table = OpenTable::new();
        // First open shares everything (wants read/write/delete).
        table
            .check_and_add(fid(1), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        // Second open wants read; existing shares read -> ok.
        table
            .check_and_add(fid(1), entry(2, 200, ShareAccess { read: true, write: false, delete: false }))
            .await
            .expect("read on read-shared should succeed");
        assert_eq!(table.count(fid(1)).await, 2);
    }

    #[tokio::test]
    async fn read_blocked_by_non_shared_read() {
        let table = OpenTable::new();
        // Existing open shares only write+delete, NOT read.
        table
            .check_and_add(
                fid(1),
                entry(1, 100, ShareAccess { read: false, write: true, delete: true }),
            )
            .await
            .unwrap();
        // New open wants read (share_access.read = true).
        let err = table
            .check_and_add(fid(1), entry(2, 200, ShareAccess { read: true, write: false, delete: false }))
            .await
            .expect_err("read should be denied");
        match err {
            OpenConflict::ReadNotShared {
                existing_open_id,
                existing_session_id,
                file_id,
            } => {
                assert_eq!(existing_open_id, oid(1));
                assert_eq!(existing_session_id, 100);
                assert_eq!(file_id, fid(1));
            }
            other => panic!("expected ReadNotShared, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_blocked_by_non_shared_write() {
        let table = OpenTable::new();
        table
            .check_and_add(
                fid(2),
                entry(1, 100, ShareAccess { read: true, write: false, delete: true }),
            )
            .await
            .unwrap();
        // New open wants write.
        let err = table
            .check_and_add(fid(2), entry(2, 200, ShareAccess { read: false, write: true, delete: false }))
            .await
            .expect_err("write should be denied");
        assert!(matches!(err, OpenConflict::WriteNotShared { .. }));
    }

    #[tokio::test]
    async fn delete_blocked_by_non_shared_delete() {
        let table = OpenTable::new();
        table
            .check_and_add(
                fid(3),
                entry(1, 100, ShareAccess { read: true, write: true, delete: false }),
            )
            .await
            .unwrap();
        // New open wants delete.
        let err = table
            .check_and_add(fid(3), entry(2, 200, ShareAccess { read: false, write: false, delete: true }))
            .await
            .expect_err("delete should be denied");
        assert!(matches!(err, OpenConflict::DeleteNotShared { .. }));
    }

    #[tokio::test]
    async fn first_open_after_remove_allows_conflicting_open() {
        let table = OpenTable::new();
        table
            .check_and_add(fid(4), entry(1, 100, ShareAccess::none()))
            .await
            .unwrap();
        table.remove(fid(4), oid(1)).await;
        assert_eq!(table.count(fid(4)).await, 0);
        table
            .check_and_add(fid(4), entry(2, 200, ShareAccess::all()))
            .await
            .expect("after removal, no conflict");
    }

    #[tokio::test]
    async fn remove_only_removes_matching_open_id() {
        let table = OpenTable::new();
        table
            .check_and_add(fid(5), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        table
            .check_and_add(fid(5), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        table.remove(fid(5), oid(1)).await;
        assert_eq!(table.count(fid(5)).await, 1);
    }

    #[tokio::test]
    async fn is_delete_pending_true_and_false() {
        let table = OpenTable::new();
        assert!(!table.is_delete_pending(fid(6)).await);
        let mut e = entry(1, 100, ShareAccess::all());
        e.delete_on_close = true;
        table.check_and_add(fid(6), e).await.unwrap();
        assert!(table.is_delete_pending(fid(6)).await);
        // Add another non-delete open.
        table
            .check_and_add(fid(6), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        // Still pending because the first open is doc.
        assert!(table.is_delete_pending(fid(6)).await);
        // Remove the delete-on-close open.
        table.remove(fid(6), oid(1)).await;
        assert!(!table.is_delete_pending(fid(6)).await);
    }

    #[tokio::test]
    async fn conflict_reports_existing_not_new_open() {
        let table = OpenTable::new();
        // Existing open shares nothing.
        table
            .check_and_add(fid(7), entry(1, 300, ShareAccess::none()))
            .await
            .unwrap();
        let err = table
            .check_and_add(fid(7), entry(2, 400, ShareAccess::all()))
            .await
            .expect_err("should conflict");
        // The conflict must reference the *existing* open (1, session 300).
        match err {
            OpenConflict::ReadNotShared { existing_open_id, existing_session_id, .. } => {
                assert_eq!(existing_open_id, oid(1));
                assert_eq!(existing_session_id, 300);
            }
            other => panic!("expected ReadNotShared, got {other:?}"),
        }
        // The conflicting new open must NOT have been added.
        assert_eq!(table.count(fid(7)).await, 1);
    }

    #[tokio::test]
    async fn any_existing_non_shared_blocks() {
        let table = OpenTable::new();
        // First open shares everything.
        table
            .check_and_add(fid(8), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        // Second open shares everything except read.
        table
            .check_and_add(
                fid(8),
                entry(2, 200, ShareAccess { read: false, write: true, delete: true }),
            )
            .await
            .unwrap();
        // New read open conflicts because open 2 does not share read.
        let err = table
            .check_and_add(fid(8), entry(3, 300, ShareAccess { read: true, write: false, delete: false }))
            .await
            .expect_err("should conflict with open 2");
        match err {
            OpenConflict::ReadNotShared { existing_open_id, .. } => {
                assert_eq!(existing_open_id, oid(2));
            }
            other => panic!("expected ReadNotShared, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_conflict_when_new_open_wants_nothing() {
        let table = OpenTable::new();
        // Existing open shares nothing.
        table
            .check_and_add(fid(9), entry(1, 100, ShareAccess::none()))
            .await
            .unwrap();
        // A new open that requests no access (share_access all false) should
        // never conflict, even against a fully unsharing existing open.
        table
            .check_and_add(fid(9), entry(2, 200, ShareAccess::none()))
            .await
            .expect("no requested access => no conflict");
        assert_eq!(table.count(fid(9)).await, 2);
    }

    #[tokio::test]
    async fn remove_nonexistent_is_noop() {
        let table = OpenTable::new();
        // Removing from an absent file id / open id must not panic.
        table.remove(fid(99), oid(99)).await;
        assert_eq!(table.count(fid(99)).await, 0);
    }

    #[tokio::test]
    async fn delete_pending_blocks_new_open() {
        // When a delete-on-close open exists, new opens requesting access must
        // still honor sharing rules. Here the delete-pending open shares all,
        // so a read open succeeds; the delete-pending flag is reported
        // separately via is_delete_pending.
        let table = OpenTable::new();
        let mut e = entry(1, 100, ShareAccess::all());
        e.delete_on_close = true;
        table.check_and_add(fid(10), e).await.unwrap();
        assert!(table.is_delete_pending(fid(10)).await);
        table
            .check_and_add(fid(10), entry(2, 200, ShareAccess { read: true, write: false, delete: false }))
            .await
            .expect("existing shares all, so read open succeeds");
    }

    #[tokio::test]
    async fn write_blocked_by_one_of_two_existing_opens() {
        let table = OpenTable::new();
        // First open shares all.
        table
            .check_and_add(fid(11), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        // Second open shares read+delete but NOT write.
        table
            .check_and_add(
                fid(11),
                entry(2, 200, ShareAccess { read: true, write: false, delete: true }),
            )
            .await
            .unwrap();
        // New open wants write; blocked by open 2.
        let err = table
            .check_and_add(fid(11), entry(3, 300, ShareAccess { read: false, write: true, delete: false }))
            .await
            .expect_err("write should be blocked by open 2");
        match err {
            OpenConflict::WriteNotShared { existing_open_id, existing_session_id, .. } => {
                assert_eq!(existing_open_id, oid(2));
                assert_eq!(existing_session_id, 200);
            }
            other => panic!("expected WriteNotShared, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn full_read_write_delete_open_after_all_sharing() {
        let table = OpenTable::new();
        table
            .check_and_add(fid(12), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        table
            .check_and_add(fid(12), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        table
            .check_and_add(fid(12), entry(3, 300, ShareAccess::all()))
            .await
            .expect("all opens share all => no conflict");
        assert_eq!(table.count(fid(12)).await, 3);
        // Remove one; count drops.
        table.remove(fid(12), oid(2)).await;
        assert_eq!(table.count(fid(12)).await, 2);
    }
}
