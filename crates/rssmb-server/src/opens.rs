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

use std::collections::{HashMap, HashSet};
use std::fmt;
use tokio::sync::RwLock;

use rssmb_vfs::{FileId, OpenId, ShareAccess, DesiredAccess};

use thiserror::Error;
use tracing::{debug, instrument};

/// A byte-range lock held by a specific open handle.
///
/// Locks are identified by `(session_id, tree_id, open_id)` — the SMB lock
/// owner tuple. A lock conflicts with another if their ranges overlap and
/// at least one is exclusive.
#[derive(Debug, Clone, Copy)]
struct RangeLock {
    offset: u64,
    length: u64,
    exclusive: bool,
    /// The open handle that owns this lock.
    open_id: OpenId,
    /// Session owning the lock (for cross-session conflict attribution).
    session_id: u64,
    /// Tree on which the lock was acquired.
    tree_id: u32,
}

/// Error describing a byte-range lock conflict.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockConflict {
    #[error("lock conflict: range [{offset}, {offset}+{length}) is locked by open {open_id:?} (session {session_id})")]
    RangeConflict {
        file_id: FileId,
        offset: u64,
        length: u64,
        open_id: OpenId,
        session_id: u64,
    },
    #[error("invalid lock range: zero length")]
    ZeroLength,
}

/// Check whether two byte ranges `[o1, o1+l1)` and `[o2, o2+l2)` overlap.
///
/// Uses `u128` arithmetic for the end calculation to correctly handle
/// ranges near `u64::MAX` without overflow or saturation.
fn ranges_overlap(o1: u64, l1: u64, o2: u64, l2: u64) -> bool {
    let s1 = o1 as u128;
    let e1 = o1 as u128 + l1 as u128;
    let s2 = o2 as u128;
    let e2 = o2 as u128 + l2 as u128;
    s1 < e2 && s2 < e1
}

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
/// declared when the open was created, the desired access it requested, and
/// the delete-on-close disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenEntry {
    /// The opaque open handle returned to the client / tracked by the VFS.
    pub open_id: OpenId,
    /// Owning session id (for cross-session conflict attribution).
    pub session_id: u64,
    /// Tree id on which the open was issued.
    pub tree_id: u32,
    /// Share-access flags declared by this open — what it shares with others.
    pub share_access: ShareAccess,
    /// Desired access requested by this open — what it needs.
    pub desired_access: DesiredAccess,
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

/// Result of removing an open from the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveResult {
    /// Whether the open was found and removed.
    pub found: bool,
    /// Whether this was the last open for the file (no remaining opens).
    pub was_last: bool,
    /// Whether any open for this file (including the one being removed)
    /// had `delete_on_close` set. Only meaningful when `found` is true.
    pub any_delete_on_close: bool,
}

/// Global open table tracking every outstanding file open keyed by file
/// identity, used to enforce share-mode conflicts across sessions.
///
/// All mutating and querying methods take an async lock on the inner map.
/// The write lock is held for the duration of a `check_and_add` so that the
/// check-then-add step is atomic with respect to concurrent openers.
///
/// A `delete_pending` set tracks files with an outstanding delete-on-close
/// disposition. This persists beyond the removal of the entry that set it,
/// so the caller can determine at last-close whether to unlink the file.
///
/// Byte-range locks are tracked per file identity in `range_locks`. Each lock
/// records the owning `(session_id, tree_id, open_id)` tuple, the byte range,
/// and whether it is exclusive. The check-then-acquire step is atomic under
/// the lock. Locks are released on CLOSE (all locks for the open_id) and on
/// tree-disconnect/session-logoff (all locks for the tree/session).
#[derive(Debug)]
pub struct OpenTable {
    opens: RwLock<HashMap<FileId, Vec<OpenEntry>>>,
    /// Files with at least one open that has delete_on_close = true.
    /// Survives entry removal until the last close clears it.
    delete_pending: RwLock<HashSet<FileId>>,
    /// Per-file byte-range locks, keyed by file identity.
    range_locks: RwLock<HashMap<FileId, Vec<RangeLock>>>,
}

impl OpenTable {
    /// Create an empty open table.
    pub fn new() -> Self {
        Self {
            opens: RwLock::new(HashMap::new()),
            delete_pending: RwLock::new(HashSet::new()),
            range_locks: RwLock::new(HashMap::new()),
        }
    }

    /// Check whether `entry` conflicts with existing opens of the same file,
    /// and if not, atomically add it to the table.
    ///
    /// Per MS-SMB2 3.3.5.15, sharing is bidirectional: for each existing
    /// open, (a) the existing open must share the new open's desired access,
    /// and (b) the new open must share the existing open's desired access.
    /// A conflict in either direction denies the open with [`OpenConflict`].
    #[instrument(skip(self, file_id, entry), fields(file_id = ?file_id, open_id = ?entry.open_id, session = entry.session_id))]
    pub async fn check_and_add(
        &self,
        file_id: FileId,
        entry: OpenEntry,
    ) -> Result<(), OpenConflict> {
        let mut map = self.opens.write().await;
        if let Some(existing) = map.get(&file_id) {
            // Categorize the new open's desired access into read/write/delete.
            let new_wants_read = entry.desired_access.read || entry.desired_access.generic_read || entry.desired_access.generic_all;
            let new_wants_write = entry.desired_access.write || entry.desired_access.generic_write || entry.desired_access.generic_all;
            let new_wants_delete = entry.desired_access.delete || entry.desired_access.generic_all;

            for ex in existing {
                // (a) Existing must share what the new open wants.
                if new_wants_read && !ex.share_access.read {
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
                if new_wants_write && !ex.share_access.write {
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
                if new_wants_delete && !ex.share_access.delete {
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

                // (b) New must share what the existing open wants.
                let ex_wants_read = ex.desired_access.read || ex.desired_access.generic_read || ex.desired_access.generic_all;
                let ex_wants_write = ex.desired_access.write || ex.desired_access.generic_write || ex.desired_access.generic_all;
                let ex_wants_delete = ex.desired_access.delete || ex.desired_access.generic_all;

                if ex_wants_read && !entry.share_access.read {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: new open does not share existing READ"
                    );
                    return Err(OpenConflict::ReadNotShared {
                        file_id,
                        existing_open_id: ex.open_id,
                        existing_session_id: ex.session_id,
                    });
                }
                if ex_wants_write && !entry.share_access.write {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: new open does not share existing WRITE"
                    );
                    return Err(OpenConflict::WriteNotShared {
                        file_id,
                        existing_open_id: ex.open_id,
                        existing_session_id: ex.session_id,
                    });
                }
                if ex_wants_delete && !entry.share_access.delete {
                    debug!(
                        file_id = ?file_id,
                        new_open_id = ?entry.open_id,
                        existing_open_id = ?ex.open_id,
                        "sharing conflict: new open does not share existing DELETE"
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
        map.entry(file_id).or_default().push(entry.clone());
        // Track delete-pending state.
        if entry.delete_on_close {
            drop(map);
            self.delete_pending.write().await.insert(file_id);
        }
        Ok(())
    }

    /// Remove an open (by `open_id`) from the file's open list.
    ///
    /// Returns a [`RemoveResult`] indicating whether the open was found,
    /// whether it was the last open for the file, and whether the file has
    /// a delete-on-close disposition pending (from any open, including ones
    /// already removed).
    ///
    /// If the removed entry was the last for a file, the file key is pruned
    /// from the opens map. The `delete_pending` set is cleared when the
    /// last open is removed, so the caller can check `any_delete_on_close`
    /// to decide whether to unlink.
    #[instrument(skip(self, file_id), fields(was_last, any_doc))]
    pub async fn remove(&self, file_id: FileId, open_id: OpenId) -> RemoveResult {
        let mut map = self.opens.write().await;
        if let Some(vec) = map.get_mut(&file_id) {
            // Check if the open_id is actually present before removing.
            let was_present = vec.iter().any(|e| e.open_id == open_id);
            if !was_present {
                return RemoveResult {
                    found: false,
                    was_last: false,
                    any_delete_on_close: false,
                };
            }
            // Check the delete_pending set — this persists across entries.
            let any_doc = self.delete_pending.read().await.contains(&file_id);
            vec.retain(|e| e.open_id != open_id);
            let was_last = vec.is_empty();
            if was_last {
                map.remove(&file_id);
                // Clear delete_pending for this file — the caller will
                // handle the actual delete based on any_delete_on_close.
                drop(map);
                self.delete_pending.write().await.remove(&file_id);
            } else {
                // If no remaining entries have doc, clear the pending flag.
                let any_remaining_doc = vec.iter().any(|e| e.delete_on_close);
                if !any_remaining_doc {
                    drop(map);
                    self.delete_pending.write().await.remove(&file_id);
                }
            }
            tracing::Span::current().record("was_last", was_last);
            tracing::Span::current().record("any_doc", any_doc);
            RemoveResult {
                found: true,
                was_last,
                any_delete_on_close: any_doc,
            }
        } else {
            RemoveResult {
                found: false,
                was_last: false,
                any_delete_on_close: false,
            }
        }
    }

    /// Update the `delete_on_close` flag for an existing open entry.
    ///
    /// Called when a SET_INFO FileDispositionInformation sets or clears
    /// the delete-on-close disposition. If the open is not found, this is
    /// a no-op (the caller may have already closed it).
    #[instrument(skip(self, file_id))]
    pub async fn update_delete_on_close(
        &self,
        file_id: FileId,
        open_id: OpenId,
        delete: bool,
    ) {
        let mut map = self.opens.write().await;
        if let Some(vec) = map.get_mut(&file_id) {
            if let Some(entry) = vec.iter_mut().find(|e| e.open_id == open_id) {
                entry.delete_on_close = delete;
            }
            // Update the delete_pending set: if any entry has doc, add;
            // if none have doc, remove.
            let any_doc = vec.iter().any(|e| e.delete_on_close);
            drop(map);
            let mut dp = self.delete_pending.write().await;
            if any_doc {
                dp.insert(file_id);
            } else {
                dp.remove(&file_id);
            }
        }
    }

    /// Returns `true` if any open of the file has `delete_on_close` set.
    ///
    /// A delete-pending file must reject new opens that would prevent the
    /// delete (and is used by the create path to honor the disposition).
    #[instrument(skip(self, file_id))]
    pub async fn is_delete_pending(&self, file_id: FileId) -> bool {
        self.delete_pending.read().await.contains(&file_id)
    }

    /// Number of outstanding opens for a file identity.
    #[instrument(skip(self, file_id))]
    pub async fn count(&self, file_id: FileId) -> usize {
        let map = self.opens.read().await;
        map.get(&file_id).map(|v| v.len()).unwrap_or(0)
    }

    // ---- Byte-range lock management ----

    /// Check whether a byte range `[offset, offset+length)` is locked by
    /// another open (not the one identified by `owner_open_id`). Returns
    /// `Ok(())` if no conflicting lock exists, or `Err(LockConflict)` with
    /// details about the conflicting lock.
    ///
    /// A lock conflicts if the ranges overlap AND the existing lock is
    /// exclusive. (Used for READ — a read conflicts only with exclusive
    /// locks by other opens.)
    /// Locks owned by the same `owner_open_id` never conflict with each other
    /// (an open can upgrade its own lock).
    #[instrument(skip(self, file_id))]
    pub async fn check_range_lock(
        &self,
        file_id: FileId,
        owner_open_id: OpenId,
        offset: u64,
        length: u64,
    ) -> Result<(), LockConflict> {
        if length == 0 {
            return Ok(());
        }
        let locks = self.range_locks.read().await;
        if let Some(list) = locks.get(&file_id) {
            for lock in list {
                if lock.open_id == owner_open_id {
                    continue;
                }
                if !ranges_overlap(offset, length, lock.offset, lock.length) {
                    continue;
                }
                // Overlap with an exclusive lock by another open → conflict.
                if lock.exclusive {
                    return Err(LockConflict::RangeConflict {
                        file_id,
                        offset: lock.offset,
                        length: lock.length,
                        open_id: lock.open_id,
                        session_id: lock.session_id,
                    });
                }
            }
        }
        Ok(())
    }

    /// Check whether a WRITE to `[offset, offset+length)` would conflict
    /// with any lock held by a different open. A write conflicts with ANY
    /// overlapping lock (shared or exclusive) held by another open,
    /// per MS-SMB2 mandatory locking semantics.
    #[instrument(skip(self, file_id))]
    pub async fn check_range_lock_for_write(
        &self,
        file_id: FileId,
        owner_open_id: OpenId,
        offset: u64,
        length: u64,
    ) -> Result<(), LockConflict> {
        if length == 0 {
            return Ok(());
        }
        let locks = self.range_locks.read().await;
        if let Some(list) = locks.get(&file_id) {
            for lock in list {
                if lock.open_id == owner_open_id {
                    continue;
                }
                if !ranges_overlap(offset, length, lock.offset, lock.length) {
                    continue;
                }
                // Any overlapping lock by another open blocks writes.
                return Err(LockConflict::RangeConflict {
                    file_id,
                    offset: lock.offset,
                    length: lock.length,
                    open_id: lock.open_id,
                    session_id: lock.session_id,
                });
            }
        }
        Ok(())
    }

    /// Acquire a byte-range lock on `file_id` for the open identified by
    /// `(owner_open_id, session_id, tree_id)`. The lock is exclusive if
    /// `exclusive` is true, shared otherwise.
    ///
    /// Checks for conflicts first: if any existing lock by a *different* open
    /// overlaps this range and either is exclusive, returns `Err(LockConflict)`.
    /// The check-and-add is atomic under the write lock.
    ///
    /// For an exclusive lock, any overlapping lock by a different open
    /// (even shared) conflicts. For a shared lock, only an overlapping
    /// exclusive lock by a different open conflicts.
    #[instrument(skip(self, file_id, owner_open_id))]
    pub async fn acquire_range_lock(
        &self,
        file_id: FileId,
        owner_open_id: OpenId,
        session_id: u64,
        tree_id: u32,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<(), LockConflict> {
        if length == 0 {
            return Err(LockConflict::ZeroLength);
        }
        let mut locks = self.range_locks.write().await;
        if let Some(list) = locks.get(&file_id) {
            for lock in list {
                if lock.open_id == owner_open_id {
                    continue;
                }
                if !ranges_overlap(offset, length, lock.offset, lock.length) {
                    continue;
                }
                // Overlap with a different open's lock.
                // Conflict if the existing is exclusive OR the new one is exclusive.
                if lock.exclusive || exclusive {
                    return Err(LockConflict::RangeConflict {
                        file_id,
                        offset: lock.offset,
                        length: lock.length,
                        open_id: lock.open_id,
                        session_id: lock.session_id,
                    });
                }
            }
        }
        locks.entry(file_id).or_default().push(RangeLock {
            offset,
            length,
            exclusive,
            open_id: owner_open_id,
            session_id,
            tree_id,
        });
        Ok(())
    }

    /// Release a byte-range lock on `file_id` for the open identified by
    /// `owner_open_id`. Only a lock with the exact same `(offset, length)`
    /// is removed. If no matching lock is found, this is a no-op (MS-SMB2
    /// allows unlocking a non-held range without error).
    #[instrument(skip(self, file_id, owner_open_id))]
    pub async fn release_range_lock(
        &self,
        file_id: FileId,
        owner_open_id: OpenId,
        offset: u64,
        length: u64,
    ) {
        let mut locks = self.range_locks.write().await;
        if let Some(list) = locks.get_mut(&file_id) {
            list.retain(|l| {
                !(l.open_id == owner_open_id
                    && l.offset == offset
                    && l.length == length)
            });
            if list.is_empty() {
                locks.remove(&file_id);
            }
        }
    }

    /// Release all byte-range locks held by `owner_open_id` on any file.
    /// Called on CLOSE. Returns the number of locks released.
    #[instrument(skip(self, owner_open_id))]
    pub async fn release_all_locks_for_open(&self, owner_open_id: OpenId) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.open_id != owner_open_id);
                released += before - list.len();
                if list.is_empty() { Some(*fid) } else { None }
            })
            .collect();
        for key in empty_keys {
            locks.remove(&key);
        }
        released
    }

    /// Release all byte-range locks held by `tree_id` on any file.
    /// Called on tree-disconnect. Returns the number of locks released.
    #[instrument(skip(self, tree_id))]
    pub async fn release_all_locks_for_tree(&self, tree_id: u32) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.tree_id != tree_id);
                released += before - list.len();
                if list.is_empty() { Some(*fid) } else { None }
            })
            .collect();
        for key in empty_keys {
            locks.remove(&key);
        }
        released
    }

    /// Release all byte-range locks held by `session_id` on any file.
    /// Called on logoff. Returns the number of locks released.
    #[instrument(skip(self, session_id))]
    pub async fn release_all_locks_for_session(&self, session_id: u64) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.session_id != session_id);
                released += before - list.len();
                if list.is_empty() { Some(*fid) } else { None }
            })
            .collect();
        for key in empty_keys {
            locks.remove(&key);
        }
        released
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
    use rssmb_vfs::{FileId, OpenId, ShareAccess, DesiredAccess};

    fn fid(n: u64) -> FileId {
        FileId(n)
    }
    fn oid(n: u64) -> OpenId {
        OpenId(n)
    }
    fn entry(open_id: u64, session_id: u64, share: ShareAccess) -> OpenEntry {
        // Test helper: desired_access mirrors share_access so that the
        // bidirectional check tests both directions. An open that declares
        // share_access.read = true also "wants" read.
        let desired = DesiredAccess {
            read: share.read,
            write: share.write,
            delete: share.delete,
            ..Default::default()
        };
        OpenEntry {
            open_id: oid(open_id),
            session_id,
            tree_id: 1,
            share_access: share,
            desired_access: desired,
            delete_on_close: false,
        }
    }

    /// Like `entry` but with explicit desired access (for tests that need
    /// share and desired to differ).
    fn entry_da(open_id: u64, session_id: u64, share: ShareAccess, desired: DesiredAccess) -> OpenEntry {
        OpenEntry {
            open_id: oid(open_id),
            session_id,
            tree_id: 1,
            share_access: share,
            desired_access: desired,
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
        // Second open shares everything, wants only read.
        // Bidirectional: existing wants read → new shares read (yes).
        // New wants read → existing shares read (yes). OK.
        let new_entry = entry_da(
            2, 200,
            ShareAccess::all(),
            DesiredAccess { read: true, ..Default::default() },
        );
        table
            .check_and_add(fid(1), new_entry)
            .await
            .expect("compatible opens should succeed");
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
        let res = table.remove(fid(4), oid(1)).await;
        assert!(res.found);
        assert!(res.was_last);
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
        // The remaining open is not the last; remove returns was_last=false.
        let res = table.remove(fid(5), oid(2)).await;
        assert!(res.found);
        assert!(res.was_last);
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
        let res = table.remove(fid(6), oid(1)).await;
        assert!(res.found);
        assert!(res.any_delete_on_close);
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
        // First open: shares everything, wants nothing (just holds the file).
        let first = entry_da(1, 100, ShareAccess::all(), DesiredAccess::default());
        table.check_and_add(fid(8), first).await.unwrap();
        // Second open: shares everything except read, wants nothing.
        let second = entry_da(
            2, 200,
            ShareAccess { read: false, write: true, delete: true },
            DesiredAccess::default(),
        );
        table.check_and_add(fid(8), second).await.unwrap();
        // New open: shares all, wants only read. (a): new wants read,
        // open 2 doesn't share read → conflict.
        let new_entry = entry_da(
            3, 300,
            ShareAccess::all(),
            DesiredAccess { read: true, ..Default::default() },
        );
        let err = table
            .check_and_add(fid(8), new_entry)
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
        // New open: shares all, wants only read. Existing shares all → (a) OK.
        // Existing wants R/W/D → new shares all → (b) OK.
        let new_entry = entry_da(
            2, 200,
            ShareAccess::all(),
            DesiredAccess { read: true, ..Default::default() },
        );
        table
            .check_and_add(fid(10), new_entry)
            .await
            .expect("existing shares all, so read open succeeds");
    }

    #[tokio::test]
    async fn write_blocked_by_one_of_two_existing_opens() {
        let table = OpenTable::new();
        // First open: shares all, wants nothing.
        let first = entry_da(1, 100, ShareAccess::all(), DesiredAccess::default());
        table.check_and_add(fid(11), first).await.unwrap();
        // Second open: shares read+delete but NOT write, wants nothing.
        let second = entry_da(
            2, 200,
            ShareAccess { read: true, write: false, delete: true },
            DesiredAccess::default(),
        );
        table.check_and_add(fid(11), second).await.unwrap();
        // New open: shares all, wants only write. (b) checks pass (new
        // shares all). (a): new wants write, open 2 doesn't share write.
        let new_entry = entry_da(
            3, 300,
            ShareAccess::all(),
            DesiredAccess { write: true, ..Default::default() },
        );
        let err = table
            .check_and_add(fid(11), new_entry)
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

    #[tokio::test]
    async fn remove_returns_any_delete_on_close() {
        let table = OpenTable::new();
        // First open: delete_on_close = true, shares all.
        let mut e1 = entry(1, 100, ShareAccess::all());
        e1.delete_on_close = true;
        table.check_and_add(fid(20), e1).await.unwrap();
        // Second open: no delete_on_close, shares all.
        table
            .check_and_add(fid(20), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        // Remove the first (doc) open — not the last, any_doc should be true.
        let res = table.remove(fid(20), oid(1)).await;
        assert!(res.found);
        assert!(!res.was_last);
        assert!(res.any_delete_on_close);
        // Remove the second — last open, any_doc should be false now (the doc
        // entry was already removed).
        let res = table.remove(fid(20), oid(2)).await;
        assert!(res.found);
        assert!(res.was_last);
        assert!(!res.any_delete_on_close);
    }

    #[tokio::test]
    async fn remove_nonexistent_returns_not_found() {
        let table = OpenTable::new();
        let res = table.remove(fid(99), oid(99)).await;
        assert!(!res.found);
        assert!(!res.was_last);
        assert!(!res.any_delete_on_close);
    }

    #[tokio::test]
    async fn update_delete_on_close_sets_and_clears() {
        let table = OpenTable::new();
        table
            .check_and_add(fid(30), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        assert!(!table.is_delete_pending(fid(30)).await);
        // Set delete_on_close on the open.
        table.update_delete_on_close(fid(30), oid(1), true).await;
        assert!(table.is_delete_pending(fid(30)).await);
        // Clear it.
        table.update_delete_on_close(fid(30), oid(1), false).await;
        assert!(!table.is_delete_pending(fid(30)).await);
    }

    #[tokio::test]
    async fn update_delete_on_close_nonexistent_is_noop() {
        let table = OpenTable::new();
        // Should not panic for a nonexistent file/open.
        table.update_delete_on_close(fid(99), oid(99), true).await;
        assert!(!table.is_delete_pending(fid(99)).await);
    }

    #[tokio::test]
    async fn bidirectional_check_existing_wants_read_new_doesnt_share() {
        let table = OpenTable::new();
        // Existing open: wants read (desired.read=true), shares all.
        let existing = OpenEntry {
            open_id: oid(1),
            session_id: 100,
            tree_id: 1,
            share_access: ShareAccess::all(),
            desired_access: DesiredAccess { read: true, ..Default::default() },
            delete_on_close: false,
        };
        table.check_and_add(fid(40), existing).await.unwrap();
        // New open: shares nothing, wants nothing.
        let new_entry = OpenEntry {
            open_id: oid(2),
            session_id: 200,
            tree_id: 1,
            share_access: ShareAccess::none(),
            desired_access: DesiredAccess::default(),
            delete_on_close: false,
        };
        let err = table
            .check_and_add(fid(40), new_entry)
            .await
            .expect_err("new open doesn't share existing's read");
        assert!(matches!(err, OpenConflict::ReadNotShared { .. }));
    }

    #[tokio::test]
    async fn remove_open_id_not_in_existing_bucket_returns_not_found() {
        let table = OpenTable::new();
        table
            .check_and_add(fid(50), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        // Remove a different open_id from the same file bucket.
        let res = table.remove(fid(50), oid(99)).await;
        assert!(!res.found);
        // The original open is still there.
        assert_eq!(table.count(fid(50)).await, 1);
    }

    #[tokio::test]
    async fn delete_on_close_survives_intermediate_close() {
        // Open A (doc) and B (no doc). Close A (not last). Close B (last).
        // The last close must report any_delete_on_close correctly.
        let table = OpenTable::new();
        let mut a = entry(1, 100, ShareAccess::all());
        a.delete_on_close = true;
        table.check_and_add(fid(60), a).await.unwrap();
        table
            .check_and_add(fid(60), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        assert!(table.is_delete_pending(fid(60)).await);
        // Close A (doc) — not the last.
        let res_a = table.remove(fid(60), oid(1)).await;
        assert!(res_a.found);
        assert!(!res_a.was_last);
        assert!(res_a.any_delete_on_close);
        // is_delete_pending should be false now (no remaining doc opens).
        assert!(!table.is_delete_pending(fid(60)).await);
        // Close B — last close. any_doc should be false because the doc
        // open was already removed and no remaining opens have doc.
        let res_b = table.remove(fid(60), oid(2)).await;
        assert!(res_b.found);
        assert!(res_b.was_last);
        assert!(!res_b.any_delete_on_close);
    }

    #[tokio::test]
    async fn delete_on_close_at_last_close_with_doc_still_set() {
        // Open A (doc) only. Close A (last). any_doc must be true.
        let table = OpenTable::new();
        let mut a = entry(1, 100, ShareAccess::all());
        a.delete_on_close = true;
        table.check_and_add(fid(70), a).await.unwrap();
        assert!(table.is_delete_pending(fid(70)).await);
        let res = table.remove(fid(70), oid(1)).await;
        assert!(res.found);
        assert!(res.was_last);
        assert!(res.any_delete_on_close);
        assert!(!table.is_delete_pending(fid(70)).await);
    }

    // ---- Byte-range lock tests ----

    #[tokio::test]
    async fn lock_acquire_and_release() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .expect("exclusive lock should succeed");
        // Same open can re-lock overlapping range (upgrade).
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 50, 200, true)
            .await
            .expect("same open can lock overlapping range");
        table.release_range_lock(fid(1), oid(1), 0, 100).await;
        table.release_range_lock(fid(1), oid(1), 50, 200).await;
    }

    #[tokio::test]
    async fn lock_exclusive_blocks_other_open() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        let err = table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 50, 100, true)
            .await
            .expect_err("should conflict");
        match err {
            LockConflict::RangeConflict { open_id, .. } => {
                assert_eq!(open_id, oid(1));
            }
            LockConflict::ZeroLength => panic!("expected RangeConflict, got ZeroLength"),
        }
    }

    #[tokio::test]
    async fn lock_shared_allows_shared_no_overlap() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, false)
            .await
            .unwrap();
        // Non-overlapping shared lock by another open should succeed.
        table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 200, 100, false)
            .await
            .expect("non-overlapping shared lock should succeed");
    }

    #[tokio::test]
    async fn lock_shared_blocks_shared_overlap() {
        // A shared lock blocks another open's shared lock if they overlap?
        // No — per MS-SMB2, shared locks don't block each other; only
        // exclusive locks block, and an exclusive lock blocks any overlap.
        // Actually, for mandatory locking: a write requires no conflicting
        // lock (shared or exclusive) by another open. But LOCK acquisition:
        // a new shared lock only conflicts with an existing exclusive lock
        // by another open. A new exclusive lock conflicts with any existing
        // lock (shared or exclusive) by another open.
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, false)
            .await
            .unwrap();
        // Another open's shared lock on overlapping range should succeed.
        table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 50, 100, false)
            .await
            .expect("overlapping shared locks should coexist");
        // Another open's exclusive lock on overlapping range should fail.
        let err = table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 50, 100, true)
            .await
            .expect_err("exclusive should conflict with existing shared");
        match err {
            LockConflict::RangeConflict { open_id, .. } => {
                // The conflict could be with either existing lock (oid 1 or oid 2).
                assert!(open_id == oid(1) || open_id == oid(2));
            }
            LockConflict::ZeroLength => panic!("expected RangeConflict, got ZeroLength"),
        }
    }

    #[tokio::test]
    async fn lock_exclusive_blocks_shared_overlap() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        let err = table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 50, 100, false)
            .await
            .expect_err("shared lock should conflict with existing exclusive");
        match err {
            LockConflict::RangeConflict { open_id, .. } => assert_eq!(open_id, oid(1)),
            LockConflict::ZeroLength => panic!("expected RangeConflict, got ZeroLength"),
        }
    }

    #[tokio::test]
    async fn lock_release_nonexistent_is_noop() {
        let table = OpenTable::new();
        // Releasing a lock that doesn't exist should not panic.
        table.release_range_lock(fid(1), oid(1), 0, 100).await;
    }

    #[tokio::test]
    async fn lock_zero_length_rejected() {
        let table = OpenTable::new();
        let err = table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 0, true)
            .await
            .expect_err("zero-length lock should be rejected");
        assert!(matches!(err, LockConflict::ZeroLength));
    }

    #[tokio::test]
    async fn lock_check_no_locks_succeeds() {
        let table = OpenTable::new();
        table
            .check_range_lock(fid(1), oid(1), 0, 100)
            .await
            .expect("no locks → no conflict");
    }

    #[tokio::test]
    async fn lock_check_same_open_no_conflict() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        // The same open checking its own range should not conflict.
        table
            .check_range_lock(fid(1), oid(1), 0, 100)
            .await
            .expect("own lock should not conflict with own read");
    }

    #[tokio::test]
    async fn lock_check_for_write_blocks_shared() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, false)
            .await
            .unwrap();
        // A write by another open on the same range should conflict
        // even though the existing lock is shared.
        let err = table
            .check_range_lock_for_write(fid(1), oid(2), 50, 50)
            .await
            .expect_err("write should conflict with shared lock by other open");
        match err {
            LockConflict::RangeConflict { open_id, .. } => assert_eq!(open_id, oid(1)),
            LockConflict::ZeroLength => panic!("expected RangeConflict, got ZeroLength"),
        }
    }

    #[tokio::test]
    async fn lock_check_for_read_allows_shared() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, false)
            .await
            .unwrap();
        // A read by another open on the same range should NOT conflict
        // with a shared lock.
        table
            .check_range_lock(fid(1), oid(2), 50, 50)
            .await
            .expect("shared lock should not block reads by other opens");
    }

    #[tokio::test]
    async fn lock_release_all_for_open() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 200, 100, true)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(2), oid(1), 100, 1, 0, 50, true)
            .await
            .unwrap();
        let released = table.release_all_locks_for_open(oid(1)).await;
        assert_eq!(released, 3);
        // No locks should remain.
        table
            .check_range_lock(fid(1), oid(2), 0, 1000)
            .await
            .expect("all locks released");
    }

    #[tokio::test]
    async fn lock_release_all_for_tree() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(2), 100, 2, 200, 100, true)
            .await
            .unwrap();
        let released = table.release_all_locks_for_tree(1).await;
        assert_eq!(released, 1);
        // oid(2)'s lock on tree 2 should remain.
        table
            .check_range_lock(fid(1), oid(3), 200, 100)
            .await
            .expect_err("tree 2 lock should still block");
    }

    #[tokio::test]
    async fn lock_release_all_for_session() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(2), 200, 2, 200, 100, true)
            .await
            .unwrap();
        let released = table.release_all_locks_for_session(100).await;
        assert_eq!(released, 1);
        // Session 200's lock should remain.
        table
            .check_range_lock(fid(1), oid(3), 0, 100)
            .await
            .expect("session 100 locks released");
        table
            .check_range_lock(fid(1), oid(3), 200, 100)
            .await
            .expect_err("session 200 lock should still block");
    }

    #[tokio::test]
    async fn lock_boundary_no_conflict_adjacent() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        // [100, 200) does not overlap [0, 100).
        table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 100, 100, true)
            .await
            .expect("adjacent range should not conflict");
    }

    #[tokio::test]
    async fn lock_check_zero_length_no_conflict() {
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 100, true)
            .await
            .unwrap();
        // Zero-length read should never conflict.
        table
            .check_range_lock(fid(1), oid(2), 0, 0)
            .await
            .expect("zero-length read never conflicts");
    }
}
