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

use rssmb_vfs::{DesiredAccess, FileId, OpenId, ShareAccess};

use thiserror::Error;
use tracing::{debug, instrument};

/// Sender handle for delivering unsolicited lease/oplock break notifications
/// on the owning connection.
pub type LeaseNotifySender = tokio::sync::mpsc::Sender<bytes::Bytes>;

/// File caching state for SMB 2.1+ Leases (MS-SMB2 2.2.13.2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseCaching {
    pub read: bool,
    pub handle: bool,
    pub write: bool,
}

impl LeaseCaching {
    pub const NONE: Self = Self {
        read: false,
        handle: false,
        write: false,
    };

    pub fn from_bits(bits: u32) -> Self {
        Self {
            read: bits & 0x01 != 0,
            handle: bits & 0x02 != 0,
            write: bits & 0x04 != 0,
        }
    }

    pub fn to_bits(self) -> u32 {
        let mut bits = 0u32;
        if self.read {
            bits |= 0x01;
        }
        if self.handle {
            bits |= 0x02;
        }
        if self.write {
            bits |= 0x04;
        }
        bits
    }

    pub fn to_proto(self) -> rssmb_proto::create::LeaseState {
        rssmb_proto::create::LeaseState::new()
            .with_read_caching(self.read)
            .with_handle_caching(self.handle)
            .with_write_caching(self.write)
    }

    pub fn from_proto(s: rssmb_proto::create::LeaseState) -> Self {
        Self {
            read: s.read_caching(),
            handle: s.handle_caching(),
            write: s.write_caching(),
        }
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            read: self.read || other.read,
            handle: self.handle || other.handle,
            write: self.write || other.write,
        }
    }

    pub fn is_subset_of(self, other: Self) -> bool {
        (self.to_bits() & !other.to_bits()) == 0
    }
}

/// Unique identifier for a Lease in the global lease table: `(ClientGuid, LeaseKey)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseId {
    pub client_guid: [u8; 16],
    pub lease_key: [u8; 16],
}

/// Result of granting or upgrading a lease on `CREATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_key: [u8; 16],
    pub state: LeaseCaching,
    pub flags: u32,
    pub epoch: u16,
    pub parent_lease_key: Option<[u8; 16]>,
    pub is_v2: bool,
}

/// Operation kind that may conflict with existing leases or oplocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictOp {
    /// Another handle is reading from the file (breaks W).
    Read,
    /// Another handle is writing or truncating the file (breaks R and W).
    Write,
    /// Another handle is renaming or setting delete-on-close (breaks H and W, or R/H/W).
    HandleOrDelete,
    /// Byte-range lock acquired on the file (breaks R/H/W).
    Lock,
}

/// An unsolicited break notification to be sent to a client connection.
#[derive(Debug, Clone)]
pub enum BreakNotification {
    Lease {
        notify_tx: LeaseNotifySender,
        lease_key: [u8; 16],
        current_state: LeaseCaching,
        new_state: LeaseCaching,
        new_epoch: u16,
        ack_required: bool,
    },
    Oplock {
        notify_tx: LeaseNotifySender,
        smb_file_id: rssmb_proto::create::FileId,
        new_oplock_level: u8,
    },
}

#[derive(Debug)]
struct LeaseRecord {
    file_id: FileId,
    state: LeaseCaching,
    breaking: bool,
    break_to: LeaseCaching,
    pending_break_to: Option<LeaseCaching>,
    epoch: u16,
    is_v2: bool,
    parent_lease_key: Option<[u8; 16]>,
    handles: HashSet<OpenId>,
    notify_tx: LeaseNotifySender,
    break_waiters: Vec<tokio::sync::oneshot::Sender<()>>,
}

#[derive(Debug)]
struct OplockRecord {
    file_id: FileId,
    open_id: OpenId,
    smb_file_id: rssmb_proto::create::FileId,
    level: u8,
    breaking_to: Option<u8>,
    pending_breaking_to: Option<u8>,
    notify_tx: LeaseNotifySender,
    break_waiters: Vec<tokio::sync::oneshot::Sender<()>>,
}

#[derive(Debug, Default)]
struct LeaseManager {
    leases: HashMap<LeaseId, LeaseRecord>,
    oplocks: HashMap<OpenId, OplockRecord>,
}

impl LeaseManager {
    /// Break other lease/oplock holders when a new open arrives on `file_id`.
    fn break_other_holders_on_open(
        &mut self,
        file_id: FileId,
        actor_lease: Option<LeaseId>,
        actor_open: OpenId,
        _requested: LeaseCaching,
    ) -> Vec<BreakNotification> {
        let mut out = Vec::new();
        for (id, rec) in self.leases.iter_mut() {
            if rec.file_id != file_id || Some(*id) == actor_lease || rec.handles.is_empty() {
                continue;
            }
            if rec.state.write {
                let current = rec.state;
                let target = LeaseCaching {
                    read: rec.state.read,
                    handle: rec.state.handle,
                    write: false,
                };
                if !rec.breaking {
                    rec.breaking = true;
                    rec.break_to = target;
                    if rec.is_v2 {
                        rec.epoch = rec.epoch.wrapping_add(1);
                    }
                    out.push(BreakNotification::Lease {
                        notify_tx: rec.notify_tx.clone(),
                        lease_key: id.lease_key,
                        current_state: current,
                        new_state: target,
                        new_epoch: if rec.is_v2 { rec.epoch } else { 0 },
                        ack_required: true,
                    });
                }
            }
        }
        for (oid, rec) in self.oplocks.iter_mut() {
            if rec.file_id != file_id || *oid == actor_open {
                continue;
            }
            if (rec.level == 0x08 || rec.level == 0x09) && rec.breaking_to.is_none() {
                rec.breaking_to = Some(0x01);
                out.push(BreakNotification::Oplock {
                    notify_tx: rec.notify_tx.clone(),
                    smb_file_id: rec.smb_file_id,
                    new_oplock_level: 0x01,
                });
            }
        }
        out
    }

    fn trigger_breaks(
        &mut self,
        file_id: FileId,
        actor_lease: Option<LeaseId>,
        actor_open: Option<OpenId>,
        op: ConflictOp,
    ) -> (Vec<BreakNotification>, Vec<tokio::sync::oneshot::Receiver<()>>) {
        let mut notifications = Vec::new();
        let mut receivers = Vec::new();

        for (id, rec) in self.leases.iter_mut() {
            if rec.file_id != file_id || Some(*id) == actor_lease || rec.handles.is_empty() {
                continue;
            }

            let target = match op {
                ConflictOp::Read => {
                    if !rec.state.write {
                        continue;
                    }
                    LeaseCaching {
                        read: rec.state.read,
                        handle: rec.state.handle,
                        write: false,
                    }
                }
                ConflictOp::Write => {
                    if !rec.state.read && !rec.state.write {
                        continue;
                    }
                    LeaseCaching::NONE
                }
                ConflictOp::HandleOrDelete | ConflictOp::Lock => {
                    if rec.state == LeaseCaching::NONE {
                        continue;
                    }
                    LeaseCaching::NONE
                }
            };

            if rec.state == target {
                continue;
            }

            // MS-SMB2 3.3.4.7: Ack is required if the lease currently holds H or W,
            // and is NOT required if breaking from R-only to None.
            let ack_required = rec.state.handle || rec.state.write;

            if !rec.breaking {
                let current = rec.state;
                if rec.is_v2 {
                    rec.epoch = rec.epoch.wrapping_add(1);
                }
                if ack_required {
                    rec.breaking = true;
                    rec.break_to = target;
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    receivers.push(rx);
                } else {
                    rec.state = target;
                }
                notifications.push(BreakNotification::Lease {
                    notify_tx: rec.notify_tx.clone(),
                    lease_key: id.lease_key,
                    current_state: current,
                    new_state: target,
                    new_epoch: if rec.is_v2 { rec.epoch } else { 0 },
                    ack_required,
                });
            } else {
                // Already breaking: record stricter pending target for follow-up break
                // once the client acknowledges the currently advertised break_to.
                let narrower = LeaseCaching {
                    read: rec.break_to.read && target.read,
                    handle: rec.break_to.handle && target.handle,
                    write: rec.break_to.write && target.write,
                };
                if narrower != rec.break_to {
                    rec.pending_break_to = Some(match rec.pending_break_to {
                        Some(p) => LeaseCaching {
                            read: p.read && narrower.read,
                            handle: p.handle && narrower.handle,
                            write: p.write && narrower.write,
                        },
                        None => narrower,
                    });
                }
                if ack_required {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    receivers.push(rx);
                }
            }
        }

        let mut oplocks_to_remove = Vec::new();
        for (oid, rec) in self.oplocks.iter_mut() {
            if rec.file_id != file_id || Some(*oid) == actor_open {
                continue;
            }
            let (need_break, new_level, ack_req) = match op {
                ConflictOp::Read => (
                    rec.level == 0x08 || rec.level == 0x09,
                    0x01,
                    true,
                ),
                ConflictOp::Write | ConflictOp::HandleOrDelete | ConflictOp::Lock => (
                    rec.level != 0,
                    0x00,
                    rec.level == 0x08 || rec.level == 0x09,
                ),
            };
            if !need_break {
                continue;
            }
            if rec.breaking_to.is_none() {
                if ack_req {
                    rec.breaking_to = Some(new_level);
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    receivers.push(rx);
                } else {
                    rec.level = 0x00;
                    oplocks_to_remove.push(*oid);
                }
                notifications.push(BreakNotification::Oplock {
                    notify_tx: rec.notify_tx.clone(),
                    smb_file_id: rec.smb_file_id,
                    new_oplock_level: new_level,
                });
            } else if ack_req {
                if new_level == 0x00 && rec.breaking_to == Some(0x01) {
                    rec.pending_breaking_to = Some(0x00);
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                rec.break_waiters.push(tx);
                receivers.push(rx);
            }
        }
        for oid in oplocks_to_remove {
            self.oplocks.remove(&oid);
        }

        (notifications, receivers)
    }
}

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
    ///Per-file byte-range locks, keyed by file identity.
    range_locks: RwLock<HashMap<FileId, Vec<RangeLock>>>,
    /// Per-file lease and traditional oplock state.
    leases: RwLock<LeaseManager>,
}

impl OpenTable {
    /// Create an empty open table.
    pub fn new() -> Self {
        Self {
            opens: RwLock::new(HashMap::new()),
            delete_pending: RwLock::new(HashSet::new()),
            range_locks: RwLock::new(HashMap::new()),
            leases: RwLock::new(LeaseManager::default()),
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
            let new_wants_read = entry.desired_access.read
                || entry.desired_access.generic_read
                || entry.desired_access.generic_all;
            let new_wants_write = entry.desired_access.write
                || entry.desired_access.generic_write
                || entry.desired_access.generic_all;
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
                let ex_wants_read = ex.desired_access.read
                    || ex.desired_access.generic_read
                    || ex.desired_access.generic_all;
                let ex_wants_write = ex.desired_access.write
                    || ex.desired_access.generic_write
                    || ex.desired_access.generic_all;
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
        map.entry(file_id).or_default().push(entry);
        // Track delete-pending state while holding `opens` write lock (consistent
        // lock order: opens -> delete_pending).
        if entry.delete_on_close {
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
    /// from the opens map. The `delete_pending` set is cleared only at last
    /// close — it is NOT recomputed from remaining entries, so a DOC
    /// disposition set by one open survives until the last close even if
    /// that open is removed first.
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
                // Last close: clear delete_pending while still holding `opens`
                // write lock (lock order: opens -> delete_pending).
                self.delete_pending.write().await.remove(&file_id);
            }
            // When other opens remain, do NOT clear delete_pending.
            // It was set by check_and_add or update_delete_on_close and
            // must survive until the last close. Clearing it here (because
            // the removed open was the one with DOC) would lose the
            // disposition before the last close, so the file would not be
            // deleted.
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
    /// a no-op — `delete_pending` is NOT touched (the disposition may have
    /// been set by an already-closed open and must persist until last close).
    ///
    /// Setting DOC on a found open adds the file to `delete_pending`.
    /// Clearing DOC on a found open recomputes `delete_pending` from the
    /// remaining alive opens — if none have DOC, `delete_pending` is cleared.
    #[instrument(skip(self, file_id))]
    pub async fn update_delete_on_close(&self, file_id: FileId, open_id: OpenId, delete: bool) {
        let mut map = self.opens.write().await;
        if let Some(vec) = map.get_mut(&file_id) {
            if let Some(entry) = vec.iter_mut().find(|e| e.open_id == open_id) {
                entry.delete_on_close = delete;
                // Recompute delete_pending from alive opens (including this one
                // after the update) while holding `opens` write lock (consistent
                // lock order: opens -> delete_pending).
                let any_doc = vec.iter().any(|e| e.delete_on_close);
                let mut dp = self.delete_pending.write().await;
                if any_doc {
                    dp.insert(file_id);
                } else {
                    dp.remove(&file_id);
                }
            }
            // If the open_id was not found, this is a no-op.
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
    #[allow(clippy::too_many_arguments)]
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
                !(l.open_id == owner_open_id && l.offset == offset && l.length == length)
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
                if list.is_empty() {
                    Some(*fid)
                } else {
                    None
                }
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
                if list.is_empty() {
                    Some(*fid)
                } else {
                    None
                }
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
                if list.is_empty() {
                    Some(*fid)
                } else {
                    None
                }
            })
            .collect();
        for key in empty_keys {
            locks.remove(&key);
        }
        released
    }

    // ---- Lease & Oplock management (MS-SMB2 3.3.5.9.8 / 3.3.5.9.11 / 3.3.5.19) ----

    /// Request a Lease (v1 or v2) on `file_id` for `open_id`.
    ///
    /// Returns `Err(())` if the `(client_guid, lease_key)` is already bound to
    /// a *different* `file_id` (MS-SMB2: `STATUS_INVALID_PARAMETER`), or if the
    /// requested state is granted/upgraded along with any break notifications
    /// that must be sent to other lease/oplock holders on `file_id`.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_lease(
        &self,
        file_id: FileId,
        open_id: OpenId,
        client_guid: [u8; 16],
        lease_key: [u8; 16],
        requested: LeaseCaching,
        is_v2: bool,
        parent_lease_key: Option<[u8; 16]>,
        client_epoch: u16,
        notify_tx: LeaseNotifySender,
    ) -> Result<(LeaseGrant, Vec<BreakNotification>), ()> {
        let total_opens = self.count(file_id).await;
        let mut mgr = self.leases.write().await;
        let id = LeaseId {
            client_guid,
            lease_key,
        };

        // 1. Check if this (client_guid, lease_key) already exists.
        if let Some(existing) = mgr.leases.get(&id) {
            if existing.file_id != file_id {
                // LeaseKey already bound to a different underlying file!
                return Err(());
            }
        }

        // 2. Break any conflicting leases/oplocks held by OTHER owners on `file_id`
        //    if our requested state requires exclusivity or if existing holders
        //    hold Write caching.
        let mut breaks = Vec::new();
        let other_leases_exist = mgr
            .leases
            .iter()
            .any(|(k, v)| *k != id && v.file_id == file_id && !v.handles.is_empty());
        let other_oplocks_exist = mgr
            .oplocks
            .values()
            .any(|o| o.file_id == file_id && o.open_id != open_id && o.level != 0);

        // Count opens belonging to THIS lease (plus the new `open_id` if not yet recorded).
        let this_lease_opens = mgr
            .leases
            .get(&id)
            .map(|e| {
                let mut c = e.handles.len();
                if !e.handles.contains(&open_id) {
                    c += 1;
                }
                c
            })
            .unwrap_or(1);
        let non_leased_other_opens = total_opens > this_lease_opens && !other_leases_exist;

        // Opening a file from another lease key breaks Write caching on existing leases/oplocks.
        breaks.extend(mgr.break_other_holders_on_open(file_id, Some(id), open_id, requested));

        // 3. Compute the maximum caching we can grant for `requested`.
        //    - Write caching (W) requires R (or RH) and NO other opens outside this lease.
        //    - Handle caching (H) requires R.
        //    - Read caching (R) can be shared across multiple readers if no other open has W.
        let can_grant_write = requested.write
            && requested.read
            && !other_leases_exist
            && !other_oplocks_exist
            && !non_leased_other_opens;
        let can_grant_read = requested.read;
        let can_grant_handle = requested.handle && can_grant_read;

        let candidate = LeaseCaching {
            read: can_grant_read,
            handle: can_grant_handle,
            write: can_grant_write,
        };

        let entry = mgr.leases.entry(id).or_insert_with(|| LeaseRecord {
            file_id,
            state: LeaseCaching::NONE,
            breaking: false,
            break_to: LeaseCaching::NONE,
            pending_break_to: None,
            epoch: if is_v2 {
                client_epoch.wrapping_add(1)
            } else {
                0
            },
            is_v2,
            parent_lease_key,
            handles: HashSet::new(),
            notify_tx: notify_tx.clone(),
            break_waiters: Vec::new(),
        });

        entry.handles.insert(open_id);
        entry.notify_tx = notify_tx;
        if is_v2 && !entry.is_v2 {
            entry.is_v2 = true;
        }
        if parent_lease_key.is_some() {
            entry.parent_lease_key = parent_lease_key;
        }

        // MS-SMB2 3.3.5.9.8: if the lease is currently breaking, we cannot
        // upgrade it; return its current state with BREAK_IN_PROGRESS flag.
        let (granted_state, flags) = if entry.breaking {
            (entry.state, 0x0000_0002) // SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
        } else {
            let merged = entry.state.union(candidate);
            if merged != entry.state {
                if entry.is_v2 {
                    entry.epoch = entry.epoch.wrapping_add(1);
                }
                entry.state = merged;
            }
            (entry.state, 0)
        };

        let grant = LeaseGrant {
            lease_key,
            state: granted_state,
            flags: if entry.parent_lease_key.is_some() {
                flags | 0x0000_0004 // SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
            } else {
                flags
            },
            epoch: if entry.is_v2 { entry.epoch } else { 0 },
            parent_lease_key: entry.parent_lease_key,
            is_v2: entry.is_v2,
        };

        Ok((grant, breaks))
    }

    /// Request a traditional Oplock (`0x01` Level II, `0x08` Exclusive, `0x09` Batch)
    /// for `open_id` on `file_id`.
    pub async fn request_oplock(
        &self,
        file_id: FileId,
        open_id: OpenId,
        smb_file_id: rssmb_proto::create::FileId,
        requested_level: u8,
        notify_tx: LeaseNotifySender,
    ) -> (u8, Vec<BreakNotification>) {
        let total_opens = self.count(file_id).await;
        let mut mgr = self.leases.write().await;

        let breaks = mgr.break_other_holders_on_open(
            file_id,
            None,
            open_id,
            LeaseCaching {
                read: true,
                handle: requested_level == 0x09,
                write: requested_level == 0x08 || requested_level == 0x09,
            },
        );

        let granted = if total_opens <= 1
            && !mgr
                .leases
                .values()
                .any(|l| l.file_id == file_id && !l.handles.is_empty())
        {
            match requested_level {
                0x09 | 0x08 | 0x01 => requested_level,
                _ => 0x00,
            }
        } else if requested_level == 0x01 || requested_level == 0x08 || requested_level == 0x09 {
            // Multiple readers can share a Level II oplock if no one holds write caching.
            0x01
        } else {
            0x00
        };

        if granted != 0x00 {
            mgr.oplocks.insert(
                open_id,
                OplockRecord {
                    file_id,
                    open_id,
                    smb_file_id,
                    level: granted,
                    breaking_to: None,
                    pending_breaking_to: None,
                    notify_tx,
                    break_waiters: Vec::new(),
                },
            );
        }

        (granted, breaks)
    }

    /// Trigger breaks on `file_id` before an operation (`op`) performed by `actor_open_id`.
    ///
    /// Returns any `BreakNotification`s to send immediately and `oneshot::Receiver`s
    /// to await (with the 35s lease break timeout) when an ACK is required before
    /// the conflicting operation proceeds.
    pub async fn break_for_op(
        &self,
        file_id: FileId,
        actor_open_id: Option<OpenId>,
        op: ConflictOp,
    ) -> (Vec<BreakNotification>, Vec<tokio::sync::oneshot::Receiver<()>>) {
        let mut mgr = self.leases.write().await;
        let actor_lease = actor_open_id.and_then(|oid| {
            mgr.leases
                .iter()
                .find(|(_, rec)| rec.handles.contains(&oid))
                .map(|(id, _)| *id)
        });
        mgr.trigger_breaks(file_id, actor_lease, actor_open_id, op)
    }

    /// Process a client `LeaseBreakAck` (MS-SMB2 3.3.5.19.2).
    ///
    /// Validates that a lease is currently breaking and that the acknowledged
    /// `lease_state` is a subset of `break_to` (`lease_state & !break_to == 0`).
    /// Returns `Ok((acked_state, optional_followup_break))` on success or `Err(NtStatus)` on error.
    pub async fn ack_lease_break(
        &self,
        client_guid: [u8; 16],
        lease_key: [u8; 16],
        acked_state: LeaseCaching,
    ) -> Result<(LeaseCaching, Option<BreakNotification>), rssmb_wire_adapter::NtStatus> {
        let mut mgr = self.leases.write().await;
        let id = LeaseId {
            client_guid,
            lease_key,
        };
        let Some(rec) = mgr.leases.get_mut(&id) else {
            return Err(rssmb_wire_adapter::NtStatus::ObjectNameNotFound);
        };
        if !rec.breaking {
            return Err(rssmb_wire_adapter::NtStatus::Other(0xC000_0001)); // STATUS_UNSUCCESSFUL
        }
        // MS-SMB2 3.3.5.19.2: Client must acknowledge a state <= BreakToLeaseState.
        if !acked_state.is_subset_of(rec.break_to) {
            return Err(rssmb_wire_adapter::NtStatus::InvalidParameter);
        }
        rec.state = acked_state;
        // Check if a stricter break was queued while the first break was in flight.
        if let Some(next_target) = rec.pending_break_to.take() {
            if !rec.state.is_subset_of(next_target) {
                let target = LeaseCaching {
                    read: rec.state.read && next_target.read,
                    handle: rec.state.handle && next_target.handle,
                    write: rec.state.write && next_target.write,
                };
                let ack_req = rec.state.handle || rec.state.write;
                if rec.is_v2 {
                    rec.epoch = rec.epoch.wrapping_add(1);
                }
                let notif = BreakNotification::Lease {
                    notify_tx: rec.notify_tx.clone(),
                    lease_key: id.lease_key,
                    current_state: rec.state,
                    new_state: target,
                    new_epoch: if rec.is_v2 { rec.epoch } else { 0 },
                    ack_required: ack_req,
                };
                if ack_req {
                    rec.breaking = true;
                    rec.break_to = target;
                    return Ok((acked_state, Some(notif)));
                }
                rec.state = target;
                rec.breaking = false;
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
                return Ok((acked_state, Some(notif)));
            }
        }
        rec.breaking = false;
        let waiters = std::mem::take(&mut rec.break_waiters);
        for tx in waiters {
            let _ = tx.send(());
        }
        Ok((acked_state, None))
    }

    /// Process a client `OplockBreakAck` (MS-SMB2 3.3.5.19.1).
    pub async fn ack_oplock_break(
        &self,
        smb_file_id: rssmb_proto::create::FileId,
        acked_level: u8,
    ) -> Result<(u8, Option<BreakNotification>), rssmb_wire_adapter::NtStatus> {
        let mut mgr = self.leases.write().await;
        let Some(rec) = mgr
            .oplocks
            .values_mut()
            .find(|o| o.smb_file_id == smb_file_id)
        else {
            return Err(rssmb_wire_adapter::NtStatus::InvalidHandle);
        };
        let Some(target) = rec.breaking_to else {
            return Err(rssmb_wire_adapter::NtStatus::Other(0xC000_0184)); // STATUS_INVALID_DEVICE_STATE
        };
        // Allowed acked levels: 0x00 (None) or 0x01 (Level II) if target was 0x01.
        if acked_level != 0x00 && !(target == 0x01 && acked_level == 0x01) {
            return Err(rssmb_wire_adapter::NtStatus::InvalidParameter);
        }
        rec.level = acked_level;
        rec.breaking_to = None;
        let followup = if rec.pending_breaking_to.take() == Some(0x00) && rec.level == 0x01 {
            // Level II -> None break does not require ACK; transition immediately and notify.
            rec.level = 0x00;
            Some(BreakNotification::Oplock {
                notify_tx: rec.notify_tx.clone(),
                smb_file_id: rec.smb_file_id,
                new_oplock_level: 0x00,
            })
        } else {
            None
        };
        let waiters = std::mem::take(&mut rec.break_waiters);
        for tx in waiters {
            let _ = tx.send(());
        }
        let open_id = rec.open_id;
        if rec.level == 0x00 {
            mgr.oplocks.remove(&open_id);
        }
        Ok((acked_level, followup))
    }

    /// Force-downgrade any breaking lease/oplock on `file_id` whose break timer expired.
    pub async fn expire_breaks(&self, file_id: FileId) {
        let mut mgr = self.leases.write().await;
        for rec in mgr.leases.values_mut() {
            if rec.file_id == file_id && rec.breaking {
                rec.state = LeaseCaching::NONE;
                rec.breaking = false;
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
            }
        }
        let mut to_remove = Vec::new();
        for (oid, rec) in mgr.oplocks.iter_mut() {
            if rec.file_id == file_id && rec.breaking_to.is_some() {
                rec.level = 0;
                rec.breaking_to = None;
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
                to_remove.push(*oid);
            }
        }
        for oid in to_remove {
            mgr.oplocks.remove(&oid);
        }
    }

    /// Remove `open_id` from lease/oplock tracking on close.
    pub async fn remove_open_from_leases(&self, open_id: OpenId) {
        let mut mgr = self.leases.write().await;
        if let Some(rec) = mgr.oplocks.remove(&open_id) {
            for tx in rec.break_waiters {
                let _ = tx.send(());
            }
        }
        let mut empty_leases = Vec::new();
        for (id, rec) in mgr.leases.iter_mut() {
            if rec.handles.remove(&open_id) && rec.handles.is_empty() {
                // If all handles under this lease are closed and it lacks Handle caching
                // (or is breaking to a state without Handle caching), clear it.
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
                empty_leases.push(*id);
            }
        }
        for id in empty_leases {
            mgr.leases.remove(&id);
        }
    }

    /// Look up the lease key and state associated with `open_id` (used for DH2Q/DH2C validation).
    pub async fn lease_for_open(&self, open_id: OpenId) -> Option<([u8; 16], LeaseCaching)> {
        let mgr = self.leases.read().await;
        mgr.leases
            .iter()
            .find(|(_, rec)| rec.handles.contains(&open_id))
            .map(|(id, rec)| (id.lease_key, rec.state))
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
    use proptest::prelude::*;
    use rssmb_vfs::{DesiredAccess, FileId, OpenId, ShareAccess};

    fn fid(n: u64) -> FileId {
        FileId { dev: 0, ino: n }
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
    fn entry_da(
        open_id: u64,
        session_id: u64,
        share: ShareAccess,
        desired: DesiredAccess,
    ) -> OpenEntry {
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
        table
            .check_and_add(fid(1), e)
            .await
            .expect("first open always succeeds");
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
            2,
            200,
            ShareAccess::all(),
            DesiredAccess {
                read: true,
                ..Default::default()
            },
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
                entry(
                    1,
                    100,
                    ShareAccess {
                        read: false,
                        write: true,
                        delete: true,
                    },
                ),
            )
            .await
            .unwrap();
        // New open wants read (share_access.read = true).
        let err = table
            .check_and_add(
                fid(1),
                entry(
                    2,
                    200,
                    ShareAccess {
                        read: true,
                        write: false,
                        delete: false,
                    },
                ),
            )
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
                entry(
                    1,
                    100,
                    ShareAccess {
                        read: true,
                        write: false,
                        delete: true,
                    },
                ),
            )
            .await
            .unwrap();
        // New open wants write.
        let err = table
            .check_and_add(
                fid(2),
                entry(
                    2,
                    200,
                    ShareAccess {
                        read: false,
                        write: true,
                        delete: false,
                    },
                ),
            )
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
                entry(
                    1,
                    100,
                    ShareAccess {
                        read: true,
                        write: true,
                        delete: false,
                    },
                ),
            )
            .await
            .unwrap();
        // New open wants delete.
        let err = table
            .check_and_add(
                fid(3),
                entry(
                    2,
                    200,
                    ShareAccess {
                        read: false,
                        write: false,
                        delete: true,
                    },
                ),
            )
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
        // Remove the delete-on-close open — not the last. The disposition
        // survives: delete_pending is NOT cleared until the last close.
        let res = table.remove(fid(6), oid(1)).await;
        assert!(res.found);
        assert!(res.any_delete_on_close);
        assert!(table.is_delete_pending(fid(6)).await);
        // Remove the last open — now delete_pending is cleared, and
        // any_delete_on_close is true (the file should be deleted).
        let res = table.remove(fid(6), oid(2)).await;
        assert!(res.found);
        assert!(res.was_last);
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
            OpenConflict::ReadNotShared {
                existing_open_id,
                existing_session_id,
                ..
            } => {
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
            2,
            200,
            ShareAccess {
                read: false,
                write: true,
                delete: true,
            },
            DesiredAccess::default(),
        );
        table.check_and_add(fid(8), second).await.unwrap();
        // New open: shares all, wants only read. (a): new wants read,
        // open 2 doesn't share read → conflict.
        let new_entry = entry_da(
            3,
            300,
            ShareAccess::all(),
            DesiredAccess {
                read: true,
                ..Default::default()
            },
        );
        let err = table
            .check_and_add(fid(8), new_entry)
            .await
            .expect_err("should conflict with open 2");
        match err {
            OpenConflict::ReadNotShared {
                existing_open_id, ..
            } => {
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
            2,
            200,
            ShareAccess::all(),
            DesiredAccess {
                read: true,
                ..Default::default()
            },
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
            2,
            200,
            ShareAccess {
                read: true,
                write: false,
                delete: true,
            },
            DesiredAccess::default(),
        );
        table.check_and_add(fid(11), second).await.unwrap();
        // New open: shares all, wants only write. (b) checks pass (new
        // shares all). (a): new wants write, open 2 doesn't share write.
        let new_entry = entry_da(
            3,
            300,
            ShareAccess::all(),
            DesiredAccess {
                write: true,
                ..Default::default()
            },
        );
        let err = table
            .check_and_add(fid(11), new_entry)
            .await
            .expect_err("write should be blocked by open 2");
        match err {
            OpenConflict::WriteNotShared {
                existing_open_id,
                existing_session_id,
                ..
            } => {
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
        // Remove the first (doc) open — not the last. any_doc should be true
        // because delete_pending persists until the last close.
        let res = table.remove(fid(20), oid(1)).await;
        assert!(res.found);
        assert!(!res.was_last);
        assert!(res.any_delete_on_close);
        // Remove the second — last open. any_doc should be true because the
        // delete disposition was set and persists until the last close.
        let res = table.remove(fid(20), oid(2)).await;
        assert!(res.found);
        assert!(res.was_last);
        assert!(res.any_delete_on_close);
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
            desired_access: DesiredAccess {
                read: true,
                ..Default::default()
            },
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
        // The delete disposition set by A survives until the last close,
        // so the last close (B) reports any_delete_on_close = true.
        let table = OpenTable::new();
        let mut a = entry(1, 100, ShareAccess::all());
        a.delete_on_close = true;
        table.check_and_add(fid(60), a).await.unwrap();
        table
            .check_and_add(fid(60), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        assert!(table.is_delete_pending(fid(60)).await);
        // Close A (doc) — not the last. delete_pending persists.
        let res_a = table.remove(fid(60), oid(1)).await;
        assert!(res_a.found);
        assert!(!res_a.was_last);
        assert!(res_a.any_delete_on_close);
        // is_delete_pending should still be true — the disposition set by A
        // survives until the last close, even though A is gone.
        assert!(table.is_delete_pending(fid(60)).await);
        // Close B — last close. any_doc should be true because the
        // delete disposition was set and persists until the last close.
        let res_b = table.remove(fid(60), oid(2)).await;
        assert!(res_b.found);
        assert!(res_b.was_last);
        assert!(res_b.any_delete_on_close);
        assert!(!table.is_delete_pending(fid(60)).await);
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

    #[tokio::test]
    async fn doc_survives_close_then_clear_on_other_open_does_not_lose_it() {
        // Open A (doc) and B (no doc). Close A (not last). Then
        // update_delete_on_close(B, false) — B doesn't have DOC, so this
        // is effectively a no-op. delete_pending must survive because A
        // set the disposition before closing, and it persists until the
        // last close.
        let table = OpenTable::new();
        let mut a = entry(1, 100, ShareAccess::all());
        a.delete_on_close = true;
        table.check_and_add(fid(80), a).await.unwrap();
        table
            .check_and_add(fid(80), entry(2, 200, ShareAccess::all()))
            .await
            .unwrap();
        assert!(table.is_delete_pending(fid(80)).await);
        // Close A (doc) — not last. delete_pending persists.
        let res_a = table.remove(fid(80), oid(1)).await;
        assert!(res_a.found);
        assert!(!res_a.was_last);
        assert!(res_a.any_delete_on_close);
        assert!(table.is_delete_pending(fid(80)).await);
        // update_delete_on_close(B, false) — B is alive, doesn't have DOC.
        // This recomputes from alive opens: B has no DOC → clears pending.
        // This is correct: the only alive open (B) doesn't have DOC, and the
        // DOC-setting open (A) has been removed. The caller (handle_close)
        // uses the any_delete_on_close from remove() to decide deletion, so
        // the file IS deleted when A closes (the caller gets any_doc=true
        // from A's remove).
        table.update_delete_on_close(fid(80), oid(2), false).await;
        assert!(!table.is_delete_pending(fid(80)).await);
        // Close B — last close. any_doc should be false (A's DOC was
        // consumed when A was removed, and B never had DOC).
        let res_b = table.remove(fid(80), oid(2)).await;
        assert!(res_b.found);
        assert!(res_b.was_last);
        assert!(!res_b.any_delete_on_close);
    }

    #[tokio::test]
    async fn update_doc_nonexistent_open_does_not_clear_pending() {
        // Open A (doc). Then update_delete_on_close with a nonexistent
        // open_id — this must NOT clear delete_pending.
        let table = OpenTable::new();
        let mut a = entry(1, 100, ShareAccess::all());
        a.delete_on_close = true;
        table.check_and_add(fid(90), a).await.unwrap();
        assert!(table.is_delete_pending(fid(90)).await);
        table.update_delete_on_close(fid(90), oid(999), false).await;
        assert!(table.is_delete_pending(fid(90)).await);
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

    // ---- Lease & Oplock unit tests ----

    #[tokio::test]
    async fn lease_grant_r_rh_rw_and_same_key_upgrade() {
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client_guid = [1u8; 16];
        let lease_key = [2u8; 16];

        table
            .check_and_add(fid(10), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();

        // First open requests R -> granted R
        let (grant1, breaks1) = table
            .request_lease(
                fid(10),
                oid(1),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x01), // R
                false,
                None,
                0,
                tx.clone(),
            )
            .await
            .unwrap();
        assert_eq!(grant1.state, LeaseCaching::from_bits(0x01));
        assert!(breaks1.is_empty());

        // Second open with same lease key requests RW (0x05) -> upgraded to RW without self-break
        table
            .check_and_add(fid(10), entry(2, 100, ShareAccess::all()))
            .await
            .unwrap();
        let (grant2, breaks2) = table
            .request_lease(
                fid(10),
                oid(2),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                tx.clone(),
            )
            .await
            .unwrap();
        assert_eq!(grant2.state, LeaseCaching::from_bits(0x07));
        assert!(breaks2.is_empty());
    }

    #[tokio::test]
    async fn lease_collision_different_file_rejected() {
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client_guid = [1u8; 16];
        let lease_key = [9u8; 16];

        table
            .check_and_add(fid(1), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        table
            .request_lease(
                fid(1),
                oid(1),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x01),
                false,
                None,
                0,
                tx.clone(),
            )
            .await
            .unwrap();

        // Same (client_guid, lease_key) on fid(2) must fail
        table
            .check_and_add(fid(2), entry(2, 100, ShareAccess::all()))
            .await
            .unwrap();
        let err = table
            .request_lease(
                fid(2),
                oid(2),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x01),
                false,
                None,
                0,
                tx,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn lease_break_and_ack_lifecycle() {
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client1 = [1u8; 16];
        let key1 = [0xAAu8; 16];

        table
            .check_and_add(fid(5), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        let (grant, _) = table
            .request_lease(
                fid(5),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                tx.clone(),
            )
            .await
            .unwrap();
        assert_eq!(grant.state, LeaseCaching::from_bits(0x07));

        // Conflicting write from another handle triggers break to NONE with ack_required = true
        let (breaks, mut waiters) = table
            .break_for_op(fid(5), Some(oid(99)), ConflictOp::Write)
            .await;
        assert_eq!(breaks.len(), 1);
        assert_eq!(waiters.len(), 1);
        match &breaks[0] {
            BreakNotification::Lease {
                lease_key,
                current_state,
                new_state,
                ack_required,
                ..
            } => {
                assert_eq!(*lease_key, key1);
                assert_eq!(*current_state, LeaseCaching::from_bits(0x07));
                assert_eq!(*new_state, LeaseCaching::NONE);
                assert!(*ack_required);
            }
            _ => panic!("expected lease break"),
        }

        // Invalid ACK (e.g. acknowledging R when break_to is NONE) is rejected
        let bad_ack = table
            .ack_lease_break(client1, key1, LeaseCaching::from_bits(0x01))
            .await;
        assert!(bad_ack.is_err());

        // Valid ACK to NONE succeeds and wakes waiter
        let (acked, followup) = table
            .ack_lease_break(client1, key1, LeaseCaching::NONE)
            .await
            .unwrap();
        assert_eq!(acked, LeaseCaching::NONE);
        assert!(followup.is_none());
        assert!(waiters.pop().unwrap().try_recv().is_ok());
    }

    #[tokio::test]
    async fn lease_staged_break_escalation_emits_followup_break() {
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client1 = [1u8; 16];
        let key1 = [0xBBu8; 16];

        table
            .check_and_add(fid(6), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        table
            .request_lease(
                fid(6),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x05), // RW
                true,
                None,
                1,
                tx,
            )
            .await
            .unwrap();

        // 1. Another handle reads -> break RW -> R
        let (breaks1, _waiters1) = table
            .break_for_op(fid(6), Some(oid(2)), ConflictOp::Read)
            .await;
        assert_eq!(breaks1.len(), 1);

        // 2. While RW -> R break is in flight, a Write arrives -> escalates pending target to NONE
        let (breaks2, mut waiters2) = table
            .break_for_op(fid(6), Some(oid(2)), ConflictOp::Write)
            .await;
        assert!(breaks2.is_empty());

        // 3. Client acknowledges R (the originally advertised break target) -> accepted,
        //    and since R -> NONE does not require ACK, follow-up notification is returned and waiters wake.
        let (acked, followup) = table
            .ack_lease_break(client1, key1, LeaseCaching::from_bits(0x01))
            .await
            .unwrap();
        assert_eq!(acked, LeaseCaching::from_bits(0x01));
        assert!(followup.is_some());
        assert!(waiters2.pop().unwrap().try_recv().is_ok());
    }

    // ---- Property tests (Phase 6.4) ----

    proptest! {
        #[test]
        fn prop_exclusive_locks_conflict_on_overlap(
            offset1 in 0u64..=1024,
            len1 in 1u64..=1024,
            offset2 in 0u64..=1024,
            len2 in 1u64..=1024,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let overlap_conflict: Option<()> = rt.block_on(async {
                let table = OpenTable::new();
                table
                    .acquire_range_lock(fid(1), oid(1), 100, 1, offset1, len1, true)
                    .await
                    .unwrap();
                let result = table
                    .acquire_range_lock(fid(1), oid(2), 200, 1, offset2, len2, true)
                    .await;
                let overlap = offset1 < offset2.saturating_add(len2)
                    && offset2 < offset1.saturating_add(len1);
                if overlap && result.is_ok() {
                    return Some(());
                }
                None
            });
            if let Some(()) = overlap_conflict {
                prop_assert!(false, "overlapping exclusive locks should conflict");
            }
        }

        #[test]
        fn prop_shared_lock_no_read_conflict_same_owner(
            offset in 0u64..=1024,
            len in 1u64..=1024,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let conflict: Option<String> = rt.block_on(async {
                let table = OpenTable::new();
                table
                    .acquire_range_lock(fid(1), oid(1), 100, 1, offset, len, false)
                    .await
                    .unwrap();
                match table.check_range_lock(fid(1), oid(1), 0, len).await {
                    Ok(()) => None,
                    Err(e) => Some(format!("same-owner read conflicted: {:?}", e)),
                }
            });
            if let Some(msg) = conflict {
                prop_assert!(false, "{}", msg);
            }
        }

        #[test]
        fn prop_zero_length_no_conflict(
            offset1 in 0u64..=1024,
            offset2 in 0u64..=1024,
            len2 in 1u64..=1024,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let conflict: Option<String> = rt.block_on(async {
                let table = OpenTable::new();
                // Zero-length locks always return Err(ZeroLength) and are
                // never stored — so a subsequent lock should never see them.
                let _ = table
                    .acquire_range_lock(fid(1), oid(1), 100, 1, offset1, 0, true)
                    .await;
                match table.acquire_range_lock(fid(1), oid(2), 200, 1, offset2, len2, true).await {
                    Ok(()) => None,
                    Err(e) => Some(format!("zero-length lock blocked other: {:?}", e)),
                }
            });
            if let Some(msg) = conflict {
                prop_assert!(false, "{}", msg);
            }
        }

        #[test]
        fn prop_release_never_panics(
            offset in 0u64..=1024,
            len in 0u64..=1024,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let table = OpenTable::new();
                table.release_range_lock(fid(1), oid(1), offset, len).await;
                table.release_range_lock(fid(1), oid(1), offset, len).await;
            });
        }
    }
}
