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
use std::sync::Arc;
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

    pub fn intersect(self, other: Self) -> Self {
        Self::from_bits(self.to_bits() & other.to_bits())
    }

    pub fn minus(self, other: Self) -> Self {
        Self::from_bits(self.to_bits() & !other.to_bits())
    }

    pub fn is_none(self) -> bool {
        self.to_bits() == 0
    }

    pub const R: Self = Self {
        read: true,
        handle: false,
        write: false,
    };
    pub const H: Self = Self {
        read: false,
        handle: true,
        write: false,
    };
    pub const W: Self = Self {
        read: false,
        handle: false,
        write: true,
    };
}

/// Placeholder access mask for callers that don't supply one: treated as a
/// full (non-stat) open.
pub const ACCESS_MASK_UNKNOWN: u32 = 0xFFFF_FFFF;

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;

/// Samba `is_oplock_stat_open` (open.c): only SYNCHRONIZE / READ_ATTRIBUTES
/// / WRITE_ATTRIBUTES requested. Such opens never break or get oplocks.
pub fn is_oplock_stat_open(access_mask: u32) -> bool {
    let bits = SYNCHRONIZE_ACCESS | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    access_mask & bits != 0 && access_mask & !bits == 0
}

/// Samba `is_lease_stat_open` (open.c): as [`is_oplock_stat_open`] plus
/// READ_CONTROL. Such opens don't break other leases.
pub fn is_lease_stat_open(access_mask: u32) -> bool {
    let bits =
        SYNCHRONIZE_ACCESS | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL_ACCESS;
    access_mask & bits != 0 && access_mask & !bits == 0
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
    /// Another handle is renaming the file. Samba `delay_rename_lease_break_fn`
    /// (smb2_setinfo.c): only leases holding H are broken, to `state & !H`.
    Rename,
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

/// A pending break acknowledgment — the oneshot resolves when the holder
/// acks (or the 35 s server break-timeout fires). Carries the identity and
/// `break_generation` so the caller can arm the per-break expiry timer
/// after releasing the write lock.
#[derive(Debug)]
pub struct BreakWaiter {
    pub receiver: tokio::sync::oneshot::Receiver<()>,
    /// Which lease or oplock this waiter belongs to.
    pub target: BreakTarget,
    /// The `break_generation` captured at break-initiation time. The
    /// timer no-ops if the generation no longer matches (the lease was
    /// acked or re-broken in the meantime).
    pub generation: u64,
    /// Whether the triggering operation must pend on this waiter. Samba
    /// `delay_for_oplock_fn`: a create only pends when the holder's state
    /// intersects the delay mask (W, or H under a sharing violation) — an
    /// ack-required RH→NONE break on overwrite does NOT block the opener
    /// (breaking4). The 35 s expiry timer is armed for every waiter.
    pub delay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakTarget {
    Lease(LeaseId),
    Oplock(OpenId),
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
    /// Internal generation — bumped every time a break is initiated (both
    /// v1 and v2). Carried by the per-break 35 s expiry timer; the timer
    /// no-ops if the generation no longer matches (the lease was acked or
    /// re-broken in the meantime). Samba calls this `lease_epoch` and
    /// guards on epoch + BREAK_IN_PROGRESS (smb2_oplock.c
    /// `lease_timeout_handler`); we use an independent counter because v1
    /// leases keep `epoch` at 0 and we don't want a race on an epoch the
    /// wire protocol doesn't carry.
    break_generation: u64,
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
    /// Same-generation guard as `LeaseRecord::break_generation` for the
    /// oplock expiry timer.
    break_generation: u64,
}

#[derive(Debug, Default)]
struct LeaseManager {
    leases: HashMap<LeaseId, LeaseRecord>,
    oplocks: HashMap<OpenId, OplockRecord>,
}

impl LeaseManager {
    /// Break other lease/oplock holders when a new open arrives on `file_id`.
    ///
    /// Returns break notifications to send immediately and oneshot receivers
    /// that resolve when each holder acks its break (or the 35 s server
    /// break-timeout fires). The caller (CREATE dispatch) awaits these to
    /// pend the conflicting create until the break completes — MS-SMB2
    /// 3.3.4.7 / Samba `delay_for_oplock_fn` (open.c).
    ///
    /// `will_overwrite` is true for SUPERSede/OVERWRITE/OVERWRITE_IF
    /// dispositions: the break target additionally drops H and R (the file
    /// is being replaced/truncated). `sharing_violation` flips the delay
    /// mask from WRITE to HANDLE — under a share conflict the create must
    /// pend on an H-removing break (timeout-disconnect golden), not just W.
    ///
    /// `skip_leases` (Samba `is_lease_stat_open`) leaves other leases
    /// untouched — only oplocks are considered for breaking.
    fn break_other_holders_on_open_mask(
        &mut self,
        file_id: FileId,
        actor_lease: Option<LeaseId>,
        actor_open: OpenId,
        will_overwrite: bool,
        sharing_violation: bool,
        skip_leases: bool,
    ) -> (Vec<BreakNotification>, Vec<BreakWaiter>) {
        // Samba delay_for_oplock (open.c): the delay mask is H under a
        // sharing violation, W otherwise; overwrite dispositions also drop
        // H and R from the break target.
        let delay_mask = if sharing_violation {
            LeaseCaching::H
        } else {
            LeaseCaching::W
        };
        let mut out = Vec::new();
        let mut waiters = Vec::new();
        for (id, rec) in self.leases.iter_mut() {
            if rec.file_id != file_id
                || Some(*id) == actor_lease
                || rec.handles.is_empty()
                || skip_leases
            {
                continue;
            }
            let e = rec.state;
            let mut break_to = e.minus(delay_mask);
            if will_overwrite {
                break_to = break_to.minus(LeaseCaching::H.union(LeaseCaching::R));
            }
            if e.minus(break_to).is_none() {
                // Nothing to break — but a lease already mid-break still
                // delays the opener until the break completes.
                if rec.breaking {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    waiters.push(BreakWaiter {
                        receiver: rx,
                        target: BreakTarget::Lease(*id),
                        generation: rec.break_generation,
                        delay: true,
                    });
                }
                continue;
            }
            let delay = !e.intersect(delay_mask).is_none();
            // Samba process_oplock_break (smb2_oplock.c).
            if rec.breaking {
                // Already breaking: narrow the required target; no new
                // break message goes out until the current one is acked.
                let required = rec
                    .pending_break_to
                    .unwrap_or(rec.break_to)
                    .intersect(break_to);
                if required != rec.break_to {
                    rec.pending_break_to = Some(required);
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                rec.break_waiters.push(tx);
                waiters.push(BreakWaiter {
                    receiver: rx,
                    target: BreakTarget::Lease(*id),
                    generation: rec.break_generation,
                    delay,
                });
                continue;
            }
            let current = rec.state;
            if rec.is_v2 {
                rec.epoch = rec.epoch.wrapping_add(1);
            }
            // MS-SMB2 3.3.4.7: an ack is required iff the lease holds H or W.
            let ack_required = e.handle || e.write;
            if ack_required {
                rec.breaking = true;
                rec.break_to = break_to;
                rec.pending_break_to = None;
                rec.break_generation = rec.break_generation.wrapping_add(1);
                let (tx, rx) = tokio::sync::oneshot::channel();
                rec.break_waiters.push(tx);
                waiters.push(BreakWaiter {
                    receiver: rx,
                    target: BreakTarget::Lease(*id),
                    generation: rec.break_generation,
                    delay,
                });
            } else {
                // R-only → NONE: async break, no ack (breaking5).
                rec.state = LeaseCaching::NONE;
            }
            out.push(BreakNotification::Lease {
                notify_tx: rec.notify_tx.clone(),
                lease_key: id.lease_key,
                current_state: current,
                new_state: break_to,
                new_epoch: if rec.is_v2 { rec.epoch } else { 0 },
                ack_required,
            });
        }
        let mut oplocks_to_remove = Vec::new();
        for (oid, rec) in self.oplocks.iter_mut() {
            if rec.file_id != file_id || *oid == actor_open || rec.level == 0 {
                continue;
            }
            // Oplock level as lease bits: batch=RWH, exclusive=RW, II=R.
            let e = match rec.level {
                0x09 => LeaseCaching::from_bits(0x07),
                0x08 => LeaseCaching::from_bits(0x05),
                _ => LeaseCaching::R,
            };
            let mut break_to = e.minus(delay_mask);
            if will_overwrite {
                break_to = break_to.minus(LeaseCaching::H.union(LeaseCaching::R));
            }
            let breaking = rec.breaking_to.is_some();
            if e.minus(break_to).is_none() {
                if breaking {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    waiters.push(BreakWaiter {
                        receiver: rx,
                        target: BreakTarget::Oplock(*oid),
                        generation: rec.break_generation,
                        delay: true,
                    });
                }
                continue;
            }
            // Oplock break targets never keep H or W.
            let new_level: u8 = if break_to.read { 0x01 } else { 0x00 };
            let delay = !e.intersect(delay_mask).is_none();
            let ack_req = rec.level == 0x08 || rec.level == 0x09;
            if breaking {
                if new_level == 0x00 && rec.breaking_to == Some(0x01) {
                    rec.pending_breaking_to = Some(0x00);
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                rec.break_waiters.push(tx);
                waiters.push(BreakWaiter {
                    receiver: rx,
                    target: BreakTarget::Oplock(*oid),
                    generation: rec.break_generation,
                    delay,
                });
                continue;
            }
            if ack_req {
                rec.breaking_to = Some(new_level);
                rec.break_generation = rec.break_generation.wrapping_add(1);
                let (tx, rx) = tokio::sync::oneshot::channel();
                rec.break_waiters.push(tx);
                waiters.push(BreakWaiter {
                    receiver: rx,
                    target: BreakTarget::Oplock(*oid),
                    generation: rec.break_generation,
                    delay,
                });
            } else {
                rec.level = 0x00;
                oplocks_to_remove.push(*oid);
            }
            out.push(BreakNotification::Oplock {
                notify_tx: rec.notify_tx.clone(),
                smb_file_id: rec.smb_file_id,
                new_oplock_level: new_level,
            });
        }
        for oid in oplocks_to_remove {
            self.oplocks.remove(&oid);
        }
        (out, waiters)
    }

    fn trigger_breaks(
        &mut self,
        file_id: FileId,
        actor_lease: Option<LeaseId>,
        actor_open: Option<OpenId>,
        op: ConflictOp,
    ) -> (Vec<BreakNotification>, Vec<BreakWaiter>) {
        let mut notifications = Vec::new();
        let mut waiters = Vec::new();

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
                ConflictOp::Rename => {
                    if !rec.state.handle {
                        continue;
                    }
                    rec.state.minus(LeaseCaching::H)
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
                    rec.break_generation = rec.break_generation.wrapping_add(1);
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    waiters.push(BreakWaiter {
                        receiver: rx,
                        target: BreakTarget::Lease(*id),
                        generation: rec.break_generation,
                        delay: true,
                    });
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
                    waiters.push(BreakWaiter {
                        receiver: rx,
                        target: BreakTarget::Lease(*id),
                        generation: rec.break_generation,
                        delay: true,
                    });
                }
            }
        }

        let mut oplocks_to_remove = Vec::new();
        for (oid, rec) in self.oplocks.iter_mut() {
            if rec.file_id != file_id || Some(*oid) == actor_open {
                continue;
            }
            let (need_break, new_level, ack_req) = match op {
                ConflictOp::Read => (rec.level == 0x08 || rec.level == 0x09, 0x01, true),
                ConflictOp::Write
                | ConflictOp::HandleOrDelete
                | ConflictOp::Rename
                | ConflictOp::Lock => {
                    (rec.level != 0, 0x00, rec.level == 0x08 || rec.level == 0x09)
                }
            };
            if !need_break {
                continue;
            }
            if rec.breaking_to.is_none() {
                if ack_req {
                    rec.breaking_to = Some(new_level);
                    rec.break_generation = rec.break_generation.wrapping_add(1);
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rec.break_waiters.push(tx);
                    waiters.push(BreakWaiter {
                        receiver: rx,
                        target: BreakTarget::Oplock(*oid),
                        generation: rec.break_generation,
                        delay: true,
                    });
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
                waiters.push(BreakWaiter {
                    receiver: rx,
                    target: BreakTarget::Oplock(*oid),
                    generation: rec.break_generation,
                    delay: true,
                });
            }
        }
        for oid in oplocks_to_remove {
            self.oplocks.remove(&oid);
        }

        (notifications, waiters)
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
    /// UNLOCK referenced a range this open has not locked (MS-SMB2 3.3.5.14
    /// — NT_STATUS_RANGE_NOT_LOCKED, 0xC000007E).
    #[error("unlock: range is not locked")]
    RangeNotLocked,
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
pub struct OpenTable {
    opens: RwLock<HashMap<FileId, Vec<OpenEntry>>>,
    /// Files with at least one open that has delete_on_close = true.
    /// Survives entry removal until the last close clears it.
    delete_pending: RwLock<HashSet<FileId>>,
    ///Per-file byte-range locks, keyed by file identity.
    range_locks: RwLock<HashMap<FileId, Vec<RangeLock>>>,
    /// Per-file lease and traditional oplock state.
    leases: RwLock<LeaseManager>,
    /// Blocking-lock waiters (K5): each pended LOCK request that waits for
    /// a conflicting range to be released registers here. Every lock
    /// release (single, open-close, tree-disconnect, logoff) wakes the
    /// matching waiters.
    lock_waiters: RwLock<Vec<LockWaiter>>,
}

/// A pended blocking LOCK request (MS-SMB2 3.3.5.14: a lock that conflicts
/// and does not carry FAIL_IMMEDIATELY waits for the range to become
/// grantable, up to a server-chosen timeout).
pub struct LockWaiter {
    /// Which file the lock targets.
    pub file_id: FileId,
    /// The requesting open (excluded from the re-check).
    pub open_id: OpenId,
    /// The pended element(s): (offset, length, exclusive).
    pub elements: Vec<(u64, u64, bool)>,
    /// Fired by the release paths when this waiter should re-check.
    pub wake: tokio::sync::watch::Sender<bool>,
}

impl LockWaiter {
    /// True if any pended element would still conflict with the current
    /// lock state.
    fn still_blocked(&self, locks: &HashMap<FileId, Vec<RangeLock>>) -> bool {
        let empty = Vec::new();
        let list = locks.get(&self.file_id).unwrap_or(&empty);
        for &(offset, length, exclusive) in &self.elements {
            for lock in list {
                if lock.open_id == self.open_id {
                    // Same open: only exclusive acquisition conflicts.
                    if exclusive && lock.exclusive
                        && ranges_overlap(offset, length, lock.offset, lock.length)
                    {
                        return true;
                    }
                    continue;
                }
                if !ranges_overlap(offset, length, lock.offset, lock.length) {
                    continue;
                }
                if lock.exclusive || exclusive {
                    return true;
                }
            }
        }
        false
    }
}

impl OpenTable {
    /// Create an empty open table.
    pub fn new() -> Self {
        Self {
            opens: RwLock::new(HashMap::new()),
            delete_pending: RwLock::new(HashSet::new()),
            range_locks: RwLock::new(HashMap::new()),
            leases: RwLock::new(LeaseManager::default()),
            lock_waiters: RwLock::new(Vec::new()),
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
            // Samba open_mode_check / share_conflict (open.c): a stat open
            // (attributes only, no data/delete access) never conflicts in
            // either direction. Narrowed to attribute-only opens so opens
            // that request nothing at all keep the existing behaviour.
            let is_stat = |d: &DesiredAccess| {
                d.read_attributes
                    && !(d.read
                        || d.write
                        || d.delete
                        || d.generic_read
                        || d.generic_write
                        || d.generic_execute
                        || d.generic_all)
            };
            let new_is_stat = is_stat(&entry.desired_access);

            for ex in existing {
                if new_is_stat || is_stat(&ex.desired_access) {
                    continue;
                }
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
    ///
    /// Same-open semantics (Samba smbd, verified by torture `rw-shared` /
    /// `rw-exclusive`): the open's own EXCLUSIVE locks permit its own
    /// writes, but its own SHARED locks still conflict — requiring the
    /// write to go through the lock/unlock protocol is the point of a
    /// shared lock (`rw-shared` asserts write-through-h1 fails with
    /// FILE_LOCK_CONFLICT while h1 holds the shared lock).
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
                if lock.open_id == owner_open_id && lock.exclusive {
                    // Own exclusive lock: the holder's own writes are fine.
                    continue;
                }
                if !ranges_overlap(offset, length, lock.offset, lock.length) {
                    continue;
                }
                // Any other overlapping lock (other open, or own shared)
                // blocks writes.
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
    ///
    /// Same-open semantics (Samba smbd, verified by torture `stacking` /
    /// `auto_unlock`): a new EXCLUSIVE lock conflicts with ANY overlapping
    /// lock held by the same open (re-acquiring exclusive over an own
    /// exclusive or shared lock → LOCK_NOT_GRANTED — no auto-unlock), while
    /// a new SHARED lock stacks freely over the open's own locks.
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
        // Zero-length locks are valid stacked entries (torture `lock`
        // "Trying 0/0 lock", `zerobytelength`; smbd grants them). The
        // u128 overlap math makes [o, o) conflict with nothing, so a
        // 0-length entry only ever conflicts with an identical 0-length
        // exclusive re-acquire — matching smbd.
        let mut locks = self.range_locks.write().await;
        if let Some(list) = locks.get(&file_id) {
            for lock in list {
                if lock.open_id == owner_open_id {
                    // Same open: exclusive acquisition conflicts with any
                    // overlapping own lock; shared stacks over own locks.
                    if exclusive && ranges_overlap(offset, length, lock.offset, lock.length) {
                        return Err(LockConflict::RangeConflict {
                            file_id,
                            offset: lock.offset,
                            length: lock.length,
                            open_id: lock.open_id,
                            session_id: lock.session_id,
                        });
                    }
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
        drop(locks);
        self.wake_lock_waiters(&[file_id]).await;
        Ok(())
    }

    /// Re-check all pended blocking-lock waiters for `file_ids` and fire
    /// the wake signal of every waiter whose elements would now be granted.
    /// Called after any lock-table mutation (single release, unlock, open
    /// close, tree disconnect, logoff).
    async fn wake_lock_waiters(&self, file_ids: &[FileId]) {
        if file_ids.is_empty() {
            return;
        }
        let locks = self.range_locks.read().await;
        let mut waiters = self.lock_waiters.write().await;
        let mut woken: Vec<usize> = Vec::new();
        for (i, w) in waiters.iter().enumerate() {
            if !file_ids.contains(&w.file_id) {
                continue;
            }
            if !w.still_blocked(&locks) {
                let _ = w.wake.send(true);
                woken.push(i);
            }
        }
        // Remove woken waiters (highest index first to keep indices valid).
        for i in woken.into_iter().rev() {
            waiters.remove(i);
        }
    }

    /// Register a blocking-lock waiter. Returns a receiver that fires
    /// (true) when the waiter may re-attempt the acquisition, or is
    /// dropped/aborted (also fired with true on abort — callers must
    /// re-check and treat a lost race as LOCK_NOT_GRANTED or cancel).
    pub async fn register_lock_waiter(
        &self,
        waiter: LockWaiter,
    ) -> tokio::sync::watch::Receiver<bool> {
        let rx = waiter.wake.subscribe();
        self.lock_waiters.write().await.push(waiter);
        rx
    }

    /// Remove all waiters registered by `open_id` (open closed / request
    /// abandoned) and wake them so their completion tasks can finish.
    pub async fn abort_lock_waiters_for_open(&self, owner_open_id: OpenId) {
        let mut waiters = self.lock_waiters.write().await;
        let mut aborted: Vec<usize> = Vec::new();
        for (i, w) in waiters.iter().enumerate() {
            if w.open_id == owner_open_id {
                let _ = w.wake.send(true);
                aborted.push(i);
            }
        }
        for i in aborted.into_iter().rev() {
            waiters.remove(i);
        }
    }

    /// Remove all waiters for `session_id` (logoff) and wake them. The
    /// session's pended locks are completed out-of-band by the LOGOFF
    /// sweep; this just drops the registry entries.
    pub async fn abort_lock_waiters_for_session(&self, _session_id: u64) {
        // Waiters don't carry the session; derive it via their open's
        // absence — simpler: wake all waiters whose open no longer exists.
        // The dispatch layer removes opens before calling this, so just
        // wake everything whose elements can no longer conflict is handled
        // by wake_lock_waiters; here we drop waiters whose open is gone by
        // waking all of them (the completion task then sees the open is
        // gone and completes RANGE_NOT_LOCKED/OK).
        let mut waiters = self.lock_waiters.write().await;
        for w in waiters.iter() {
            let _ = w.wake.send(true);
        }
        waiters.clear();
    }

    /// Release ONE byte-range lock on `file_id` for the open identified by
    /// `owner_open_id`. Only a lock with the exact same `(offset, length)`
    /// is removed; when several identical entries are held (Samba smbd
    /// treats locks as a stack — torture `stacking` unlocks one at a time
    /// and expects the extra unlock to fail with RANGE_NOT_LOCKED), exactly
    /// one is removed. Returns `Err(RangeNotLocked)` when no matching entry
    /// exists (a no-op unlock of a never-held range stays silently OK per
    /// MS-SMB2 3.3.5.14; the error is only for callers that need the
    /// missing-entry signal).
    #[instrument(skip(self, file_id, owner_open_id))]
    pub async fn release_range_lock(
        &self,
        file_id: FileId,
        owner_open_id: OpenId,
        offset: u64,
        length: u64,
    ) -> Result<(), LockConflict> {
        let mut locks = self.range_locks.write().await;
        if let Some(list) = locks.get_mut(&file_id) {
            if let Some(pos) = list
                .iter()
                .position(|l| l.open_id == owner_open_id && l.offset == offset && l.length == length)
            {
                list.remove(pos);
                if list.is_empty() {
                    locks.remove(&file_id);
                }
                drop(locks);
                self.wake_lock_waiters(&[file_id]).await;
                return Ok(());
            }
        }
        Err(LockConflict::RangeNotLocked)
    }

    /// Release all byte-range locks held by `owner_open_id` on any file.
    /// Called on CLOSE. Returns the number of locks released.
    #[instrument(skip(self, owner_open_id))]
    pub async fn release_all_locks_for_open(&self, owner_open_id: OpenId) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let mut touched: Vec<FileId> = Vec::new();
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.open_id != owner_open_id);
                let removed = before - list.len();
                if removed > 0 {
                    released += removed;
                    touched.push(*fid);
                }
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
        drop(locks);
        self.abort_lock_waiters_for_open(owner_open_id).await;
        self.wake_lock_waiters(&touched).await;
        released
    }

    /// Release all byte-range locks held by `tree_id` on any file.
    /// Called on tree-disconnect. Returns the number of locks released.
    #[instrument(skip(self, tree_id))]
    pub async fn release_all_locks_for_tree(&self, tree_id: u32) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let mut touched: Vec<FileId> = Vec::new();
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.tree_id != tree_id);
                let removed = before - list.len();
                if removed > 0 {
                    released += removed;
                    touched.push(*fid);
                }
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
        drop(locks);
        // Waiters pended by opens of this tree are aborted by their own
        // close path (release_all_locks_for_open); wake the rest.
        self.wake_lock_waiters(&touched).await;
        released
    }

    /// Release all byte-range locks held by `session_id` on any file.
    /// Called on logoff. Returns the number of locks released.
    #[instrument(skip(self, session_id))]
    pub async fn release_all_locks_for_session(&self, session_id: u64) -> usize {
        let mut locks = self.range_locks.write().await;
        let mut released = 0;
        let mut touched: Vec<FileId> = Vec::new();
        let empty_keys: Vec<FileId> = locks
            .iter_mut()
            .filter_map(|(fid, list)| {
                let before = list.len();
                list.retain(|l| l.session_id != session_id);
                let removed = before - list.len();
                if removed > 0 {
                    released += removed;
                    touched.push(*fid);
                }
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
        drop(locks);
        self.abort_lock_waiters_for_session(session_id).await;
        self.wake_lock_waiters(&touched).await;
        released
    }

    // ---- Lease & Oplock management (MS-SMB2 3.3.5.9.8 / 3.3.5.9.11 / 3.3.5.19) ----

    /// Request a Lease (v1 or v2) on `file_id` for `open_id`.
    ///
    /// Returns `Err(())` if the `(client_guid, lease_key)` is already bound to
    /// a *different* `file_id` (MS-SMB2: `STATUS_INVALID_PARAMETER`), or if the
    /// requested state is granted/upgraded along with any break notifications
    /// that must be sent to other lease/oplock holders on `file_id`.
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
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
        will_overwrite: bool,
        notify_tx: LeaseNotifySender,
    ) -> Result<(LeaseGrant, Vec<BreakNotification>, Vec<BreakWaiter>), ()> {
        self.request_lease_with_access(
            file_id,
            open_id,
            client_guid,
            lease_key,
            requested,
            is_v2,
            parent_lease_key,
            client_epoch,
            will_overwrite,
            notify_tx,
            ACCESS_MASK_UNKNOWN,
        )
        .await
    }

    /// Open ids of every other open on `file_id` (excluding `open_id`).
    async fn other_open_ids(&self, file_id: FileId, open_id: OpenId) -> Vec<OpenId> {
        let map = self.opens.read().await;
        map.get(&file_id)
            .map(|v| {
                v.iter()
                    .map(|e| e.open_id)
                    .filter(|o| *o != open_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn file_has_brlocks(&self, file_id: FileId) -> bool {
        self.range_locks
            .read()
            .await
            .get(&file_id)
            .is_some_and(|l| !l.is_empty())
    }

    /// [`Self::request_lease`] with the opener's raw desired-access mask.
    /// Grant rules follow Samba `delay_for_oplock` / `try_lease_upgrade`
    /// (open.c): stat opens break nothing, another open drops W, a non-lease
    /// open drops H, byte-range locks drop R, and an existing lease is only
    /// upgraded to a strict superset that can be granted in full.
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
    pub async fn request_lease_with_access(
        &self,
        file_id: FileId,
        open_id: OpenId,
        client_guid: [u8; 16],
        lease_key: [u8; 16],
        requested: LeaseCaching,
        is_v2: bool,
        parent_lease_key: Option<[u8; 16]>,
        client_epoch: u16,
        will_overwrite: bool,
        notify_tx: LeaseNotifySender,
        access_mask: u32,
    ) -> Result<(LeaseGrant, Vec<BreakNotification>, Vec<BreakWaiter>), ()> {
        let others = self.other_open_ids(file_id, open_id).await;
        let has_brlocks = self.file_has_brlocks(file_id).await;
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

        // 2. Classify the other opens on `file_id` (Samba delay_for_oplock_fn):
        //    any open outside this lease is an "other lease" (drops W); any
        //    open not covered by a lease at all is an "oplock" entry (drops H).
        let this_lease_handles: HashSet<OpenId> = mgr
            .leases
            .get(&id)
            .map(|e| e.handles.clone())
            .unwrap_or_default();
        let leased_handles: HashSet<OpenId> = mgr
            .leases
            .values()
            .filter(|v| v.file_id == file_id)
            .flat_map(|v| v.handles.iter().copied())
            .collect();
        let have_other_lease = others.iter().any(|o| !this_lease_handles.contains(o));
        let got_oplock = others.iter().any(|o| !leased_handles.contains(o));

        // Stat opens (oplock sense) neither break nor wait; lease stat opens
        // additionally skip breaking other leases.
        let (breaks, break_waiters) = if is_oplock_stat_open(access_mask) {
            (Vec::new(), Vec::new())
        } else {
            mgr.break_other_holders_on_open_mask(
                file_id,
                Some(id),
                open_id,
                will_overwrite,
                false,
                is_lease_stat_open(access_mask),
            )
        };

        // 3. Compute the grant (Samba delay_for_oplock `grant:` block).
        let mut candidate = requested;
        if !candidate.read && !candidate.write {
            candidate = LeaseCaching::NONE;
        }
        if !candidate.read && candidate.write {
            // W or WH without R is never granted.
            candidate = LeaseCaching::NONE;
        }
        if has_brlocks {
            candidate.read = false;
        }
        if have_other_lease {
            candidate.write = false;
        }
        if got_oplock {
            candidate.handle = false;
        }

        let is_new = !mgr.leases.contains_key(&id);
        let entry = mgr.leases.entry(id).or_insert_with(|| LeaseRecord {
            file_id,
            state: candidate,
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
            break_generation: 0,
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
            // Samba try_lease_upgrade: only a strict superset of the
            // existing state, granted in full, changes the lease.
            let existing = entry.state;
            let do_upgrade = !is_new
                && existing.is_subset_of(requested)
                && candidate != existing
                && candidate == requested;
            if do_upgrade {
                if entry.is_v2 {
                    entry.epoch = entry.epoch.wrapping_add(1);
                }
                entry.state = candidate;
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

        Ok((grant, breaks, break_waiters))
    }
    pub async fn request_oplock(
        &self,
        file_id: FileId,
        open_id: OpenId,
        smb_file_id: rssmb_proto::create::FileId,
        requested_level: u8,
        notify_tx: LeaseNotifySender,
        will_overwrite: bool,
    ) -> (u8, Vec<BreakNotification>, Vec<BreakWaiter>) {
        self.request_oplock_with_access(
            file_id,
            open_id,
            smb_file_id,
            requested_level,
            notify_tx,
            will_overwrite,
            ACCESS_MASK_UNKNOWN,
        )
        .await
    }

    /// [`Self::request_oplock`] with the opener's raw desired-access mask.
    /// Grant rules follow Samba `delay_for_oplock` (open.c): stat opens get
    /// no oplock and break nothing; another open drops W; any handle-caching
    /// lease on the file forbids an oplock; byte-range locks drop R.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_oplock_with_access(
        &self,
        file_id: FileId,
        open_id: OpenId,
        smb_file_id: rssmb_proto::create::FileId,
        requested_level: u8,
        notify_tx: LeaseNotifySender,
        will_overwrite: bool,
        access_mask: u32,
    ) -> (u8, Vec<BreakNotification>, Vec<BreakWaiter>) {
        if is_oplock_stat_open(access_mask) {
            return (0x00, Vec::new(), Vec::new());
        }
        let others = self.other_open_ids(file_id, open_id).await;
        let has_brlocks = self.file_has_brlocks(file_id).await;
        let mut mgr = self.leases.write().await;

        // Samba evaluates holder state before sending breaks.
        let got_handle_lease = mgr
            .leases
            .values()
            .any(|l| l.file_id == file_id && !l.handles.is_empty() && l.state.handle)
            || mgr
                .oplocks
                .values()
                .any(|o| o.file_id == file_id && o.open_id != open_id && o.level == 0x09);

        let (breaks, break_waiters) = mgr.break_other_holders_on_open_mask(
            file_id,
            None,
            open_id,
            will_overwrite,
            false,
            is_lease_stat_open(access_mask),
        );

        let mut want = match requested_level {
            0x09 => LeaseCaching::from_bits(0x07),
            0x08 => LeaseCaching::from_bits(0x05),
            0x01 => LeaseCaching::R,
            _ => LeaseCaching::NONE,
        };
        if has_brlocks {
            want.read = false;
        }
        if !others.is_empty() {
            want.write = false;
        }
        if got_handle_lease {
            want = LeaseCaching::NONE;
        }
        let granted = match (want.read, want.write, want.handle) {
            (true, true, true) => 0x09,
            (true, true, false) => 0x08,
            (true, false, _) => 0x01,
            _ => 0x00,
        };
        let granted = if requested_level == 0x00 {
            0x00
        } else {
            granted
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
                    break_generation: 0,
                },
            );
        }

        (granted, breaks, break_waiters)
    }

    /// Trigger breaks on `file_id` before an operation (`op`) performed by `actor_open_id`.
    ///
    /// Returns any `BreakNotification`s to send immediately and `BreakWaiter`s
    /// to await (with the 35 s lease break timeout) when an ACK is required
    /// before the conflicting operation proceeds.
    /// Break other holders for a new open that requests no lease/oplock
    /// (Samba `delay_for_oplock`, open.c). `sharing_violation` selects the H
    /// delay mask: the opener pends on an H-removing break and re-checks the
    /// share modes afterwards (timeout-disconnect).
    pub async fn break_for_open(
        &self,
        file_id: FileId,
        actor_open: OpenId,
        will_overwrite: bool,
        sharing_violation: bool,
    ) -> (Vec<BreakNotification>, Vec<BreakWaiter>) {
        self.break_for_open_with_access(
            file_id,
            actor_open,
            will_overwrite,
            sharing_violation,
            ACCESS_MASK_UNKNOWN,
        )
        .await
    }

    /// [`Self::break_for_open`] honouring Samba's stat-open exemptions:
    /// oplock stat opens break nothing, lease stat opens skip leases.
    pub async fn break_for_open_with_access(
        &self,
        file_id: FileId,
        actor_open: OpenId,
        will_overwrite: bool,
        sharing_violation: bool,
        access_mask: u32,
    ) -> (Vec<BreakNotification>, Vec<BreakWaiter>) {
        if is_oplock_stat_open(access_mask) {
            return (Vec::new(), Vec::new());
        }
        let mut mgr = self.leases.write().await;
        mgr.break_other_holders_on_open_mask(
            file_id,
            None,
            actor_open,
            will_overwrite,
            sharing_violation,
            is_lease_stat_open(access_mask),
        )
    }

    pub async fn break_for_op(
        &self,
        file_id: FileId,
        actor_open_id: Option<OpenId>,
        op: ConflictOp,
    ) -> (Vec<BreakNotification>, Vec<BreakWaiter>) {
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
        // Samba smbd_smb2_lease_break_ack (smb2_oplock.c): the acked state
        // must be a subset of the advertised break_to, else
        // STATUS_REQUEST_NOT_ACCEPTED (breaking2).
        if !acked_state.is_subset_of(rec.break_to) {
            return Err(rssmb_wire_adapter::NtStatus::Other(0xC000_00D0));
        }
        rec.state = acked_state;
        // If a stricter break was required while this one was in flight,
        // break further. Samba breaks in steps: while the state still holds
        // W or H, the next advertised target keeps R (breaking3).
        let required = rec.pending_break_to.take().unwrap_or(rec.break_to);
        if !acked_state.is_subset_of(required) {
            let mut next = required;
            let ack_req = acked_state.handle || acked_state.write;
            if ack_req {
                next = next.union(LeaseCaching::R).intersect(acked_state);
            }
            let notif = BreakNotification::Lease {
                notify_tx: rec.notify_tx.clone(),
                lease_key: id.lease_key,
                current_state: acked_state,
                new_state: next,
                // Samba does not bump the epoch for the additional break.
                new_epoch: if rec.is_v2 { rec.epoch } else { 0 },
                ack_required: ack_req,
            };
            if ack_req {
                rec.breaking = true;
                rec.break_to = next;
                if next != required {
                    rec.pending_break_to = Some(required);
                }
                return Ok((acked_state, Some(notif)));
            }
            rec.state = LeaseCaching::NONE;
            rec.breaking = false;
            for tx in std::mem::take(&mut rec.break_waiters) {
                let _ = tx.send(());
            }
            return Ok((acked_state, Some(notif)));
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

    /// Expire a specific lease's break — the 35 s server break-timeout fired.
    ///
    /// Golden (Samba `lease_timeout_handler`, smb2_oplock.c:285): on expiry
    /// the lease is downgraded to `NONE` (NOT to `break_to`), `breaking` is
    /// cleared, and all break waiters are resolved so the pending operation
    /// proceeds. The `expected_generation` guard prevents a stale timer
    /// from firing after the lease was acked or re-broken (Samba's
    /// epoch + BREAK_IN_PROGRESS race checks).
    pub async fn expire_lease_break(&self, lease_id: LeaseId, expected_generation: u64) {
        let mut mgr = self.leases.write().await;
        if let Some(rec) = mgr.leases.get_mut(&lease_id) {
            if rec.break_generation == expected_generation && rec.breaking {
                rec.state = LeaseCaching::NONE;
                rec.breaking = false;
                rec.break_to = LeaseCaching::NONE;
                rec.pending_break_to = None;
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
            }
        }
    }

    /// Expire a specific oplock's break — the 35 s server break-timeout fired.
    ///
    /// Same generation-guarded expiry as `expire_lease_break` for the
    /// oplock path.
    pub async fn expire_oplock_break(&self, open_id: OpenId, expected_generation: u64) {
        let mut mgr = self.leases.write().await;
        let mut to_remove = false;
        if let Some(rec) = mgr.oplocks.get_mut(&open_id) {
            if rec.break_generation == expected_generation && rec.breaking_to.is_some() {
                rec.level = 0;
                rec.breaking_to = None;
                rec.pending_breaking_to = None;
                for tx in std::mem::take(&mut rec.break_waiters) {
                    let _ = tx.send(());
                }
                to_remove = true;
            }
        }
        if to_remove {
            mgr.oplocks.remove(&open_id);
        }
    }

    /// Arm the 35 s server break-timeout for a lease break (MS-SMB2
    /// 3.3.4.7; Samba `OPLOCK_BREAK_TIMEOUT` = 35, local.h:131).
    ///
    /// Spawns a tokio task that sleeps 35 s then calls
    /// `expire_lease_break` with the current `break_generation`. The
    /// generation guard inside `expire_lease_break` makes a stale timer
    /// (the lease was acked or re-broken since) a no-op.
    fn arm_lease_break_timer(self: &Arc<Self>, lease_id: LeaseId, generation: u64) {
        let open_table = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(35)).await;
            open_table.expire_lease_break(lease_id, generation).await;
        });
    }

    /// Arm the 35 s server break-timeout for an oplock break.
    fn arm_oplock_break_timer(self: &Arc<Self>, open_id: OpenId, generation: u64) {
        let open_table = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(35)).await;
            open_table.expire_oplock_break(open_id, generation).await;
        });
    }

    /// Arm the 35 s server break-timeout for each waiter in `waiters`.
    /// Called by the dispatch layer after receiving break waiters from
    /// `request_lease` / `request_oplock` / `break_for_op` — the
    /// generation captured in each `BreakWaiter` makes a stale timer
    /// (the lease was acked or re-broken since arming) a no-op.
    pub fn arm_break_timers(self: &Arc<Self>, waiters: &[BreakWaiter]) {
        for w in waiters {
            match w.target {
                BreakTarget::Lease(id) => self.arm_lease_break_timer(id, w.generation),
                BreakTarget::Oplock(oid) => self.arm_oplock_break_timer(oid, w.generation),
            }
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
        // Shared stacks over the open's own exclusive lock (K2: torture
        // `stacking` — "stacking a shared on top of an exclusive lock
        // succeeds").
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 50, 200, false)
            .await
            .expect("same open can stack shared over own exclusive");
        table.release_range_lock(fid(1), oid(1), 0, 100).await.unwrap();
        table.release_range_lock(fid(1), oid(1), 50, 200).await.unwrap();
    }

    #[tokio::test]
    async fn lock_same_open_exclusive_over_own_lock_conflicts() {
        // K2: re-acquiring an exclusive lock over an overlapping own lock
        // (exclusive or shared) fails — no auto-unlock (torture
        // `auto_unlock`: repeated identical exclusive lock →
        // LOCK_NOT_GRANTED).
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, true)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, true)
            .await
            .expect_err("exclusive over own exclusive must conflict");
        // Sanity: shared stacks over the own exclusive lock (torture
        // `stacking`), and stacking does not grant exclusive rights.
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, false)
            .await
            .expect("shared stacks over own exclusive");
        // Exclusive over the same range (now also covered by own shared)
        // still conflicts.
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, true)
            .await
            .expect_err("exclusive over own shared must conflict");
        // Disjoint own shared lock, then exclusive over it: conflict.
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 20, 10, false)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 20, 10, true)
            .await
            .expect_err("exclusive over own shared (disjoint lock) must conflict");
    }

    #[tokio::test]
    async fn lock_unlock_removes_one_entry_and_miss_is_error() {
        // K2: locks stack — two identical locks need two unlocks, and the
        // third unlock reports RangeNotLocked (torture `stacking`: the 4th
        // unlock after 3 locks → RANGE_NOT_LOCKED).
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, false)
            .await
            .unwrap();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, false)
            .await
            .unwrap();
        table.release_range_lock(fid(1), oid(1), 0, 10).await.unwrap();
        // One entry still held: another open's exclusive still conflicts.
        table
            .acquire_range_lock(fid(1), oid(2), 200, 1, 0, 10, true)
            .await
            .expect_err("one stacked entry remains");
        table.release_range_lock(fid(1), oid(1), 0, 10).await.unwrap();
        let err = table
            .release_range_lock(fid(1), oid(1), 0, 10)
            .await
            .expect_err("unlock of a now-unheld range must report miss");
        assert!(matches!(err, LockConflict::RangeNotLocked));
    }

    #[tokio::test]
    async fn lock_write_own_exclusive_ok_own_shared_conflicts() {
        // K2: the open's own exclusive lock permits its own writes, but its
        // own shared lock still conflicts (torture `rw-exclusive` /
        // `rw-shared` write_h1 expectations).
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, true)
            .await
            .unwrap();
        table
            .check_range_lock_for_write(fid(1), oid(1), 5, 10)
            .await
            .expect("own exclusive permits own write");
        table.release_range_lock(fid(1), oid(1), 0, 10).await.unwrap();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 10, false)
            .await
            .unwrap();
        let err = table
            .check_range_lock_for_write(fid(1), oid(1), 5, 10)
            .await
            .expect_err("own shared lock must block own write");
        assert!(matches!(err, LockConflict::RangeConflict { .. }));
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
            LockConflict::ZeroLength | LockConflict::RangeNotLocked => {
                panic!("expected RangeConflict, got {:?}", err)
            }
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
            LockConflict::ZeroLength | LockConflict::RangeNotLocked => {
                panic!("expected RangeConflict, got {:?}", err)
            }
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
            LockConflict::ZeroLength | LockConflict::RangeNotLocked => {
                panic!("expected RangeConflict, got {:?}", err)
            }
        }
    }

    #[tokio::test]
    async fn lock_release_nonexistent_is_noop() {
        let table = OpenTable::new();
        // Releasing a lock that doesn't exist should not panic; via the
        // SMB2 UNLOCK path the miss maps to RANGE_NOT_LOCKED, the raw API
        // just reports it.
        let _ = table.release_range_lock(fid(1), oid(1), 0, 100).await;
    }

    #[tokio::test]
    async fn lock_zero_length_is_valid_stacked_entry() {
        // K4: 0-byte locks are valid (torture `lock` 0/0, `zerobytelength`);
        // they stack and unlock like any entry.
        let table = OpenTable::new();
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 0, true)
            .await
            .expect("zero-length exclusive lock is valid");
        table
            .acquire_range_lock(fid(1), oid(1), 100, 1, 0, 0, false)
            .await
            .expect("zero-length shared stacks over own exclusive");
        // A 0-length range never conflicts with a positive-length range.
        table
            .acquire_range_lock(fid(2), oid(2), 200, 1, 0, 10, true)
            .await
            .expect("other open's exclusive over [0,10) unaffected by 0-byte lock");
        table.release_range_lock(fid(1), oid(1), 0, 0).await.unwrap();
        table.release_range_lock(fid(1), oid(1), 0, 0).await.unwrap();
        let err = table
            .release_range_lock(fid(1), oid(1), 0, 0)
            .await
            .expect_err("third unlock of the stacked 0-byte entries must miss");
        assert!(matches!(err, LockConflict::RangeNotLocked));
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
            LockConflict::ZeroLength | LockConflict::RangeNotLocked => {
                panic!("expected RangeConflict, got {:?}", err)
            }
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
        let (grant1, breaks1, _waiters1) = table
            .request_lease(
                fid(10),
                oid(1),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x01), // R
                false,
                None,
                0,
                false,
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
        let (grant2, breaks2, _waiters2) = table
            .request_lease(
                fid(10),
                oid(2),
                client_guid,
                lease_key,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                false,
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
                false,
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
                false,
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
        let (grant, _, _) = table
            .request_lease(
                fid(5),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                false,
                tx.clone(),
            )
            .await
            .unwrap();
        assert_eq!(grant.state, LeaseCaching::from_bits(0x07));

        // Conflicting write from another handle triggers break to NONE with ack_required = true
        let (breaks, waiters) = table
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
        assert!(waiters
            .into_iter()
            .next()
            .unwrap()
            .receiver
            .try_recv()
            .is_ok());
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
                false,
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
        let (breaks2, waiters2) = table
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
        assert!(waiters2
            .into_iter()
            .next()
            .unwrap()
            .receiver
            .try_recv()
            .is_ok());
    }

    #[tokio::test]
    async fn lease_break_waiter_carries_generation_for_timer_guard() {
        // L1: a break waiter carries the break_generation captured at
        // break-initiation time, so the 35 s expiry timer can no-op if the
        // lease was acked or re-broken in the meantime (Samba
        // lease_timeout_handler epoch/flags race checks).
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client1 = [1u8; 16];
        let key1 = [0xCCu8; 16];

        table
            .check_and_add(fid(7), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        let (_grant, _breaks, _) = table
            .request_lease(
                fid(7),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                false,
                tx,
            )
            .await
            .unwrap();

        // A conflicting write triggers break RWH -> NONE with an ack-required
        // waiter carrying generation 1 (first break).
        let (breaks, waiters) = table
            .break_for_op(fid(7), Some(oid(2)), ConflictOp::Write)
            .await;
        assert_eq!(breaks.len(), 1);
        assert_eq!(waiters.len(), 1);
        assert_eq!(waiters[0].generation, 1);
        match waiters[0].target {
            BreakTarget::Lease(id) => {
                assert_eq!(id.client_guid, client1);
                assert_eq!(id.lease_key, key1);
            }
            BreakTarget::Oplock(_) => panic!("expected lease target"),
        }

        // Ack the break — this resolves the waiter.
        let (acked, followup) = table
            .ack_lease_break(client1, key1, LeaseCaching::NONE)
            .await
            .unwrap();
        assert_eq!(acked, LeaseCaching::NONE);
        assert!(followup.is_none());
    }

    #[tokio::test]
    async fn lease_break_expiry_downgrades_to_none_and_resolves_waiter() {
        // L1: the 35 s server break-timeout fires → lease downgraded to NONE
        // (NOT to break_to), breaking cleared, waiter resolved (Samba
        // lease_timeout_handler: downgrade_lease(..., SMB2_LEASE_NONE)).
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client1 = [1u8; 16];
        let key1 = [0xDDu8; 16];

        table
            .check_and_add(fid(8), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        let (_grant, _breaks, _) = table
            .request_lease(
                fid(8),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                false,
                tx,
            )
            .await
            .unwrap();

        // Trigger a break RWH -> RH (ack required).
        let (_breaks, waiters) = table
            .break_for_op(fid(8), Some(oid(2)), ConflictOp::Read)
            .await;
        assert_eq!(waiters.len(), 1);
        let generation = waiters[0].generation;
        let mut waiter_rx = waiters.into_iter().next().unwrap().receiver;

        // Simulate the 35 s timer firing — expire the break.
        let lease_id = LeaseId {
            client_guid: client1,
            lease_key: key1,
        };
        table.expire_lease_break(lease_id, generation).await;

        // The waiter should be resolved.
        assert!(waiter_rx.try_recv().is_ok());

        // The lease state should be NONE (not break_to RH).
        let (stored_key, stored_state) = table.lease_for_open(oid(1)).await.unwrap();
        assert_eq!(stored_key, key1);
        assert_eq!(stored_state, LeaseCaching::NONE);

        // A late ack should now return UNSUCCESSFUL (not breaking).
        let late_ack = table
            .ack_lease_break(client1, key1, LeaseCaching::NONE)
            .await;
        assert!(late_ack.is_err());
    }

    #[tokio::test]
    async fn lease_break_expiry_stale_generation_is_noop() {
        // L1: if the lease was acked (or re-broken) between arming the timer
        // and its fire, the generation guard makes the expiry a no-op.
        let table = OpenTable::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client1 = [1u8; 16];
        let key1 = [0xEEu8; 16];

        table
            .check_and_add(fid(9), entry(1, 100, ShareAccess::all()))
            .await
            .unwrap();
        let (_grant, _breaks, _) = table
            .request_lease(
                fid(9),
                oid(1),
                client1,
                key1,
                LeaseCaching::from_bits(0x07), // RWH
                true,
                None,
                1,
                false,
                tx,
            )
            .await
            .unwrap();

        // Break RWH -> RH (generation 1).
        let (_breaks, waiters) = table
            .break_for_op(fid(9), Some(oid(2)), ConflictOp::Read)
            .await;
        let stale_generation = waiters[0].generation;

        // Ack the break (generation moves past 1).
        let _ = table
            .ack_lease_break(client1, key1, LeaseCaching::from_bits(0x02))
            .await
            .unwrap();

        // Stale timer fires with generation 1 — should be a no-op.
        // The lease is now RH (acked), not NONE.
        let lease_id = LeaseId {
            client_guid: client1,
            lease_key: key1,
        };
        table.expire_lease_break(lease_id, stale_generation).await;

        let (_, stored_state) = table.lease_for_open(oid(1)).await.unwrap();
        assert_eq!(stored_state, LeaseCaching::from_bits(0x02)); // still RH, not NONE
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
            let rt_result: Result<(), String> = rt.block_on(async {
                let table = OpenTable::new();
                // A zero-length exclusive lock behaves like any stacked
                // entry: positional intersection over u128 means it can
                // conflict only with an identical 0-length exclusive
                // re-acquire — never with a positive-length range
                // (torture unlock "stacked 0-byte locks" asserts a 0-byte
                // lock at 10 blocks another open's exclusive over [5,15),
                // which the u128 math delivers because a 0-length range
                // [10,10) intersects [5,15) positionally).
                table
                    .acquire_range_lock(fid(1), oid(1), 100, 1, offset1, 0, true)
                    .await
                    .expect("zero-length exclusive lock is valid");
                match table
                    .acquire_range_lock(fid(1), oid(2), 200, 1, offset2, len2, true)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        // The only legal conflict here is positional: a
                        // 0-byte lock at offset1 inside [offset2, offset2+len2)
                        // intersecting — smbd blocks that too. Accept only
                        // RangeConflict.
                        if offset2 <= offset1 && offset1 <= offset2 + len2 {
                            match e {
                                LockConflict::RangeConflict { .. } => Ok(()),
                                other => Err(format!("unexpected conflict type: {:?}", other)),
                            }
                        } else {
                            Err(format!(
                                "zero-length lock at {} blocked disjoint [{}, {}+{}): {:?}",
                                offset1, offset2, offset2, len2, e
                            ))
                        }
                    }
                }
            });
            prop_assert!(rt_result.is_ok(), "{:?}", rt_result.err());
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
