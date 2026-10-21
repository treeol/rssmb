//! Atomic publish-on-close — hidden temp files renamed to the final name.
//!
//! A client that pre-sizes a new file (SET_INFO EndOfFile, then writes) makes
//! the file visible on the backing filesystem at full logical size with zero
//! data from the first second. With `publish_on_close` enabled on a share,
//! new files are instead created under a hidden temp name
//! (`.rssmb-tmp.<final-name>.<8 hex>`) in the same directory, and atomically
//! renamed to the final name when the **last** SMB handle is closed.
//! All SMB clients observe the final name throughout; only the backing
//! filesystem sees the temp name.
//!
//! ## Map design
//!
//! The [`PendingPublishTable`] holds `final_name → temp` per directory.
//! All acquisition state lives behind a single per-share [`RwLock`], so:
//!
//! - **Acquisition is atomic** ([`PendingPublishTable::resolve_or_acquire`]):
//!   one write-lock transition either attaches to an existing pending file
//!   or mints a new one. Two concurrent CREATEs can never end up writing to
//!   two different temp files where the map only knows one.
//! - **Reservation rollback** ([`PendingPublishTable::abort`]): the LocalFs
//!   CREATE path acquires (count++) *before* opening the backing file; every
//!   subsequent error path must abort (count--, remove at zero) so a failed
//!   open never permanently shadows the final name with a phantom entry.
//! - **Case handling**: on a case-insensitive share every key is lowercased
//!   (SMB names compare case-insensitively there), while the *temp placement
//!   path* keeps the on-disk casing of the parent directory so the temp
//!   really lands in the right directory.
//! - **Last close** ([`PendingPublishTable::close`]) decrements and removes
//!   the entry atomically; the caller then renames (or unlinks) the temp.
//!   A publish can therefore never be lost to a racing second acquire: the
//!   entry is removed under the same lock that an acquire would need.
//!
//! ## Registry
//!
//! [`LocalFs`](crate::localfs::LocalFs) is constructed once per TREE_CONNECT,
//! so two trees on the same share must share one pending map: tables live in
//! a process-global [`REGISTRY`] keyed by **canonical share root path**
//! (canonicalized by the LocalFs constructor). The share root is also what
//! bounds the orphan sweep:
//!
//! - startup sweep runs **once per root** (not per TREE_CONNECT) via a
//!   [`AtomicBool`] guard on the registry entry;
//! - the sweep **skips temp files that live beneath a different registered
//!   publish root** — two publish-enabled shares with nested roots
//!   (`/data` and `/data/sub`) must not sweep each other's live temps.
//!
//! ## Orphans
//!
//! A server crash can leave `.rssmb-tmp.*` files behind. The sweep
//! ([`PendingPublishTable::sweep_orphans`]) removes temp files that have no
//! map entry and an mtime older than [`ORPHAN_MAX_AGE`]. It is invoked once
//! at first construction for a root, and every 10 minutes from the server
//! sweeper. Race safety: live temps are excluded by the snapshot *and* by
//! the age guard — a temp inserted after the snapshot was created has a
//! fresh mtime, well under [`ORPHAN_MAX_AGE`].
//!
//! ## Coverage (semantics contract)
//!
//! `CREATE`, `OPEN_IF` (when creating), `OVERWRITE_IF`, `SUPERSEDE` — on
//! regular files. Directories and plain `OPEN`/`OVERWRITE` of existing files
//! are untouched (their handles are on the real file). Not covered,
//! deliberately: appends/overwrites via a plain OPEN of an existing file —
//! no temp file is created; the handle is on the real file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Temp-file name prefix. Anything starting with this in a watched directory
/// is a publish-on-close temp file and must never be exposed to SMB clients.
pub const TEMP_PREFIX: &str = ".rssmb-tmp.";

/// Random-suffix length in hex characters.
const SUFFIX_LEN: usize = 8;

/// Age threshold for orphan removal (see module docs).
pub const ORPHAN_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// One pending file: final name → temp name, within one directory.
#[derive(Debug, Clone)]
pub struct PendingPublish {
    /// The backing (temp) file path, relative to the share root.
    pub temp_name: PathBuf,
    /// Outstanding SMB handles on the temp file.
    pub open_count: u64,
    /// Delete-on-close requested on the pending file (any handle). When the
    /// last handle closes, the temp is unlinked instead of published.
    pub delete_on_close: bool,
    /// The client-visible final name with original casing (the map key is
    /// case-folded on CI shares; listings show this instead).
    pub display_name: String,
}

/// Per-directory pending map: `final_name → PendingPublish`.
type DirMap = HashMap<String, PendingPublish>;

/// Result of a pending-file acquisition.
#[derive(Debug)]
pub enum Acquire {
    /// Attached to an existing pending file (second CREATE on a pending
    /// name). Carries the *authoritative* temp path from the map.
    Attached(PathBuf),
    /// A new pending entry was created with the freshly minted temp path.
    Created(PathBuf),
}

/// Pending-publish state for one share root.
#[derive(Debug)]
struct SharePending {
    /// Pending files, bucketed by directory (normalized key).
    dirs: RwLock<HashMap<PathBuf, DirMap>>,
    /// Nonce for temp-name suffixes. Seeded with pid ^ time so two
    /// processes (or a restart) do not produce the same suffix sequence —
    /// a colliding suffix could otherwise silently reopen a young orphan.
    counter: AtomicU64,
    /// The canonical share root path (bounds and keys the sweep).
    root: PathBuf,
    /// Whether the startup orphan sweep already ran for this root.
    /// Sweeping on every TREE_CONNECT would walk the whole share per
    /// connection (B6); the flag makes it once per root per process.
    startup_swept: AtomicBool,
    /// Whether file name lookup is case-insensitive on this share —
    /// all map keys are lowercased then (B5).
    case_insensitive: bool,
}

impl SharePending {
    fn new(root: PathBuf, case_insensitive: bool) -> Self {
        let seed = std::process::id() as u64
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Self {
            dirs: RwLock::new(HashMap::new()),
            counter: AtomicU64::new(seed | 1),
            root,
            startup_swept: AtomicBool::new(false),
            case_insensitive,
        }
    }

    /// Normalize a map key component (lowercase on case-insensitive shares).
    fn key_dir(&self, dir: &Path) -> PathBuf {
        if self.case_insensitive {
            PathBuf::from(dir.to_string_lossy().to_lowercase())
        } else {
            dir.to_path_buf()
        }
    }
    fn key_name(&self, name: &str) -> String {
        if self.case_insensitive {
            name.to_lowercase()
        } else {
            name.to_string()
        }
    }

    /// Generate a fresh temp name for `final_name` in `dir`.
    ///
    /// `dir` must be the *on-disk-cased* parent directory (the caller passes
    /// the case-resolved path) so the temp really lands in that directory.
    ///
    /// Visible name budget: [`crate::path::MAX_COMPONENT_UTF16`] minus the
    /// `.rssmb-tmp.` prefix, one dot, and the 8-char suffix. The suffix is
    /// never truncated; the visible part is. The seed is pid^time-mixed, so
    /// a same-named orphan from a previous process does not collide with a
    /// deterministic sequence; the caller additionally opens the temp with
    /// `create_new` (exclusive) and retries with a fresh suffix on collision
    /// (B4).
    fn temp_name_for(&self, dir: &Path, final_name: &str) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut z = n.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_4913_3113_7eb5);
        z ^= z >> 31;
        let suffix: String = format!("{z:016x}")[..SUFFIX_LEN].to_string();

        // Budget the visible part so the total temp component fits the same
        // UTF-16 component limit the final name had to pass. `.rssmb-tmp.` is
        // ASCII, so its UTF-16 length equals its byte length.
        const PREFIX_LEN_UTF16: usize = TEMP_PREFIX.len();
        const BUDGET: usize = crate::path::MAX_COMPONENT_UTF16 - PREFIX_LEN_UTF16 - 1 - SUFFIX_LEN;
        let mut visible = String::new();
        let mut used = 0usize;
        for ch in final_name.chars() {
            let units = ch.len_utf16();
            if used + units > BUDGET {
                break;
            }
            visible.push(ch);
            used += units;
        }

        let mut name = String::with_capacity(TEMP_PREFIX.len() + visible.len() + SUFFIX_LEN + 1);
        name.push_str(TEMP_PREFIX);
        name.push_str(&visible);
        name.push('.');
        name.push_str(&suffix);
        dir.join(name)
    }
}

/// Is this on-disk name a publish-on-close temp file?
pub fn is_temp_name(name: &str) -> bool {
    name.starts_with(TEMP_PREFIX)
}

/// Process-global registry of pending-publish maps, keyed by canonical share
/// root path.
static REGISTRY: OnceLock<RwLock<HashMap<PathBuf, Arc<SharePending>>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<PathBuf, Arc<SharePending>>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// All registered publish roots (for the nested-root sweep exclusion).
fn registered_roots() -> Vec<PathBuf> {
    registry()
        .read()
        .expect("publish registry lock poisoned")
        .keys()
        .cloned()
        .collect()
}

impl Acquire {
    /// The authoritative temp path (map-recorded) for this acquisition.
    pub fn into_temp(self) -> PathBuf {
        match self {
            Acquire::Attached(t) | Acquire::Created(t) => t,
        }
    }
}

/// Pending-publish table for one share root (keyed by canonical path).
///
/// Handle-based VFS operations (read/write/close/rename) locate the pending
/// entry via the handle's `rel_path` (which **is** the temp path); path-based
/// resolution (create, case-insensitive lookup, directory listing) goes
/// through [`Self::resolve_or_acquire`] / [`Self::resolve`] so no client ever
/// observes a temp name.
#[derive(Debug)]
pub struct PendingPublishTable {
    share: Arc<SharePending>,
}

impl PendingPublishTable {
    /// Fetch or create the table for the share rooted at `root`.
    ///
    /// `root` must be canonicalized by the caller (the LocalFs constructor
    /// canonicalizes before calling). On first construction for a root the
    /// startup orphan sweep runs (once per root per process).
    pub fn for_root(root: impl Into<PathBuf>, case_insensitive: bool) -> Self {
        let root = root.into();
        let reg = registry();
        let mut reg = reg.write().expect("publish registry lock poisoned");
        let share = match reg.get(&root) {
            Some(s) => s.clone(),
            None => {
                let s = Arc::new(SharePending::new(root.clone(), case_insensitive));
                reg.insert(root.clone(), s.clone());
                s
            }
        };
        drop(reg);
        // Startup sweep for `.rssmb-tmp.*` orphans left by a previous crash —
        // ONCE per root (the flag lives on the registry entry), not per
        // TREE_CONNECT (B6). Synchronous and cheap (pure std::fs walk).
        if !share.startup_swept.swap(true, Ordering::AcqRel) {
            let t = Self {
                share: share.clone(),
            };
            let removed = t.sweep_orphans();
            tracing::debug!(removed, "publish_on_close: startup orphan sweep");
        }
        Self { share }
    }

    /// Resolve a client-visible path against the pending map (no state
    /// change). Returns the authoritative temp path if `rel` names a pending
    /// file.
    pub fn resolve(&self, rel: &Path) -> Option<(PathBuf, String, PathBuf)> {
        let (dir, name) = split_parent(rel);
        let kdir = self.share.key_dir(&dir);
        let kname = self.share.key_name(&name);
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        let temp = dirs
            .get(&kdir)
            .and_then(|m| m.get(&kname))
            .map(|p| p.temp_name.clone());
        temp.map(|t| (dir, name, t))
    }

    /// Atomically resolve-or-acquire a pending file: attach to an existing
    /// pending entry (count++) or mint a new one, all under one write lock
    /// (B1). Returns the **authoritative** temp path from the map — the
    /// caller must open exactly this path.
    ///
    /// `disk_dir` is the on-disk-cased parent directory for temp placement
    /// (differs from the logical `dir` on case-insensitive shares where the
    /// client's casing may not match the disk).
    pub fn resolve_or_acquire(&self, dir: &Path, name: &str, disk_dir: &Path) -> Acquire {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let map = dirs.entry(kdir).or_default();
        if let Some(p) = map.get_mut(&kname) {
            let temp = p.temp_name.clone();
            p.open_count += 1;
            Acquire::Attached(temp)
        } else {
            let temp = self.share.temp_name_for(disk_dir, name);
            map.insert(
                kname,
                PendingPublish {
                    temp_name: temp.clone(),
                    open_count: 1,
                    delete_on_close: false,
                    display_name: name.to_string(),
                },
            );
            Acquire::Created(temp)
        }
    }

    /// Roll back an acquisition (a CREATE failed after
    /// [`Self::resolve_or_acquire`]). Decrements the count; removes the entry
    /// when it reaches zero, returning the temp path so the caller can
    /// best-effort unlink a freshly-created (empty) temp. Never unlinks an
    /// entry other handles still use (count > 0 keeps the entry).
    pub fn abort(&self, dir: &Path, name: &str) -> Option<PathBuf> {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let map = dirs.get_mut(&kdir)?;
        let p = map.get_mut(&kname)?;
        p.open_count = p.open_count.saturating_sub(1);
        if p.open_count == 0 {
            return map.remove(&kname).map(|p| p.temp_name);
        }
        None
    }

    /// A handle on the pending file `dir/name` was closed.
    ///
    /// Returns `Some((temp, delete_on_close))` when this was the **last**
    /// close — the caller must publish (rename temp → final) or, if flagged
    /// delete-on-close, unlink the temp. The entry removal and the count
    /// decrement are one atomic transition, so a racing acquire can never
    /// attach to an entry that is about to publish.
    pub fn close(&self, dir: &Path, name: &str) -> Option<(PathBuf, bool)> {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let map = dirs.get_mut(&kdir)?;
        let pending = map.get_mut(&kname)?;
        pending.open_count = pending.open_count.saturating_sub(1);
        if pending.open_count > 0 {
            return None;
        }
        let pending = map.remove(&kname)?;
        Some((pending.temp_name, pending.delete_on_close))
    }

    /// Set or clear delete-on-close on the pending entry for `dir/name`.
    pub fn set_delete_on_close(&self, dir: &Path, name: &str, delete: bool) {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        if let Some(map) = dirs.get_mut(&kdir) {
            if let Some(pending) = map.get_mut(&kname) {
                pending.delete_on_close = delete;
            }
        }
    }

    /// Move the pending entry `dir/name` to `new_dir/new_name` (a rename of a
    /// pending file keeps the temp; only the publish target moves).
    ///
    /// Returns `true` when the **destination already pends** (a collision):
    /// with `replace` the caller discards the destination entry (its temp
    /// is unlinked via [`Self::take_destination`]) and retries; without
    /// `replace` the caller refuses (`AlreadyExists`). On collision nothing
    /// is changed.
    pub fn rename(&self, dir: &Path, name: &str, new_dir: &Path, new_name: &str) -> bool {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let nkdir = self.share.key_dir(new_dir);
        let nkname = self.share.key_name(new_name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let Some(pending) = dirs.get_mut(&kdir).and_then(|m| m.remove(&kname)) else {
            // Source was not pending (renaming a regular file) — caller
            // handles it. Report no-collision.
            return false;
        };
        if dirs
            .get_mut(&nkdir)
            .and_then(|m| m.get_mut(&nkname))
            .is_some()
        {
            // Destination already pends: put the source back untouched so
            // the caller can refuse (or discard the destination and retry).
            dirs.get_mut(&kdir).and_then(|m| m.insert(kname, pending));
            return true;
        }
        dirs.entry(nkdir).or_default().insert(nkname, pending);
        false
    }

    /// Take (remove + return) the pending entry at `dir/name`'s destination —
    /// used when a rename with `replace` must overwrite a pending destination.
    /// The caller unlinks the returned temp so its data never publishes.
    pub fn take_destination(&self, new_dir: &Path, new_name: &str) -> Option<PendingPublish> {
        let nkdir = self.share.key_dir(new_dir);
        let nkname = self.share.key_name(new_name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        dirs.get_mut(&nkdir).and_then(|m| m.remove(&nkname))
    }

    /// Delete the pending entry (the temp unlink happened on the temp path).
    /// No publish.
    pub fn remove(&self, dir: &Path, name: &str) {
        let kdir = self.share.key_dir(dir);
        let kname = self.share.key_name(name);
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        if let Some(map) = dirs.get_mut(&kdir) {
            map.remove(&kname);
        }
    }

    /// List pending files in one directory: `(display_name, temp_rel)` pairs —
    /// the display name keeps the original client-visible casing — for
    /// QUERY_DIRECTORY synthesis (temps are hidden; finals are listed with
    /// the temp's attributes).
    pub fn pending_in_dir(&self, dir: &Path) -> Vec<(String, PathBuf)> {
        let kdir = self.share.key_dir(dir);
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        match dirs.get(&kdir) {
            Some(map) => map
                .values()
                .map(|p| (p.display_name.clone(), p.temp_name.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Live (pending) temp paths, absolutized under each entry's recorded
    /// root-relative temp path, for the orphan sweep exclusion.
    fn live_temps(&self, root: &Path) -> std::collections::HashSet<PathBuf> {
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        dirs.values()
            .flat_map(|m| m.values())
            .map(|p| root.join(&p.temp_name))
            .collect()
    }

    /// Sweep an explicit root — only if a table is already registered for it
    /// (the periodic server sweeper must not create registry entries for
    /// shares that never opened a publish backend).
    pub fn sweep_registered_root(root: &Path) -> Option<usize> {
        let reg = registry();
        let reg = reg.read().expect("publish registry lock poisoned");
        reg.get(root).map(|share| {
            let t = Self {
                share: share.clone(),
            };
            t.sweep_orphans_at(root)
        })
    }

    /// Remove `.rssmb-tmp.*` orphans: temp files with no pending-map entry
    /// and mtime older than [`ORPHAN_MAX_AGE`], anywhere under this table's
    /// share root. Each removal is logged at INFO.
    ///
    /// Walks the real directory tree (backing-FS concern, not client-visible).
    /// Synchronous (pure std::fs I/O) so it can run at construction time.
    ///
    /// Nested roots: temp files that live beneath a **different** registered
    /// publish root are skipped — that root's own sweep owns them (B7).
    /// Race safety: live temps are excluded by this snapshot *and* by the
    /// age guard (a temp acquired after the snapshot has a fresh mtime,
    /// well under [`ORPHAN_MAX_AGE`]).
    pub fn sweep_orphans(&self) -> usize {
        self.sweep_orphans_at(&self.share.root.clone())
    }

    /// Sweep an explicit root (the periodic server sweeper passes the
    /// per-share canonical root; it equals this table's root for
    /// per-share tables).
    pub fn sweep_orphans_at(&self, root: &Path) -> usize {
        let mut removed = 0usize;
        let other_roots: Vec<PathBuf> = registered_roots()
            .into_iter()
            .filter(|r| r != root)
            .collect();
        let live = self.live_temps(root);
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(path = ?dir, error = %e, "publish sweep: read_dir failed");
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    // Descend into subdirectories, but not into another
                    // registered publish root (its sweep owns it).
                    if other_roots.iter().any(|r| path.starts_with(r)) {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !is_temp_name(name) {
                    continue;
                }
                if live.contains(&path) {
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                let Ok(modified) = meta.modified() else {
                    continue;
                };
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age < ORPHAN_MAX_AGE {
                    continue;
                }
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        tracing::info!(path = ?path, "publish_on_close: removed orphaned temp file");
                        removed += 1;
                    }
                    Err(e) => {
                        tracing::debug!(path = ?path, error = %e, "publish sweep: remove failed");
                    }
                }
            }
        }
        removed
    }
}

/// Split a relative path into (parent-dir-relative-to-root, final component).
pub(crate) fn split_parent(rel: &Path) -> (PathBuf, String) {
    match (rel.parent(), rel.file_name()) {
        (Some(p), Some(n)) if !p.as_os_str().is_empty() && p != Path::new(".") => {
            (p.to_path_buf(), n.to_string_lossy().into_owned())
        }
        (_, Some(n)) => (PathBuf::new(), n.to_string_lossy().into_owned()),
        _ => (PathBuf::new(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(case_insensitive: bool) -> PendingPublishTable {
        let root = tempfile::tempdir().expect("tempdir");
        let t = PendingPublishTable::for_root(root.path(), case_insensitive);
        // Keep root alive for the test duration: tempdirs are fine to leak
        // per-test (tempfile cleans at process exit).
        std::mem::forget(root);
        t
    }

    #[test]
    fn temp_name_shape() {
        let t = table(false);
        let temp = t.share.temp_name_for(Path::new(""), "f.txt");
        let name = temp.to_str().unwrap();
        assert!(name.starts_with(TEMP_PREFIX));
        let rest = &name[TEMP_PREFIX.len()..];
        let (vis, suf) = rest.rsplit_once('.').unwrap();
        assert_eq!(suf.len(), 8);
        assert!(suf.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(vis, "f.txt");
    }

    #[test]
    fn temp_name_suffixes_differ_within_process() {
        let t = table(false);
        let a = t.share.temp_name_for(Path::new(""), "f.txt");
        let b = t.share.temp_name_for(Path::new(""), "f.txt");
        assert_ne!(a, b);
    }

    #[test]
    fn temp_name_long_final_name_truncates_visible_only() {
        let t = table(false);
        let final_name = "a".repeat(200) + ".txt";
        let temp = t.share.temp_name_for(Path::new(""), &final_name);
        let name = temp.to_str().unwrap();
        let rest = &name[TEMP_PREFIX.len()..];
        let (_, suf) = rest.rsplit_once('.').unwrap();
        assert_eq!(suf.len(), 8);
        assert!(name.encode_utf16().count() <= crate::path::MAX_COMPONENT_UTF16);
    }

    #[test]
    fn acquire_is_atomic_and_counts() {
        let t = table(false);
        // First acquire mints; the authoritative temp is returned.
        let Acquire::Created(temp1) = t.resolve_or_acquire(Path::new(""), "out.bin", Path::new(""))
        else {
            panic!("first acquire must create");
        };
        // Second acquire attaches to the SAME temp and bumps the count.
        let Acquire::Attached(temp2) =
            t.resolve_or_acquire(Path::new(""), "out.bin", Path::new(""))
        else {
            panic!("second acquire must attach");
        };
        assert_eq!(temp1, temp2);
        // Two outstanding handles: first close is not last.
        assert!(t.close(Path::new(""), "out.bin").is_none());
        // The last close publishes.
        assert_eq!(t.close(Path::new(""), "out.bin"), Some((temp1, false)));
        let (_, _, mapped) = unpack(t.resolve(Path::new("out.bin")));
        assert!(mapped.is_none());
    }

    fn unpack(r: Option<(PathBuf, String, PathBuf)>) -> (PathBuf, String, Option<PathBuf>) {
        match r {
            Some((d, n, t)) => (d, n, Some(t)),
            None => (PathBuf::new(), String::new(), None),
        }
    }

    #[test]
    fn abort_first_acquisition_removes_entry() {
        let t = table(false);
        let Acquire::Created(temp) = t.resolve_or_acquire(Path::new(""), "a.txt", Path::new(""))
        else {
            panic!()
        };
        assert_eq!(t.abort(Path::new(""), "a.txt"), Some(temp));
        let (_, _, mapped) = unpack(t.resolve(Path::new("a.txt")));
        assert!(mapped.is_none());
    }

    #[test]
    fn ci_share_keys_case_fold() {
        let t = table(true);
        let Acquire::Created(temp1) = t.resolve_or_acquire(Path::new(""), "F.TXT", Path::new(""))
        else {
            panic!()
        };
        // Resolve via different casing — same entry.
        let Acquire::Attached(temp2) = t.resolve_or_acquire(Path::new(""), "f.txt", Path::new(""))
        else {
            panic!("ci resolve must attach");
        };
        assert_eq!(temp1, temp2);
        // First of two outstanding closes is not last.
        assert!(t.close(Path::new(""), "F.TxT").is_none());
        assert_eq!(t.close(Path::new(""), "f.txt"), Some((temp2, false)));
    }

    #[test]
    fn cs_share_keys_exact() {
        let t = table(false);
        let Acquire::Created(_) = t.resolve_or_acquire(Path::new(""), "F.TXT", Path::new(""))
        else {
            panic!()
        };
        let Acquire::Created(_) = t.resolve_or_acquire(Path::new(""), "f.txt", Path::new(""))
        else {
            panic!("case-sensitive share: different case is a distinct file");
        };
        assert!(t.close(Path::new(""), "F.TXT").is_some());
        assert!(t.close(Path::new(""), "f.txt").is_some());
    }

    #[test]
    fn rename_moves_entry_and_reports_collision() {
        let t = table(false);
        let Acquire::Created(temp) = t.resolve_or_acquire(Path::new(""), "old.txt", Path::new(""))
        else {
            panic!()
        };
        assert!(!t.rename(Path::new(""), "old.txt", Path::new(""), "new.txt"));
        let Acquire::Attached(temp2) =
            t.resolve_or_acquire(Path::new(""), "new.txt", Path::new(""))
        else {
            panic!()
        };
        assert_eq!(temp, temp2);
        let (_, _, mapped) = unpack(t.resolve(Path::new("old.txt")));
        assert!(mapped.is_none());
        // Two outstanding (the original acquire moved by the rename + the
        // Attached above): first close not last, second publishes.
        assert!(t.close(Path::new(""), "new.txt").is_none());
        assert_eq!(t.close(Path::new(""), "new.txt"), Some((temp2, false)));
    }

    #[test]
    fn rename_collision_is_reported() {
        let t = table(false);
        let _ = t.resolve_or_acquire(Path::new(""), "a.txt", Path::new(""));
        let _ = t.resolve_or_acquire(Path::new(""), "b.txt", Path::new(""));
        assert!(t.rename(Path::new(""), "a.txt", Path::new(""), "b.txt"));
        // Source unchanged (still pending under a.txt).
        let (_, _, mapped) = unpack(t.resolve(Path::new("a.txt")));
        assert!(mapped.is_some());
    }

    #[test]
    fn delete_on_close_flag_flows_to_last_close() {
        let t = table(false);
        let Acquire::Created(temp) = t.resolve_or_acquire(Path::new(""), "d.txt", Path::new(""))
        else {
            panic!()
        };
        t.set_delete_on_close(Path::new(""), "d.txt", true);
        assert_eq!(t.close(Path::new(""), "d.txt"), Some((temp, true)));
    }

    #[test]
    fn sweep_removes_only_stale_orphans() {
        let root = tempfile::tempdir().unwrap();
        let t = PendingPublishTable::for_root(root.path(), false);
        let stale = root.path().join(format!("{TEMP_PREFIX}stale.bin.deadbeef"));
        std::fs::write(&stale, b"x").unwrap();
        f2_set_old(&stale);
        let fresh = root.path().join(format!("{TEMP_PREFIX}fresh.bin.deadbeef"));
        std::fs::write(&fresh, b"x").unwrap();
        // A live pending file: must NOT be removed.
        let Acquire::Created(live_rel) =
            t.resolve_or_acquire(Path::new(""), "live.bin", Path::new(""))
        else {
            panic!()
        };
        let live = root.path().join(&live_rel);
        std::fs::write(&live, b"x").unwrap();
        f2_set_old(&live);
        let normal = root.path().join("normal.txt");
        std::fs::write(&normal, b"x").unwrap();

        let removed = t.sweep_orphans();
        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(fresh.exists());
        assert!(live.exists());
        assert!(normal.exists());
    }

    fn f2_set_old(path: &Path) {
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(ORPHAN_MAX_AGE.as_secs() + 600);
        let f = std::fs::File::options().append(true).open(path).unwrap();
        f.set_modified(old).unwrap();
    }

    #[test]
    fn sweep_recurses_subdirs() {
        let root = tempfile::tempdir().unwrap();
        let t = PendingPublishTable::for_root(root.path(), false);
        std::fs::create_dir(root.path().join("sub")).unwrap();
        let stale = root
            .path()
            .join("sub")
            .join(format!("{TEMP_PREFIX}s.bin.deadbeef"));
        std::fs::write(&stale, b"x").unwrap();
        f2_set_old(&stale);
        let removed = t.sweep_orphans_at(root.path());
        assert_eq!(removed, 1);
        assert!(!stale.exists());
    }

    #[test]
    fn is_temp_name_check() {
        assert!(is_temp_name(&format!("{TEMP_PREFIX}x")));
        assert!(!is_temp_name("x.txt"));
        assert!(!is_temp_name(".rssmb-tmp"));
    }
}
