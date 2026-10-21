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
//! The [`PendingPublishTable`] holds the per-directory `final_name → temp`
//! mapping. It is a process-global registry keyed by the **canonical share
//! root path**, because [`crate::localfs::LocalFs`] is constructed once per
//! TREE_CONNECT — two trees on the same share must share one map, or a
//! pending file opened through tree A would be invisible (and
//! double-published) from tree B.
//!
//! Covered (MS dispositions per crate docs):
//! `CREATE`, `OPEN_IF` (when creating), `OVERWRITE_IF`, `SUPERSEDE` — on
//! regular files. Directories and plain `OPEN`/`OVERWRITE` of existing
//! files are untouched (their handles are on the real file).
//!
//! Not covered, deliberately: appends/overwrites via a plain `OPEN` of an
//! existing file — no temp file is created; the handle is on the real file.
//!
//! Orphans: a server crash can leave `.rssmb-tmp.*` files behind. The sweep
//! ([`PendingPublishTable::sweep_orphans`]) removes temp files that have no
//! map entry and an mtime older than 1 hour. It is invoked at share startup
//! and every 10 minutes from the server sweeper.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

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
    /// The backing (temp) file name, e.g. `.rssmb-tmp.f.txt.a1b2c3d4`.
    pub temp_name: PathBuf,
    /// Outstanding SMB handles on the temp file.
    pub open_count: u64,
    /// Delete-on-close requested on the pending file (any handle). When the
    /// last handle closes, the temp is unlinked instead of published.
    pub delete_on_close: bool,
}

impl PendingPublish {
    fn new(temp_name: PathBuf) -> Self {
        // open_count starts at 0: `insert`'s or-insert-then-increment counts
        // the first handle, so a single CREATE yields 1 and a single close
        // is the last close.
        Self {
            temp_name,
            open_count: 0,
            delete_on_close: false,
        }
    }
}

/// Per-directory pending map: `final_name → PendingPublish`.
type DirMap = HashMap<String, PendingPublish>;

/// Pending-publish state for one share root.
#[derive(Debug)]
struct SharePending {
    /// Pending files, bucketed by directory (relative to the share root).
    dirs: RwLock<HashMap<PathBuf, DirMap>>,
    /// Nonce for temp-name suffixes.
    counter: std::sync::atomic::AtomicU64,
}

impl SharePending {
    fn new() -> Self {
        Self {
            dirs: RwLock::new(HashMap::new()),
            counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Generate a fresh temp name for `final_name` in `dir`.
    ///
    /// Visible name budget: `path::MAX_COMPONENT_UTF16` minus the
    /// `.rssmb-tmp.` prefix, one dot, and the 8-char suffix. The suffix is
    /// never truncated; the visible part is.
    fn temp_name_for(&self, dir: &Path, final_name: &str) -> PathBuf {
        // Random-ish, unique-per-process suffix: a monotonically increasing
        // counter mixed into a splitmix64-style finalizer. Uniqueness within
        // the process is all that is needed — collisions with *other* files
        // in the directory (client-visible names) are impossible because the
        // `.rssmb-tmp.` prefix is rejected by SMB name validation, and
        // final names can never start with `.` + `rssmb-tmp`-style prefixes
        // conflict-free. Uniqueness across restarts (orphan sweeps) is not
        // required: a collision would make create fail with AlreadyExists
        // and the caller retries with a fresh suffix.
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut z = n.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_4913_3113_7eb5);
        z ^= z >> 31;
        let suffix = format!("{z:016x}");
        let suffix: String = suffix[..SUFFIX_LEN].to_string();

        // Budget the visible part so the total temp component fits the same
        // UTF-16 component limit the final name had to pass. `.rssmb-tmp.` is
        // ASCII, so its UTF-16 length equals its byte length (11).
        const PREFIX_LEN_UTF16: usize = TEMP_PREFIX.len(); // ".rssmb-tmp."
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
static REGISTRY: OnceLock<RwLock<HashMap<PathBuf, std::sync::Arc<SharePending>>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<PathBuf, std::sync::Arc<SharePending>>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Pending-publish table for one share root (keyed by canonical path).
///
/// Handle-based VFS operations (read/write/close/rename) locate the pending
/// entry via the handle's `rel_path` (which **is** the temp path); path-based
/// resolution (create, case-insensitive lookup, directory listing) consults
/// [`Self::resolve`] first so no client ever observes a temp name.
#[derive(Debug)]
pub struct PendingPublishTable {
    share: std::sync::Arc<SharePending>,
}

impl PendingPublishTable {
    /// Fetch or create the table for the share rooted at `root`.
    ///
    /// `root` must be canonicalized by the caller (the LocalFs constructor
    /// already opens it via `Dir::open_ambient_dir`; the path it was opened
    /// from is the stable identity across TREE_CONNECTs).
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let reg = registry();
        let mut reg = reg.write().expect("publish registry lock poisoned");
        let share = reg
            .entry(root)
            .or_insert_with(|| Arc::new(SharePending::new()));
        Self {
            share: share.clone(),
        }
    }

    /// Resolve a client-visible path against the pending map.
    ///
    /// Returns `(dir, final_name, Some(temp_rel))` if `rel` names a pending
    /// file (the caller must operate on `temp_rel` instead of `rel`),
    /// `(dir, final_name, None)` if it does not.
    pub fn resolve(&self, rel: &Path) -> (PathBuf, String, Option<PathBuf>) {
        let (dir, name) = split_parent(rel);
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        if let Some(map) = dirs.get(&dir) {
            if let Some(pending) = map.get(&name) {
                return (dir, name, Some(pending.temp_name.clone()));
            }
        }
        (dir, name, None)
    }

    /// Register a newly-created temp file: `final_name` in `dir` backed by
    /// `temp_rel`. Idempotent per (dir, final): a second CREATE resolves to
    /// the existing temp via [`Self::resolve`] and only bumps `open_count`.
    pub fn insert(&self, dir: &Path, final_name: &str, temp_rel: PathBuf) {
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        dirs.entry(dir.to_path_buf())
            .or_default()
            .entry(final_name.to_string())
            .or_insert_with(|| PendingPublish::new(temp_rel))
            .open_count += 1;
    }

    /// A handle on the pending file `final_name` in `dir` was closed.
    ///
    /// Returns `Some((temp_rel, delete_on_close))` when this was the
    /// **last** close — the caller must publish (rename temp → final) or,
    /// if the entry is marked delete-on-close, unlink the temp. Returns
    /// `None` while other handles remain open.
    pub fn close(&self, dir: &Path, final_name: &str) -> Option<(PathBuf, bool)> {
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let map = dirs.get_mut(dir)?;
        let pending = map.get_mut(final_name)?;
        pending.open_count = pending.open_count.saturating_sub(1);
        if pending.open_count > 0 {
            return None;
        }
        let pending = map.remove(final_name)?;
        Some((pending.temp_name, pending.delete_on_close))
    }

    /// Set or clear delete-on-close on the pending entry for `final_name`
    /// in `dir`.
    pub fn set_delete_on_close(&self, dir: &Path, final_name: &str, delete: bool) {
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        if let Some(map) = dirs.get_mut(dir) {
            if let Some(pending) = map.get_mut(final_name) {
                pending.delete_on_close = delete;
            }
        }
    }

    /// The pending entry was renamed: `final_name` in `dir` becomes
    /// `new_final_name` in `new_dir`; the temp file keeps its name and is
    /// published under the new name at the last close.
    pub fn rename(&self, dir: &Path, final_name: &str, new_dir: &Path, new_final_name: &str) {
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        let Some(pending) = dirs.get_mut(dir).and_then(|map| map.remove(final_name)) else {
            return;
        };
        dirs.entry(new_dir.to_path_buf())
            .or_default()
            .entry(new_final_name.to_string())
            .or_insert(pending);
    }

    /// Delete the pending entry (unlink happened on the temp). No publish.
    pub fn remove(&self, dir: &Path, final_name: &str) {
        let mut dirs = self.share.dirs.write().expect("publish map lock poisoned");
        if let Some(map) = dirs.get_mut(dir) {
            map.remove(final_name);
        }
    }

    /// Generate a fresh temp name for a new pending file.
    pub fn temp_name_for(&self, dir: &Path, final_name: &str) -> PathBuf {
        self.share.temp_name_for(dir, final_name)
    }

    /// List pending files in one directory: `(final_name, temp_rel)`
    /// pairs, for QUERY_DIRECTORY synthesis (temps are hidden; finals are
    /// listed with the temp's attributes).
    pub fn pending_in_dir(&self, dir: &Path) -> Vec<(String, PathBuf)> {
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        match dirs.get(dir) {
            Some(map) => map
                .iter()
                .map(|(final_name, p)| (final_name.clone(), p.temp_name.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Live (pending) temp paths, absolutized under `root`, for the orphan
    /// sweep. Map entries are root-relative; the sweep walks absolute paths.
    fn live_temps(&self, root: &Path) -> std::collections::HashSet<PathBuf> {
        let dirs = self.share.dirs.read().expect("publish map lock poisoned");
        dirs.values()
            .flat_map(|m| m.values())
            .map(|p| root.join(&p.temp_name))
            .collect()
    }

    /// Remove `.rssmb-tmp.*` orphans: temp files with no pending-map entry
    /// and mtime older than [`ORPHAN_MAX_AGE`], anywhere under `root`.
    /// Each removal is logged at INFO.
    ///
    /// Walks the real directory tree (this is a backing-FS concern, not a
    /// client-visible one). Called at share startup and from the periodic
    /// sweeper; errors are logged and skipped (best-effort — a later sweep
    /// retries). Synchronous because it performs only `std::fs` I/O; no
    /// async runtime is needed at LocalFs construction time.
    ///
    /// Race safety: live temps are excluded by (a) this snapshot and (b)
    /// the age guard — a temp inserted after the snapshot was created has a
    /// fresh mtime, well under [`ORPHAN_MAX_AGE`], so the age check alone
    /// already protects it. The snapshot is belt-and-braces for clock skew.
    pub fn sweep_orphans(&self, root: &Path) -> usize {
        let mut removed = 0usize;
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

    fn table() -> PendingPublishTable {
        let root = tempfile::tempdir().expect("tempdir");
        let t = PendingPublishTable::for_root(root.path());
        // Keep root alive via the table for the test duration: tempdirs are
        // fine to leak per-test (tempfile cleans at process exit).
        std::mem::forget(root);
        t
    }

    #[test]
    fn temp_name_shape() {
        let t = table();
        let temp = t.temp_name_for(Path::new(""), "f.txt");
        let name = temp.to_str().unwrap();
        assert!(name.starts_with(TEMP_PREFIX));
        // 8-hex suffix after a dot
        let rest = &name[TEMP_PREFIX.len()..];
        let (vis, suf) = rest.rsplit_once('.').unwrap();
        assert_eq!(suf.len(), 8);
        assert!(suf.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(vis, "f.txt");
    }

    #[test]
    fn temp_name_long_final_name_truncates_visible_only() {
        let t = table();
        // 200 'a' chars + ".txt" — over the budget; suffix must stay intact.
        let final_name = "a".repeat(200) + ".txt";
        let temp = t.temp_name_for(Path::new(""), &final_name);
        let name = temp.to_str().unwrap();
        let rest = &name[TEMP_PREFIX.len()..];
        let (_, suf) = rest.rsplit_once('.').unwrap();
        assert_eq!(suf.len(), 8);
        assert!(name.encode_utf16().count() <= crate::path::MAX_COMPONENT_UTF16);
    }

    #[test]
    fn insert_resolve_close_cycle() {
        let t = table();
        let temp = t.temp_name_for(Path::new(""), "out.bin");
        t.insert(Path::new(""), "out.bin", temp.clone());
        // resolve maps final → temp
        let (dir, name, mapped) = t.resolve(Path::new("out.bin"));
        assert_eq!((dir, name), (PathBuf::new(), "out.bin".to_string()));
        assert_eq!(mapped, Some(temp.clone()));
        // first close: not last (open_count 1 → 0)... it IS last
        let result = t.close(Path::new(""), "out.bin");
        assert_eq!(result, Some((temp, false)));
        // after close, resolve is empty
        let (_, _, mapped) = t.resolve(Path::new("out.bin"));
        assert!(mapped.is_none());
    }

    #[test]
    fn second_insert_bumps_count() {
        let t = table();
        let temp = t.temp_name_for(Path::new(""), "a.txt");
        t.insert(Path::new(""), "a.txt", temp.clone());
        t.insert(Path::new(""), "a.txt", temp.clone()); // second CREATE
        let result = t.close(Path::new(""), "a.txt");
        assert!(result.is_none(), "first close must not be last");
        let result = t.close(Path::new(""), "a.txt");
        assert_eq!(result, Some((temp, false)));
    }

    #[test]
    fn rename_moves_entry() {
        let t = table();
        let temp = t.temp_name_for(Path::new(""), "old.txt");
        t.insert(Path::new(""), "old.txt", temp.clone());
        t.rename(Path::new(""), "old.txt", Path::new(""), "new.txt");
        let (_, _, mapped) = t.resolve(Path::new("new.txt"));
        assert_eq!(mapped, Some(temp.clone()));
        let (_, _, mapped) = t.resolve(Path::new("old.txt"));
        assert!(mapped.is_none());
        let result = t.close(Path::new(""), "new.txt");
        assert_eq!(result, Some((temp, false)));
    }

    #[test]
    fn delete_on_close_flag_flows_to_last_close() {
        let t = table();
        let temp = t.temp_name_for(Path::new(""), "d.txt");
        t.insert(Path::new(""), "d.txt", temp.clone());
        t.set_delete_on_close(Path::new(""), "d.txt", true);
        let result = t.close(Path::new(""), "d.txt");
        assert_eq!(result, Some((temp, true)));
    }

    #[test]
    fn sweep_removes_only_stale_orphans() {
        let root = tempfile::tempdir().unwrap();
        let t = PendingPublishTable::for_root(root.path());
        // A stale orphan: temp name, old mtime.
        let stale = root.path().join(format!("{TEMP_PREFIX}stale.bin.deadbeef"));
        std::fs::write(&stale, b"x").unwrap();
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(ORPHAN_MAX_AGE.as_secs() + 600);
        let f = std::fs::File::options().append(true).open(&stale).unwrap();
        f.set_modified(old).unwrap();
        // A fresh temp (would be live): must NOT be removed.
        let fresh = root.path().join(format!("{TEMP_PREFIX}fresh.bin.deadbeef"));
        std::fs::write(&fresh, b"x").unwrap();
        // A live pending file: must NOT be removed.
        let live_rel = t.temp_name_for(Path::new(""), "live.bin");
        let live = root.path().join(&live_rel);
        std::fs::write(&live, b"x").unwrap();
        f2_set_old(&live);
        t.insert(Path::new(""), "live.bin", live_rel);
        // A normal client-visible file: untouched.
        let normal = root.path().join("normal.txt");
        std::fs::write(&normal, b"x").unwrap();

        let removed = t.sweep_orphans(root.path());
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
        let t = PendingPublishTable::for_root(root.path());
        std::fs::create_dir(root.path().join("sub")).unwrap();
        let stale = root
            .path()
            .join("sub")
            .join(format!("{TEMP_PREFIX}s.bin.deadbeef"));
        std::fs::write(&stale, b"x").unwrap();
        f2_set_old(&stale);
        let removed = t.sweep_orphans(root.path());
        assert_eq!(removed, 1);
        assert!(!stale.exists());
    }

    #[test]
    fn is_temp_name_check() {
        assert!(is_temp_name(&format!("{TEMP_PREFIX}x")));
        assert!(!is_temp_name("x.txt"));
        assert!(!is_temp_name(".rssmb-tmp")); // prefix without trailing dot
    }
}
