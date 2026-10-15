//! CHANGE_NOTIFY — directory change notification.
//!
//! Uses the `notify` crate (inotify on Linux, FSEvents on macOS,
//! ReadDirectoryChangesW on Windows) to watch a directory for changes.
//! Events are translated into FILE_NOTIFY_INFORMATION (MS-FSCC §2.4.34)
//! and sent as async completions via `send_unsolicited`.
//!
//! MS-SMB2 3.3.5.15.4: the server registers a watch, returns STATUS_PENDING,
//! and completes the request when changes are observed or the watch is
//! cancelled (CANCEL, CLOSE, tree-disconnect, logoff).

use std::path::PathBuf;

use notify::event::ModifyKind;
use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use rssmb_proto::notify::ChangeNotifyResponse;
use rssmb_proto::plain::ResponseContent;
use rssmb_wire_adapter::FramedResponse;

use crate::dispatch::{build_response, send_unsolicited, ConnState};

// ── FILE_NOTIFY_CHANGE_* constants (MS-FSCC §2.4.34) ───────────────────

const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x00000004;
const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x00000020;
const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x00000040;
const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x00000080;
const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x00000100;
const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x00000200;
const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x00000400;

// ── FILE_ACTION_* constants (MS-FSCC §2.4.34) ──────────────────────────

const FILE_ACTION_ADDED: u32 = 0x00000001;
const FILE_ACTION_REMOVED: u32 = 0x00000002;
const FILE_ACTION_MODIFIED: u32 = 0x00000003;
#[allow(dead_code)]
const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x00000004;
#[allow(dead_code)]
const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x00000005;

/// CompletionFilter bits from the SMB2 CHANGE_NOTIFY request (MS-SMB2 2.2.35).
/// Maps to the NotifyFilter proto bitfield.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompletionFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,
    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,
    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,
}

impl CompletionFilter {
    /// Convert to a bitmask of FILE_NOTIFY_CHANGE_* flags for filtering.
    fn change_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.file_name {
            mask |= FILE_NOTIFY_CHANGE_FILE_NAME;
        }
        if self.dir_name {
            mask |= FILE_NOTIFY_CHANGE_DIR_NAME;
        }
        if self.attributes {
            mask |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
        }
        if self.size {
            mask |= FILE_NOTIFY_CHANGE_SIZE;
        }
        if self.last_write {
            mask |= FILE_NOTIFY_CHANGE_LAST_WRITE;
        }
        if self.last_access {
            mask |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
        }
        if self.creation {
            mask |= FILE_NOTIFY_CHANGE_CREATION;
        }
        if self.security {
            mask |= FILE_NOTIFY_CHANGE_SECURITY;
        }
        if self.stream_name {
            mask |= FILE_NOTIFY_CHANGE_STREAM_NAME;
        }
        if self.stream_size {
            mask |= FILE_NOTIFY_CHANGE_STREAM_SIZE;
        }
        if self.stream_write {
            mask |= FILE_NOTIFY_CHANGE_STREAM_WRITE;
        }
        mask
    }
}

/// A single FILE_NOTIFY_INFORMATION entry (MS-FSCC §2.4.34).
struct FileNotifyEntry {
    action: u32,
    file_name: String,
}

/// Serialize FILE_NOTIFY_INFORMATION entries into a byte buffer.
/// Each entry: NextEntryOffset(4) + Action(4) + FileNameLength(4) + FileName(UTF-16LE).
/// The last entry has NextEntryOffset = 0. Entries are 4-byte aligned.
fn serialize_notify_buffer(entries: &[FileNotifyEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let name_utf16: Vec<u16> = entry.file_name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let name_len = name_bytes.len() as u32;

        let entry_size = 12 + name_bytes.len();
        let padded_size = (entry_size + 3) & !3; // 4-byte align
        let next_offset = if i + 1 < entries.len() {
            padded_size as u32
        } else {
            0
        };

        buf.extend_from_slice(&next_offset.to_le_bytes());
        buf.extend_from_slice(&entry.action.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&name_bytes);
        // Pad to 4-byte alignment.
        buf.extend(std::iter::repeat_n(0u8, padded_size - entry_size));
    }
    buf
}

/// Map a notify::Event to (action, change_mask) for FILE_NOTIFY_INFORMATION.
fn map_event(event: &notify::Event) -> Option<(u32, u32)> {
    match &event.kind {
        EventKind::Create(_) => Some((
            FILE_ACTION_ADDED,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
        )),
        EventKind::Remove(_) => Some((
            FILE_ACTION_REMOVED,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
        )),
        EventKind::Modify(kind) => match kind {
            ModifyKind::Name(_) => {
                // The notify crate doesn't pair old/new name reliably.
                // Report as MODIFIED with the FILE_NAME change flag.
                Some((FILE_ACTION_MODIFIED, FILE_NOTIFY_CHANGE_FILE_NAME))
            }
            ModifyKind::Data(_) => Some((
                FILE_ACTION_MODIFIED,
                FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )),
            ModifyKind::Metadata(_) => Some((
                FILE_ACTION_MODIFIED,
                FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SECURITY
                    | FILE_NOTIFY_CHANGE_CREATION
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_LAST_ACCESS,
            )),
            _ => Some((
                FILE_ACTION_MODIFIED,
                FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )),
        },
        EventKind::Access(_) => None, // Access events don't map to FILE_ACTION_*
        EventKind::Other | EventKind::Any => None,
    }
}

/// Handle for cancelling a directory watch. Dropping or calling `cancel()`
/// signals the background task to stop.
pub struct NotifyHandle {
    cancel_tx: Option<oneshot::Sender<()>>,
}

impl NotifyHandle {
    pub fn cancel(mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Start a directory watch for CHANGE_NOTIFY.
///
/// Spawns a background task that:
/// 1. Creates a `RecommendedWatcher` on `dir_path`
/// 2. Receives filesystem events via an mpsc channel
/// 3. Filters events by the `CompletionFilter`
/// 4. Serializes matching events as FILE_NOTIFY_INFORMATION
/// 5. Sends the completion via `send_unsolicited`
/// 6. **Removes the op from `pending_async` after the first successful
///    completion** (MS-SMB2: one completion per request; the client
///    re-submits for subsequent changes)
///
/// The task exits when cancelled (CANCEL, CLOSE, tree-disconnect, logoff)
/// or when the watcher errors.
pub fn start_watch(
    conn_state: &ConnState,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    dir_path: PathBuf,
    watch_tree: bool,
    filter: CompletionFilter,
) -> NotifyHandle {
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

    let conn_state_clone = conn_state.clone();
    let change_mask = filter.change_mask();
    let conn_id = conn_state.conn_id;
    let pending_async = conn_state.pending_async.clone();

    tokio::spawn(async move {
        let (event_tx, mut event_rx) = mpsc::channel::<notify::Result<notify::Event>>(128);

        let watcher =
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                let _ = event_tx.blocking_send(res);
            }) {
                Ok(w) => w,
                Err(e) => {
                    warn!(conn_id, error = %e, "change_notify: failed to create watcher");
                    return;
                }
            };

        let mut watcher = watcher;
        let mode = if watch_tree {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        if let Err(e) = watcher.watch(&dir_path, mode) {
            warn!(conn_id, path = ?dir_path, error = %e, "change_notify: failed to watch directory");
            return;
        }

        debug!(conn_id, path = ?dir_path, watch_tree, "change_notify: watch started");

        let mut cancel_rx = cancel_rx;

        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    debug!(conn_id, message_id, "change_notify: cancelled");
                    break;
                }
                event = event_rx.recv() => {
                    match event {
                        Some(Ok(notify_event)) => {
                            if let Some((action, mask)) = map_event(&notify_event) {
                                if mask & change_mask == 0 {
                                    continue;
                                }

                                // Build FILE_NOTIFY_INFORMATION entries.
                                // Convert paths to SMB `\` separators.
                                let entries: Vec<FileNotifyEntry> = notify_event
                                    .paths
                                    .iter()
                                    .filter_map(|p| {
                                        let rel = p.strip_prefix(&dir_path).unwrap_or(p);
                                        let name = rel.to_string_lossy()
                                            .replace('/', "\\")
                                            .to_string();
                                        if name.is_empty() {
                                            None
                                        } else {
                                            Some(FileNotifyEntry { action, file_name: name })
                                        }
                                    })
                                    .collect();

                                if entries.is_empty() {
                                    continue;
                                }

                                let buffer = serialize_notify_buffer(&entries);

                                // Build the async completion response.
                                let header = rssmb_proto::header::Header {
                                    credit_charge: 0,
                                    status: rssmb_wire_adapter::NtStatus::Success.to_u32(),
                                    command: rssmb_proto::header::Command::ChangeNotify,
                                    credit_request: 0,
                                    flags: rssmb_proto::header::HeaderFlags::new()
                                        .with_server_to_redir(true)
                                        .with_async_command(true),
                                    next_command: 0,
                                    message_id,
                                    tree_id: Some(tree_id),
                                    async_id: Some(message_id),
                                    session_id,
                                    signature: 0,
                                };

                                let resp = build_response(
                                    &header,
                                    ResponseContent::ChangeNotify(ChangeNotifyResponse { buffer }),
                                );

                                let framed = FramedResponse::Plain(resp);
                                send_unsolicited(&conn_state_clone, &framed, true).await;

                                // Remove the op from pending_async so CANCEL
                                // can't target it and we don't send
                                // duplicate completions. MS-SMB2: one
                                // completion per request; the client
                                // re-submits for subsequent changes.
                                pending_async.lock().await.remove(&message_id);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            warn!(conn_id, error = %e, "change_notify: watcher error");
                            break;
                        }
                        None => {
                            debug!(conn_id, "change_notify: watcher closed");
                            break;
                        }
                    }
                }
            }
        }

        let _ = watcher.unwatch(&dir_path);
        debug!(conn_id, "change_notify: watch stopped");
    });

    NotifyHandle {
        cancel_tx: Some(cancel_tx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, CreateKind, RemoveKind};

    #[test]
    fn test_serialize_notify_buffer_single_entry() {
        let entries = vec![FileNotifyEntry {
            action: FILE_ACTION_ADDED,
            file_name: "test.txt".to_string(),
        }];
        let buf = serialize_notify_buffer(&entries);
        // NextEntryOffset(4) + Action(4) + FileNameLength(4) + "test.txt"(16 bytes UTF-16LE)
        // = 12 + 16 = 28, padded to 28 (already 4-aligned)
        assert_eq!(buf.len(), 28);
        // Last entry: NextEntryOffset = 0
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 0);
        // Action = FILE_ACTION_ADDED
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            FILE_ACTION_ADDED
        );
        // FileNameLength = 16 (8 chars × 2 bytes)
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 16);
    }

    #[test]
    fn test_serialize_notify_buffer_multiple_entries() {
        let entries = vec![
            FileNotifyEntry {
                action: FILE_ACTION_ADDED,
                file_name: "a.txt".to_string(),
            },
            FileNotifyEntry {
                action: FILE_ACTION_REMOVED,
                file_name: "b.txt".to_string(),
            },
        ];
        let buf = serialize_notify_buffer(&entries);
        // First entry: NextEntryOffset should be non-zero
        let next_off = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert!(next_off > 0);
        // Second entry (at next_off): NextEntryOffset should be 0
        let second_off = next_off as usize;
        let second_next = u32::from_le_bytes(buf[second_off..second_off + 4].try_into().unwrap());
        assert_eq!(second_next, 0);
    }

    #[test]
    fn test_map_event_create() {
        let event = notify::Event::new(EventKind::Create(CreateKind::File));
        let result = map_event(&event);
        assert!(result.is_some());
        let (action, _) = result.unwrap();
        assert_eq!(action, FILE_ACTION_ADDED);
    }

    #[test]
    fn test_map_event_remove() {
        let event = notify::Event::new(EventKind::Remove(RemoveKind::File));
        let result = map_event(&event);
        assert!(result.is_some());
        let (action, _) = result.unwrap();
        assert_eq!(action, FILE_ACTION_REMOVED);
    }

    #[test]
    fn test_map_event_access_returns_none() {
        let event = notify::Event::new(EventKind::Access(AccessKind::Read));
        let result = map_event(&event);
        assert!(result.is_none());
    }

    #[test]
    fn test_completion_filter_change_mask() {
        let filter = CompletionFilter {
            file_name: true,
            size: true,
            ..Default::default()
        };
        let mask = filter.change_mask();
        assert!(mask & FILE_NOTIFY_CHANGE_FILE_NAME != 0);
        assert!(mask & FILE_NOTIFY_CHANGE_SIZE != 0);
        assert!(mask & FILE_NOTIFY_CHANGE_DIR_NAME == 0);
    }
}
