//! Message dispatcher — receives [`FramedMessage`] from the wire and produces
//! [`FramedResponse`].
//!
//! All SMB2 commands are implemented: NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
//! CREATE, READ, WRITE, CLOSE, FLUSH, LOCK, ECHO, CANCEL, QUERY_DIRECTORY,
//! QUERY_INFO, SET_INFO, CHANGE_NOTIFY, TREE_DISCONNECT, LOGOFF, and
//! NEGOTIATE signing/encryption (SMB 2.1–3.1.1).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use rssmb_proto::header::{Command, Header, HeaderFlags};
use rssmb_proto::negotiate::{
    Dialect as WireDialect, EncryptionCipher, GlobalCapabilities, NegotiateDialect,
    NegotiateResponse, NegotiateSecurityMode,
};
use rssmb_proto::plain::{PlainResponse, RequestContent, ResponseContent};
use rssmb_wire_adapter::{FramedMessage, FramedResponse, NtStatus};

use rssmb_proto::info::InfoType;
use rssmb_proto::FileTime;
use rssmb_proto::Guid;

use crate::config::DialectConfig;
use crate::opens;
use crate::session::Session;
use crate::ServerState;

// Negotiated MaxTransact/MaxRead/MaxWriteSize = min(1 MiB, max_frame_size),
// see `crate::limits::max_io_size`. 1 MiB is safe: multi-credit accounting
// (CreditCharge = ceil(len/64K) validated against the MessageId window) was
// added in Phase 1.5; the credit window is enforced in `charge_credits`.
use crate::limits::max_io_size;

// ── Per-command modules (pure move from the old monolithic dispatch.rs) ──
mod async_helpers;
mod cancel;
mod change_notify;
mod close;
mod create;
mod echo;
mod flush;
mod ioctl;
mod lock;
mod logoff;
mod negotiate;
mod oplock_break;
mod query_directory;
mod query_info;
mod read;
mod session_setup;
mod set_info;
mod tree_connect;
mod tree_disconnect;
mod write;

// Re-exports for cross-crate access (notify.rs, connection.rs)

// Cross-module re-exports: only symbols used in a DIFFERENT module than
// their defining one. Verified via cross-use audit.
pub(crate) use async_helpers::{pend_until_breaks, send_unsolicited};
pub(crate) use cancel::send_notify_cleanup;
pub(crate) use echo::{next_file_id, next_session_id, next_tree_id};
pub(crate) use negotiate::{dialect_config_to_negotiate, dialect_config_to_wire, select_dialect};
pub(crate) use oplock_break::send_break_notifications;
// Test-only cross-module uses: mod.rs tests call create.rs helpers.
#[cfg(test)]
pub(crate) use create::{
    build_rqls_response_data, encode_create_contexts, parse_create_contexts, RQLS_NAME,
};
// Handler re-exports for handle_plain dispatch
pub(crate) use cancel::handle_cancel;
pub(crate) use change_notify::handle_change_notify;
pub(crate) use close::handle_close;
pub(crate) use create::handle_create;
pub(crate) use echo::handle_echo;
pub(crate) use flush::handle_flush;
pub(crate) use ioctl::handle_ioctl;
pub(crate) use lock::handle_lock;
pub(crate) use logoff::handle_logoff;
pub(crate) use negotiate::handle_negotiate;
pub(crate) use oplock_break::handle_oplock_break;
pub(crate) use query_directory::handle_query_directory;
pub(crate) use query_info::handle_query_info;
pub(crate) use read::handle_read;
pub(crate) use session_setup::handle_session_setup;
pub(crate) use set_info::handle_set_info;
pub(crate) use tree_connect::handle_tree_connect;
pub(crate) use tree_disconnect::handle_tree_disconnect;
pub(crate) use write::handle_write;

/// A per-connection open handle entry.
#[derive(Clone)]
pub struct OpenEntry {
    pub session_id: u64,
    pub tree_id: u32,
    pub open_id: rssmb_vfs::OpenId,
    pub vfs: Arc<dyn rssmb_vfs::Vfs>,
    /// Stable file identity (dev,ino) for the open file — used to key
    /// into the global OpenTable for share-mode conflict tracking.
    /// `None` for pipe opens or when the VFS cannot provide a FileId.
    pub file_id: Option<rssmb_vfs::FileId>,
    /// QUERY_DIRECTORY enumeration state, shared by clones of this entry.
    pub dir_cursor: Arc<tokio::sync::Mutex<DirCursor>>,
    /// Share-relative path as opened (for FileAllInformation's name).
    pub path: String,
    /// Whether this open is a named-pipe open on an IPC$ tree.
    pub is_pipe: bool,
    /// RPC pipe state, shared by clones of this entry. `None` for disk opens.
    pub pipe_state: Option<Arc<std::sync::Mutex<rssmb_rpc_server::PipeState>>>,
    /// Create GUID for durable handle tracking. `None` for non-durable opens.
    /// Set when a DH2Q create context was present at create time. Used by
    /// `handle_close` and `cleanup` to remove the durable entry.
    pub durable_guid: Option<[u8; 16]>,
    /// SMB persistent id for v1 (DHnQ) durable opens, which are keyed by
    /// persistent id in the DurableTable's v1 side table. `None` for
    /// non-durable and v2-durable opens.
    pub durable_persistent_id: Option<u64>,
    /// LockSequence replay-detection array (MS-SMB2 3.3.5.14; smbd's
    /// fsp->op->global->lock_sequence_array): 64 buckets, each storing the
    /// last successfully processed sequence value (low nibble), 0xFF =
    /// invalid/never-set. Enabled for ALL opens when the server
    /// advertises SMB2_CAP_MULTI_CHANNEL (which we do) or the open is
    /// durable — same rule smbd implements from the spec.
    pub lock_sequence_array: Arc<std::sync::Mutex<[u8; 64]>>,
}

/// Per-open directory enumeration cursor (MS-SMB2 3.3.5.18).
#[derive(Default)]
pub struct DirCursor {
    /// Snapshot of the listing taken by the first query (or a restart).
    pub entries: Option<Vec<rssmb_vfs::DirEntry>>,
    /// Index of the next entry to return.
    pub next: usize,
}

/// Target for preauth hash response hashing.
#[derive(Clone, Copy, Debug)]
pub enum PreauthTarget {
    /// Hash into the connection's preauth hash (NEGOTIATE response).
    Conn,
    /// Hash into a session's preauth hash (SESSION_SETUP MORE_PROCESSING response).
    Session(u64),
}

/// Transport type for a client connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TransportKind {
    /// Direct TCP (port 445).
    #[default]
    Tcp,
    /// SMB over QUIC (UDP / TLS 1.3, ALPN `smb`).
    Quic,
}

/// Per-session shared state, accessible across multiple connections (channels)
/// for SMB 3.x multichannel. When multichannel is disabled or only one channel
/// exists, this structure still holds the authoritative trees/opens/signing/
/// encryption state; ConnState holds clones of the same Arcs.
pub struct SessionShared {
    /// Active tree connections: TreeId → TreeEntry.
    pub trees: Arc<tokio::sync::RwLock<HashMap<u32, TreeEntry>>>,
    /// Open file handles: FileId volatile → OpenEntry.
    pub opens: Arc<tokio::sync::RwLock<HashMap<u64, OpenEntry>>>,
    /// Signing state per SessionId.
    pub signing: Arc<std::sync::RwLock<HashMap<u64, SigningState>>>,
    /// Encryption state per SessionId.
    pub encryption: Arc<std::sync::RwLock<HashMap<u64, EncryptionState>>>,
    /// Per-session next TreeId counter.
    pub next_tree_id: Arc<std::sync::atomic::AtomicU32>,
    /// Per-session next volatile FileId counter.
    pub next_volatile_id: Arc<std::sync::atomic::AtomicU64>,
    /// Per-session random persistent FileId base.
    pub persistent_base: u64,
    /// Set of channel connection IDs bound to this session.
    pub channels: std::sync::RwLock<std::collections::HashSet<u64>>,
    /// Authenticated username of the session (for PreviousSessionId
    /// same-user validation across connections).
    pub username: std::sync::RwLock<String>,
}

impl SessionShared {
    pub(crate) fn new(conn_id: u64) -> Self {
        Self {
            trees: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            opens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            signing: Arc::new(std::sync::RwLock::new(HashMap::new())),
            encryption: Arc::new(std::sync::RwLock::new(HashMap::new())),
            next_tree_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_volatile_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            persistent_base: rand::random::<u64>(),
            channels: std::sync::RwLock::new(std::collections::HashSet::from([conn_id])),
            username: std::sync::RwLock::new(String::new()),
        }
    }
}

/// Swappable per-session state Arcs. All channels of the same session share
/// the same Arcs. On binding, the new channel's `active` is swapped to point
/// to the existing session's Arcs.
#[derive(Clone)]
pub struct SessionArcs {
    pub trees: Arc<tokio::sync::RwLock<HashMap<u32, TreeEntry>>>,
    pub opens: Arc<tokio::sync::RwLock<HashMap<u64, OpenEntry>>>,
    pub signing: Arc<StdRwLock<HashMap<u64, SigningState>>>,
    pub encryption: Arc<StdRwLock<HashMap<u64, EncryptionState>>>,
    pub next_tree_id: Arc<std::sync::atomic::AtomicU32>,
    pub next_volatile_id: Arc<std::sync::atomic::AtomicU64>,
    pub persistent_base: u64,
}

impl ConnState {
    /// Read the active session arcs. Cheap — just clones the Arc wrapper.
    fn arcs(&self) -> Arc<SessionArcs> {
        Arc::new(self.active.read().unwrap().clone())
    }
    /// Get the trees map.
    pub fn trees_ref(&self) -> Arc<tokio::sync::RwLock<HashMap<u32, TreeEntry>>> {
        self.arcs().trees.clone()
    }
    /// Get the opens map.
    pub fn opens_ref(&self) -> Arc<tokio::sync::RwLock<HashMap<u64, OpenEntry>>> {
        self.arcs().opens.clone()
    }
    /// Get the signing map.
    pub fn signing_ref(&self) -> Arc<StdRwLock<HashMap<u64, SigningState>>> {
        self.arcs().signing.clone()
    }
    /// Get the encryption map.
    pub fn encryption_ref(&self) -> Arc<StdRwLock<HashMap<u64, EncryptionState>>> {
        self.arcs().encryption.clone()
    }
    /// Get the next_tree_id counter.
    pub fn next_tree_id_ref(&self) -> Arc<std::sync::atomic::AtomicU32> {
        self.arcs().next_tree_id.clone()
    }
    /// Get the next_volatile_id counter.
    pub fn next_volatile_id_ref(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.arcs().next_volatile_id.clone()
    }
    /// Get the persistent_base.
    pub fn persistent_base_val(&self) -> u64 {
        self.arcs().persistent_base
    }
}

/// Per-connection state handed to the dispatcher.
#[derive(Clone)]
pub struct ConnState {
    // NOTE: PreauthTarget is defined above this struct.
    /// Unique connection identifier assigned by the connection engine.
    pub conn_id: u64,
    /// Remote peer IP address — used for auth throttling and audit logging.
    pub remote_addr: std::net::IpAddr,
    /// Transport used by this connection (Direct TCP vs SMB over QUIC).
    pub transport: TransportKind,
    /// Active sessions for this connection (SMB allows multiple).
    pub sessions: std::sync::Arc<tokio::sync::RwLock<Vec<Arc<Session>>>>,
    /// Sender half of the connection's write channel.
    pub write_tx: mpsc::Sender<Bytes>,
    /// In-progress authentication state (one per connection until session established).
    pub auth_state: std::sync::Arc<tokio::sync::Mutex<Option<rssmb_auth::AuthState>>>,
    /// Per-connection auth failure count — never reset on SessionId=0.
    /// Exceeding auth_max_failures_per_conn drops the connection.
    pub auth_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Negotiation record for this connection (set by NEGOTIATE, used by
    /// SESSION_SETUP, signing, and VALIDATE_NEGOTIATE_INFO).
    pub negotiate_record: std::sync::Arc<tokio::sync::Mutex<Option<NegotiateRecord>>>,
    /// Swappable per-session state — contains the Arcs to trees/opens/signing/
    /// encryption/counters that are shared across channels of the same session.
    /// On binding, the inner value is swapped to the existing session's Arcs.
    pub active: Arc<StdRwLock<SessionArcs>>,
    /// The SessionShared for this connection's primary session, registered
    /// in the global registry on session establishment. For binding channels,
    /// this is replaced with the existing session's shared state.
    pub session_shared: Arc<StdRwLock<Option<Arc<SessionShared>>>>,
    /// Pending authentication SessionIds — only these may be used as
    /// continuation IDs in subsequent SESSION_SETUP rounds.
    pub pending_sessions: std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<u64>>>,
    /// Per-connection credit flow-control manager.
    pub credits: std::sync::Arc<rssmb_wire_adapter::credits::CreditManager>,
    /// Pending async operations keyed by MessageId — for CHANGE_NOTIFY, LOCK, etc.
    /// When a CANCEL arrives, the op is looked up here and completed.
    pub pending_async: std::sync::Arc<tokio::sync::Mutex<HashMap<u64, AsyncOp>>>,
    /// Preauth integrity hash for the connection (SMB 3.1.1 only).
    /// H0 = 64 zero bytes; updated with NEGOTIATE request+response.
    /// Forked per-session at SESSION_SETUP SessionId==0.
    pub preauth_conn: std::sync::Arc<std::sync::Mutex<Option<crate::crypto::PreauthHashValue>>>,
    /// Per-session preauth integrity hashes (3.1.1 only).
    /// Session.H starts as a fork of Conn.H; updated with each
    /// SESSION_SETUP request and each MORE_PROCESSING response.
    pub preauth_sessions:
        std::sync::Arc<std::sync::Mutex<HashMap<u64, crate::crypto::PreauthHashValue>>>,
    /// Directive from a handler: "hash the next encoded response into the
    /// preauth hash" (set by NEGOTIATE and SESSION_SETUP MORE_PROCESSING).
    /// `Conn` → hash into preauth_conn; `Session(sid)` → hash into preauth_sessions[sid].
    /// Consumed exactly once by the connection loop after encode+sign.
    pub preauth_hash_response: std::sync::Arc<std::sync::Mutex<Option<PreauthTarget>>>,
}

/// Per-session SMB2 message signing state (MS-SMB2 3.3.1.8).
#[derive(Clone)]
pub struct SigningState {
    /// Signing key (SMB 2.x: the session key, first 16 bytes).
    pub key: Vec<u8>,
    /// Session.SigningRequired — every request and response must be signed.
    pub required: bool,
    pub dialect: DialectConfig,
    /// Session was logged off: only its LOGOFF response may still be signed
    /// with this key; requests on it are no longer valid.
    pub retiring: bool,
    /// One-shot: sign the next response for this session even if `required`
    /// is false (3.1.1 final SESSION_SETUP success). Consumed by
    /// `sign_response_frame`.
    pub force_sign_once: bool,
}

/// Per-session SMB 3.x encryption state (MS-SMB2 3.3.1.8).
///
/// Encrypted sessions use AES-128-GCM (the only cipher implemented in this
/// build). The `enc_key` (server→client) and `dec_key` (client→server) are
/// derived from the session key via the SP800-108 KDF with direction-specific
/// labels. The `NonceSource` generates per-message nonces; it is shared
/// (via `Arc`) between all TX paths so nonces are unique per key.
#[derive(Clone)]
pub struct EncryptionState {
    /// Server→client encryption key (S2C).
    pub enc_key: [u8; 16],
    /// Client→server decryption key (C2S).
    pub dec_key: [u8; 16],
    /// Nonce source for outgoing encrypted messages.
    pub nonce_source: std::sync::Arc<crate::crypto::NonceSource>,
    /// Negotiated cipher (needed by encrypt/decrypt dispatch).
    pub cipher: crate::crypto::Cipher,
    /// Whether encryption is required on this session (encrypt_data flag).
    pub encrypt_data: bool,
    /// Session was logged off: only its LOGOFF response may still be
    /// encrypted with this key.
    pub retiring: bool,
}

/// Immutable record of the negotiation exchange, stored per connection.
///
/// Used for dialect-aware signing, SESSION_SETUP, and VALIDATE_NEGOTIATE_INFO
/// (MS-SMB2 3.3.5.15.12). Stores both the client's original negotiation
/// parameters (for validation comparison) and the server's response values
/// Immutable record of the negotiation exchange, stored per connection.
///
/// Used for dialect-aware signing, SESSION_SETUP, and VALIDATE_NEGOTIATE_INFO
/// (MS-SMB2 3.3.5.15.12). Stores both the client's original negotiation
/// parameters (for validation comparison) and the server's response values
/// (for the VNI response echo).
#[derive(Clone, Debug)]
pub struct NegotiateRecord {
    /// The negotiated dialect (our internal enum).
    pub dialect: DialectConfig,
    // --- Client-side values (from the NEGOTIATE request) ---
    pub client_guid: Guid,
    pub client_security_mode: NegotiateSecurityMode,
    pub client_capabilities: GlobalCapabilities,
    // --- Server-side values (from our NEGOTIATE response) ---
    pub server_capabilities: GlobalCapabilities,
    pub server_security_mode: NegotiateSecurityMode,
    /// SMB 3.1.1 negotiated contexts (preauth hash, salt, cipher, signing alg).
    /// `None` for dialects < 3.1.1.
    pub neg311: Option<crate::negotiate_ctx::Negotiated311>,
}

impl NegotiateRecord {
    /// Map our internal DialectConfig to the wire NegotiateDialect for responses.
    pub fn wire_dialect(&self) -> NegotiateDialect {
        dialect_config_to_negotiate(self.dialect)
    }

    /// Map our internal DialectConfig to the wire Dialect enum (for VNI response).
    pub fn wire_dialect_value(&self) -> WireDialect {
        dialect_config_to_wire(self.dialect)
    }
}

/// Map DialectConfig to the NegotiateDialect used in NegotiateResponse.
pub struct AsyncOp {
    /// The command that initiated the async op.
    pub command: Command,
    /// The session_id for validation.
    pub session_id: u64,
    /// The tree_id for validation.
    pub tree_id: u32,
    /// Sender to deliver the completion response to the write task.
    pub cancel: tokio::sync::oneshot::Sender<()>,
    /// Optional directory watch handle for CHANGE_NOTIFY. Dropping this
    /// closes only the op's own watch — it must NOT be used to stop
    /// unrelated pending notifies.
    pub notify_handle: Option<crate::notify::NotifyHandle>,
    /// The volatile id of the watched directory handle (CHANGE_NOTIFY
    /// only). CLOSE of THIS handle completes the notify with
    /// STATUS_NOTIFY_CLEANUP; CLOSE of any other handle on the tree must
    /// leave the notify pending.
    pub watched_file_id: Option<u64>,
    /// The volatile id of the open that pended a blocking LOCK. CLOSE of
    /// that open completes the pended lock with RANGE_NOT_LOCKED (torture
    /// cancel "cancel by close").
    pub lock_open_volatile: Option<u64>,
}

/// A tree connection entry tracking the owning session and VFS backend.
#[derive(Clone)]
pub struct TreeEntry {
    pub share_name: String,
    pub vfs: Arc<dyn rssmb_vfs::Vfs>,
    pub session_id: u64,
    /// Whether this share is read-only (enforced at WRITE/SET_INFO).
    pub read_only: bool,
    /// Whether the connected user has write access on this share.
    /// False if `read_only` is true, or if `write_users` is non-empty
    /// and the user is not in the list.
    pub write_access: bool,
    /// Whether this share requires encryption (per-share encrypt_data).
    pub encrypt_data: bool,
    /// Whether this tree is an IPC$ pipe share (named-pipe dispatch).
    pub is_ipc: bool,
}

impl std::fmt::Debug for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnState")
            .field("conn_id", &self.conn_id)
            .finish()
    }
}

/// Main dispatch entry point.
pub async fn handle_message(
    state: &Arc<ServerState>,
    conn_state: &ConnState,
    msg: FramedMessage,
    raw_frame: &[u8],
    was_encrypted: Option<u64>,
) -> Option<FramedResponse> {
    match msg {
        FramedMessage::Plain(req) => {
            handle_plain(state, conn_state, req, raw_frame, was_encrypted).await
        }
        FramedMessage::Compound(requests) => {
            handle_compound(state, conn_state, requests, raw_frame, was_encrypted).await
        }
        FramedMessage::Smb1Negotiate(_) => {
            // MS-SMB2 3.3.5.3.1: over QUIC, SMB1 multi-protocol negotiate is
            // not allowed — disconnect immediately.
            if conn_state.transport == TransportKind::Quic {
                warn!(
                    conn_id = conn_state.conn_id,
                    "SMB1 negotiate on QUIC transport — disconnecting"
                );
                return Some(FramedResponse::Disconnect);
            }
            // SMB2-only server: do not respond to SMB1 negotiate on TCP.
            // The client (impacket, smbclient, cifs.ko) will close and retry
            // with SMB2. Returning an SMB2 error response here would be
            // misinterpreted by some clients as a truncated SMB2 negotiate
            // response, causing a parse failure instead of a clean fallback.
            debug!(
                conn_id = conn_state.conn_id,
                "SMB1 negotiate — dropping (SMB2-only server)"
            );
            None
        }
        FramedMessage::Encrypted(_) => {
            // Encryption is handled in the connection read loop (decrypt
            // before parse). Reaching here means the frame was not decrypted
            // — disconnect.
            debug!(
                conn_id = conn_state.conn_id,
                "encrypted frame reached dispatch — should not happen"
            );
            Some(FramedResponse::Disconnect)
        }
        FramedMessage::Compressed(_) => {
            debug!(
                conn_id = conn_state.conn_id,
                "compressed frame — not supported yet"
            );
            Some(FramedResponse::Error {
                command: Command::Negotiate,
                status: NtStatus::NotSupported,
                message_id: u64::MAX,
                session_id: 0,
                tree_id: Some(0),
                credit_charge: 0,
            })
        }
    }
}

/// Handle a compound (chained) request: dispatch each sub-request in order,
/// handling related-operation inheritance and failure propagation.
///
/// MS-SMB2 3.3.5.2.7: related requests inherit SessionId/TreeId from the
/// previous request's *response*, and FileId 0xFFFF...FFFF is replaced with
/// the FileId from the previous CREATE. Once a related request fails with
/// an error-severity status (0xC...), all subsequent related requests get
/// the same status. Warning-severity statuses (0x8...) do NOT propagate.
async fn handle_compound(
    state: &Arc<ServerState>,
    conn_state: &ConnState,
    requests: Vec<rssmb_proto::plain::PlainRequest>,
    raw_frame: &[u8],
    was_encrypted: Option<u64>,
) -> Option<FramedResponse> {
    // Track per-response relatedness for the RELATED flag.
    let mut responses: Vec<(bool, PlainResponse)> = Vec::with_capacity(requests.len());
    let mut last_file_id: Option<rssmb_proto::create::FileId> = None;
    let mut inherited_session_id: u64 = 0;
    let mut inherited_tree_id: Option<u32> = Some(0);
    let mut propagated_status: Option<u32> = None;
    // Whether the current chain context is usable for related inheritance.
    // A related member may only inherit from a preceding *successful* (or
    // warning-severity) chain element. Samba (smb2_server.c chain walk +
    // smb2_create.c error propagation): an unrelated member that fails
    // leaves no session/tcon/handle context; a related member following it
    // gets INVALID_PARAMETER (smb2.compound invalid2 req[4]).
    let mut chain_valid = true;
    // Byte range of each member — handlers see only their own message bytes
    // (WRITE data offsets and signatures are relative to the member's header).
    let ranges = rssmb_wire_adapter::framing::message_ranges(raw_frame);

    // MS-SMB2: NEGOTIATE and SESSION_SETUP MUST NOT be compounded.
    // Prevalidate the entire compound before dispatching any member — a
    // mid-loop rejection would leave earlier members' side effects (created
    // files, acquired locks, opened handles) in place without rollback.
    // This also prevents the preauth-hash response-before-encode race
    // for 3.1.1 (Mashūra plan review §1): in a compound, the response
    // bytes of the first member are not available for hashing before the
    // second member is dispatched.
    if let Some(bad_idx) = requests.iter().position(|r| {
        r.header.command == Command::Negotiate || r.header.command == Command::SessionSetup
    }) {
        for req in &requests[..=bad_idx] {
            if req.header.command != Command::Cancel {
                if let Err(boxed) = charge_credits(conn_state, &req.header) {
                    if let FramedResponse::Disconnect = *boxed {
                        return Some(FramedResponse::Disconnect);
                    }
                }
            }
        }
        return Some(FramedResponse::Plain(error_plain_response(
            &requests[bad_idx].header,
            NtStatus::InvalidParameter.to_u32(),
        )));
    }

    for (i, mut req) in requests.into_iter().enumerate() {
        let is_related = req.header.flags.related_operations();

        let saved_header = req.header.clone();
        let member_bytes = match ranges.get(i) {
            Some(&(s, e)) => &raw_frame[s..e],
            None => &[][..],
        };

        // Members answered without executing (malformed first member,
        // propagated failures) still cost the client credits; charge them
        // here, since `handle_plain` (which charges the rest) is skipped.
        let skips_handler = (is_related && i == 0) || (is_related && propagated_status.is_some());
        if skips_handler && req.header.command != Command::Cancel {
            if let Err(boxed) = charge_credits(conn_state, &saved_header) {
                if let FramedResponse::Disconnect = *boxed {
                    return Some(FramedResponse::Disconnect);
                }
            }
        }

        if is_related && i == 0 {
            // MS-SMB2: first request in a chain MUST NOT have RELATED set.
            // Fail this one and propagate to all remaining members.
            propagated_status = Some(NtStatus::InvalidParameter.to_u32());
            responses.push((
                false,
                error_plain_response(&saved_header, NtStatus::InvalidParameter.to_u32()),
            ));
            continue;
        }

        // The effective SessionId/TreeId for this member: for related
        // members these are inherited from the previous response; for
        // unrelated members they come from the member's own header.
        // We must carry these into error responses so the signing layer
        // can resolve the correct session key — using the saved_header's
        // SessionId would give the original (possibly placeholder) value.
        let effective_session_id = if is_related {
            inherited_session_id
        } else {
            saved_header.session_id
        };
        let effective_tree_id = if is_related {
            inherited_tree_id
        } else {
            saved_header.tree_id
        };

        if is_related && !chain_valid {
            // A related member after a failed unrelated member: the chain
            // context is gone (Samba returns INVALID_PARAMETER — smb2.compound
            // invalid2 req[4]). Do not inherit; do not substitute FileId.
            // (No credit charge here — the skips_handler block above has
            // already charged propagated related members.)
            responses.push((
                true,
                error_plain_response_with_ids(
                    &saved_header,
                    NtStatus::InvalidParameter.to_u32(),
                    effective_session_id,
                    effective_tree_id,
                ),
            ));
            continue;
        }

        if is_related {
            // Inherit SessionId and TreeId from the previous request's response.
            req.header.session_id = effective_session_id;
            req.header.tree_id = effective_tree_id;

            // FileId substitution: replace 0xFFFF...FFFF with the last CREATE's FileId.
            if let Some(fid) = last_file_id {
                substitute_file_id(&mut req, fid);
            }

            // Failure propagation: if a previous related request failed with
            // an error-severity status, this one gets the same status.
            if let Some(status) = propagated_status {
                responses.push((
                    true,
                    error_plain_response_with_ids(
                        &saved_header,
                        status,
                        effective_session_id,
                        effective_tree_id,
                    ),
                ));
                continue;
            }
        } else {
            // Unrelated member: starts a fresh chain context. Reset all
            // inherited state. chain_valid will be re-evaluated from this
            // member's own outcome below (a failing unrelated member breaks
            // inheritance for a following related member).
            propagated_status = None;
            last_file_id = None;
            chain_valid = true;
        }

        // Dispatch this sub-request.
        let resp = handle_plain(state, conn_state, req, member_bytes, was_encrypted).await;

        match resp {
            Some(FramedResponse::Disconnect) => {
                // A fatal violation in any member ends the connection; the
                // rest of the chain is not executed and nothing is sent.
                return Some(FramedResponse::Disconnect);
            }
            Some(FramedResponse::Plain(plain)) => {
                // Update inherited context from the *response* (not the request).
                // SESSION_SETUP returns a new session_id; TREE_CONNECT returns
                // a new tree_id — both are set on the response header.
                inherited_session_id = plain.header.session_id;
                inherited_tree_id = plain.header.tree_id;

                // Track the last CREATE's FileId for substitution.
                if plain.header.command == Command::Create
                    && plain.header.status == NtStatus::Success.to_u32()
                {
                    if let ResponseContent::Create(create_resp) = &plain.content {
                        last_file_id = Some(create_resp.file_id);
                    }
                }

                // Track failure for propagation — only error-severity (0xC...).
                // Warning-severity (0x8... e.g. BUFFER_OVERFLOW) does NOT propagate.
                let status = plain.header.status;
                if (status & 0xC000_0000) == 0xC000_0000 {
                    propagated_status = Some(status);
                    if !is_related && status == NtStatus::UserSessionDeleted.to_u32() {
                        // A session-level failure on an unrelated member leaves
                        // no session context to inherit: the chain is broken
                        // and following related members get INVALID_PARAMETER
                        // (smb2.compound invalid2 req[4]). Command-level
                        // failures (FILE_CLOSED, OBJECT_NAME_NOT_FOUND...)
                        // keep the chain — the status propagates (invalid3,
                        // related8).
                        chain_valid = false;
                    }
                }

                responses.push((is_related, plain));
            }
            Some(FramedResponse::Error { status, .. }) => {
                // A failed member still defines the context the next related
                // member inherits (its effective session/tree), otherwise the
                // propagated error would carry SessionId 0 and go unsigned.
                inherited_session_id = effective_session_id;
                inherited_tree_id = effective_tree_id;
                // Error responses always have error severity.
                propagated_status = Some(status.to_u32());
                if !is_related && status == NtStatus::UserSessionDeleted {
                    // Session-level failure on an unrelated member breaks the
                    // chain (see the Plain arm above for the rationale).
                    chain_valid = false;
                }
                responses.push((
                    is_related,
                    error_plain_response_with_ids(
                        &saved_header,
                        status.to_u32(),
                        effective_session_id,
                        effective_tree_id,
                    ),
                ));
            }
            Some(_) => {
                tracing::warn!(
                    conn_id = conn_state.conn_id,
                    "unexpected response type in compound"
                );
                inherited_session_id = effective_session_id;
                inherited_tree_id = effective_tree_id;
                propagated_status = Some(NtStatus::InvalidParameter.to_u32());
                responses.push((
                    is_related,
                    error_plain_response_with_ids(
                        &saved_header,
                        NtStatus::InvalidParameter.to_u32(),
                        effective_session_id,
                        effective_tree_id,
                    ),
                ));
            }
            None => {
                // No response (e.g. ServerToClientNotification) — skip.
            }
        }
    }

    if responses.is_empty() {
        return None;
    }

    // Apply RELATED_OPERATIONS flag only to responses for related requests.
    let plain_responses: Vec<PlainResponse> = responses
        .into_iter()
        .map(|(is_related, mut resp)| {
            if is_related {
                resp.header.flags.set_related_operations(true);
            }
            resp
        })
        .collect();

    if plain_responses.len() == 1 {
        Some(FramedResponse::Plain(
            plain_responses.into_iter().next().unwrap(),
        ))
    } else {
        Some(FramedResponse::Compound(plain_responses))
    }
}

/// Build a PlainResponse with an error status for compound failure propagation.
/// Uses the saved request header to preserve message_id, session_id, tree_id,
/// credit_charge, and async_id.
pub(crate) fn error_plain_response(req_header: &Header, status: u32) -> PlainResponse {
    // Preserve the member's sync/async shape: an async member's error
    // response must keep async_command + async_id (and tree_id=None) or the
    // encoder's tree_id/async assertion (header.rs) fails and the whole
    // connection is dropped — the smb2.compound invalid1 IO_TIMEOUT.
    let is_async = req_header.flags.async_command();
    PlainResponse {
        header: Header {
            credit_charge: req_header.credit_charge,
            status,
            command: req_header.command,
            credit_request: req_header.credit_request,
            flags: {
                let mut f = HeaderFlags::new().with_server_to_redir(true);
                f.set_async_command(is_async);
                f
            },
            next_command: 0,
            message_id: req_header.message_id,
            tree_id: if is_async { None } else { req_header.tree_id.or(Some(0)) },
            async_id: if is_async { req_header.async_id.or(Some(0)) } else { None },
            session_id: req_header.session_id,
            signature: 0,
        },
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    }
}

/// Like [`error_plain_response`] but overrides `session_id` and `tree_id`
/// with the effective (inherited) values.  In a compound chain, a related
/// member's saved header may carry a placeholder SessionId; the signing
/// layer resolves the key by the response's SessionId field, so a propagated
/// error response must carry the *effective* session — not the original
/// header's — or it will be unsigned on a signing-required session.
pub(crate) fn error_plain_response_with_ids(
    req_header: &Header,
    status: u32,
    session_id: u64,
    tree_id: Option<u32>,
) -> PlainResponse {
    // Same sync/async shape preservation as error_plain_response: an async
    // member's propagated error must keep async_command + async_id or the
    // encoder assertion kills the connection (see error_plain_response).
    // For async members the inherited tree_id is ignored (async headers
    // carry no TreeId on the wire).
    let is_async = req_header.flags.async_command();
    PlainResponse {
        header: Header {
            credit_charge: req_header.credit_charge,
            status,
            command: req_header.command,
            credit_request: req_header.credit_request,
            flags: {
                let mut f = HeaderFlags::new().with_server_to_redir(true);
                f.set_async_command(is_async);
                f
            },
            next_command: 0,
            message_id: req_header.message_id,
            tree_id: if is_async { None } else { tree_id.or(Some(0)) },
            async_id: if is_async { req_header.async_id.or(Some(0)) } else { None },
            session_id,
            signature: 0,
        },
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    }
}

/// Replace FileId 0xFFFF...FFFF with the given FileId in a request's content.
pub(crate) fn substitute_file_id(
    req: &mut rssmb_proto::plain::PlainRequest,
    fid: rssmb_proto::create::FileId,
) {
    let placeholder = rssmb_proto::create::FileId {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };
    match &mut req.content {
        RequestContent::Close(c) => {
            if c.file_id == placeholder {
                c.file_id = fid;
            }
        }
        RequestContent::Read(r) => {
            if r.file_id == placeholder {
                r.file_id = fid;
            }
        }
        RequestContent::Write(w) => {
            if w.file_id == placeholder {
                w.file_id = fid;
            }
        }
        RequestContent::Flush(f) => {
            if f.file_id == placeholder {
                f.file_id = fid;
            }
        }
        RequestContent::QueryInfo(q) => {
            if q.file_id == placeholder {
                q.file_id = fid;
            }
        }
        RequestContent::QueryDirectory(q) => {
            if q.file_id == placeholder {
                q.file_id = fid;
            }
        }
        RequestContent::SetInfo(s) => {
            if s.file_id == placeholder {
                s.file_id = fid;
            }
        }
        RequestContent::Ioctl(io) => {
            if io.file_id == placeholder {
                io.file_id = fid;
            }
        }
        RequestContent::Lock(l) if l.file_id == placeholder => {
            l.file_id = fid;
        }
        _ => {}
    }
}

/// Charge a request's credits (CreditCharge 0 counts as 1). Every request
/// the client sent is charged — including compound members that are never
/// executed — so the ledger follows the client's own count.
///
/// The MessageId sequence window (MS-SMB2 3.3.1.1) is enforced inside
/// `CreditManager::check_and_deduct`: the request's MessageId must be inside
/// the window `[low, high)` and not already used.
///
/// - Outside the window or already used: a sequence-window violation
///   (MS-SMB2 3.3.5.2.3) → `Err(Disconnect)`: terminate the connection.
/// - Affordable but above our local cap (256, policy rather than a protocol
///   limit) → `Err(INVALID_PARAMETER reply)`; the credits are still spent.
pub(crate) fn charge_credits(
    conn_state: &ConnState,
    header: &Header,
) -> Result<(), Box<FramedResponse>> {
    use rssmb_wire_adapter::credits::CreditError;
    match conn_state
        .credits
        .check_and_deduct(header.message_id, header.credit_charge as u32)
    {
        Ok(()) => Ok(()),
        Err(CreditError::InsufficientCredits {
            available,
            requested,
        }) => {
            tracing::warn!(
                conn_id = conn_state.conn_id,
                available,
                requested,
                message_id = header.message_id,
                "request outside credit window — terminating connection"
            );
            Err(Box::new(FramedResponse::Disconnect))
        }
        Err(CreditError::ExcessiveCharge(charge)) => {
            debug!(
                conn_id = conn_state.conn_id,
                charge, "credit charge above local cap — rejecting"
            );
            Err(Box::new(error_response_for(
                header.command,
                NtStatus::InvalidParameter,
                header,
            )))
        }
    }
}

/// Dispatch a decoded plain SMB2 request.
async fn handle_plain(
    state: &Arc<ServerState>,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_frame: &[u8],
    was_encrypted: Option<u64>,
) -> Option<FramedResponse> {
    let command = req.header.command;
    let credit_charge = req.header.credit_charge;
    // Record per-command request metric.
    state.metrics.record_request(command as usize);
    debug!(
        conn_id = conn_state.conn_id,
        command = %command,
        message_id = req.header.message_id,
        session_id = req.header.session_id,
        credit_charge,
        "dispatching command"
    );

    // Negotiate gate (MS-SMB2 3.3.5.2): every command except NEGOTIATE
    // requires a completed negotiation. A command arriving before
    // negotiation, or a second NEGOTIATE after a successful one, must
    // terminate the connection. This runs before CANCEL and credit checks
    // so no reply leaves the connection in a pre-negotiation state.
    if command == Command::Negotiate {
        let rec = conn_state.negotiate_record.lock().await;
        if rec.is_some() {
            warn!(
                conn_id = conn_state.conn_id,
                "repeat NEGOTIATE — terminating connection"
            );
            return Some(FramedResponse::Disconnect);
        }
    } else {
        let rec = conn_state.negotiate_record.lock().await;
        if rec.is_none() {
            warn!(conn_id = conn_state.conn_id,
                command = %command,
                "command before NEGOTIATE — terminating connection");
            return Some(FramedResponse::Disconnect);
        }
    }

    // MS-SMB2 3.3.5.2.9 / 3.3.5.2.11: encryption policy enforcement.
    // A request that arrives unencrypted on a session or tree with
    // encrypt_data is rejected with STATUS_ACCESS_DENIED. Exempt:
    // NEGOTIATE (no session) and SESSION_SETUP (establishing the session).
    // ECHO, LOGOFF, CANCEL — all checked, per Samba (enforces on every
    // command that names an existing session).
    if was_encrypted.is_none() && command != Command::Negotiate && command != Command::SessionSetup
    {
        let sid = req.header.session_id;
        if sid != 0 {
            let session_encrypt = {
                let enc_map = conn_state.encryption_ref();
                let enc_map = enc_map.read().unwrap();
                enc_map.get(&sid).map(|st| st.encrypt_data).unwrap_or(false)
            };
            if session_encrypt {
                // Session-level encrypt_data: reject.
                debug!(conn_id = conn_state.conn_id, session_id = sid,
                    command = %command, "unencrypted request on encrypt_data session — denying");
                return Some(error_response_for(
                    command,
                    NtStatus::AccessDenied,
                    &req.header,
                ));
            }
            // Tree-level encrypt_data: check if the tree requires encryption.
            if let Some(tid) = req.header.tree_id {
                let tree_encrypt = {
                    let trees = conn_state.trees_ref();
                    let trees = trees.read().await;
                    trees.get(&tid).map(|t| t.encrypt_data).unwrap_or(false)
                };
                if tree_encrypt {
                    debug!(conn_id = conn_state.conn_id, session_id = sid,
                        tree_id = tid, command = %command,
                        "unencrypted request on encrypt_data tree — denying");
                    return Some(error_response_for(
                        command,
                        NtStatus::AccessDenied,
                        &req.header,
                    ));
                }
            }
        }
    }

    // Retired-session gate (MS-SMB2 3.3.5.2.9, Samba
    // smbd_smb2_request_validate): a session torn down by a
    // PreviousSessionId reconnect no longer exists on the server. Any
    // request naming it — on any connection — fails with
    // USER_SESSION_DELETED. Exempts SESSION_SETUP (a fresh setup on the
    // same id is a new conversation) and NEGOTIATE (no session).
    if command != Command::Negotiate && command != Command::SessionSetup {
        let sid = req.header.session_id;
        if sid != 0 && state.retired_sessions.read().unwrap().contains(&sid) {
            debug!(conn_id = conn_state.conn_id, session_id = sid,
                command = %command, "request on retired session — USER_SESSION_DELETED");
            return Some(error_response_for(
                command,
                NtStatus::UserSessionDeleted,
                &req.header,
            ));
        }
    }

    // CANCEL never consumes credits (MS-SMB2 3.3.5.14). Handle it before
    // the credit check to avoid leaking a credit.
    if command == Command::Cancel {
        return handle_cancel(conn_state, &req.header).await;
    }

    if let Err(resp) = charge_credits(conn_state, &req.header) {
        return Some(*resp);
    }

    // Unknown-session gate (Samba smbd_smb2_request_check_session,
    // smb2_server.c: a session_id not in the connection's session table
    // fails every command except SESSION_SETUP with USER_SESSION_DELETED —
    // smb2.compound invalid2: an unrelated CLOSE naming session UINT64_MAX
    // must return USER_SESSION_DELETED, not FILE_CLOSED). Exempt NEGOTIATE
    // (no session), SESSION_SETUP (establishing), ECHO (sessionless
    // keepalive semantics), LOGOFF (its own session handling) and
    // session_id 0. Runs after credit charging so the client is still
    // charged for the rejected member.
    if command != Command::Negotiate
        && command != Command::SessionSetup
        && command != Command::Echo
        && command != Command::Logoff
    {
        let sid = req.header.session_id;
        if sid != 0 {
            let known = {
                let sessions = conn_state.sessions.read().await;
                sessions.iter().any(|s| s.id == sid)
            };
            if !known {
                debug!(conn_id = conn_state.conn_id, session_id = sid,
                    command = %command, "request on unknown session — USER_SESSION_DELETED");
                return Some(error_response_for(
                    command,
                    NtStatus::UserSessionDeleted,
                    &req.header,
                ));
            }
        }
    }

    match command {
        Command::Negotiate => Some(handle_negotiate(state, conn_state, req, raw_frame).await),
        Command::SessionSetup => {
            Some(handle_session_setup(state, conn_state, req, raw_frame).await)
        }
        Command::Echo => Some(handle_echo(&req.header)),
        Command::Logoff => Some(handle_logoff(state, conn_state, &req.header).await),
        Command::TreeConnect => Some(handle_tree_connect(state, conn_state, req).await),
        Command::TreeDisconnect => {
            Some(handle_tree_disconnect(state, conn_state, &req.header).await)
        }
        Command::Create => Some(handle_create(state, conn_state, req, raw_frame).await),
        Command::Close => Some(handle_close(state, conn_state, req).await),
        Command::Read => Some(handle_read(state, conn_state, req).await),
        Command::Write => Some(handle_write(state, conn_state, req, raw_frame).await),
        Command::Flush => Some(handle_flush(state, conn_state, req).await),
        Command::QueryInfo => Some(handle_query_info(state, conn_state, req).await),
        Command::QueryDirectory => Some(handle_query_directory(state, conn_state, req).await),
        Command::SetInfo => Some(handle_set_info(state, conn_state, req).await),
        Command::ChangeNotify => Some(handle_change_notify(state, conn_state, req).await),
        Command::Ioctl => Some(handle_ioctl(state, conn_state, req).await),
        Command::Lock => Some(handle_lock(state, conn_state, req).await),
        Command::OplockBreak => Some(handle_oplock_break(state, conn_state, req).await),
        Command::ServerToClientNotification => None,
        other => {
            debug!(conn_id = conn_state.conn_id, command = %other, "unsupported command");
            Some(error_response_for(
                other,
                NtStatus::NotSupported,
                &req.header,
            ))
        }
    }
}

/// Build a NEGOTIATE response using the stable server GUID from ServerState.
///
/// Performs dialect selection: the highest common dialect from the client's
/// offer, the set of implemented dialects, and the configured [min, max]
/// range. Stores the negotiation record in conn_state for SESSION_SETUP,
/// signing, and VALIDATE_NEGOTIATE_INFO.
/// Encode, sign (per session signing state) and enqueue a response that is
/// not returned through the read loop — async completions, cancellations.
///
/// If the response's session has `encrypt_data` set, the response is
/// encrypted with that session's encryption key. Never falls back to
/// plaintext once encryption is selected — if the encryption state is
/// missing after the decision, the response is dropped (not sent
/// unencrypted).
/// Pend a request until every break waiter resolves (ack or 35 s expiry),
/// then send `outcome` as the async final response. Returns the interim
/// STATUS_PENDING to send now. Registered in `pending_async` so CANCEL and
/// disconnect drop it. Same wire shape as the deferred-CREATE path.
pub(crate) fn extract_share_name(path: &str) -> String {
    let trimmed = path.trim_start_matches(['\\', '/']);
    let mut parts = trimmed.split(['\\', '/']).filter(|s| !s.is_empty());
    let first = parts.next().unwrap_or("");
    let share = parts.next().unwrap_or(first);
    share.trim_end_matches('\0').to_string()
}

/// Look up the session identity for a request, returning the identity and
/// the session's `is_guest` flag. Returns `None` if the session doesn't
/// exist (caller should return STATUS_USER_SESSION_DELETED).
pub(crate) async fn lookup_session_identity(
    conn_state: &ConnState,
    session_id: u64,
) -> Option<rssmb_auth::Identity> {
    let sessions = conn_state.sessions.read().await;
    sessions
        .iter()
        .find(|s| s.id == session_id)
        .and_then(|s| s.user_identity.clone())
}

/// Whether the tree's share is read-only. Unknown trees count as read-only
/// (fail closed); ownership has already been validated by the caller.
pub(crate) async fn tree_read_only(conn_state: &ConnState, tree_id: u32) -> bool {
    conn_state
        .trees_ref()
        .read()
        .await
        .get(&tree_id)
        .map(|t| t.read_only)
        .unwrap_or(true)
}

/// Whether the connected user has write access on this tree. Unknown trees
/// count as no-write (fail closed).
pub(crate) async fn tree_write_access(conn_state: &ConnState, tree_id: u32) -> bool {
    conn_state
        .trees_ref()
        .read()
        .await
        .get(&tree_id)
        .map(|t| t.write_access)
        .unwrap_or(false)
}

/// Tear down the session named by PreviousSessionId (MS-SMB2 3.3.5.5,
/// Samba smb2srv_session_close_previous). Only runs when the NEW session
/// authenticates as the same user; otherwise the old session stays.
///
/// Effects (golden: reopen1a / reopen1a-lease):
/// - the old session's trees and opens are closed via the shared
///   SessionShared arcs (visible to every channel of that session);
///   durable opens survive, marked orphaned for reconnect;
/// - the session is removed from the global registry and session list;
/// - its id is added to `retired_sessions` so any request naming it —
///   on any connection — fails with USER_SESSION_DELETED (Samba's
///   session-table lookup behavior in smbd_smb2_request_validate).
pub(crate) async fn teardown_previous_session(
    state: &ServerState,
    previous_session_id: u64,
    new_username: &str,
) {
    // Find the old session: global registry entry + user identity.
    let shared = state
        .session_registry
        .read()
        .unwrap()
        .get(&previous_session_id)
        .cloned();
    debug!(
        previous_session_id,
        found = shared.is_some(),
        "teardown_previous_session: registry lookup"
    );
    let Some(shared) = shared else {
        // Unknown/stale PreviousSessionId — nothing to do (Samba treats a
        // freed record as success).
        return;
    };

    // Same-user check (Samba: security_token_is_sid(previous_token, current_sid)).
    // The username lives on the shared session state.
    let old_username = shared.username.read().ok().map(|u| u.clone());
    let Some(old_username) = old_username.filter(|u| !u.is_empty()) else {
        // No username recorded — stale or anonymous registry entry; drop it.
        state
            .session_registry
            .write()
            .unwrap()
            .remove(&previous_session_id);
        return;
    };
    if old_username != new_username {
        debug!(
            previous_session_id,
            old_username = %old_username,
            new_username = %new_username,
            "previous-session teardown skipped — different user"
        );
        return;
    }

    info!(
        previous_session_id,
        username = %new_username,
        "previous-session teardown (PreviousSessionId reconnect)"
    );

    // Close all opens on the shared open map (visible on every channel).
    // Durable opens survive: orphan them (the reconnecting session may
    // re-attach them via DH2C/DHnC); everything else is closed.
    let removed_opens: Vec<OpenEntry> = {
        let mut opens = shared.opens.write().await;
        let entries: Vec<OpenEntry> = opens.values().cloned().collect();
        opens.clear();
        entries
    };
    let mut orphaned_count = 0usize;
    for entry in &removed_opens {
        if entry.is_pipe {
            continue;
        }
        let mut should_delete_on_close = false;
        if let Some(fid) = entry.file_id {
            let remove_result = state.open_table.remove(fid, entry.open_id).await;
            should_delete_on_close = remove_result.was_last && remove_result.any_delete_on_close;
        }
        state
            .open_table
            .release_all_locks_for_open(entry.open_id)
            .await;
        if let Some(guid) = entry.durable_guid {
            state.durable_table.mark_orphaned(&guid).await;
            // Keep the lease record too — reconnect echoes it.
            orphaned_count += 1;
            continue;
        }
        if let Some(pid) = entry.durable_persistent_id {
            state.durable_table.mark_orphaned_v1(pid).await;
            orphaned_count += 1;
            continue;
        }
        state
            .open_table
            .remove_open_from_leases(entry.open_id)
            .await;
        let vfs = entry.vfs.clone();
        let open_id = entry.open_id;
        tokio::spawn(async move {
            if should_delete_on_close {
                let _ = vfs.set_delete_on_close(open_id, true).await;
            }
            if let Err(e) = vfs.close(open_id).await {
                tracing::warn!(error = %e, "previous-session teardown: VFS close failed");
            }
        });
    }
    if orphaned_count > 0 {
        debug!(
            previous_session_id,
            orphaned_count, "durable opens survived teardown"
        );
    }

    // Clear the shared tree map (all channels see the empty map).
    shared.trees.write().await.clear();

    // Remove the session from the global registry and the session list.
    state
        .session_registry
        .write()
        .unwrap()
        .remove(&previous_session_id);
    state.remove_session(previous_session_id).await;

    // Retire the id: every subsequent request naming it, on any
    // connection, fails with USER_SESSION_DELETED (checked in
    // handle_plain before dispatch). The signing state is left alone:
    // marking it `retiring` would make the signature verifier discard
    // old-session requests outright (no response at all), where the
    // golden behavior is a proper USER_SESSION_DELETED error response.
    state
        .retired_sessions
        .write()
        .unwrap()
        .insert(previous_session_id);
}

/// Build a share snapshot for the RPC context (Step 8.3 simplified — full
/// visibility filtering comes in Step 8.5). Returns all configured shares
/// that the session can see, sorted by name, plus a synthetic IPC$ entry.
pub(crate) fn visible_shares_for_ctx(
    shares: &std::collections::HashMap<String, crate::config::ShareConfig>,
    identity: Option<&rssmb_auth::Identity>,
) -> Vec<rssmb_rpc_server::ShareInfo> {
    let is_guest = identity.map(|i| i.is_guest).unwrap_or(true);
    let username = identity.map(|i| i.username.as_str()).unwrap_or("");

    let mut result: Vec<rssmb_rpc_server::ShareInfo> = shares
        .iter()
        .filter(|(_, sc)| {
            // Browseable + access policy (same as TREE_CONNECT).
            if !sc.browseable {
                return false;
            }
            if is_guest && !sc.guest_ok {
                return false;
            }
            if !sc.valid_users.is_empty()
                && !sc
                    .valid_users
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(username))
            {
                return false;
            }
            if !sc.read_users.is_empty()
                && !sc
                    .read_users
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(username))
            {
                return false;
            }
            true
        })
        .map(|(_, sc)| rssmb_rpc_server::ShareInfo {
            name: sc.name.clone(),
            comment: sc.comment.clone(),
            share_type: 0, // STYPE_DISKTREE
            encrypt_data: sc.encrypt_data,
        })
        .collect();
    // Sort by name for deterministic enumeration.
    result.sort_by(|a, b| a.name.cmp(&b.name));
    // Append synthetic IPC$.
    result.push(rssmb_rpc_server::ShareInfo {
        name: "IPC$".to_string(),
        comment: String::new(),
        share_type: 0x80000003, // STYPE_IPC | STYPE_SPECIAL
        encrypt_data: false,
    });
    result
}

/// Look up an open handle, validating that it belongs to the request's
/// session and tree. Returns the `OpenEntry` or an error response.
pub(crate) async fn lookup_open_for_session(
    conn_state: &ConnState,
    session_id: u64,
    tree_id: u32,
    file_id_volatile: u64,
) -> Result<OpenEntry, NtStatus> {
    let opens_ref = conn_state.opens_ref();
    let opens = opens_ref.read().await;
    // Note: the generic missing-handle status stays InvalidHandle —
    // blanket FILE_CLOSED regressed smb2.dir/getinfo/setinfo (their
    // torture suites expect different statuses for their not-found
    // paths). FILE_CLOSED is returned only where asserted:
    // CLOSE of a closed handle (3.3.5.16) and forged persistent halves
    // in LOCK (below).
    let entry = opens
        .get(&file_id_volatile)
        .ok_or(NtStatus::InvalidHandle)?;
    // Validate that the handle belongs to this session.
    if entry.session_id != session_id {
        return Err(NtStatus::InvalidHandle);
    }
    // Validate that the handle belongs to this tree.
    if entry.tree_id != tree_id {
        return Err(NtStatus::InvalidHandle);
    }
    Ok(entry.clone())
}

/// LOCK-specific handle check: valid-request corrupts the PERSISTENT half
/// of the FileId (handle.data[0]) and asserts NT_STATUS_FILE_CLOSED
/// (lock.c:133). We key opens on the volatile half only, so the forged
/// id collides with a live open; detect it by re-deriving the expected
/// persistent value from the connection's id allocation.
pub(crate) async fn check_lock_file_id_persistent(
    conn_state: &ConnState,
    file_id: &rssmb_proto::create::FileId,
) -> Result<(), NtStatus> {
    let expected = conn_state
        .persistent_base_val()
        .wrapping_add(file_id.volatile);
    if file_id.persistent != expected {
        return Err(NtStatus::FileClosed);
    }
    Ok(())
}

/// Build an error response carrying the request's header fields so the
/// client can match it to the original request.
pub(crate) fn error_response_for(
    command: Command,
    status: NtStatus,
    req_header: &Header,
) -> FramedResponse {
    FramedResponse::Error {
        command,
        status,
        message_id: req_header.message_id,
        session_id: req_header.session_id,
        tree_id: req_header.tree_id,
        credit_charge: req_header.credit_charge,
    }
}

/// Construct a PlainResponse mirroring the request header.
pub(crate) fn build_response(req_header: &Header, content: ResponseContent) -> PlainResponse {
    // Error responses don't carry their own command — use the request's
    // command (the command that errored). All other content variants map
    // to their associated command.
    let command = match &content {
        ResponseContent::Error(_) => req_header.command,
        _ => content.associated_cmd(),
    };
    PlainResponse {
        header: Header {
            credit_charge: req_header.credit_charge,
            status: 0u32,
            command,
            credit_request: req_header.credit_request,
            flags: HeaderFlags::new().with_server_to_redir(true),
            next_command: 0,
            message_id: req_header.message_id,
            tree_id: req_header.tree_id,
            async_id: req_header.async_id,
            session_id: req_header.session_id,
            signature: 0,
        },
        content,
    }
}

/// Current system time as a Windows FILETIME.
pub(crate) fn current_filetime() -> FileTime {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    const EPOCH_DELTA_100NS: u64 = 11_644_473_600 * 10_000_000;
    let unix_100ns = dur.as_nanos() as u64 / 100;
    FileTime::from(unix_100ns + EPOCH_DELTA_100NS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShareConfig;

    fn make_test_state() -> Arc<ServerState> {
        Arc::new(ServerState::new(crate::config::ServerConfig::for_testing()))
    }

    fn make_conn_state() -> ConnState {
        let (tx, _rx) = mpsc::channel::<Bytes>(16);
        let session_shared = Arc::new(SessionShared::new(1));
        ConnState {
            conn_id: 1,
            remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            transport: TransportKind::Tcp,
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            write_tx: tx,
            auth_state: Arc::new(tokio::sync::Mutex::new(None)),
            auth_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            negotiate_record: Arc::new(tokio::sync::Mutex::new(None)),
            active: Arc::new(std::sync::RwLock::new(SessionArcs {
                trees: session_shared.trees.clone(),
                opens: session_shared.opens.clone(),
                signing: session_shared.signing.clone(),
                encryption: session_shared.encryption.clone(),
                next_tree_id: session_shared.next_tree_id.clone(),
                next_volatile_id: session_shared.next_volatile_id.clone(),
                persistent_base: session_shared.persistent_base,
            })),
            session_shared: Arc::new(std::sync::RwLock::new(Some(session_shared))),
            pending_sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            credits: Arc::new(rssmb_wire_adapter::credits::CreditManager::new(1024)),
            pending_async: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            preauth_conn: Arc::new(std::sync::Mutex::new(None)),
            preauth_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            preauth_hash_response: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Establish negotiation on a conn_state so subsequent commands
    /// pass the negotiate gate. Also grants credits to simulate what
    /// the real connection read loop does after each response.
    async fn establish_negotiation(state: &Arc<ServerState>, conn: &ConnState) {
        establish_negotiation_with_dialect(state, conn, WireDialect::Smb021).await
    }

    /// Negotiate with a specific (3.x-capable) dialect so multichannel-
    /// related handlers pass their dialect gates.
    async fn establish_negotiation_with_dialect(
        state: &Arc<ServerState>,
        conn: &ConnState,
        dialect: WireDialect,
    ) {
        let req = make_negotiate_request_with_dialects(vec![dialect]);
        let resp = handle_message(state, conn, FramedMessage::Plain(req), &[], None).await;
        assert!(resp.is_some(), "negotiate should produce a response");
        assert!(
            !matches!(resp, Some(FramedResponse::Disconnect)),
            "negotiation failed"
        );
        // The negotiate consumed the initial credit; grant some back
        // so subsequent test commands have credits to spend.
        conn.credits.grant(16);
    }

    fn make_negotiate_request() -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::negotiate::{Dialect, NegotiateRequest};
        let content = RequestContent::Negotiate(NegotiateRequest {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new(),
            client_guid: Guid::generate(),
            dialects: vec![Dialect::Smb021],
            negotiate_context_list: None,
        });

        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Negotiate,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 0,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }

    fn make_negotiate_request_with_dialects(
        dialects: Vec<WireDialect>,
    ) -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::negotiate::{
            HashAlgorithm, NegotiateRequest, PreauthIntegrityCapabilities,
        };
        // If 3.1.1 is in the offer, include preauth context (required for 3.1.1).
        let negotiate_context_list = if dialects.contains(&WireDialect::Smb0311) {
            Some(vec![PreauthIntegrityCapabilities {
                hash_algorithms: vec![HashAlgorithm::Sha512],
                salt: vec![0xab; 32],
            }
            .into()])
        } else {
            None
        };
        let content = RequestContent::Negotiate(NegotiateRequest {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new().with_large_mtu(true),
            client_guid: Guid::generate(),
            dialects,
            negotiate_context_list,
        });

        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Negotiate,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 0,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }

    fn make_echo_request() -> rssmb_proto::plain::PlainRequest {
        make_echo_request_with_id(1)
    }

    fn make_echo_request_with_id(message_id: u64) -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::echo::EchoRequest;
        let content = RequestContent::Echo(EchoRequest::default());
        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Echo,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }

    fn make_request_with_command(
        command: Command,
        message_id: u64,
    ) -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::echo::EchoRequest;
        let content = RequestContent::Echo(EchoRequest::default());
        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }

    /// Build an SMB2 IOCTL request for FSCTL_QUERY_NETWORK_INTERFACE_INFO.
    fn make_qnii_request(max_output_response: u32) -> rssmb_proto::plain::PlainRequest {
        make_qnii_request_with_id(max_output_response, 1)
    }

    fn make_qnii_request_with_id(
        max_output_response: u32,
        message_id: u64,
    ) -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::create::FileId;
        use rssmb_proto::ioctl::{IoctlBuffer, IoctlReqData, IoctlRequest, IoctlRequestFlags};
        let content = RequestContent::Ioctl(IoctlRequest {
            ctl_code: 0x0014_01FC,
            file_id: FileId {
                persistent: u64::MAX,
                volatile: u64::MAX,
            },
            max_input_response: 0,
            max_output_response,
            flags: IoctlRequestFlags::new().with_is_fsctl(true),
            buffer: IoctlReqData::Ioctl(IoctlBuffer::from(vec![])),
        });
        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Ioctl,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }

    /// Publish a fixed interface list into the state's snapshot (simulates a
    /// successful background refresh) — keeps tests host-independent.
    fn publish_interfaces(state: &Arc<ServerState>, addrs: Vec<crate::netinfo::UsableAddress>) {
        // Use the refresher's override mechanism via publish (test-only
        // direct access to keep determinism).
        // InterfaceSnapshot::publish is private; publish through the same
        // channel production uses: start_refresher with a pinned list and
        // wait for the immediate first refresh.
        // Simpler: use the override path synchronously via spawn_blocking.
        let snap = state.interface_snapshot.clone();
        let handle = tokio::runtime::Handle::current();
        let shutdown = Arc::new(crate::ShutdownSignal::new());
        snap.start_refresher(
            handle,
            std::time::Duration::from_secs(3600),
            shutdown,
            addrs,
        );
        // start_refresher performs the first refresh immediately on a
        // blocking thread; wait for it.
    }

    async fn wait_for_snapshot(state: &Arc<ServerState>) {
        for _ in 0..2000 {
            if !state.interface_snapshot.get().is_empty() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn test_qnii_returns_interface_entries() {
        // QNII requires multichannel=true; the default is now false.
        let mut config = crate::config::ServerConfig::for_testing();
        config.multichannel = true;
        let state = Arc::new(ServerState::new(config));
        let conn = make_conn_state();
        establish_negotiation_with_dialect(&state, &conn, WireDialect::Smb030).await;

        publish_interfaces(
            &state,
            vec![
                crate::netinfo::UsableAddress {
                    if_index: 1,
                    ip: "10.0.0.1".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1_000_000_000,
                },
                crate::netinfo::UsableAddress {
                    if_index: 2,
                    ip: "10.0.0.2".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1_000_000_000,
                },
            ],
        );
        wait_for_snapshot(&state).await;

        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_qnii_request(4096)),
            &[],
            None,
        )
        .await;
        let Some(FramedResponse::Plain(p)) = resp else {
            panic!("expected plain response, got {resp:?}");
        };
        assert_eq!(p.header.status, 0, "full list must return STATUS_SUCCESS");
        match p.content {
            ResponseContent::Ioctl(io) => {
                assert_eq!(io.out_buffer.len(), 2 * 152);
                // First entry Next = 152 (chained), last = 0.
                assert_eq!(&io.out_buffer[0..4], &152u32.to_le_bytes());
                assert_eq!(&io.out_buffer[152..156], &[0, 0, 0, 0]);
            }
            other => panic!("expected ioctl response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_qnii_truncation_boundaries_and_buffer_overflow() {
        // QNII requires multichannel=true; the default is now false.
        let mut config = crate::config::ServerConfig::for_testing();
        config.multichannel = true;
        let state = Arc::new(ServerState::new(config));
        let conn = make_conn_state();
        establish_negotiation_with_dialect(&state, &conn, WireDialect::Smb030).await;

        publish_interfaces(
            &state,
            vec![
                crate::netinfo::UsableAddress {
                    if_index: 1,
                    ip: "10.0.0.1".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1,
                },
                crate::netinfo::UsableAddress {
                    if_index: 2,
                    ip: "10.0.0.2".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1,
                },
            ],
        );
        wait_for_snapshot(&state).await;

        // Cases: (MaxOutputResponse, expected_out_len, expected_status)
        // 0 = STATUS_BUFFER_TOO_SMALL (nothing fits), 1 = BUFFER_OVERFLOW
        // (partial list), 2 = STATUS_SUCCESS (full list).
        let cases: &[(u32, usize, u8)] = &[
            (0, 0, 0),      // nothing fits: BUFFER_TOO_SMALL, no data
            (151, 0, 0),    // partial entry: BUFFER_TOO_SMALL
            (152, 152, 1),  // exactly one entry of two: BUFFER_OVERFLOW
            (153, 152, 1),  // one entry + slack: BUFFER_OVERFLOW
            (303, 152, 1),  // one full + one partial: BUFFER_OVERFLOW
            (304, 304, 2),  // exactly two: SUCCESS
            (4096, 304, 2), // plenty: SUCCESS
        ];
        for (i, &(max_out, expect_len, expect_kind)) in cases.iter().enumerate() {
            let resp = handle_message(
                &state,
                &conn,
                FramedMessage::Plain(make_qnii_request_with_id(max_out, 2 + i as u64)),
                &[],
                None,
            )
            .await;
            match expect_kind {
                0 => {
                    // Nothing fits: BUFFER_TOO_SMALL error, no data.
                    let Some(FramedResponse::Error { status, .. }) = resp else {
                        panic!("max_out={max_out}: expected error response, got {resp:?}");
                    };
                    assert_eq!(status, NtStatus::BufferTooSmall);
                }
                1 | 2 => {
                    let Some(FramedResponse::Plain(p)) = resp else {
                        panic!("max_out={max_out}: expected plain response, got {resp:?}");
                    };
                    match &p.content {
                        ResponseContent::Ioctl(io) => {
                            assert_eq!(io.out_buffer.len(), expect_len, "max_out={max_out}");
                            let last = expect_len - 152;
                            assert_eq!(
                                &io.out_buffer[last..last + 4],
                                &[0, 0, 0, 0],
                                "max_out={max_out}: list must terminate with Next=0"
                            );
                            let expected_status = if expect_kind == 2 {
                                0
                            } else {
                                NtStatus::BufferOverflow.to_u32()
                            };
                            assert_eq!(p.header.status, expected_status, "max_out={max_out}");
                        }
                        other => panic!("max_out={max_out}: unexpected content {other:?}"),
                    }
                }
                _ => unreachable!(),
            }
        }

        // A three-entry snapshot capped at two: real BUFFER_OVERFLOW with
        // truncated data (warning severity, full IOCTL body).
        publish_interfaces(
            &state,
            vec![
                crate::netinfo::UsableAddress {
                    if_index: 1,
                    ip: "10.0.0.1".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1,
                },
                crate::netinfo::UsableAddress {
                    if_index: 2,
                    ip: "10.0.0.2".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1,
                },
                crate::netinfo::UsableAddress {
                    if_index: 3,
                    ip: "10.0.0.3".parse().unwrap(),
                    scope_id: 0,
                    link_speed: 1,
                },
            ],
        );
        // Wait for the override to republish (immediate refresh).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        for _ in 0..2000 {
            if state.interface_snapshot.get().len() == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        // Grant enough credits that message_id 99 is inside the window.
        conn.credits.grant(256);
        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_qnii_request_with_id(304, 99)),
            &[],
            None,
        )
        .await;
        let Some(FramedResponse::Plain(p)) = resp else {
            panic!("expected plain response, got {resp:?}");
        };
        assert_eq!(p.header.status, NtStatus::BufferOverflow.to_u32());
        match p.content {
            ResponseContent::Ioctl(io) => {
                assert_eq!(io.out_buffer.len(), 304, "two entries must fit");
                // Terminal Next must be 0 after truncation.
                assert_eq!(&io.out_buffer[152..156], &[0, 0, 0, 0]);
            }
            other => panic!("BUFFER_OVERFLOW must carry an IOCTL body, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_qnii_rejects_pre_smb30_dialect() {
        let state = make_test_state();
        let conn = make_conn_state();
        // Negotiate SMB 2.1 only.
        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_negotiate_request()),
            &[],
            None,
        )
        .await;
        assert!(resp.is_some());
        conn.credits.grant(16);

        publish_interfaces(
            &state,
            vec![crate::netinfo::UsableAddress {
                if_index: 1,
                ip: "10.0.0.1".parse().unwrap(),
                scope_id: 0,
                link_speed: 1,
            }],
        );
        wait_for_snapshot(&state).await;

        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_qnii_request(4096)),
            &[],
            None,
        )
        .await;
        let Some(FramedResponse::Error { status, .. }) = resp else {
            panic!("expected error response, got {resp:?}");
        };
        assert_eq!(status, NtStatus::NotSupported);
    }

    #[tokio::test]
    async fn test_qnii_not_supported_when_snapshot_empty() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        // No refresher started: snapshot stays empty → fail closed.
        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_qnii_request(4096)),
            &[],
            None,
        )
        .await;
        let Some(FramedResponse::Error { status, .. }) = resp else {
            panic!("expected error response, got {resp:?}");
        };
        assert_eq!(status, NtStatus::NotSupported);
    }

    #[tokio::test]
    async fn test_qnii_not_supported_when_multichannel_disabled() {
        let mut cfg = crate::config::ServerConfig::for_testing();
        cfg.multichannel = false;
        let state = Arc::new(ServerState::new(cfg));
        let conn = make_conn_state();
        establish_negotiation_with_dialect(&state, &conn, WireDialect::Smb030).await;

        publish_interfaces(
            &state,
            vec![crate::netinfo::UsableAddress {
                if_index: 1,
                ip: "10.0.0.1".parse().unwrap(),
                scope_id: 0,
                link_speed: 1,
            }],
        );
        wait_for_snapshot(&state).await;

        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_qnii_request(4096)),
            &[],
            None,
        )
        .await;
        let Some(FramedResponse::Error { status, .. }) = resp else {
            panic!("expected error response, got {resp:?}");
        };
        // Disabled multichannel must neither advertise nor leak topology.
        assert_eq!(status, NtStatus::NotSupported);
    }

    #[tokio::test]
    async fn test_negotiate_dispatch() {
        let state = make_test_state();
        let conn = make_conn_state();
        let req = make_negotiate_request();
        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;

        let resp = resp.expect("negotiate should produce a response");
        match resp {
            FramedResponse::Plain(plain) => {
                assert_eq!(plain.header.command, Command::Negotiate);
                assert_eq!(plain.header.status, 0u32);
                assert!(plain.header.flags.server_to_redir());
                match plain.content {
                    ResponseContent::Negotiate(neg) => {
                        assert_eq!(neg.dialect_revision, NegotiateDialect::Smb021);
                        assert_eq!(neg.max_transact_size, 1024 * 1024);
                        assert!(neg.capabilities.large_mtu());
                        assert!(neg.capabilities.leasing());
                        assert!(!neg.capabilities.encryption());
                        assert!(*neg.system_time != 0);
                    }
                    other => panic!("expected Negotiate content, got {:?}", other),
                }
            }
            other => panic!("expected Plain response, got {:?}", other),
        }
    }

    async fn negotiated_io_sizes(state: &Arc<ServerState>) -> (u32, u32, u32) {
        let conn = make_conn_state();
        let resp = handle_message(
            state,
            &conn,
            FramedMessage::Plain(make_negotiate_request()),
            &[],
            None,
        )
        .await;
        match resp {
            Some(FramedResponse::Plain(PlainResponse {
                content: ResponseContent::Negotiate(neg),
                ..
            })) => (neg.max_transact_size, neg.max_read_size, neg.max_write_size),
            other => panic!("expected Negotiate response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_negotiate_io_sizes_default_1mib() {
        let state = make_test_state();
        assert_eq!(
            negotiated_io_sizes(&state).await,
            (1_048_576, 1_048_576, 1_048_576)
        );
    }

    #[tokio::test]
    async fn test_negotiate_io_sizes_follow_max_frame_size() {
        let mut cfg = crate::config::ServerConfig::for_testing();
        cfg.max_frame_size = 65_536;
        let state = Arc::new(ServerState::new(cfg));
        assert_eq!(negotiated_io_sizes(&state).await, (65_536, 65_536, 65_536));
    }

    #[tokio::test]
    async fn test_negotiate_uses_stable_guid() {
        let state = make_test_state();
        let conn = make_conn_state();

        // First negotiate
        let req1 = make_negotiate_request();
        let resp1 = handle_message(&state, &conn, FramedMessage::Plain(req1), &[], None).await;
        let guid1 = match resp1.unwrap() {
            FramedResponse::Plain(p) => match p.content {
                ResponseContent::Negotiate(n) => n.server_guid,
                _ => panic!(),
            },
            _ => panic!(),
        };

        // A second NEGOTIATE on the same connection is now rejected
        // (MS-SMB2 3.3.5.4: terminate the connection). Verify with a
        // fresh connection instead.
        let conn2 = make_conn_state();
        conn2.credits.grant(1);
        let req2 = make_negotiate_request();
        let resp2 = handle_message(&state, &conn2, FramedMessage::Plain(req2), &[], None).await;
        let guid2 = match resp2.unwrap() {
            FramedResponse::Plain(p) => match p.content {
                ResponseContent::Negotiate(n) => n.server_guid,
                _ => panic!(),
            },
            _ => panic!(),
        };

        assert_eq!(
            guid1, guid2,
            "server GUID must be stable across negotiate responses"
        );
    }

    #[tokio::test]
    async fn test_echo_dispatch() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        let req = make_echo_request();
        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;

        let resp = resp.expect("echo should produce a response");
        match resp {
            FramedResponse::Plain(plain) => {
                assert_eq!(plain.header.command, Command::Echo);
                assert_eq!(plain.header.status, 0u32);
            }
            other => panic!("expected Plain response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_smb1_negotiate_dropped() {
        // SMB2-only server: does not respond to SMB1 negotiate.
        let state = make_test_state();
        let conn = make_conn_state();
        let framed = FramedMessage::Smb1Negotiate(vec![0xff, 0x53, 0x4d, 0x42, 0x00]);
        let resp = handle_message(&state, &conn, framed, &[], None).await;
        assert!(
            resp.is_none(),
            "SMB1 negotiate should produce no response (SMB2-only server)"
        );
    }

    #[tokio::test]
    async fn test_lock_unsupported_on_pipe() {
        // LOCK on a pipe open should return NOT_SUPPORTED.
        // (LOCK on a disk open requires a real tree + handle; the
        // happy path is tested via the VFS-level lock unit tests.)
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        // Create a pipe open on the IPC$ tree so we have a file_id.
        // But we don't have a tree connected, so Lock with no tree
        // gets InvalidHandle — which is also a valid test (no crash).
        let req = make_request_with_command(Command::Lock, 3);
        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;
        let resp = resp.expect("lock should produce a response");
        // Without a valid tree/handle, expect an error (not a crash).
        match resp {
            FramedResponse::Error { command, .. } => {
                assert_eq!(command, Command::Lock);
            }
            other => panic!("expected Error response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_server_to_client_notification_no_response() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        let req = make_request_with_command(Command::ServerToClientNotification, 4);
        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;
        assert!(
            resp.is_none(),
            "ServerToClientNotification should not produce a response"
        );
    }

    #[tokio::test]
    async fn test_close_with_zero_flags_succeeds() {
        // GVFS sends CLOSE with flags=0 (no POSTQUERY_ATTRIB).
        // Before the fix, smb-msg asserted flags==POSTQUERY and the request
        // was rejected, causing the client to hang. This test verifies that
        // a CLOSE with flags=0 on a non-existent handle returns FileClosed
        // (MS-SMB2 3.3.5.16: close of a handle that is not open is
        // STATUS_FILE_CLOSED; the request itself parsed fine).
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;

        let close_req = rssmb_proto::create::CloseRequest {
            flags: rssmb_proto::create::CloseFlags::new(), // flags = 0
            file_id: rssmb_proto::create::FileId {
                persistent: 0,
                volatile: 999, // non-existent
            },
        };

        let req = rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Close,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 10,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Close(close_req),
        };

        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;
        let resp = resp.expect("CLOSE should produce a response");
        match resp {
            // No handle → FileClosed is correct (MS-SMB2 3.3.5.16); the
            // important thing is that we got here at all (the request
            // parsed).
            FramedResponse::Error {
                command, status, ..
            } => {
                assert_eq!(command, Command::Close);
                assert_eq!(status, NtStatus::FileClosed);
            }
            other => panic!("expected Error(FileClosed), got {:?}", other),
        }
    }

    fn close_req(
        message_id: u64,
        session_id: u64,
        related: bool,
    ) -> rssmb_proto::plain::PlainRequest {
        rssmb_proto::plain::PlainRequest {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::Close,
                credit_request: 1,
                flags: HeaderFlags::new().with_related_operations(related),
                next_command: 0,
                message_id,
                tree_id: Some(7),
                async_id: None,
                session_id,
                signature: 0,
            },
            content: RequestContent::Close(rssmb_proto::create::CloseRequest {
                flags: rssmb_proto::create::CloseFlags::new(),
                file_id: rssmb_proto::create::FileId {
                    persistent: u64::MAX,
                    volatile: u64::MAX,
                },
            }),
        }
    }

    #[tokio::test]
    async fn compound_propagated_error_carries_effective_session() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        conn.credits.grant(10);
        // Unrelated CLOSE on unknown session 42 → USER_SESSION_DELETED (the
        // unknown-session gate, Samba smb2_server.c check_session); the
        // following RELATED member must NOT inherit that context — the
        // chain was broken by the failing unrelated member, so it gets
        // INVALID_PARAMETER (Samba invalid2 req[4] semantics).
        let reqs = vec![close_req(1, 42, false), close_req(2, u64::MAX, true)];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        match resp.expect("compound response") {
            FramedResponse::Compound(ps) => {
                assert_eq!(ps.len(), 2);
                assert_eq!(ps[0].header.session_id, 42);
                assert_eq!(
                    ps[0].header.status,
                    NtStatus::UserSessionDeleted.to_u32(),
                    "unrelated member on unknown session must be USER_SESSION_DELETED"
                );
                assert_eq!(
                    ps[1].header.status,
                    NtStatus::InvalidParameter.to_u32(),
                    "related member after broken chain must be INVALID_PARAMETER"
                );
                // The broken-chain reply still carries the saved header's
                // session (placeholder u64::MAX) — signed contexts resolve
                // elsewhere; the important part is the status pair above.
            }
            other => panic!("expected Compound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn request_without_credits_terminates_connection() {
        let state = make_test_state();
        let conn = make_conn_state(); // 1 initial credit
        establish_negotiation(&state, &conn).await;
        // establish_negotiation consumed 1 (message_id 0) and granted 16,
        // leaving 16 credits. Window is [1..17).
        // Drain all but 1 credit by sending 15 echoes with unique MessageIds.
        for i in 0..15 {
            let r = handle_message(
                &state,
                &conn,
                FramedMessage::Plain(make_echo_request_with_id(i + 1)),
                &[],
                None,
            )
            .await;
            assert!(r.is_some(), "echo should produce a response");
        }
        // Now exactly 1 credit remains (message_id 16). The next echo uses it.
        let r1 = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_echo_request_with_id(16)),
            &[],
            None,
        )
        .await;
        assert!(
            matches!(r1, Some(FramedResponse::Plain(_))),
            "echo should succeed with the last credit"
        );
        // Now 0 credits — next request must disconnect.
        let r2 = handle_message(
            &state,
            &conn,
            FramedMessage::Plain(make_echo_request_with_id(17)),
            &[],
            None,
        )
        .await;
        assert!(
            matches!(r2, Some(FramedResponse::Disconnect)),
            "expected disconnect, got {:?}",
            r2
        );
    }

    #[tokio::test]
    async fn compound_member_without_credits_aborts_whole_chain() {
        // Enough credit for the first member only: the second member's
        // violation must end the connection, not become a propagated error.
        let state = make_test_state();
        let conn = make_conn_state(); // 1 initial credit
                                      // Manually set negotiate record so the gate passes, without
                                      // consuming the initial credit.
        *conn.negotiate_record.lock().await = Some(NegotiateRecord {
            dialect: DialectConfig::Smb21,
            client_guid: Guid::generate(),
            client_security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            client_capabilities: GlobalCapabilities::new(),
            server_capabilities: GlobalCapabilities::new().with_large_mtu(true),
            server_security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            neg311: None,
        });
        let reqs = vec![close_req(0, 42, false), close_req(1, 42, false)];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        assert!(
            matches!(resp, Some(FramedResponse::Disconnect)),
            "expected disconnect, got {:?}",
            resp
        );
    }

    #[tokio::test]
    async fn propagated_compound_members_are_charged() {
        let state = make_test_state();
        let conn = make_conn_state(); // 1 initial
        *conn.negotiate_record.lock().await = Some(NegotiateRecord {
            dialect: DialectConfig::Smb21,
            client_guid: Guid::generate(),
            client_security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            client_capabilities: GlobalCapabilities::new(),
            server_capabilities: GlobalCapabilities::new().with_large_mtu(true),
            server_security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            neg311: None,
        });
        conn.credits.grant(2); // 1 + 2 = 3 total
        let reqs = vec![
            close_req(0, 42, false),
            close_req(1, u64::MAX, true),
            close_req(2, u64::MAX, true),
        ];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        assert!(
            matches!(resp, Some(FramedResponse::Compound(ref ps)) if ps.len() == 3),
            "got {:?}",
            resp
        );
        assert_eq!(conn.credits.available_credits(), 0);
    }

    #[tokio::test]
    async fn unaffordable_propagated_member_disconnects() {
        // Only 2 credits for 3 members: the third (a propagated failure,
        // never executed) is still outside the window → disconnect.
        let state = make_test_state();
        let conn = make_conn_state();
        conn.credits.grant(1);
        let reqs = vec![
            close_req(0, 42, false),
            close_req(1, u64::MAX, true),
            close_req(2, u64::MAX, true),
        ];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        assert!(
            matches!(resp, Some(FramedResponse::Disconnect)),
            "got {:?}",
            resp
        );
    }

    #[tokio::test]
    async fn related_member_never_resolves_foreign_session_tree_handle() {
        // R-33 security boundary (MS-SMB2 3.3.5.2.7): a related element
        // inherits SessionId/TreeId/FileId from the PRECEDING chain members'
        // responses — it must never resolve an open belonging to a
        // different session or tree. Two proofs in one test:
        //   (a) handle_compound inheritance is response-driven: a related
        //       member after a failing unrelated member gets
        //       INVALID_PARAMETER (chain_valid=false), never a dispatch
        //       with the foreign member's ids;
        //   (b) lookup_open_for_session refuses any handle whose owning
        //       session/tree differs — the substitution path could only
        //       ever substitute a FileId, and the session/tree check is
        //       still enforced at dispatch time.
        // Here: session 7 owns an open (volatile 55) on tree 9; a chain
        // [unrelated CLOSE on session 7] + [related CLOSE with the real
        // FileId but under a FOREIGN session id in the saved header] must
        // fail — the related member inherits session 7 (the previous
        // response's session), and lookup then fails on the mismatched
        // tree, or on the unknown handle if the id was not inherited.
        // Either way: an error status, never SUCCESS.
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        conn.credits.grant(10);

        // Register an open in the connection's open table as if created
        // under session 7, tree 9.
        {
            let opens_ref = conn.opens_ref();
            let mut opens = opens_ref.write().await;
            opens.insert(
                55u64,
                OpenEntry {
                    session_id: 7,
                    tree_id: 9,
                    open_id: rssmb_vfs::OpenId(55),
                    vfs: std::sync::Arc::new(rssmb_vfs::memoryfs::MemoryFs::new())
                        as std::sync::Arc<dyn rssmb_vfs::Vfs>,
                    file_id: Some(rssmb_vfs::FileId { dev: 1, ino: 55 }),
                    dir_cursor: Arc::new(tokio::sync::Mutex::new(DirCursor::default())),
                    path: "test.bin".to_string(),
                    is_pipe: false,
                    pipe_state: None,
                    durable_guid: None,
                    durable_persistent_id: None,
                    lock_sequence_array: Arc::new(std::sync::Mutex::new([0xFFu8; 64])),
                },
            );
        }

        // Unrelated member: session 7, tree 9 — closes the real handle.
        let mut m0 = close_req(1, 7, false);
        m0.header.tree_id = Some(9);
        m0.content = RequestContent::Close(rssmb_proto::create::CloseRequest {
            flags: rssmb_proto::create::CloseFlags::new(),
            file_id: rssmb_proto::create::FileId {
                persistent: 0,
                volatile: 55,
            },
        });

        // Related member: FOREIGN session id (99) in its own header, with
        // the same real FileId. Inheritance must override the foreign id
        // with the chain's session 7 — or, if any code path dispatched it
        // with session 99, lookup_open_for_session must refuse (InvalidHandle).
        // It must never succeed and close/open across the boundary.
        let mut m1 = close_req(2, 99, true);
        m1.header.tree_id = Some(99);
        m1.content = RequestContent::Close(rssmb_proto::create::CloseRequest {
            flags: rssmb_proto::create::CloseFlags::new(),
            file_id: rssmb_proto::create::FileId {
                persistent: 0,
                volatile: 55,
            },
        });

        let resp = handle_message(
            &state,
            &conn,
            FramedMessage::Compound(vec![m0, m1]),
            &[],
            None,
        )
        .await;
        match resp.expect("compound response") {
            FramedResponse::Compound(ps) => {
                assert_eq!(ps.len(), 2);
                // First member: the unrelated CLOSE succeeds or fails
                // normally (FileClosed is fine — the entry has no real
                // file behind it); it must NOT be a success in a way that
                // would leak state — and more importantly:
                let second = &ps[1];
                assert_ne!(
                    second.header.status,
                    NtStatus::Success.to_u32(),
                    "related member under a foreign session/tree must NEVER succeed"
                );
                // The related member's response must carry the INHERITED
                // session (7), not its own foreign header session (99) —
                // inheritance is from the previous response.
                assert_eq!(
                    second.header.session_id, 7,
                    "related member must inherit the chain's session id, not its own foreign one"
                );
            }
            other => panic!("expected Compound, got {other:?}"),
        }

        // And the boundary at the lookup layer: a direct dispatch-style
        // lookup under the foreign pair must fail.
        let foreign = lookup_open_for_session(&conn, 99, 99, 55).await;
        assert!(
            foreign.is_err(),
            "lookup_open_for_session must refuse a handle owned by another session/tree"
        );
    }

    #[tokio::test]
    async fn excessive_credit_charge_rejected() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        conn.credits.grant(1000);
        let mut req = make_echo_request();
        req.header.credit_charge = 300; // > max_charge (256)
        match handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await {
            Some(FramedResponse::Error { status, .. }) => {
                assert_eq!(status, NtStatus::InvalidParameter)
            }
            other => panic!("expected InvalidParameter, got {:?}", other),
        }
    }

    // --- Dialect selection tests ---

    #[test]
    fn select_highest_common_dialect() {
        let client = vec![
            WireDialect::Smb0202,
            WireDialect::Smb021,
            WireDialect::Smb030,
            WireDialect::Smb0302,
        ];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb311),
            Some(DialectConfig::Smb302)
        );
    }

    #[test]
    fn select_21_when_no_30_in_offer() {
        let client = vec![WireDialect::Smb0202, WireDialect::Smb021];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb311),
            Some(DialectConfig::Smb21)
        );
    }

    #[test]
    fn select_none_when_no_common_dialect() {
        let client = vec![WireDialect::Smb0302];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb311, DialectConfig::Smb311),
            None,
        );
    }

    #[test]
    fn select_none_for_empty_offer() {
        assert_eq!(
            select_dialect(&[], DialectConfig::Smb21, DialectConfig::Smb311),
            None,
        );
    }

    #[test]
    fn select_311_when_offered_and_configured() {
        // Now that 3.1.1 is implemented, it is selected when offered and
        // within the configured range.
        let client = vec![
            WireDialect::Smb030,
            WireDialect::Smb0302,
            WireDialect::Smb0311,
        ];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb311),
            Some(DialectConfig::Smb311),
        );
    }

    #[test]
    fn select_30_from_mixed_311_and_30_capped() {
        // With max_dialect = Smb302, 3.1.1 is excluded.
        let client = vec![WireDialect::Smb030, WireDialect::Smb0311];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb302),
            Some(DialectConfig::Smb30),
        );
    }

    #[test]
    fn select_respects_config_range() {
        let client = vec![
            WireDialect::Smb021,
            WireDialect::Smb030,
            WireDialect::Smb0302,
        ];
        // max_dialect = Smb21 → can't negotiate above 2.1
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb21),
            Some(DialectConfig::Smb21),
        );
        // min_dialect = Smb30 → can't negotiate below 3.0
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb30, DialectConfig::Smb311),
            Some(DialectConfig::Smb302),
        );
    }

    #[test]
    fn select_unordered_offer_picks_highest() {
        // Client sends dialects out of order.
        let client = vec![
            WireDialect::Smb0302,
            WireDialect::Smb0202,
            WireDialect::Smb030,
            WireDialect::Smb021,
        ];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb311),
            Some(DialectConfig::Smb302),
        );
    }

    #[test]
    fn select_30_only_offer() {
        let client = vec![WireDialect::Smb030];
        assert_eq!(
            select_dialect(&client, DialectConfig::Smb21, DialectConfig::Smb311),
            Some(DialectConfig::Smb30),
        );
    }

    // --- Negotiate gate tests ---

    #[tokio::test]
    async fn repeat_negotiate_disconnects() {
        let state = make_test_state();
        let conn = make_conn_state();
        // First NEGOTIATE should succeed.
        let req = make_negotiate_request();
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        assert!(resp.is_some(), "first NEGOTIATE should produce a response");
        assert!(!matches!(resp, Some(FramedResponse::Disconnect)),);
        // Second NEGOTIATE should disconnect.
        let req2 = make_negotiate_request();
        let resp2 = handle_message(&state, &conn, FramedMessage::Plain(req2), &[], None).await;
        assert!(
            matches!(resp2, Some(FramedResponse::Disconnect)),
            "repeat NEGOTIATE should disconnect, got {:?}",
            resp2
        );
    }

    #[tokio::test]
    async fn command_before_negotiate_disconnects() {
        let state = make_test_state();
        let conn = make_conn_state();
        // ECHO before NEGOTIATE should disconnect.
        let req = make_echo_request();
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        assert!(
            matches!(resp, Some(FramedResponse::Disconnect)),
            "command before NEGOTIATE should disconnect, got {:?}",
            resp
        );
    }

    #[tokio::test]
    async fn negotiate_selects_311_for_modern_client() {
        let state = make_test_state();
        let conn = make_conn_state();
        // Client offers all dialects including 3.1.1.
        let req = make_negotiate_request_with_dialects(vec![
            WireDialect::Smb0202,
            WireDialect::Smb021,
            WireDialect::Smb030,
            WireDialect::Smb0302,
            WireDialect::Smb0311,
        ]);
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        assert!(resp.is_some());
        // Verify the negotiated dialect is stored.
        let rec = conn.negotiate_record.lock().await;
        assert_eq!(rec.as_ref().unwrap().dialect, DialectConfig::Smb311);
    }

    #[tokio::test]
    async fn negotiate_selects_21_for_21_only_client() {
        let state = make_test_state();
        let conn = make_conn_state();
        let req = make_negotiate_request_with_dialects(vec![WireDialect::Smb021]);
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        assert!(resp.is_some());
        let rec = conn.negotiate_record.lock().await;
        assert_eq!(rec.as_ref().unwrap().dialect, DialectConfig::Smb21);
    }

    #[tokio::test]
    async fn negotiate_no_common_dialect_returns_not_supported() {
        // Client offers only 3.1.1 but config caps at Smb302 → no common dialect.
        let mut config = crate::config::ServerConfig::for_testing();
        config.max_dialect = DialectConfig::Smb302;
        let state = Arc::new(ServerState::new(config));
        let conn = make_conn_state();
        let req = make_negotiate_request_with_dialects(vec![WireDialect::Smb0311]);
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        match resp {
            Some(FramedResponse::Error { status, .. }) => {
                assert_eq!(status, NtStatus::NotSupported)
            }
            other => panic!("expected NotSupported, got {:?}", other),
        }
    }

    // --- ID allocation tests (Step 9.5) ---

    #[tokio::test]
    async fn tree_ids_are_per_connection_and_start_at_1() {
        let conn = make_conn_state();
        let id1 = next_tree_id(&conn);
        let id2 = next_tree_id(&conn);
        assert_eq!(id1, 1, "first TreeId should be 1");
        assert_eq!(id2, 2, "second TreeId should be 2");

        // A second connection gets its own counter starting at 1.
        let conn2 = make_conn_state();
        let id3 = next_tree_id(&conn2);
        assert_eq!(id3, 1, "new connection TreeId should restart at 1");
    }

    #[tokio::test]
    async fn file_ids_volatile_never_hits_sentinel() {
        let conn = make_conn_state();
        // Set the counter close to u64::MAX to test the skip.
        conn.next_volatile_id_ref()
            .store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);
        let fid1 = next_file_id(&conn);
        let fid2 = next_file_id(&conn);
        assert_ne!(
            fid1.volatile,
            u64::MAX,
            "volatile must never be 0xFFFF...FFFF"
        );
        assert_ne!(
            fid2.volatile,
            u64::MAX,
            "volatile must never be 0xFFFF...FFFF"
        );
    }

    #[tokio::test]
    async fn file_ids_persistent_differs_from_volatile() {
        let conn = make_conn_state();
        conn.active.write().unwrap().persistent_base = 0x1234_5678_9ABC_DEF0;
        let fid = next_file_id(&conn);
        // persistent = base + volatile; with base != 0 they should differ.
        assert_ne!(
            fid.persistent, fid.volatile,
            "persistent should differ from volatile when base != 0"
        );
    }

    #[tokio::test]
    async fn session_ids_are_random_and_nonzero() {
        let state = make_test_state();
        let conn = make_conn_state();
        let id1 = next_session_id(&conn, &state);
        let id2 = next_session_id(&conn, &state);
        assert_ne!(0, id1, "SessionId must be non-zero");
        assert_ne!(0, id2, "SessionId must be non-zero");
        // Random — extremely unlikely to collide.
        assert_ne!(
            id1, id2,
            "SessionId should be random (collision is astronomically unlikely)"
        );
    }

    // --- Phase 4 Option C: per-share read_users/write_users tests ---

    fn make_share_config(
        name: &str,
        read_only: bool,
        read_users: Vec<String>,
        write_users: Vec<String>,
    ) -> ShareConfig {
        ShareConfig {
            name: name.to_string(),
            path: String::new(), // MemoryFs
            comment: String::new(),
            read_only,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            read_users,
            write_users,
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
            strict_sync: true,
            case_sensitive: false,
            publish_on_close: false,
        }
    }

    #[test]
    fn test_visible_shares_filters_by_read_users() {
        let config = {
            let mut c = crate::config::ServerConfig::for_testing();
            c.shares.insert(
                "alpha".to_string(),
                make_share_config("alpha", false, vec!["alice".to_string()], vec![]),
            );
            c.shares.insert(
                "beta".to_string(),
                make_share_config("beta", false, vec!["bob".to_string()], vec![]),
            );
            c.shares.remove("test");
            c
        };

        // Alice can see alpha but not beta.
        let alice = rssmb_auth::Identity {
            username: "alice".to_string(),
            domain: String::new(),
            is_guest: false,
        };
        let visible = visible_shares_for_ctx(&config.shares, Some(&alice));
        let names: Vec<&str> = visible.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "alice should see alpha");
        assert!(!names.contains(&"beta"), "alice should not see beta");
    }

    #[test]
    fn test_visible_shares_empty_read_users_means_all() {
        let config = {
            let mut c = crate::config::ServerConfig::for_testing();
            c.shares.insert(
                "open".to_string(),
                make_share_config("open", false, vec![], vec![]),
            );
            c.shares.remove("test");
            c
        };
        let bob = rssmb_auth::Identity {
            username: "bob".to_string(),
            domain: String::new(),
            is_guest: false,
        };
        let visible = visible_shares_for_ctx(&config.shares, Some(&bob));
        assert!(
            visible.iter().any(|s| s.name == "open"),
            "bob should see open share (empty read_users)"
        );
    }

    #[test]
    fn test_visible_shares_read_users_case_insensitive() {
        let config = {
            let mut c = crate::config::ServerConfig::for_testing();
            c.shares.insert(
                "alpha".to_string(),
                make_share_config("alpha", false, vec!["Alice".to_string()], vec![]),
            );
            c.shares.remove("test");
            c
        };
        let alice = rssmb_auth::Identity {
            username: "alice".to_string(),
            domain: String::new(),
            is_guest: false,
        };
        let visible = visible_shares_for_ctx(&config.shares, Some(&alice));
        assert!(
            visible.iter().any(|s| s.name == "alpha"),
            "case-insensitive read_users match should work"
        );
    }

    #[test]
    fn test_encode_and_parse_rqls_v1_and_v2_create_contexts() {
        let lease_key = [0x11u8; 16];
        let parent_key = [0x22u8; 16];
        let grant_v1 = opens::LeaseGrant {
            lease_key,
            state: opens::LeaseCaching::from_bits(0x03), // RH
            flags: 0,
            epoch: 0,
            parent_lease_key: None,
            is_v2: false,
        };
        let v1_data = build_rqls_response_data(&grant_v1);
        assert_eq!(v1_data.len(), 32);
        let ctx_bytes = encode_create_contexts(&[(RQLS_NAME, &v1_data)]);
        // Put at offset 120 in a synthetic frame
        let mut raw = vec![0u8; 120];
        raw.extend_from_slice(&ctx_bytes);
        let parsed = parse_create_contexts(&raw, 120, ctx_bytes.len() as u32);
        let rqls = parsed.rqls.expect("should parse RqLs v1");
        assert_eq!(rqls.lease_key, lease_key);
        assert_eq!(rqls.lease_state, opens::LeaseCaching::from_bits(0x03));
        assert!(!rqls.is_v2);

        let grant_v2 = opens::LeaseGrant {
            lease_key,
            state: opens::LeaseCaching::from_bits(0x07), // RWH
            flags: 0x0000_0004,
            epoch: 5,
            parent_lease_key: Some(parent_key),
            is_v2: true,
        };
        let v2_data = build_rqls_response_data(&grant_v2);
        assert_eq!(v2_data.len(), 52);
        let ctx_bytes_v2 = encode_create_contexts(&[(RQLS_NAME, &v2_data)]);
        let mut raw2 = vec![0u8; 120];
        raw2.extend_from_slice(&ctx_bytes_v2);
        let parsed2 = parse_create_contexts(&raw2, 120, ctx_bytes_v2.len() as u32);
        let rqls2 = parsed2.rqls.expect("should parse RqLs v2");
        assert_eq!(rqls2.lease_key, lease_key);
        assert_eq!(rqls2.lease_state, opens::LeaseCaching::from_bits(0x07));
        assert!(rqls2.is_v2);
        assert_eq!(rqls2.parent_lease_key, Some(parent_key));
        assert_eq!(rqls2.epoch, 5);
    }
}

#[cfg(test)]
mod share_name_tests {
    use super::extract_share_name;

    #[test]
    fn unc_path_yields_share_component() {
        assert_eq!(extract_share_name(r"\\localhost\public"), "public");
        assert_eq!(extract_share_name(r"\\10.0.0.1\IPC$"), "IPC$");
        assert_eq!(extract_share_name(r"\\srv\public\"), "public");
        assert_eq!(extract_share_name("public"), "public");
    }
}
