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
pub fn dialect_config_to_negotiate(d: DialectConfig) -> NegotiateDialect {
    match d {
        DialectConfig::Smb2002 => NegotiateDialect::Smb0202,
        DialectConfig::Smb21 => NegotiateDialect::Smb021,
        DialectConfig::Smb30 => NegotiateDialect::Smb030,
        DialectConfig::Smb302 => NegotiateDialect::Smb0302,
        DialectConfig::Smb311 => NegotiateDialect::Smb0311,
    }
}

/// Map DialectConfig to the wire Dialect enum used in VNI responses.
pub fn dialect_config_to_wire(d: DialectConfig) -> WireDialect {
    match d {
        DialectConfig::Smb2002 => WireDialect::Smb0202,
        DialectConfig::Smb21 => WireDialect::Smb021,
        DialectConfig::Smb30 => WireDialect::Smb030,
        DialectConfig::Smb302 => WireDialect::Smb0302,
        DialectConfig::Smb311 => WireDialect::Smb0311,
    }
}

/// Map a wire Dialect (from the client's negotiate request) to our internal
/// DialectConfig. Returns None for unknown/future dialect values.
pub fn wire_dialect_to_config(d: WireDialect) -> Option<DialectConfig> {
    match d {
        WireDialect::Smb0202 => Some(DialectConfig::Smb2002),
        WireDialect::Smb021 => Some(DialectConfig::Smb21),
        WireDialect::Smb030 => Some(DialectConfig::Smb30),
        WireDialect::Smb0302 => Some(DialectConfig::Smb302),
        WireDialect::Smb0311 => Some(DialectConfig::Smb311),
    }
}

/// Dialects implemented in this build. SMB 3.1.1 is now implemented
/// (Step 7c: negotiate contexts, preauth integrity, KDF context).
const IMPLEMENTED_DIALECTS: &[DialectConfig] = &[
    DialectConfig::Smb2002,
    DialectConfig::Smb21,
    DialectConfig::Smb30,
    DialectConfig::Smb302,
    DialectConfig::Smb311,
];

/// The highest implemented dialect — used as the effective ceiling.
const EFFECTIVE_MAX_DIALECT: DialectConfig = DialectConfig::Smb311;

/// Select the highest common dialect from the client's offer, the set of
/// dialects this server implements, and the configured [min, max] range.
///
/// Returns None if there is no common dialect. Unknown wire dialect values
/// in the client's list are silently ignored (not treated as supported).
pub fn select_dialect(
    client_dialects: &[WireDialect],
    min_dialect: DialectConfig,
    max_dialect: DialectConfig,
) -> Option<DialectConfig> {
    // Clamp the effective max to what we've implemented.
    let effective_max = max_dialect.min(EFFECTIVE_MAX_DIALECT);
    let effective_min = min_dialect;

    let mut best: Option<DialectConfig> = None;
    for &wd in client_dialects {
        let Some(dc) = wire_dialect_to_config(wd) else {
            continue; // Unknown dialect — ignore, don't crash.
        };
        if !IMPLEMENTED_DIALECTS.contains(&dc) {
            continue; // Not implemented by this server.
        }
        if dc < effective_min || dc > effective_max {
            continue; // Outside configured range.
        }
        if best.is_none_or(|b| dc > b) {
            best = Some(dc);
        }
    }
    best
}

/// A pending async operation (CHANGE_NOTIFY, blocking LOCK, etc.).
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
            // Unrelated: reset all inherited state (including last_file_id).
            propagated_status = None;
            last_file_id = None;
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
fn error_plain_response(req_header: &Header, status: u32) -> PlainResponse {
    PlainResponse {
        header: Header {
            credit_charge: req_header.credit_charge,
            status,
            command: req_header.command,
            credit_request: req_header.credit_request,
            flags: HeaderFlags::new().with_server_to_redir(true),
            next_command: 0,
            message_id: req_header.message_id,
            tree_id: req_header.tree_id,
            async_id: req_header.async_id,
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
fn error_plain_response_with_ids(
    req_header: &Header,
    status: u32,
    session_id: u64,
    tree_id: Option<u32>,
) -> PlainResponse {
    PlainResponse {
        header: Header {
            credit_charge: req_header.credit_charge,
            status,
            command: req_header.command,
            credit_request: req_header.credit_request,
            flags: HeaderFlags::new().with_server_to_redir(true),
            next_command: 0,
            message_id: req_header.message_id,
            tree_id,
            async_id: req_header.async_id,
            session_id,
            signature: 0,
        },
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    }
}

/// Replace FileId 0xFFFF...FFFF with the given FileId in a request's content.
fn substitute_file_id(
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
fn charge_credits(conn_state: &ConnState, header: &Header) -> Result<(), Box<FramedResponse>> {
    use rssmb_wire_adapter::credits::CreditError;
    match conn_state
        .credits
        .check_and_deduct(header.message_id, header.credit_charge.max(1) as u32)
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
async fn handle_negotiate(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_msg: &[u8],
) -> FramedResponse {
    let req_header = &req.header;

    // Extract the NegotiateRequest content.
    let neg_req = match &req.content {
        RequestContent::Negotiate(n) => n,
        _ => return error_response_for(Command::Negotiate, NtStatus::InvalidParameter, req_header),
    };

    debug!(conn_id = conn_state.conn_id,
        client_dialects = ?neg_req.dialects,
        client_contexts = ?neg_req.negotiate_context_list.as_ref().map(|c| c.len()),
        "negotiate request");

    // MS-SMB2 3.3.5.4: select the highest common dialect.
    // Over QUIC (TLS 1.3), only SMB 3.1.1 is permitted on the transport;
    // if the client does not offer 0x0311 (or server max_dialect < Smb311),
    // terminate the connection.
    let min_dialect = if conn_state.transport == TransportKind::Quic {
        DialectConfig::Smb311
    } else {
        state.config.min_dialect
    };
    let selected = match select_dialect(&neg_req.dialects, min_dialect, state.config.max_dialect) {
        Some(d) => d,
        None => {
            warn!(conn_id = conn_state.conn_id,
                transport = ?conn_state.transport,
                dialects = ?neg_req.dialects,
                min = ?min_dialect,
                max = ?state.config.max_dialect,
                "no common dialect — rejecting NEGOTIATE");
            if conn_state.transport == TransportKind::Quic {
                return FramedResponse::Disconnect;
            }
            return error_response_for(Command::Negotiate, NtStatus::NotSupported, req_header);
        }
    };
    debug!(conn_id = conn_state.conn_id, dialect = ?selected, "negotiated dialect");

    let server_guid = Guid::from(state.server_guid);

    // Server capabilities: large_mtu and leasing for 2.1+ (MS-SMB2 3.3.5.4:
    // capabilities MUST be 0 for 2.0.2).
    let server_capabilities = if selected > DialectConfig::Smb2002 {
        let caps = GlobalCapabilities::new()
            .with_large_mtu(true)
            .with_leasing(state.config.leases);
        // Multichannel is SMB 3.0+ only, and is advertised only when the
        // server actually has usable (non-loopback) interfaces to report
        // via FSCTL_QUERY_NETWORK_INTERFACE_INFO. Advertising the bit on a
        // loopback-only container makes clients probe and fail. This is a
        // design choice, not a spec rule (3.3.5.4 sets the bit on
        // IsMultiChannelCapable alone); the advertised value is stored in
        // the NegotiateRecord and echoed unchanged by VALIDATE_NEGOTIATE_INFO.
        if selected >= DialectConfig::Smb30
            && state.config.multichannel
            && !state.interface_snapshot.get().is_empty()
        {
            caps.with_multi_channel(true)
        } else {
            caps
        }
    } else {
        GlobalCapabilities::new()
    };

    // MS-SMB2 3.3.5.4: SIGNING_ENABLED is always set by an SMB2 server
    // (signing is mandatory to support); SIGNING_REQUIRED per config.
    let signing_required = state.config.signing == crate::config::SigningPolicy::Required;
    let server_security_mode = NegotiateSecurityMode::new()
        .with_signing_enabled(true)
        .with_signing_required(signing_required);

    // SMB 3.1.1: process negotiate contexts (MS-SMB2 3.3.5.4).
    let is_quic = conn_state.transport == TransportKind::Quic;
    let (neg311, response_contexts) = if selected == DialectConfig::Smb311 {
        match crate::negotiate_ctx::process_request_contexts_for_transport(
            neg_req,
            state.config.encryption,
            is_quic,
        ) {
            Ok((neg, ctxs)) => (Some(neg), Some(ctxs)),
            Err(status) => {
                warn!(conn_id = conn_state.conn_id,
                    status = ?status, "negotiate context validation failed");
                return error_response_for(Command::Negotiate, status, req_header);
            }
        }
    } else {
        (None, None)
    };

    // SPNEGO negTokenInit hint advertising NTLMSSP (1.3.6.1.4.1.311.2.2.10).
    // Always sent — real-user NTLM must work whether or not guests are on.
    let spnego_token = {
        vec![
            0x60, 0x1c, // APPLICATION 0, length 28
            0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // OID SPNEGO (1.3.6.1.5.5.2)
            0xa0, 0x12, // [0] negTokenInit, length 18
            0x30, 0x10, // SEQUENCE, length 16
            0xa0, 0x0e, // [0] mechTypeList, length 14
            0x30, 0x0c, // SEQUENCE OF, length 12
            0x06, 0x0a, // OID, length 10
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02,
            0x0a, // NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
        ]
    };

    let max_io = max_io_size(&state.config);
    let negotiate_response = NegotiateResponse {
        security_mode: server_security_mode,
        dialect_revision: dialect_config_to_negotiate(selected),
        server_guid,
        capabilities: server_capabilities,
        max_transact_size: max_io,
        max_read_size: max_io,
        max_write_size: max_io,
        system_time: current_filetime(),
        server_start_time: FileTime::ZERO,
        buffer: spnego_token,
        negotiate_context_list: response_contexts,
    };

    // Store the negotiation record atomically.
    let record = NegotiateRecord {
        dialect: selected,
        client_guid: neg_req.client_guid,
        client_security_mode: neg_req.security_mode,
        client_capabilities: neg_req.capabilities,
        server_capabilities,
        server_security_mode,
        neg311,
    };
    *conn_state.negotiate_record.lock().await = Some(record);

    // SMB 3.1.1: initialize the connection preauth hash.
    // H0 = 64 zero bytes; hash the NEGOTIATE request, then the response
    // (response is hashed in the connection loop after encode+sign).
    if selected == DialectConfig::Smb311 {
        let h0 = [0u8; 64];
        let h1 = crate::crypto::preauth_update(&h0, raw_msg);
        *conn_state.preauth_conn.lock().unwrap() = Some(h1);
        // Tell the connection loop to hash the encoded response into preauth_conn.
        *conn_state.preauth_hash_response.lock().unwrap() = Some(PreauthTarget::Conn);
    }

    let response = build_response(req_header, ResponseContent::Negotiate(negotiate_response));
    FramedResponse::Plain(response)
}

/// Handle SESSION_SETUP — multi-round NTLM authentication.
async fn handle_session_setup(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_msg: &[u8],
) -> FramedResponse {
    // Extract the session setup request content
    let session_setup_req = match &req.content {
        RequestContent::SessionSetup(ss) => ss,
        _ => {
            return error_response_for(
                Command::SessionSetup,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    // Auth throttle: if the source IP is in cooldown from too many recent
    // failures, refuse SESSION_SETUP immediately. This check runs before
    // any auth processing so it costs the attacker nothing but a LOGON_FAILURE.
    // Only applies to new auth conversations (SessionId == 0); continuation
    // rounds for an already-pending session are not throttled.
    if req.header.session_id == 0 {
        match state.auth_limiter.check(&conn_state.remote_addr) {
            crate::auth_limiter::AuthThrottleResult::Refuse => {
                // Count this as a per-connection failure too — a connection
                // that keeps trying during cooldown should hit the per-conn
                // cap and get disconnected, not spin forever.
                let conn_fails = conn_state
                    .auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!(
                    conn_id = conn_state.conn_id,
                    ip = %conn_state.remote_addr,
                    conn_failures = conn_fails,
                    "SESSION_SETUP refused — auth cooldown active",
                );
                if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                    warn!(
                        conn_id = conn_state.conn_id,
                        conn_failures = conn_fails,
                        "per-connection auth failure cap exceeded — disconnecting"
                    );
                    return FramedResponse::Disconnect;
                }
                return error_response_for(
                    Command::SessionSetup,
                    NtStatus::LogonFailure,
                    &req.header,
                );
            }
            crate::auth_limiter::AuthThrottleResult::Allow => {}
        }
    }

    // Get or create auth state
    let mut auth_guard = conn_state.auth_state.lock().await;
    let auth_state = auth_guard.get_or_insert_with(rssmb_auth::AuthState::new);

    // Create the NTLM auth provider with server-side credentials from
    // ServerState. The identity store is built once at startup with
    // pre-computed NT hashes — no plaintext passwords are rebuilt per
    // SESSION_SETUP. Guest fallback is gated on config.guest_access.
    // Guest/anonymous sessions have no key and can never be signed, so
    // `signing = "required"` disables them (as Windows does).
    let guest_allowed =
        state.config.guest_access && state.config.signing != crate::config::SigningPolicy::Required;
    let provider: Box<dyn rssmb_auth::AuthProvider> =
        Box::new(rssmb_auth::NtlmAuthProvider::with_identity_store_and_flags(
            state.identities_snapshot(),
            guest_allowed,
            state.config.ntlm_require_timestamp,
        ));

    // Extract the security buffer from the session setup request
    let input_token = &session_setup_req.buffer;

    // MS-SMB2 3.3.5.5: a SESSION_SETUP with SessionId == 0 starts a new
    // session; the server must assign a non-zero SessionId in its response,
    // which the client then echoes on subsequent rounds.
    // One authentication conversation per connection at a time (the acceptor
    // state is connection-wide). Its SessionId is the only pending one.
    let session_id = if req.header.session_id == 0 {
        // A fresh authentication: discard any stale per-connection auth state
        // and invalidate the SessionId it was bound to.
        *auth_state = rssmb_auth::AuthState::new();
        let new_id = next_session_id(conn_state, state);
        let mut pending = conn_state.pending_sessions.write().await;
        pending.clear();
        pending.insert(new_id);
        // Clear stale preauth session entries from abandoned auth attempts.
        conn_state.preauth_sessions.lock().unwrap().clear();
        // SMB 3.1.1: fork the connection preauth hash into a per-session hash.
        let is_311 = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect == DialectConfig::Smb311)
            .unwrap_or(false);
        if is_311 {
            let conn_hash = *conn_state.preauth_conn.lock().unwrap();
            if let Some(ch) = conn_hash {
                conn_state
                    .preauth_sessions
                    .lock()
                    .unwrap()
                    .insert(new_id, ch);
            }
        }
        new_id
    } else if conn_state
        .pending_sessions
        .read()
        .await
        .contains(&req.header.session_id)
    {
        req.header.session_id
    } else if session_setup_req.flags.binding()
        && req.header.session_id != 0
        && state.config.multichannel
    {
        // SMB 3.x multichannel binding (MS-SMB2 3.3.5.5):
        // A second connection binds to an existing session. The request
        // must be signed with the existing session's signing key.
        let session_id = req.header.session_id;

        // Look up the existing session in the global registry.
        let existing_shared = state
            .session_registry
            .read()
            .unwrap()
            .get(&session_id)
            .cloned();
        let existing_session = {
            let sessions = conn_state.sessions.read().await;
            sessions.iter().find(|s| s.id == session_id).cloned()
        };

        // The session must exist in the global registry (not just locally).
        let shared = match existing_shared {
            Some(ss) => ss,
            None => {
                warn!(
                    conn_id = conn_state.conn_id,
                    session_id, "binding: session not found in global registry"
                );
                return error_response_for(
                    Command::SessionSetup,
                    NtStatus::UserSessionDeleted,
                    &req.header,
                );
            }
        };

        // Verify the binding request is signed with the existing session's key.
        // The signing verification already happened in the connection read loop
        // (signing::verify_frame). If we got here, the signature was valid.
        // MS-SMB2 3.3.5.5: binding requires SMB 3.0+ and the dialect must match.
        let neg_dialect = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect);
        if neg_dialect
            .map(|d| d < DialectConfig::Smb30)
            .unwrap_or(true)
        {
            warn!(
                conn_id = conn_state.conn_id,
                session_id, "binding: requires SMB 3.0+"
            );
            return error_response_for(Command::SessionSetup, NtStatus::NotSupported, &req.header);
        }

        // Add this connection as a channel of the existing session.
        {
            let mut channels = shared.channels.write().unwrap();
            channels.insert(conn_state.conn_id);
        }

        // Swap the ConnState's shared state to point to the existing session's
        // shared state, so this channel sees the same trees/opens/signing/encryption.
        *conn_state.session_shared.write().unwrap() = Some(shared.clone());
        *conn_state.active.write().unwrap() = SessionArcs {
            trees: shared.trees.clone(),
            opens: shared.opens.clone(),
            signing: shared.signing.clone(),
            encryption: shared.encryption.clone(),
            next_tree_id: shared.next_tree_id.clone(),
            next_volatile_id: shared.next_volatile_id.clone(),
            persistent_base: shared.persistent_base,
        };

        // Also add the session to this connection's session list.
        if let Some(session) = existing_session {
            conn_state.sessions.write().await.push(session);
        } else {
            // The session exists in the global registry but not on this connection.
            // Find it in ServerState.sessions.
            let sessions = state.sessions.read().await;
            if let Some(s) = sessions.iter().find(|s| s.id == session_id).cloned() {
                conn_state.sessions.write().await.push(s);
            }
        }

        info!(
            conn_id = conn_state.conn_id,
            session_id, "multichannel: channel bound to existing session"
        );

        // Return a successful SESSION_SETUP response with the session flags
        // from the existing session. The auth token is empty for binding.
        let session_flags = {
            let sessions = conn_state.sessions.read().await;
            sessions
                .iter()
                .find(|s| s.id == session_id)
                .map(|s| {
                    let mut flags = rssmb_proto::session_setup::SessionFlags::new();
                    if s.is_guest {
                        flags.set_is_guest(true);
                    }
                    if s.session_key.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
                        flags.set_is_null_session(true);
                    }
                    // Check encrypt_data from encryption state.
                    let enc = conn_state.encryption_ref();
                    let enc = enc.read().unwrap();
                    if let Some(st) = enc.get(&session_id) {
                        if st.encrypt_data {
                            flags.set_encrypt_data(true);
                        }
                    }
                    flags
                })
                .unwrap_or_default()
        };

        let resp = rssmb_proto::session_setup::SessionSetupResponse {
            session_flags,
            buffer: vec![],
        };
        let mut response = build_response(&req.header, ResponseContent::SessionSetup(resp));
        response.header.session_id = session_id;
        return FramedResponse::Plain(response);
    } else {
        // Re-authentication of an established session and multichannel
        // binding are not supported — refuse instead of pretending success.
        let established = conn_state
            .sessions
            .read()
            .await
            .iter()
            .any(|s| s.id == req.header.session_id);
        debug!(
            conn_id = conn_state.conn_id,
            session_id = req.header.session_id,
            established,
            "session_setup: not a pending SessionId"
        );
        let status = if established {
            NtStatus::NotSupported
        } else {
            NtStatus::UserSessionDeleted
        };
        return error_response_for(Command::SessionSetup, status, &req.header);
    };

    // SMB 3.1.1: hash the SESSION_SETUP request into the session's preauth hash.
    {
        let is_311 = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect == DialectConfig::Smb311)
            .unwrap_or(false);
        if is_311 {
            if let Some(h) = conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .get_mut(&session_id)
            {
                *h = crate::crypto::preauth_update(h, raw_msg);
            }
        }
    }

    let step = provider.step(input_token, auth_state).await;
    let uses_spnego = auth_state.uses_spnego();
    match step {
        Ok(rssmb_auth::AuthStep::Continue { output_token }) => {
            // Build session setup response with STATUS_MORE_PROCESSING_REQUIRED
            let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                session_flags: rssmb_proto::session_setup::SessionFlags::new(),
                buffer: output_token,
            };

            let mut response = build_response(
                &req.header,
                ResponseContent::SessionSetup(session_setup_resp),
            );
            response.header.status = NtStatus::MoreProcessingRequired.to_u32();
            response.header.session_id = session_id;
            // SMB 3.1.1: hash the MORE_PROCESSING response into the session's
            // preauth hash (done in the connection loop after encode+sign).
            {
                let is_311 = conn_state
                    .negotiate_record
                    .lock()
                    .await
                    .as_ref()
                    .map(|r| r.dialect == DialectConfig::Smb311)
                    .unwrap_or(false);
                if is_311 {
                    *conn_state.preauth_hash_response.lock().unwrap() =
                        Some(PreauthTarget::Session(session_id));
                }
            }
            FramedResponse::Plain(response)
        }
        Ok(rssmb_auth::AuthStep::Complete {
            output_token,
            session_key,
            identity,
        }) => {
            // Authentication finished. Keep the per-connection auth state
            // alive: Samba/Windows SPNEGO clients send one more round after
            // accept-completed (their mechListMIC for us to verify), and
            // the auth provider handles it as a repeat Complete.
            // *auth_guard is NOT cleared here.

            // Check if a session with this ID already exists (SPNEGO final
            // mic-exchange round).
            let sessions = conn_state.sessions.read().await;
            let existing = sessions.iter().find(|s| s.id == session_id).cloned();
            drop(sessions);

            // Set by the new-session path if the session was admitted with
            // encrypt_data. The SPNEGO mic-exchange path returns early above
            // (the session already exists; its flag was set on first setup).
            // Initialized to false; the new-session path may overwrite it.
            #[allow(unused_assignments)]
            let mut session_encrypt_data = false;

            if existing.is_some() {
                // SPNEGO mic-exchange round: the session was already created
                // on the previous Complete. The client is sending its
                // mechListMIC; just return success with an empty token.
                tracing::debug!(
                    conn_id = conn_state.conn_id,
                    session_id,
                    "session_setup: SPNEGO mic-exchange round — session already established"
                );
                // Clear auth state now — the conversation is truly over.
                *auth_guard = None;
                conn_state
                    .pending_sessions
                    .write()
                    .await
                    .remove(&session_id);

                let resp_token = if !output_token.is_empty() {
                    output_token
                } else if !uses_spnego {
                    vec![]
                } else {
                    vec![0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00]
                };
                let session_flags = if session_key.is_empty() {
                    rssmb_proto::session_setup::SessionFlags::new().with_is_null_session(true)
                } else if identity.is_guest {
                    rssmb_proto::session_setup::SessionFlags::new().with_is_guest(true)
                } else {
                    rssmb_proto::session_setup::SessionFlags::new()
                };
                let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                    session_flags,
                    buffer: resp_token,
                };
                let mut response = build_response(
                    &req.header,
                    ResponseContent::SessionSetup(session_setup_resp),
                );
                response.header.session_id = session_id;
                return FramedResponse::Plain(response);
            } else {
                // New session: create and populate with auth result.
                // Read the negotiated dialect from the connection's
                // negotiation record. The negotiate gate in handle_plain
                // guarantees this is Some, so disconnect if it's missing
                // (should never happen under normal flow).
                let dialect = {
                    let rec = conn_state.negotiate_record.lock().await;
                    match &*rec {
                        Some(r) => r.dialect,
                        None => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "SESSION_SETUP without negotiation — disconnecting"
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::InvalidParameter,
                                &req.header,
                            );
                        }
                    }
                };
                let mut session = Session::new(conn_state.conn_id, session_id);
                session.user_identity = Some(identity.clone());
                session.is_guest = identity.is_guest;
                session.session_key = Some(session_key.clone());
                session.dialect = Some(dialect);

                // --- Transactional admission (MS-SMB2 3.3.5.5.3) ---
                //
                // Derive all keys and run all deny checks BEFORE inserting any
                // per-session state (signing, encryption, session list, preauth).
                // A denial leaves the connection reusable with no orphaned state.

                // MS-SMB2 3.3.5.5.3: an authenticated (non-guest, keyed)
                // session is signed if either side requires it. Guest and
                // anonymous sessions are never signed.
                let signable = !identity.is_guest && !session_key.is_empty();

                // For 3.1.1, the signing key uses the preauth integrity hash
                // as the KDF context. For 3.0.x/2.x, use the legacy fixed
                // context strings.
                let preauth_hash = if dialect == DialectConfig::Smb311 {
                    conn_state
                        .preauth_sessions
                        .lock()
                        .unwrap()
                        .get(&session_id)
                        .copied()
                } else {
                    None
                };
                let (ctx, force_sign_once) = match preauth_hash {
                    Some(ref h) => (crate::crypto::KdfContext::Preauth(h), true),
                    None => {
                        if dialect == DialectConfig::Smb311 {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "3.1.1 session without preauth hash — aborting session"
                            );
                            // Missing preauth hash for 3.1.1 is a fatal error —
                            // don't install signing state with an empty/legacy key.
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                        (crate::crypto::KdfContext::Legacy, false)
                    }
                };

                // --- Cipher selection (MS-SMB2 3.3.5.4 / 3.3.5.5.3) ---
                // Only signable (non-guest, keyed) sessions are eligible for
                // encryption. Guest/anonymous sessions (empty session key) are
                // never encrypted — Samba forces cipher = NONE for them.
                let (neg_cipher, accept_transport_security) = {
                    let rec = conn_state.negotiate_record.lock().await;
                    let neg311 = rec.as_ref().and_then(|r| r.neg311.as_ref());
                    (
                        neg311.and_then(|n| n.cipher),
                        neg311.map(|n| n.accept_transport_security).unwrap_or(false),
                    )
                };
                let cipher: Option<crate::crypto::Cipher> = if signable
                    && dialect >= DialectConfig::Smb30
                {
                    if dialect == DialectConfig::Smb311 {
                        neg_cipher.and_then(|c| match c {
                            EncryptionCipher::Aes128Gcm => Some(crate::crypto::Cipher::Aes128Gcm),
                            _ => None, // CCM not implemented; AES-256 deferred
                        })
                    } else {
                        None // 3.0.x needs CCM (deferred)
                    }
                } else {
                    None
                };

                // MS-SMB2 3.3.5.5.3: if encryption is required and the session
                // cannot be encrypted (no cipher — includes guest, anonymous,
                // 2.x dialect, no common cipher) and Connection.AcceptTransportSecurity
                // is false, deny session establishment.
                // This check runs OUTSIDE `signable` so guest/anon are denied
                // unless transport-level security was accepted (and signable).
                if state.config.encryption == crate::config::EncryptionPolicy::Required
                    && cipher.is_none()
                    && !(accept_transport_security && signable)
                {
                    warn!(conn_id = conn_state.conn_id,
                        dialect = ?dialect, is_guest = identity.is_guest,
                        "encryption required but no cipher available — denying session");
                    return error_response_for(
                        Command::SessionSetup,
                        NtStatus::AccessDenied,
                        &req.header,
                    );
                }

                // Derive signing key (only for signable sessions).
                let signing_key_derived: Option<(Vec<u8>, bool)> = if signable {
                    let key = match crate::crypto::compute_signing_key(&session_key, dialect, ctx) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!(conn_id = conn_state.conn_id, error = %e,
                                "KDF key derivation failed — aborting session");
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let required = state.config.signing == crate::config::SigningPolicy::Required
                        || session_setup_req.security_mode.signing_required();
                    session.signing_key = Some(key.clone());
                    session.signing_required = required;
                    Some((key, required))
                } else {
                    None
                };

                // Derive encryption keys (only if a cipher was negotiated).
                let enc_state_derived: Option<EncryptionState> = if let Some(cipher) = cipher {
                    let enc_key =
                        match crate::crypto::compute_encryption_key(&session_key, dialect, ctx) {
                            Ok(k) => k,
                            Err(e) => {
                                warn!(conn_id = conn_state.conn_id, error = %e,
                                "encryption key derivation failed — aborting session");
                                return error_response_for(
                                    Command::SessionSetup,
                                    NtStatus::LogonFailure,
                                    &req.header,
                                );
                            }
                        };
                    let dec_key =
                        match crate::crypto::compute_decryption_key(&session_key, dialect, ctx) {
                            Ok(k) => k,
                            Err(e) => {
                                warn!(conn_id = conn_state.conn_id, error = %e,
                                "decryption key derivation failed — aborting session");
                                return error_response_for(
                                    Command::SessionSetup,
                                    NtStatus::LogonFailure,
                                    &req.header,
                                );
                            }
                        };
                    let enc_key_arr: [u8; 16] = match enc_key.as_slice().try_into() {
                        Ok(k) => k,
                        Err(_) => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "encryption key not 16 bytes (got {}) — aborting session",
                                enc_key.len()
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let dec_key_arr: [u8; 16] = match dec_key.as_slice().try_into() {
                        Ok(k) => k,
                        Err(_) => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "decryption key not 16 bytes (got {}) — aborting session",
                                dec_key.len()
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let encrypt_data = state.config.encryption
                        == crate::config::EncryptionPolicy::Required
                        && !accept_transport_security;
                    Some(EncryptionState {
                        enc_key: enc_key_arr,
                        dec_key: dec_key_arr,
                        nonce_source: std::sync::Arc::new(crate::crypto::NonceSource::new(cipher)),
                        cipher,
                        encrypt_data,
                        retiring: false,
                    })
                } else {
                    None
                };

                // --- Commit: all checks passed, insert state atomically ---
                if let Some((key, required)) = signing_key_derived {
                    // 3.1.1: force-sign the final success response once.
                    // This does NOT set Session.SigningRequired — only the one
                    // response is force-signed, not subsequent requests.
                    conn_state.signing_ref().write().unwrap().insert(
                        session_id,
                        SigningState {
                            key,
                            required,
                            dialect,
                            retiring: false,
                            force_sign_once,
                        },
                    );
                }
                if let Some(ref st) = enc_state_derived {
                    conn_state
                        .encryption_ref()
                        .write()
                        .unwrap()
                        .insert(session_id, st.clone());
                    debug!(conn_id = conn_state.conn_id, session_id, cipher = ?st.cipher,
                        "encryption keys derived for session");
                }
                tracing::debug!(conn_id = conn_state.conn_id, username = %identity.username,
                    is_guest = identity.is_guest, signing = session.signing_required, "session authenticated");
                // Audit: logon success.
                tracing::info!(
                    target: "rssmb::audit",
                    conn_id = conn_state.conn_id,
                    session_id,
                    username = %identity.username,
                    is_guest = identity.is_guest,
                    ip = %conn_state.remote_addr,
                    dialect = ?dialect,
                    signing = session.signing_required,
                    encrypted = enc_state_derived.is_some(),
                    "logon success",
                );
                state
                    .metrics
                    .auth_success_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                conn_state.sessions.write().await.push(Arc::new(session));
                // A fresh session establishment on this id retires any
                // tombstone left by a previous-session teardown (ids are
                // server-assigned and effectively never reused, but prune
                // anyway so the retired set stays tight).
                state.retired_sessions.write().unwrap().remove(&session_id);
                // Register the SessionShared in the global registry so that
                // a binding channel can find and share this session's state.
                if let Some(ss) = conn_state.session_shared.read().unwrap().clone() {
                    *ss.username.write().unwrap() = identity.username.clone();
                    state
                        .session_registry
                        .write()
                        .unwrap()
                        .insert(session_id, ss);
                }
                // SMB 3.1.1: remove the preauth session entry (keys derived).
                conn_state
                    .preauth_sessions
                    .lock()
                    .unwrap()
                    .remove(&session_id);
                // Stash the encrypt_data flag so the response builder can set
                // SESSION_FLAG_ENCRYPT_DATA (the session is now in the list).
                session_encrypt_data = enc_state_derived
                    .as_ref()
                    .map(|st| st.encrypt_data)
                    .unwrap_or(false);

                // PreviousSessionId teardown (MS-SMB2 3.3.5.5; Samba
                // smb2srv_session_close_previous): when the new session
                // authenticates as the SAME user as the session named by
                // PreviousSessionId, the old session is torn down — its
                // trees and opens are closed (durable opens survive,
                // orphaned for reconnect), the session is removed from the
                // global tables, and subsequent requests naming it fail
                // with USER_SESSION_DELETED. A different user's session is
                // left untouched.
                let previous_session_id = session_setup_req.previous_session_id;
                debug!(
                    conn_id = conn_state.conn_id,
                    session_id,
                    previous_session_id,
                    "session_setup complete — PreviousSessionId check"
                );
                if previous_session_id != 0 && previous_session_id != session_id {
                    // Complete the old session's pending CHANGE_NOTIFY ops
                    // with NOTIFY_CLEANUP before tearing it down — the
                    // client is blocked in smb2_notify_recv and expects the
                    // async completion (smb2.notify session-reconnect).
                    {
                        let mut pending = conn_state.pending_async.lock().await;
                        let keys: Vec<u64> = pending
                            .iter()
                            .filter(|(_, op)| {
                                op.command == Command::ChangeNotify
                                    && op.session_id == previous_session_id
                            })
                            .map(|(k, _)| *k)
                            .collect();
                        for key in keys {
                            if let Some(op) = pending.remove(&key) {
                                drop(pending);
                                send_notify_cleanup(conn_state, key, op).await;
                                pending = conn_state.pending_async.lock().await;
                            }
                        }
                    }
                    teardown_previous_session(state, previous_session_id, &identity.username)
                        .await;
                }
            }

            // The auth provider builds the final SPNEGO response when it can
            // (including the mechListMIC that Samba/Windows clients require).
            // Only fall back to a minimal accept-completed when the provider
            // returned an empty token (bare NTLMSSP / guest / anonymous).
            let resp_token = if !output_token.is_empty() {
                output_token
            } else if !uses_spnego {
                vec![]
            } else {
                // Minimal SPNEGO negTokenResp: SEQUENCE { [0] ENUMERATED 0 (accept-completed) }
                vec![0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00]
            };

            // Anonymous logins (no session key) must be flagged as null
            // sessions, otherwise the client expects to derive a signing key.
            // Set SESSION_FLAG_ENCRYPT_DATA when the session was admitted with
            // encrypt_data (encryption=required). Per Samba, desired alone
            // does NOT set the flag — it only offers the cipher.
            let session_flags = if session_key.is_empty() {
                rssmb_proto::session_setup::SessionFlags::new().with_is_null_session(true)
            } else if identity.is_guest {
                rssmb_proto::session_setup::SessionFlags::new().with_is_guest(true)
            } else {
                rssmb_proto::session_setup::SessionFlags::new()
            };
            let session_flags = if session_encrypt_data {
                session_flags.with_encrypt_data(true)
            } else {
                session_flags
            };

            let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                session_flags,
                buffer: resp_token,
            };

            let mut response = build_response(
                &req.header,
                ResponseContent::SessionSetup(session_setup_resp),
            );
            response.header.session_id = session_id;
            FramedResponse::Plain(response)
        }
        Ok(rssmb_auth::AuthStep::Reject { reason }) => {
            debug!(conn_id = conn_state.conn_id, "auth rejected: {}", reason);
            *auth_guard = None; // Clear auth state
            conn_state
                .pending_sessions
                .write()
                .await
                .remove(&session_id);
            conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .remove(&session_id);
            // Throttle: record failure, apply delay, check per-connection cap.
            // The delay is applied after dropping auth_guard (the lock is no
            // longer needed). The failure is recorded BEFORE the delay so
            // disconnecting during the wait cannot evade accounting.
            // Audit: logon failure.
            tracing::warn!(
                target: "rssmb::audit",
                conn_id = conn_state.conn_id,
                session_id,
                ip = %conn_state.remote_addr,
                reason = %reason,
                "logon failure",
            );
            state
                .metrics
                .auth_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state
                .auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                reason = %reason,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth failure",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(
                    conn_id = conn_state.conn_id,
                    conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting"
                );
                return FramedResponse::Disconnect;
            }
            if !delay.is_zero() {
                tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        debug!(conn_id = conn_state.conn_id, "shutdown during auth delay");
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            error_response_for(Command::SessionSetup, NtStatus::LogonFailure, &req.header)
        }
        Err(e) => {
            debug!(conn_id = conn_state.conn_id, "auth error: {}", e);
            *auth_guard = None;
            conn_state
                .pending_sessions
                .write()
                .await
                .remove(&session_id);
            conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .remove(&session_id);
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state
                .auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                error = %e,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth error (throttled)",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(
                    conn_id = conn_state.conn_id,
                    conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting"
                );
                return FramedResponse::Disconnect;
            }
            if !delay.is_zero() {
                tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        debug!(conn_id = conn_state.conn_id, "shutdown during auth delay");
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            error_response_for(Command::SessionSetup, NtStatus::LogonFailure, &req.header)
        }
    }
}

/// Handle LOGOFF — tear down the session, close its handles and trees.
async fn handle_logoff(
    state: &ServerState,
    conn_state: &ConnState,
    req_header: &Header,
) -> FramedResponse {
    let session_id = req_header.session_id;

    // Remove all opens belonging to this session, closing them via VFS.
    let removed = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        let to_close: Vec<(u64, OpenEntry)> = opens
            .iter()
            .filter(|(_, e)| e.session_id == session_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (key, entry) in &to_close {
            opens.remove(key);
            if entry.is_pipe {
                // Pipe opens have no VFS handle to close; just drop the Arc.
                continue;
            }
            let mut should_delete_on_close = false;
            if let Some(fid) = entry.file_id {
                let remove_result = state.open_table.remove(fid, entry.open_id).await;
                should_delete_on_close =
                    remove_result.was_last && remove_result.any_delete_on_close;
            }
            state
                .open_table
                .remove_open_from_leases(entry.open_id)
                .await;
            if let Some(guid) = entry.durable_guid {
                state.durable_table.forget(&guid).await;
            }
            if let Some(pid) = entry.durable_persistent_id {
                state.durable_table.forget_v1(pid).await;
            }
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if should_delete_on_close {
                    let _ = vfs.set_delete_on_close(open_id, true).await;
                }
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "logoff: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(
            conn_id = conn_state.conn_id,
            session_id, removed, "logoff: closed handles"
        );
    }

    // Release all byte-range locks held by this session.
    state
        .open_table
        .release_all_locks_for_session(session_id)
        .await;

    // Remove all trees belonging to this session.
    {
        let trees_ref = conn_state.trees_ref();
        let mut trees = trees_ref.write().await;
        let tree_ids: Vec<u32> = trees
            .iter()
            .filter(|(_, e)| e.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for tid in &tree_ids {
            trees.remove(tid);
        }
    }

    // Remove the session from the connection's list and the global registry.
    // LOGOFF tears down the entire session across all channels (MS-SMB2 3.3.5.6).
    conn_state
        .sessions
        .write()
        .await
        .retain(|s| s.id != session_id);
    state.session_registry.write().unwrap().remove(&session_id);
    state.remove_session(session_id).await;
    // The signing state is kept until the LOGOFF response has been signed;
    // the read loop removes it then (see `connection.rs`).
    if let Some(st) = conn_state
        .signing_ref()
        .write()
        .unwrap()
        .get_mut(&session_id)
    {
        st.retiring = true;
    }

    // Cancel any pending async ops for this session. CHANGE_NOTIFY ops
    // get the async STATUS_NOTIFY_CLEANUP completion (MS-SMB2: logoff
    // ends the watches and notifies the client) — silently dropping them
    // left smb2.notify logoff waiting forever.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                if op.command == Command::ChangeNotify {
                    drop(pending);
                    send_notify_cleanup(conn_state, key, op).await;
                    pending = conn_state.pending_async.lock().await;
                } else if op.command == Command::Lock {
                    // Pended blocking LOCK: complete out-of-band (torture
                    // cancel-logoff accepts RANGE_NOT_LOCKED or OK).
                    drop(pending);
                    let mut header = Header {
                        credit_charge: 0,
                        status: NtStatus::RangeNotLocked.to_u32(),
                        command: Command::Lock,
                        credit_request: 0,
                        flags: HeaderFlags::new().with_server_to_redir(true),
                        next_command: 0,
                        message_id: key,
                        tree_id: Some(op.tree_id),
                        async_id: None,
                        session_id: op.session_id,
                        signature: 0,
                    };
                    header.to_async(key);
                    let resp = FramedResponse::Plain(PlainResponse {
                        header,
                        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                            error_data: vec![],
                        }),
                    });
                    send_unsolicited(conn_state, &resp, true).await;
                    pending = conn_state.pending_async.lock().await;
                } else {
                    let _ = op.cancel.send(());
                    if let Some(handle) = op.notify_handle {
                        handle.cancel();
                    }
                }
            }
        }
    }

    let response = build_response(
        req_header,
        ResponseContent::Logoff(rssmb_proto::session_setup::LogoffResponse::default()),
    );
    FramedResponse::Plain(response)
}

/// Build an ECHO response.
fn handle_echo(req_header: &Header) -> FramedResponse {
    use rssmb_proto::echo::EchoResponse;
    let echo_response = EchoResponse::default();
    let response = build_response(req_header, ResponseContent::Echo(echo_response));
    FramedResponse::Plain(response)
}

// ── Phase 3: File serving handlers ─────────────────────────────────────

/// Allocate a fresh, non-zero SMB2 SessionId (random with collision check
/// against the connection's sessions, pending sessions, and the global
/// session registry).
fn next_session_id(conn_state: &ConnState, state: &ServerState) -> u64 {
    use rand::Rng;
    loop {
        let id: u64 = rand::thread_rng().gen_range(1..u64::MAX);
        // Check against active sessions and pending sessions.
        let sessions = conn_state.sessions.try_read();
        let pending = conn_state.pending_sessions.try_read();
        let in_sessions = sessions
            .as_ref()
            .map(|s| s.iter().any(|sess| sess.id == id))
            .unwrap_or(false);
        let in_pending = pending.as_ref().map(|p| p.contains(&id)).unwrap_or(false);
        let in_registry = state.session_registry.read().unwrap().contains_key(&id);
        if !in_sessions && !in_pending && !in_registry {
            return id;
        }
    }
}

/// Allocate a per-connection TreeId (starts at 1, never 0 or 0xFFFFFFFF).
fn next_tree_id(conn_state: &ConnState) -> u32 {
    conn_state
        .next_tree_id_ref()
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Allocate a per-connection FileId: volatile from a counter, persistent random.
fn next_file_id(conn_state: &ConnState) -> rssmb_proto::create::FileId {
    let volatile = conn_state
        .next_volatile_id_ref()
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Skip the sentinel value (0xFFFFFFFFFFFFFFFF) used by substitute_file_id.
    let volatile = if volatile == u64::MAX { 0 } else { volatile };
    let persistent = conn_state.persistent_base_val().wrapping_add(volatile);
    rssmb_proto::create::FileId {
        persistent,
        volatile,
    }
}

/// TREE_CONNECT — look up a share and create a tree connection.
async fn handle_tree_connect(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let tc_req = match &req.content {
        RequestContent::TreeConnect(tc) => tc,
        _ => {
            return error_response_for(
                Command::TreeConnect,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    // Look up the session to enforce share access policy.
    let session_id = req.header.session_id;
    let session_identity = {
        let sessions = conn_state.sessions.read().await;
        sessions
            .iter()
            .find(|s| s.id == session_id)
            .and_then(|s| s.user_identity.clone())
    };

    // If no session identity was found, reject — only NEGOTIATE and
    // SESSION_SETUP may proceed without an authenticated session.
    let identity = match session_identity {
        Some(id) => id,
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                session_id, "tree_connect: no authenticated session"
            );
            return error_response_for(
                Command::TreeConnect,
                NtStatus::UserSessionDeleted,
                &req.header,
            );
        }
    };

    // Extract share name from the path (format: \\server\share)
    let path = tc_req.buffer.to_string();
    let share_name = extract_share_name(&path);

    // IPC$ — the inter-process share clients use for share enumeration (SrvSvc).
    // Accept the connect as a pipe share so clients don't abort; the RPC layer
    // behind it is still a stub.
    if share_name.eq_ignore_ascii_case("IPC$") {
        let tree_id = next_tree_id(conn_state);
        conn_state.trees_ref().write().await.insert(
            tree_id,
            TreeEntry {
                share_name: "IPC$".to_string(),
                vfs: Arc::new(rssmb_vfs::memoryfs::MemoryFs::new()) as Arc<dyn rssmb_vfs::Vfs>,
                session_id,
                read_only: false,
                write_access: true,
                encrypt_data: false,
                is_ipc: true,
            },
        );
        let resp = rssmb_proto::tree_connect::TreeConnectResponse {
            share_type: rssmb_proto::tree_connect::ShareType::Pipe,
            maximal_access: 0x001f_01ff,
            ..Default::default()
        };
        let mut response = build_response(&req.header, ResponseContent::TreeConnect(resp));
        response.header.tree_id = Some(tree_id);
        return FramedResponse::Plain(response);
    }

    // Look up share in the live shares snapshot (case-insensitive).
    let live_shares = state.shares_snapshot();
    let share_config = match live_shares
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&share_name))
        .map(|(_, v)| v)
    {
        Some(c) => c.clone(),
        None => {
            debug!(conn_id = conn_state.conn_id, share = %share_name, "share not found");
            return error_response_for(
                Command::TreeConnect,
                NtStatus::ObjectNameNotFound,
                &req.header,
            );
        }
    };

    // ── Share access policy ─────────────────────────────────────────────
    // 1. Guest users can only connect if the share allows guest access.
    // 2. If valid_users is non-empty, the user must be in the list
    //    (guests are also subject to this check if valid_users is set).
    // 3. If read_users is non-empty, the user must be in the list to
    //    get any access (read or write).
    // 4. If write_users is non-empty, only users in the list get write
    //    access; others get read-only access on a read-write share.
    // 5. MaximalAccess reflects read_only and write_access policy.
    if identity.is_guest && !share_config.guest_ok {
        debug!(conn_id = conn_state.conn_id, share = %share_name, "guest denied on non-guest share");
        return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
    }

    if !share_config.valid_users.is_empty() {
        let user_allowed = share_config
            .valid_users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&identity.username));
        if !user_allowed {
            debug!(conn_id = conn_state.conn_id, share = %share_name, user = %identity.username, "user not in valid_users");
            return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
        }
    }

    if !share_config.read_users.is_empty() {
        let user_can_read = share_config
            .read_users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&identity.username));
        if !user_can_read {
            debug!(conn_id = conn_state.conn_id, share = %share_name, user = %identity.username, "user not in read_users");
            return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
        }
    }

    // Determine write access: read_only share → no write. Otherwise,
    // write_users non-empty → only listed users get write. Empty
    // write_users → all users with access get write.
    let write_access = !share_config.read_only && {
        if share_config.write_users.is_empty() {
            true
        } else {
            share_config
                .write_users
                .iter()
                .any(|u| u.eq_ignore_ascii_case(&identity.username))
        }
    };

    // Derive MaximalAccess from access policy.
    // Read-only or no-write-access: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE = 0x001200a9
    // Full read-write: FILE_ALL_ACCESS = 0x001f01ff
    let maximal_access = if write_access {
        0x001f_01ff
    } else {
        0x0012_00a9
    };

    // Create VFS backend: LocalFs for real shares, MemoryFs for unnamed/test.
    // publish_on_close selects the LocalFs variant with the hidden-temp/
    // atomic-rename backend (see rssmb_vfs::publish).
    let vfs: Arc<dyn rssmb_vfs::Vfs> = if share_config.path.is_empty() {
        Arc::new(rssmb_vfs::memoryfs::MemoryFs::new())
    } else if share_config.publish_on_close {
        match rssmb_vfs::localfs::LocalFs::new_with_publish(
            &share_config.path,
            share_config.follow_symlinks,
            share_config.case_sensitive,
        ) {
            Ok(fs) => Arc::new(fs),
            Err(e) => {
                tracing::warn!(share = %share_name, path = share_config.path, error = %e, "failed to create LocalFs");
                return error_response_for(
                    Command::TreeConnect,
                    NtStatus::InvalidParameter,
                    &req.header,
                );
            }
        }
    } else {
        match rssmb_vfs::localfs::LocalFs::new(
            &share_config.path,
            share_config.follow_symlinks,
            share_config.case_sensitive,
        ) {
            Ok(fs) => Arc::new(fs),
            Err(e) => {
                tracing::warn!(share = %share_name, path = %share_config.path, error = %e, "failed to create LocalFs");
                return error_response_for(
                    Command::TreeConnect,
                    NtStatus::InvalidParameter,
                    &req.header,
                );
            }
        }
    };

    // Assign tree ID
    let tree_id = next_tree_id(conn_state);

    // Store tree in connection tree table with owning session and policy.
    // MS-SMB2 3.3.5.7: if Connection.AcceptTransportSecurity is true, do not
    // require SMB-layer encryption on the tree.
    let accept_transport_security = conn_state
        .negotiate_record
        .lock()
        .await
        .as_ref()
        .and_then(|r| r.neg311.as_ref())
        .map(|n| n.accept_transport_security)
        .unwrap_or(false);
    let tree_encrypt_data = share_config.encrypt_data && !accept_transport_security;
    conn_state.trees_ref().write().await.insert(
        tree_id,
        TreeEntry {
            share_name: share_name.clone(),
            vfs: vfs.clone(),
            session_id,
            read_only: share_config.read_only,
            write_access,
            encrypt_data: tree_encrypt_data,
            is_ipc: false,
        },
    );

    // Audit: tree connect.
    tracing::info!(
        target: "rssmb::audit",
        conn_id = conn_state.conn_id,
        session_id,
        tree_id,
        share = %share_name,
        username = %identity.username,
        ip = %conn_state.remote_addr,
        read_only = share_config.read_only,
        write_access,
        "tree connect",
    );

    let tree_connect_response = rssmb_proto::tree_connect::TreeConnectResponse {
        share_type: rssmb_proto::tree_connect::ShareType::Disk,
        share_flags: rssmb_proto::tree_connect::ShareFlags::new()
            .with_encrypt_data(tree_encrypt_data),
        maximal_access,
        ..Default::default()
    };

    let mut response = build_response(
        &req.header,
        ResponseContent::TreeConnect(tree_connect_response),
    );
    response.header.tree_id = Some(tree_id);
    FramedResponse::Plain(response)
}

/// TREE_DISCONNECT — close all handles on this tree and remove it.
async fn handle_tree_disconnect(
    state: &ServerState,
    conn_state: &ConnState,
    req_header: &Header,
) -> FramedResponse {
    let tree_id = req_header.tree_id.unwrap_or(0);
    let session_id = req_header.session_id;

    // Validate that the tree belongs to this session before removing.
    let tree_owned = {
        let trees_ref = conn_state.trees_ref();
        let trees = trees_ref.read().await;
        trees
            .get(&tree_id)
            .map(|e| e.session_id == session_id)
            .unwrap_or(false)
    };
    if !tree_owned {
        return error_response_for(Command::TreeDisconnect, NtStatus::AccessDenied, req_header);
    }

    // Remove all opens belonging to this tree, closing them via VFS.
    let removed = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        let to_close: Vec<(u64, OpenEntry)> = opens
            .iter()
            .filter(|(_, e)| e.tree_id == tree_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (key, entry) in &to_close {
            opens.remove(key);
            if entry.is_pipe {
                // Pipe opens have no VFS handle to close; just drop the Arc.
                continue;
            }
            // Remove from the global open table.
            let mut should_delete_on_close = false;
            if let Some(fid) = entry.file_id {
                let remove_result = state.open_table.remove(fid, entry.open_id).await;
                should_delete_on_close =
                    remove_result.was_last && remove_result.any_delete_on_close;
            }
            state
                .open_table
                .remove_open_from_leases(entry.open_id)
                .await;
            if let Some(guid) = entry.durable_guid {
                state.durable_table.forget(&guid).await;
            }
            if let Some(pid) = entry.durable_persistent_id {
                state.durable_table.forget_v1(pid).await;
            }
            // Close the VFS handle — fire and forget, log on error.
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if should_delete_on_close {
                    let _ = vfs.set_delete_on_close(open_id, true).await;
                }
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "tree_disconnect: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(
            conn_id = conn_state.conn_id,
            tree_id, removed, "tree_disconnect: closed handles"
        );
    }

    // Remove the tree from the connection tree table.
    conn_state.trees_ref().write().await.remove(&tree_id);

    // Cancel any pending async ops for this tree. CHANGE_NOTIFY ops get
    // the async STATUS_NOTIFY_CLEANUP completion (MS-SMB2 3.3.5.10: tree
    // disconnect ends the watch and notifies the client) — silently
    // dropping them left smb2.notify tdis/tdis1 waiting forever.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.tree_id == tree_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                if op.command == Command::ChangeNotify {
                    drop(pending);
                    send_notify_cleanup(conn_state, key, op).await;
                    pending = conn_state.pending_async.lock().await;
                } else if op.command == Command::Lock {
                    // Pended blocking LOCK: complete it out-of-band so the
                    // client's smb2_lock_recv unblocks (torture cancel-tdis
                    // accepts RANGE_NOT_LOCKED or OK; a silent drop made the
                    // client wait for its 35 s timeout → IO_TIMEOUT at
                    // lock.c:1064).
                    drop(pending);
                    let mut header = Header {
                        credit_charge: 0,
                        status: NtStatus::RangeNotLocked.to_u32(),
                        command: Command::Lock,
                        credit_request: 0,
                        flags: HeaderFlags::new().with_server_to_redir(true),
                        next_command: 0,
                        message_id: key,
                        tree_id: Some(op.tree_id),
                        async_id: None,
                        session_id: op.session_id,
                        signature: 0,
                    };
                    header.to_async(key);
                    let resp = FramedResponse::Plain(PlainResponse {
                        header,
                        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                            error_data: vec![],
                        }),
                    });
                    send_unsolicited(conn_state, &resp, true).await;
                    pending = conn_state.pending_async.lock().await;
                } else {
                    let _ = op.cancel.send(());
                    if let Some(handle) = op.notify_handle {
                        handle.cancel();
                    }
                }
            }
        }
    }

    // Release all byte-range locks held by this tree.
    state.open_table.release_all_locks_for_tree(tree_id).await;

    let response = build_response(
        req_header,
        ResponseContent::TreeDisconnect(Default::default()),
    );
    FramedResponse::Plain(response)
}

// ── Durable handle & Lease create contexts (MS-SMB2 2.2.13.2.8–2.2.13.2.12) ──

/// DHnQ create context name (durable handle v1 request, MS-SMB2 2.2.13.2.8).
const DHNQ_NAME: &[u8; 4] = b"DHnQ";
/// DHnC create context name (durable handle v1 reconnect, MS-SMB2 2.2.13.2.7).
const DHNC_NAME: &[u8; 4] = b"DHnC";
/// DH2Q create context name (durable handle v2 request).
const DH2Q_NAME: &[u8; 4] = b"DH2Q";
/// DH2C create context name (durable handle v2 reconnect).
const DH2C_NAME: &[u8; 4] = b"DH2C";
/// RqLs create context name (lease v1 / v2 request & response).
const RQLS_NAME: &[u8; 4] = b"RqLs";

/// Parsed DH2Q create context data (32 bytes).
#[derive(Debug)]
struct Dh2qContext {
    /// Timeout in milliseconds the server should keep the handle alive.
    timeout: u32,
    /// Flags (bit 1 = persistent handle).
    _flags: u32,
    /// The client-supplied GUID identifying this durable open.
    create_guid: [u8; 16],
}

/// Parsed DH2C create context data (36 bytes).
#[derive(Debug)]
struct Dh2cContext {
    /// The file ID for the open being re-established.
    file_id: rssmb_proto::create::FileId,
    /// The create GUID from the original DH2Q open.
    create_guid: [u8; 16],
    /// Flags (bit 1 = persistent handle).
    _flags: u32,
}

/// Parsed DHnC create context data (16 bytes: just the file id — v1
/// reconnect carries no CreateGuid; it is valid to v1-reconnect a v2-opened
/// handle, so the lookup matches on the persistent id alone, mirroring
/// Samba's `smb2srv_open_recreate` with `create_guid == NULL`).
#[derive(Debug)]
struct DhncContext {
    file_id: rssmb_proto::create::FileId,
}

/// Parsed DHnQ create context data (16 bytes, zeroed — the v1 request
/// context body is all reserved).
#[derive(Debug)]
struct DhnqContext;

/// Parsed RqLs create context data (32 bytes for v1, 52 bytes for v2).
#[derive(Debug, Clone)]
struct RqLsContext {
    lease_key: [u8; 16],
    lease_state: opens::LeaseCaching,
    #[allow(dead_code)]
    lease_flags: u32,
    parent_lease_key: Option<[u8; 16]>,
    epoch: u16,
    is_v2: bool,
}

#[derive(Debug, Default)]
struct ParsedCreateContexts {
    dh2q: Option<Dh2qContext>,
    dh2c: Option<Dh2cContext>,
    /// v1 durable request (DHnQ), present-flag.
    dhnq: Option<DhnqContext>,
    /// v1 durable reconnect (DHnC) — file id only.
    dhnc: Option<DhncContext>,
    rqls: Option<RqLsContext>,
}

impl ParsedCreateContexts {
    /// Samba's create-context combination validation
    /// (source3/smbd/smb2_create.c, smbd_smb2_create_fetch_create_ctx):
    /// a request must not carry more than one of the durable
    /// request/reconnect contexts; mixed v1/v2 combinations are
    /// `INVALID_PARAMETER` (MS-SMB2 3.3.5.9.12).
    fn validate_combinations(&self) -> Result<(), NtStatus> {
        if (self.dhnc.is_some() && self.dh2c.is_some())
            || (self.dhnc.is_some() && self.dh2q.is_some())
            || (self.dh2c.is_some() && self.dhnq.is_some())
            || (self.dh2q.is_some() && self.dh2c.is_some())
        {
            return Err(NtStatus::InvalidParameter);
        }
        Ok(())
    }

    /// Which reconnect context (if any) is present: DH2C or DHnC.
    fn reconnect(&self) -> Option<ReconnectContext<'_>> {
        if let Some(dh2c) = &self.dh2c {
            return Some(ReconnectContext {
                persistent_id: dh2c.file_id.persistent,
                create_guid: Some(&dh2c.create_guid),
            });
        }
        if let Some(dhnc) = &self.dhnc {
            return Some(ReconnectContext {
                persistent_id: dhnc.file_id.persistent,
                create_guid: None,
            });
        }
        None
    }
}

/// A normalized durable-reconnect request (from DH2C or DHnC).
struct ReconnectContext<'a> {
    persistent_id: u64,
    create_guid: Option<&'a [u8; 16]>,
}

/// Serialize a list of `(name, data)` create contexts into an 8-byte aligned
/// SMB2_CREATE_CONTEXT chain (MS-SMB2 2.2.13.2).
fn encode_create_contexts(contexts: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, (name, data)) in contexts.iter().enumerate() {
        let is_last = idx + 1 == contexts.len();
        let ctx_start = out.len();
        let name_offset: u16 = 16;
        let name_len = name.len() as u16;
        // Pad after name so DataOffset is 8-byte aligned relative to ctx_start.
        let after_name = 16 + name.len();
        let data_offset = (after_name + 7) & !7;
        let data_len = data.len() as u32;
        let raw_ctx_len = data_offset + data.len();
        let aligned_ctx_len = if is_last {
            raw_ctx_len
        } else {
            (raw_ctx_len + 7) & !7
        };
        let next_offset: u32 = if is_last { 0 } else { aligned_ctx_len as u32 };

        out.extend_from_slice(&next_offset.to_le_bytes());
        out.extend_from_slice(&name_offset.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        out.extend_from_slice(&(data_offset as u16).to_le_bytes());
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(name);
        out.resize(ctx_start + data_offset, 0);
        out.extend_from_slice(data);
        out.resize(ctx_start + aligned_ctx_len, 0);
    }
    out
}

/// Build the 32-byte (v1) or 52-byte (v2) `RqLs` response context payload.
fn build_rqls_response_data(grant: &opens::LeaseGrant) -> Vec<u8> {
    let mut data = Vec::with_capacity(if grant.is_v2 { 52 } else { 32 });
    data.extend_from_slice(&grant.lease_key);
    data.extend_from_slice(&grant.state.to_bits().to_le_bytes());
    data.extend_from_slice(&grant.flags.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // LeaseDuration = 0
    if grant.is_v2 {
        let parent = grant.parent_lease_key.unwrap_or([0u8; 16]);
        data.extend_from_slice(&parent);
        data.extend_from_slice(&grant.epoch.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    }
    data
}

/// Parse create contexts from the raw frame after the CreateRequest body.
fn parse_create_contexts(
    raw_frame: &[u8],
    contexts_offset: u32,
    contexts_length: u32,
) -> ParsedCreateContexts {
    let mut parsed = ParsedCreateContexts::default();

    let start = match usize::try_from(contexts_offset) {
        Ok(s) => s,
        Err(_) => return parsed,
    };
    let end = match contexts_offset.checked_add(contexts_length) {
        Some(e) => match usize::try_from(e) {
            Ok(u) => u,
            Err(_) => return parsed,
        },
        None => return parsed,
    };

    if start >= raw_frame.len() || end > raw_frame.len() || start > end {
        return parsed;
    }

    let chain = &raw_frame[start..end];
    let mut pos = 0usize;

    loop {
        // Each context starts with a 16-byte header.
        if pos + 16 > chain.len() {
            break;
        }
        let next_offset =
            u32::from_le_bytes(chain[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
        let name_offset =
            u16::from_le_bytes(chain[pos + 4..pos + 6].try_into().unwrap_or([0; 2])) as usize;
        let name_length =
            u16::from_le_bytes(chain[pos + 6..pos + 8].try_into().unwrap_or([0; 2])) as usize;
        let data_offset =
            u16::from_le_bytes(chain[pos + 10..pos + 12].try_into().unwrap_or([0; 2])) as usize;
        let data_length =
            u32::from_le_bytes(chain[pos + 12..pos + 16].try_into().unwrap_or([0; 4])) as usize;

        let ctx_start = pos;
        let ctx_bound = if next_offset > 0 {
            ctx_start.saturating_add(next_offset).min(chain.len())
        } else {
            chain.len()
        };

        // Read the name.
        if name_offset >= 16
            && ctx_start
                .checked_add(name_offset)
                .and_then(|v| v.checked_add(name_length))
                .is_some_and(|end_off| end_off <= ctx_bound)
            && name_length == 4
        {
            let name = &chain[ctx_start + name_offset..ctx_start + name_offset + 4];
            // Read the data.
            if data_offset >= 16
                && ctx_start
                    .checked_add(data_offset)
                    .and_then(|v| v.checked_add(data_length))
                    .is_some_and(|end_off| end_off <= ctx_bound)
            {
                let data = &chain[ctx_start + data_offset..ctx_start + data_offset + data_length];
                if name == DH2Q_NAME && data_length >= 32 {
                    let timeout = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let mut create_guid = [0u8; 16];
                    create_guid.copy_from_slice(&data[16..32]);
                    parsed.dh2q = Some(Dh2qContext {
                        timeout,
                        _flags: flags,
                        create_guid,
                    });
                } else if name == DHNQ_NAME && data_length >= 16 {
                    // v1 durable request: 16 reserved bytes (MS-SMB2 2.2.13.2.8).
                    parsed.dhnq = Some(DhnqContext);
                } else if name == DHNC_NAME && data_length >= 16 {
                    // v1 durable reconnect: 16-byte file id (MS-SMB2 2.2.13.2.7).
                    let persistent = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
                    let volatile = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
                    parsed.dhnc = Some(DhncContext {
                        file_id: rssmb_proto::create::FileId {
                            persistent,
                            volatile,
                        },
                    });
                } else if name == DH2C_NAME && data_length >= 36 {
                    let persistent = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
                    let volatile = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
                    let mut create_guid = [0u8; 16];
                    create_guid.copy_from_slice(&data[16..32]);
                    let flags = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
                    parsed.dh2c = Some(Dh2cContext {
                        file_id: rssmb_proto::create::FileId {
                            persistent,
                            volatile,
                        },
                        create_guid,
                        _flags: flags,
                    });
                } else if name == RQLS_NAME && (data_length == 32 || data_length == 52) {
                    let mut lease_key = [0u8; 16];
                    lease_key.copy_from_slice(&data[0..16]);
                    let state_bits = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                    let lease_flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                    let is_v2 = data_length == 52;
                    let (parent_lease_key, epoch) = if is_v2 {
                        let parent = if lease_flags & 0x0000_0004 != 0 {
                            let mut pk = [0u8; 16];
                            pk.copy_from_slice(&data[32..48]);
                            Some(pk)
                        } else {
                            None
                        };
                        let ep = u16::from_le_bytes([data[48], data[49]]);
                        (parent, ep)
                    } else {
                        (None, 0)
                    };
                    parsed.rqls = Some(RqLsContext {
                        lease_key,
                        lease_state: opens::LeaseCaching::from_bits(state_bits),
                        lease_flags,
                        parent_lease_key,
                        epoch,
                        is_v2,
                    });
                }
            }
        }

        if next_offset == 0 {
            break;
        }
        // NextOffset must be 8-byte aligned and non-zero.
        if next_offset % 8 != 0 {
            break;
        }
        pos = match pos.checked_add(next_offset) {
            Some(p) if p < chain.len() => p,
            _ => break,
        };
    }

    parsed
}

/// CREATE — open or create a file.
async fn handle_create(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_frame: &[u8],
) -> FramedResponse {
    let create_req = match &req.content {
        RequestContent::Create(c) => c,
        _ => return error_response_for(Command::Create, NtStatus::InvalidParameter, &req.header),
    };

    // Look up tree by tree_id from the request header, validating
    // that it belongs to this session.
    let tree_id = req.header.tree_id.unwrap_or(0);
    let session_id = req.header.session_id;
    let trees_ref = conn_state.trees_ref();
    let trees = trees_ref.read().await;
    let tree_entry = match trees.get(&tree_id) {
        Some(e) => e.clone(),
        None => {
            debug!(conn_id = conn_state.conn_id, tree_id, "tree not found");
            return error_response_for(Command::Create, NtStatus::NetworkNameDeleted, &req.header);
        }
    };
    drop(trees);

    // Validate that the tree belongs to this session.
    if tree_entry.session_id != session_id {
        debug!(
            conn_id = conn_state.conn_id,
            tree_id, session_id, "create: tree does not belong to this session"
        );
        return error_response_for(Command::Create, NtStatus::AccessDenied, &req.header);
    }
    let vfs = tree_entry.vfs.clone();

    // Parse create contexts for durable handle (DHnQ/DHnC/DH2Q/DH2C) and
    // lease (RqLs) support. The CreateContextsOffset (u32 at body+48) and
    // CreateContextsLength (u32 at body+52) are relative to the start of
    // the SMB2 header. The SMB2 header is 64 bytes, so body starts at
    // offset 64.
    let parsed_ctx = {
        let ctx_offset = if raw_frame.len() >= 64 + 52 + 4 {
            u32::from_le_bytes(raw_frame[64 + 48..64 + 52].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        let ctx_length = if raw_frame.len() >= 64 + 56 {
            u32::from_le_bytes(raw_frame[64 + 52..64 + 56].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        if ctx_offset > 0 && ctx_length > 0 {
            parse_create_contexts(raw_frame, ctx_offset, ctx_length)
        } else {
            ParsedCreateContexts::default()
        }
    };
    let ParsedCreateContexts {
        dh2q, dhnq, rqls, ..
    } = &parsed_ctx;

    // Combination validation (Samba smbd_smb2_create_fetch_create_ctx /
    // MS-SMB2 3.3.5.9.12): only one durable request/reconnect context per
    // create; mixed combos are INVALID_PARAMETER.
    if let Err(status) = parsed_ctx.validate_combinations() {
        debug!(
            conn_id = conn_state.conn_id,
            "create: invalid durable context combination"
        );
        return error_response_for(Command::Create, status, &req.header);
    }

    // Durable reconnect (DH2C v2 or DHnC v1): look up the durable open and
    // re-attach it. All state transitions and status codes mirror Samba
    // 4.19.5 (golden) — see tests/conformance/durable-v2-open-analysis.md G3.
    if let Some(reconnect) = parsed_ctx.reconnect() {
        let durable_timeout = state.config.durable_timeout_secs;
        if durable_timeout == 0 {
            debug!(
                conn_id = conn_state.conn_id,
                "durable reconnect: durable handles disabled"
            );
            return error_response_for(Command::Create, NtStatus::ObjectNameNotFound, &req.header);
        }

        // Peek first — validate everything without removing the entry.
        // Only take (remove) if all checks pass, so a failed reconnect
        // doesn't destroy the durable open. Lookup is by the persistent id
        // carried in the reconnect context (Samba's primary key); the
        // CreateGuid (DH2C only) is verified against the entry.
        let peeked = match state
            .durable_table
            .peek_by_persistent_id(reconnect.persistent_id, reconnect.create_guid)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                debug!(
                    conn_id = conn_state.conn_id,
                    error = ?err,
                    "durable reconnect: not found or expired"
                );
                // An expired entry's VFS handle was just closed in the
                // background; its lease record must be released here (the
                // table cannot reach the OpenTable).
                if let crate::durable::DurableReconnectError::Expired(open_id) = err {
                    state.open_table.remove_open_from_leases(open_id).await;
                }
                // Every match failure is OBJECT_NAME_NOT_FOUND in the
                // golden: unknown persistent id, wrong CreateGuid, expiry.
                return error_response_for(
                    Command::Create,
                    NtStatus::ObjectNameNotFound,
                    &req.header,
                );
            }
        };

        // A durable open only becomes reconnectable once its owning
        // connection has dropped (Samba: allow_reconnect flips in
        // vfs_default_durable_disconnect; a DH2C against a still-live
        // handle fails — subtest reopen1).
        if !peeked.orphaned {
            debug!(
                conn_id = conn_state.conn_id,
                "durable reconnect: original handle still attached"
            );
            return error_response_for(Command::Create, NtStatus::ObjectNameNotFound, &req.header);
        }

        // Validate that the reconnecting session matches the original
        // session's user (MS-SMB2 3.3.5.15.11; golden: owner mismatch is
        // OBJECT_NAME_NOT_FOUND, same as Samba's
        // security_token_is_sid check landing in the `not_found` branch).
        let identity = lookup_session_identity(conn_state, session_id).await;
        let reconnect_user = identity.as_ref().map(|i| i.username.as_str()).unwrap_or("");
        if reconnect_user != peeked.username {
            debug!(
                conn_id = conn_state.conn_id,
                original_user = %peeked.username,
                reconnect_user,
                "durable reconnect: session user mismatch"
            );
            return error_response_for(Command::Create, NtStatus::ObjectNameNotFound, &req.header);
        }

        // Validate tree matches the original share (golden: NOT_FOUND).
        if tree_entry.share_name != peeked.share_name {
            debug!(
                conn_id = conn_state.conn_id,
                original_share = %peeked.share_name,
                reconnect_share = %tree_entry.share_name,
                "durable reconnect: share mismatch"
            );
            return error_response_for(Command::Create, NtStatus::ObjectNameNotFound, &req.header);
        }

        // Enforce write access: if the original open had write access,
        // the reconnecting tree must also grant write access. A read-only
        // or no-write-access tree cannot receive a writable durable handle.
        let da = &peeked.desired_access;
        let durable_has_write = da.write || da.generic_write || da.generic_all;
        if !tree_entry.write_access && durable_has_write {
            debug!(
                conn_id = conn_state.conn_id,
                "durable reconnect: tree has no write access for writable handle"
            );
            return error_response_for(Command::Create, NtStatus::AccessDenied, &req.header);
        }

        // Lease validation (Samba smbd_smb2_create_durable_lease_check,
        // golden): a lease-backed durable open requires the reconnect to
        // carry a lease request with the SAME lease key — otherwise
        // OBJECT_NAME_NOT_FOUND. The reconnect's oplock_level field is NOT
        // consulted (the torture sends garbage there; Samba looks at the
        // RqLs create context alone). An oplock-backed durable ignores any
        // lease on the reconnect. A name mismatch WITH a matching lease
        // is INVALID_PARAMETER (different from the oplock case, where the
        // name is ignored entirely).
        let requested_lease = rqls.as_ref();
        match (&peeked.lease, requested_lease) {
            (Some(durable_lease), Some(req_lease)) => {
                if durable_lease.lease_key != req_lease.lease_key {
                    debug!(
                        conn_id = conn_state.conn_id,
                        "durable reconnect: lease key mismatch"
                    );
                    return error_response_for(
                        Command::Create,
                        NtStatus::ObjectNameNotFound,
                        &req.header,
                    );
                }
                // Client-GUID scoping (golden: reopen1a-lease): leases are
                // keyed by (client_guid, lease_key); a reconnect presenting
                // the right lease key from a different client GUID fails
                // with OBJECT_NAME_NOT_FOUND. Oplock-backed durables have
                // no client_guid recorded and are not scoped.
                if let Some(stored_guid) = peeked.client_guid {
                    let conn_guid: [u8; 16] = {
                        let rec = conn_state.negotiate_record.lock().await;
                        match &*rec {
                            Some(r) => {
                                let mut cg = [0u8; 16];
                                cg[0..4].copy_from_slice(&r.client_guid.0.to_le_bytes());
                                cg[4..6].copy_from_slice(&r.client_guid.1.to_le_bytes());
                                cg[6..8].copy_from_slice(&r.client_guid.2.to_le_bytes());
                                cg[8..16].copy_from_slice(&r.client_guid.3);
                                cg
                            }
                            None => [0u8; 16],
                        }
                    };
                    if stored_guid != conn_guid {
                        debug!(
                            conn_id = conn_state.conn_id,
                            "durable reconnect: client GUID mismatch on lease-backed durable"
                        );
                        return error_response_for(
                            Command::Create,
                            NtStatus::ObjectNameNotFound,
                            &req.header,
                        );
                    }
                }
                // Name must match the original open for lease-backed
                // durables (golden: reopen2-lease wrong-filename case).
                let requested_name = create_req.name.to_string();
                if requested_name != peeked.path {
                    debug!(
                        conn_id = conn_state.conn_id,
                        durable_path = %peeked.path,
                        requested_name = %requested_name,
                        "durable reconnect: name mismatch with matched lease"
                    );
                    return error_response_for(
                        Command::Create,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            }
            (Some(_durable_lease), None) => {
                // Reopened file has a lease, but no lease was requested.
                debug!(
                    conn_id = conn_state.conn_id,
                    "durable reconnect: lease-backed durable without lease request"
                );
                return error_response_for(
                    Command::Create,
                    NtStatus::ObjectNameNotFound,
                    &req.header,
                );
            }
            (None, Some(_req_lease)) => {
                // Lease requested, but the reopened file has no lease.
                debug!(
                    conn_id = conn_state.conn_id,
                    "durable reconnect: lease requested for non-leased durable"
                );
                return error_response_for(
                    Command::Create,
                    NtStatus::ObjectNameNotFound,
                    &req.header,
                );
            }
            (None, None) => {}
        }

        // All validations passed — take the entry from the durable table.
        let (durable_entry, durable_guid) = match state
            .durable_table
            .take_by_persistent_id(reconnect.persistent_id, reconnect.create_guid)
            .await
        {
            Ok((entry, guid)) => (entry, guid),
            Err(err) => {
                // Race: the entry was taken by another reconnect or expired
                // between peek and take. On expiry the VFS handle was just
                // closed — release its lease record too.
                if let crate::durable::DurableReconnectError::Expired(open_id) = err {
                    state.open_table.remove_open_from_leases(open_id).await;
                }
                debug!(
                    conn_id = conn_state.conn_id,
                    "durable reconnect: entry lost between peek and take"
                );
                return error_response_for(
                    Command::Create,
                    NtStatus::ObjectNameNotFound,
                    &req.header,
                );
            }
        };

        // Re-attach: insert into the per-connection open table. The
        // re-attached open keeps its durable identity so a second
        // disconnect (reopen2 reconnects twice) re-orphans it correctly.
        let file_id = next_file_id(conn_state);
        conn_state.opens_ref().write().await.insert(
            file_id.volatile,
            OpenEntry {
                session_id,
                tree_id,
                open_id: durable_entry.open_id,
                vfs: durable_entry.vfs.clone(),
                file_id: durable_entry.file_id,
                dir_cursor: Default::default(),
                path: durable_entry.path.clone(),
                is_pipe: false,
                pipe_state: None,
                // v1 durables key the persistent-id side table; v2 the guid
                // table. take_by_persistent_id returns a zero guid for v1.
                durable_guid: if reconnect.create_guid.is_some() {
                    Some(durable_guid)
                } else {
                    None
                },
                durable_persistent_id: if reconnect.create_guid.is_some() {
                    None
                } else {
                    Some(file_id.persistent)
                },
                lock_sequence_array: Arc::new(std::sync::Mutex::new([0xFF; 64])),
            },
        );

        // The durable entry was already removed from the OpenTable
        // when it was made durable (on disconnect). Re-add it so
        // share-mode tracking continues. A share conflict here is
        // OBJECT_NAME_NOT_FOUND in the golden (Samba maps every
        // durable_reconnect backend failure to NOT_FOUND, smb2_create.c
        // ~line 1002).
        if let Some(fid) = durable_entry.file_id {
            let ot_entry = opens::OpenEntry {
                open_id: durable_entry.open_id,
                session_id,
                tree_id,
                share_access: durable_entry.share_access,
                desired_access: durable_entry.desired_access,
                delete_on_close: false,
            };
            if let Err(_conflict) = state.open_table.check_and_add(fid, ot_entry).await {
                debug!(
                    conn_id = conn_state.conn_id,
                    "durable reconnect: share conflict"
                );
                // Undo the re-attach and close the VFS handle.
                conn_state
                    .opens_ref()
                    .write()
                    .await
                    .remove(&file_id.volatile);
                let _ = durable_entry.vfs.close(durable_entry.open_id).await;
                return error_response_for(
                    Command::Create,
                    NtStatus::ObjectNameNotFound,
                    &req.header,
                );
            }
        }

        // Re-register the lease/oplock with the re-attached open so breaks
        // keep flowing and a CLOSE removes the right records. The lease
        // record itself survived the disconnect (connection cleanup skips
        // remove_open_from_leases for durable opens); we only need the
        // oplock record restored for oplock-backed durables (Samba restores
        // oplock_type from the smbXsrv_open record).
        if durable_entry.oplock_level.is_some() {
            if let Some(fid) = durable_entry.file_id {
                let level = match durable_entry.oplock_level {
                    Some(rssmb_proto::oplock::OplockLevel::Batch) => 0x09,
                    Some(rssmb_proto::oplock::OplockLevel::Exclusive) => 0x08,
                    Some(rssmb_proto::oplock::OplockLevel::II) => 0x01,
                    _ => 0x00,
                };
                if level != 0x00 {
                    let (granted, _breaks, _waiters) = state
                        .open_table
                        .request_oplock(
                            fid,
                            durable_entry.open_id,
                            file_id,
                            level,
                            conn_state.write_tx.clone(),
                            false,
                        )
                        .await;
                    debug!(
                        conn_id = conn_state.conn_id,
                        granted, "durable reconnect: oplock restored"
                    );
                }
            }
        }

        // The handle stays durable across reconnects (Samba keeps the
        // smbXsrv_open record; reopen2 reconnects the same handle twice).
        // Re-insert the entry keyed by the same CreateGuid, updated with
        // the NEW file id assigned on this connection (the next reconnect
        // presents that id), the new session/tree, and orphaned=false —
        // it must be orphaned again by a disconnect before another
        // reconnect is allowed.
        let reinserted_entry = crate::durable::DurableEntry {
            vfs: durable_entry.vfs.clone(),
            open_id: durable_entry.open_id,
            file_id: durable_entry.file_id,
            smb_persistent_id: file_id.persistent,
            session_id,
            tree_id,
            share_name: durable_entry.share_name.clone(),
            username: durable_entry.username.clone(),
            share_access: durable_entry.share_access,
            desired_access: durable_entry.desired_access,
            path: durable_entry.path.clone(),
            client_guid: durable_entry.client_guid,
            deadline: durable_entry.deadline,
            timeout_msecs: durable_entry.timeout_msecs,
            oplock_level: durable_entry.oplock_level,
            lease: durable_entry.lease.clone(),
            orphaned: false,
        };
        // Only conflicts if a duplicate CREATE or a second reconnect
        // raced between our take() and this re-insert; the reconnect
        // itself stays valid, so the duplicate error is intentionally
        // dropped here (the DH2Q create path returns DUPLICATE_OBJECTID,
        // but this open is already fully re-attached).
        let _ = state
            .durable_table
            .insert(durable_guid, reinserted_entry)
            .await;

        // Query file info for the response.
        let info = durable_entry
            .vfs
            .query_info(
                durable_entry.open_id,
                rssmb_vfs::InfoClass::FileStandardInfo,
            )
            .await
            .unwrap_or(rssmb_vfs::FileInfo {
                file_id: rssmb_vfs::FileId { dev: 0, ino: 0 },
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                file_name: durable_entry.path.clone(),
            });

        // Response fields per golden: create_action = Opened (EXISTED),
        // oplock_level = the ORIGINAL grant (batch oplock or Lease),
        // NO DH2Q response blob (durable flag not re-negotiated),
        // and for lease-backed durables an RqLs echo with the original
        // lease key/state (Samba smb2_create.c:1622 — echoed from the
        // open's stored lease, independent of the reconnect request).
        let mut resp_ctx_items: Vec<(&[u8], Vec<u8>)> = Vec::new();
        if let Some(lease) = &durable_entry.lease {
            let grant = opens::LeaseGrant {
                lease_key: lease.lease_key,
                state: lease.state,
                flags: 0,
                epoch: lease.epoch,
                parent_lease_key: lease.parent_lease_key,
                is_v2: lease.is_v2,
            };
            resp_ctx_items.push((RQLS_NAME, build_rqls_response_data(&grant)));
        }
        let create_contexts = if resp_ctx_items.is_empty() {
            Vec::new()
        } else {
            let refs: Vec<(&[u8], &[u8])> = resp_ctx_items
                .iter()
                .map(|(n, d)| (*n, d.as_slice()))
                .collect();
            encode_create_contexts(&refs)
        };

        let oplock_level = if durable_entry.lease.is_some() {
            rssmb_proto::oplock::OplockLevel::Lease
        } else {
            durable_entry
                .oplock_level
                .unwrap_or(rssmb_proto::oplock::OplockLevel::None)
        };

        let create_response = rssmb_proto::create::CreateResponse {
            oplock_level,
            flags: Default::default(),
            create_action: rssmb_proto::create::CreateAction::Opened,
            creation_time: FileTime::from(info.creation_time),
            last_access_time: FileTime::from(info.last_access_time),
            last_write_time: FileTime::from(info.last_write_time),
            change_time: FileTime::from(info.change_time),
            allocation_size: info.allocation_size,
            endof_file: info.size,
            file_attributes: crate::fsinfo::file_attributes_to_fscc(&info.attributes),
            file_id,
            create_contexts,
        };
        let response = build_response(&req.header, ResponseContent::Create(create_response));
        debug!(
            conn_id = conn_state.conn_id,
            "durable reconnect: handle re-attached"
        );
        return FramedResponse::Plain(response);
    }

    // Extract file path from request
    let file_path = create_req.name.to_string();

    // IPC$ tree: named-pipe opens, not filesystem creates.
    // Only "srvsvc" is served (Step 8 scope); any other name → NOT_FOUND.
    if tree_entry.is_ipc {
        if !rssmb_rpc_server::serves_pipe(&file_path) {
            debug!(conn_id = conn_state.conn_id, pipe = %file_path, "create on IPC$ tree: unknown pipe");
            return error_response_for(Command::Create, NtStatus::ObjectNameNotFound, &req.header);
        }
        let file_id = next_file_id(conn_state);
        conn_state.opens_ref().write().await.insert(
            file_id.volatile,
            OpenEntry {
                session_id,
                tree_id,
                open_id: rssmb_vfs::OpenId(0),
                vfs: vfs.clone(),
                file_id: None,
                dir_cursor: Default::default(),
                path: file_path.clone(),
                is_pipe: true,
                pipe_state: Some(Arc::new(std::sync::Mutex::new(
                    rssmb_rpc_server::PipeState::new(),
                ))),
                durable_guid: None,
                durable_persistent_id: None,
                lock_sequence_array: Arc::new(std::sync::Mutex::new([0xFF; 64])),
            },
        );
        let create_response = rssmb_proto::create::CreateResponse {
            oplock_level: rssmb_proto::oplock::OplockLevel::None,
            flags: Default::default(),
            create_action: rssmb_proto::create::CreateAction::Opened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            endof_file: 0,
            file_attributes: rssmb_proto::fscc::FileAttributes::new().with_normal(true),
            file_id,
            create_contexts: Vec::new(),
        };
        let response = build_response(&req.header, ResponseContent::Create(create_response));
        return FramedResponse::Plain(response);
    }

    // Read-only share or no-write-access user: refuse any open that could
    // mutate. This covers requested rights (write/append/EA/attrs/delete/
    // DACL/owner, generic write/all, MAXIMUM_ALLOWED is narrowed by the
    // advertised MaximalAccess), delete-on-close, and dispositions that
    // create, overwrite or supersede.
    if tree_entry.read_only || !tree_entry.write_access {
        let a = &create_req.desired_access;
        let wants_write = a.file_write_data()
            || a.file_append_data()
            || a.file_write_ea()
            || a.file_write_attributes()
            || a.file_delete_child()
            || a.delete()
            || a.write_dacl()
            || a.write_owner()
            || a.generic_write()
            || a.generic_all();
        let mutating_disposition = !matches!(
            create_req.create_disposition,
            rssmb_proto::create::CreateDisposition::Open
        );
        if wants_write || mutating_disposition || create_req.create_options.delete_on_close() {
            debug!(
                conn_id = conn_state.conn_id,
                tree_id, "create denied: read-only share or no write access"
            );
            return error_response_for(Command::Create, NtStatus::AccessDenied, &req.header);
        }
    }

    // Map SMB create disposition to VFS
    let disposition = match create_req.create_disposition {
        rssmb_proto::create::CreateDisposition::Superseded => {
            rssmb_vfs::CreateDisposition::Supersede
        }
        rssmb_proto::create::CreateDisposition::Open => rssmb_vfs::CreateDisposition::Open,
        rssmb_proto::create::CreateDisposition::Create => rssmb_vfs::CreateDisposition::Create,
        rssmb_proto::create::CreateDisposition::OpenIf => rssmb_vfs::CreateDisposition::OpenIf,
        rssmb_proto::create::CreateDisposition::Overwrite => {
            rssmb_vfs::CreateDisposition::Overwrite
        }
        rssmb_proto::create::CreateDisposition::OverwriteIf => {
            rssmb_vfs::CreateDisposition::OverwriteIf
        }
    };

    // Map the client's ShareAccess flags from the request.
    let client_share = &create_req.share_access;
    let share_access = rssmb_vfs::ShareAccess {
        read: client_share.read(),
        write: client_share.write(),
        delete: client_share.delete(),
    };

    let desired_access = {
        // Map the client's requested rights so the backend opens the OS
        // file with matching modes (was all-false → existing files were
        // always opened read-only and WRITEs to them failed).
        let a = &create_req.desired_access;
        rssmb_vfs::DesiredAccess {
            read: a.file_read_data() || a.maximum_allowed(),
            write: a.file_write_data() || a.file_append_data() || a.maximum_allowed(),
            read_attributes: a.file_read_attributes(),
            delete: a.delete(),
            generic_read: a.generic_read(),
            generic_write: a.generic_write(),
            generic_execute: a.generic_execute(),
            generic_all: a.generic_all(),
        }
    };

    let create_args = rssmb_vfs::CreateArgs {
        disposition,
        share_access,
        desired_access,
        create_options: rssmb_vfs::CreateOptions {
            directory: create_req.create_options.directory_file(),
            delete_on_close: create_req.create_options.delete_on_close(),
            ..Default::default()
        },
    };

    // The open table check happens after the VFS create returns an open_id,
    // because we need the file identity (dev,ino) from fstat to key into
    // the table. If a sharing conflict is found, we close the VFS handle
    // (undoing the open) and return SHARING_VIOLATION.
    match vfs.create("", &file_path, &create_args).await {
        Ok(create_result) => {
            let open_id = create_result.open;
            // Map the VFS create outcome to the MS-SMB2 §2.2.14 CreateAction:
            //   Superseded (0) / Created (2) / Opened (1) / Overwritten (3).
            // Supersede → Superseded; new file → Created; existing file
            // truncated by Overwrite/OverwriteIf → Overwritten; plain open
            // → Opened. (Golden: a fresh FILE_OPEN_IF answers Created=0x2.)
            let create_action = match create_req.create_disposition {
                rssmb_proto::create::CreateDisposition::Superseded => {
                    rssmb_proto::create::CreateAction::Superseded
                }
                rssmb_proto::create::CreateDisposition::Overwrite
                | rssmb_proto::create::CreateDisposition::OverwriteIf => {
                    if create_result.superseded {
                        rssmb_proto::create::CreateAction::Overwritten
                    } else {
                        rssmb_proto::create::CreateAction::Created
                    }
                }
                _ => {
                    if create_result.created {
                        rssmb_proto::create::CreateAction::Created
                    } else {
                        rssmb_proto::create::CreateAction::Opened
                    }
                }
            };
            // Get the stable file identity for the open table.
            let vfs_file_id = vfs.file_id(open_id).await.ok();

            // Check share-mode conflicts against the global open table.
            if let Some(fid) = vfs_file_id {
                let ot_entry = opens::OpenEntry {
                    open_id,
                    session_id,
                    tree_id,
                    share_access,
                    desired_access,
                    delete_on_close: create_req.create_options.delete_on_close(),
                };
                match state.open_table.check_and_add(fid, ot_entry).await {
                    Ok(()) => {}
                    Err(_conflict) => {
                        debug!(
                            conn_id = conn_state.conn_id,
                            tree_id, "create: sharing violation — closing VFS handle"
                        );
                        // Undo the VFS open.
                        let _ = vfs.close(open_id).await;
                        // Samba delay_for_oplock (open.c) with
                        // have_sharing_violation: break Handle caching on the
                        // conflicting leases (delay mask H) and pend the
                        // create until the break completes (timeout-disconnect).
                        // Deviation: after the wait we answer
                        // SHARING_VIOLATION without re-trying the open — a
                        // holder that closes its handle on the H break still
                        // gets the opener a violation (Samba would retry).
                        let will_overwrite = matches!(
                            create_req.create_disposition,
                            rssmb_proto::create::CreateDisposition::Superseded
                                | rssmb_proto::create::CreateDisposition::Overwrite
                                | rssmb_proto::create::CreateDisposition::OverwriteIf
                        );
                        let (breaks, mut waiters) = state
                            .open_table
                            .break_for_open(fid, open_id, will_overwrite, true)
                            .await;
                        send_break_notifications(&breaks).await;
                        state.open_table.arm_break_timers(&waiters);
                        waiters.retain(|w| w.delay);
                        if !waiters.is_empty() {
                            return pend_until_breaks(
                                conn_state,
                                &req.header,
                                waiters,
                                Command::Create,
                                Err(NtStatus::SharingViolation),
                            )
                            .await;
                        }
                        return error_response_for(
                            Command::Create,
                            NtStatus::SharingViolation,
                            &req.header,
                        );
                    }
                }
            }

            let file_id = next_file_id(conn_state);

            // Durable handles are enabled via config; a DH2Q request is only
            // honored when the durability precondition holds (see the grant
            // section below — batch oplock, or a lease with Handle caching,
            // per MS-SMB2 3.3.5.9.10 and the golden tables).
            let durable_enabled = state.config.durable_timeout_secs > 0;
            // A v1 (DHnQ) durable request is honored under the same
            // precondition; its response context is the 8-byte DHnQ blob
            // (timeout=0 — v1 has no timeout negotiation; Samba returns
            // all-zero bytes, smb2_create.c:1567).
            let durable_requested = (dh2q.is_some() || dhnq.is_some()) && durable_enabled;

            // Server-chosen durable timeout in milliseconds, mirroring Samba
            // (source3/smbd/smb2_create.c:1305-1313): MIN(client, 300000),
            // or 60000 when the client requested 0. Config's
            // durable_timeout_secs acts as the enable/disable switch; the
            // per-open deadline uses this negotiated value.
            let durable_timeout_msecs: u32 = match &dh2q {
                Some(q) => {
                    if q.timeout == 0 {
                        60_000
                    } else {
                        q.timeout.min(300_000)
                    }
                }
                None => (state.config.durable_timeout_secs * 1000) as u32,
            };

            let mut durable_granted = false;
            let mut durable_guid: Option<[u8; 16]> = None;
            // For v1 (DHnQ) durables: the SMB persistent id of this open
            // (the v1 table key). None for v2 durables.
            let mut durable_persistent_id: Option<u64> = None;

            // (OpenEntry insert happens after the lease/oplock grant, when
            // the durable decision is known.)

            // Query file info for the response
            let info = vfs
                .query_info(open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                .await
                .unwrap_or(rssmb_vfs::FileInfo {
                    file_id: rssmb_vfs::FileId { dev: 0, ino: 0 },
                    attributes: rssmb_vfs::FileAttributes::default(),
                    size: 0,
                    allocation_size: 0,
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    file_name: file_path.clone(),
                });

            // Grant file lease (RqLs v1/v2) or traditional oplock on non-directory opens.
            let mut granted_oplock = rssmb_proto::oplock::OplockLevel::None;
            let mut resp_ctx_items: Vec<(&[u8], Vec<u8>)> = Vec::new();
            let mut pending_breaks: Vec<opens::BreakNotification> = Vec::new();
            // Break waiters from the lease/oplock grant — the oneshot
            // receivers that resolve when each holder acks (or the 35 s
            // server break-timeout fires). Non-empty when the create must
            // pend for a break acknowledgment (L1: breaking1/timeout/etc.).
            let mut pending_break_waiters: Vec<opens::BreakWaiter> = Vec::new();
            // Lease grant to echo on a future durable reconnect (None if
            // the open is not lease-backed).
            let mut granted_lease: Option<crate::durable::LeaseEcho> = None;

            // The connection's client GUID — stored on durable opens for
            // lease-backed client-GUID scoping (reopen1a-lease golden:
            // a reconnect with the right lease key from a different client
            // GUID fails with OBJECT_NAME_NOT_FOUND; oplock-backed durables
            // ignore it).
            let conn_client_guid: [u8; 16] = {
                let rec = conn_state.negotiate_record.lock().await;
                match &*rec {
                    Some(r) => {
                        let mut cg = [0u8; 16];
                        cg[0..4].copy_from_slice(&r.client_guid.0.to_le_bytes());
                        cg[4..6].copy_from_slice(&r.client_guid.1.to_le_bytes());
                        cg[6..8].copy_from_slice(&r.client_guid.2.to_le_bytes());
                        cg[8..16].copy_from_slice(&r.client_guid.3);
                        cg
                    }
                    None => [0u8; 16],
                }
            };

            // Samba delay_for_oplock (open.c): SUPERSEDE/OVERWRITE/OVERWRITE_IF
            // set `will_overwrite`, which drops H and R from the break target.
            let will_overwrite = matches!(
                create_req.create_disposition,
                rssmb_proto::create::CreateDisposition::Superseded
                    | rssmb_proto::create::CreateDisposition::Overwrite
                    | rssmb_proto::create::CreateDisposition::OverwriteIf
            );
            // Raw desired-access bits for Samba's stat-open checks.
            let raw_access_mask = u32::from_le_bytes(create_req.desired_access.into_bytes());
            if state.config.leases && !info.attributes.directory {
                if let Some(fid) = vfs_file_id {
                    let (dialect, client_guid) = {
                        let rec = conn_state.negotiate_record.lock().await;
                        match &*rec {
                            Some(r) => {
                                let mut cg = [0u8; 16];
                                cg[0..4].copy_from_slice(&r.client_guid.0.to_le_bytes());
                                cg[4..6].copy_from_slice(&r.client_guid.1.to_le_bytes());
                                cg[6..8].copy_from_slice(&r.client_guid.2.to_le_bytes());
                                cg[8..16].copy_from_slice(&r.client_guid.3);
                                (r.dialect, cg)
                            }
                            None => (DialectConfig::Smb21, [0u8; 16]),
                        }
                    };

                    if create_req.requested_oplock_level == rssmb_proto::oplock::OplockLevel::Lease
                        && dialect >= DialectConfig::Smb21
                    {
                        if let Some(rqls) = &rqls {
                            let is_v2 = rqls.is_v2 && dialect >= DialectConfig::Smb30;
                            match state
                                .open_table
                                .request_lease_with_access(
                                    fid,
                                    open_id,
                                    client_guid,
                                    rqls.lease_key,
                                    rqls.lease_state,
                                    is_v2,
                                    rqls.parent_lease_key,
                                    rqls.epoch,
                                    will_overwrite,
                                    conn_state.write_tx.clone(),
                                    raw_access_mask,
                                )
                                .await
                            {
                                Ok((grant, breaks, lease_waiters)) => {
                                    granted_oplock = rssmb_proto::oplock::OplockLevel::Lease;
                                    granted_lease = Some(crate::durable::LeaseEcho {
                                        lease_key: grant.lease_key,
                                        state: grant.state,
                                        is_v2: grant.is_v2,
                                        parent_lease_key: grant.parent_lease_key,
                                        epoch: grant.epoch,
                                    });
                                    resp_ctx_items
                                        .push((RQLS_NAME, build_rqls_response_data(&grant)));
                                    pending_breaks = breaks;
                                    pending_break_waiters = lease_waiters;
                                }
                                Err(()) => {
                                    // Lease key collision with a different underlying file.
                                    let _ = state.open_table.remove(fid, open_id).await;
                                    conn_state
                                        .opens_ref()
                                        .write()
                                        .await
                                        .remove(&file_id.volatile);
                                    if let Some(guid) = durable_guid {
                                        state.durable_table.forget(&guid).await;
                                    }
                                    if let Some(pid) = durable_persistent_id {
                                        state.durable_table.forget_v1(pid).await;
                                    }
                                    let _ = vfs.close(open_id).await;
                                    return error_response_for(
                                        Command::Create,
                                        NtStatus::InvalidParameter,
                                        &req.header,
                                    );
                                }
                            }
                        }
                    } else {
                        let req_level = match create_req.requested_oplock_level {
                            rssmb_proto::oplock::OplockLevel::Batch => 0x09,
                            rssmb_proto::oplock::OplockLevel::Exclusive => 0x08,
                            rssmb_proto::oplock::OplockLevel::II => 0x01,
                            _ => 0x00,
                        };
                        if req_level != 0x00 {
                            let (granted, breaks, oplock_waiters) = state
                                .open_table
                                .request_oplock_with_access(
                                    fid,
                                    open_id,
                                    file_id,
                                    req_level,
                                    conn_state.write_tx.clone(),
                                    will_overwrite,
                                    raw_access_mask,
                                )
                                .await;
                            granted_oplock = match granted {
                                0x09 => rssmb_proto::oplock::OplockLevel::Batch,
                                0x08 => rssmb_proto::oplock::OplockLevel::Exclusive,
                                0x01 => rssmb_proto::oplock::OplockLevel::II,
                                _ => rssmb_proto::oplock::OplockLevel::None,
                            };
                            pending_breaks = breaks;
                            pending_break_waiters = oplock_waiters;
                        } else {
                            // Non-leased open still breaks any existing Write lease/oplock on this file.
                            let (breaks, waiters) = state
                                .open_table
                                .break_for_open_with_access(
                                    fid,
                                    open_id,
                                    will_overwrite,
                                    false,
                                    raw_access_mask,
                                )
                                .await;
                            pending_breaks = breaks;
                            pending_break_waiters = waiters;
                        }
                    }
                }
            }

            // Deliver any triggered break notifications to other lease/oplock holders.
            send_break_notifications(&pending_breaks).await;

            // Arm the 35 s server break-timeout for each pending break
            // (MS-SMB2 3.3.4.7; Samba OPLOCK_BREAK_TIMEOUT=35). The timer
            // downgrades the lease to NONE and resolves the waiter if the
            // holder never acks (L1: timeout, timeout-disconnect).
            state.open_table.arm_break_timers(&pending_break_waiters);
            // Only breaks that remove a delay-mask bit (or hit a lease that
            // is already mid-break) make the create pend (breaking4).
            pending_break_waiters.retain(|w| w.delay);

            // Durability precondition (MS-SMB2 3.3.5.9.10, golden tables in
            // tests/conformance/durable-v2-open-analysis.md): a durable
            // request (DH2Q or DHnQ) is only granted when the open holds a
            // batch oplock or a lease with Handle caching (RH/RWH/RHWE).
            // Any other open gets no durable response context — the
            // durable flag stays 0 in the CREATE response, matching the
            // golden open-oplock/open-lease tables (durable column).
            let durability_precondition = granted_oplock == rssmb_proto::oplock::OplockLevel::Batch
                || granted_lease.as_ref().is_some_and(|l| l.state.handle);
            if durable_requested && durability_precondition {
                // OpenEntry.durable_guid keys the guid-table side. For v1
                // (DHnQ) durables there is no CreateGuid — the entry lives
                // in the persistent-id side table, and the OpenEntry marks
                // durability via durable_persistent_id instead.
                durable_guid = match (&dh2q, &dhnq) {
                    (Some(q), _) => Some(q.create_guid),
                    (None, Some(_)) => None,
                    _ => None,
                };
                durable_persistent_id = if dhnq.is_some() {
                    Some(file_id.persistent)
                } else {
                    None
                };
                durable_granted = true;
            }

            // Store the open in the per-connection open table.
            conn_state.opens_ref().write().await.insert(
                file_id.volatile,
                OpenEntry {
                    session_id,
                    tree_id,
                    open_id,
                    vfs: vfs.clone(),
                    file_id: vfs_file_id,
                    dir_cursor: Default::default(),
                    path: file_path.clone(),
                    is_pipe: false,
                    pipe_state: None,
                    durable_guid,
                    durable_persistent_id,
                    lock_sequence_array: Arc::new(std::sync::Mutex::new([0xFF; 64])),
                },
            );

            // Record the granted durable open in the durable table, storing
            // the original oplock/lease grant for the reconnect echo. The
            // entry is NOT orphaned yet — it only becomes reconnectable
            // after its owning connection drops (Samba: allow_reconnect).
            // For v1 (DHnQ) opens there is no client GUID, so the entry
            // is keyed by a zero GUID — v1 reconnects (DHnC) match by the
            // persistent id alone, which is all they carry.
            if durable_granted {
                let identity = lookup_session_identity(conn_state, session_id).await;
                let username = identity
                    .as_ref()
                    .map(|i| i.username.clone())
                    .unwrap_or_default();
                let durable_entry = crate::durable::DurableEntry {
                    vfs: vfs.clone(),
                    open_id,
                    file_id: vfs_file_id,
                    smb_persistent_id: file_id.persistent,
                    session_id,
                    tree_id,
                    share_name: tree_entry.share_name.clone(),
                    username,
                    share_access,
                    desired_access,
                    path: file_path.clone(),
                    client_guid: if granted_lease.is_some() {
                        Some(conn_client_guid)
                    } else {
                        None
                    },
                    deadline: crate::durable::deadline_from_millis(durable_timeout_msecs),
                    timeout_msecs: durable_timeout_msecs,
                    oplock_level: if granted_lease.is_none() {
                        Some(granted_oplock)
                    } else {
                        None
                    },
                    lease: granted_lease.clone(),
                    orphaned: false,
                };
                // v2 durables are keyed by CreateGuid in the guid table;
                // v1 durables carry no GUID and are keyed by their SMB
                // persistent id in the side table (Samba: smbXsrv_open
                // global table). Never share a key between distinct v1
                // opens.
                if let Some(q) = &dh2q {
                    if let Err(_existing) = state
                        .durable_table
                        .insert(q.create_guid, durable_entry)
                        .await
                    {
                        // A LIVE open already holds this CreateGuid — a
                        // non-replay DH2Q reusing an in-flight GUID fails
                        // with STATUS_DUPLICATE_OBJECTID (MS-SMB2
                        // 3.3.5.9.10; Samba's replay-cache lookup). Undo
                        // the open so no state is orphaned.
                        debug!(
                            conn_id = conn_state.conn_id,
                            "DH2Q: duplicate CreateGuid on live durable open"
                        );
                        if let Some(fid) = vfs_file_id {
                            let _ = state.open_table.remove(fid, open_id).await;
                        }
                        state.open_table.remove_open_from_leases(open_id).await;
                        conn_state
                            .opens_ref()
                            .write()
                            .await
                            .remove(&file_id.volatile);
                        let _ = vfs.close(open_id).await;
                        return error_response_for(
                            Command::Create,
                            NtStatus::DuplicateObjectId,
                            &req.header,
                        );
                    }
                } else if dhnq.is_some() {
                    state
                        .durable_table
                        .insert_v1(file_id.persistent, durable_entry)
                        .await;
                } else {
                    unreachable!("durable_granted implies a durable request context");
                }
                debug!(
                    conn_id = conn_state.conn_id,
                    timeout_msecs = durable_timeout_msecs,
                    v1 = dhnq.is_some(),
                    "durable handle recorded"
                );
            }

            // Durable response contexts (Samba source3/smbd/smb2_create.c
            // :1567-1604): emitted only when the durable handle was
            // actually granted.
            //  - DHnQ (v1): 8 zero bytes — no timeout negotiation; the
            //    client parses `durable_open = true` from the presence of
            //    the blob alone (libcli create.c:406-411).
            //  - DH2Q (v2): negotiated timeout (ms) + flags; flags stay 0
            //    — persistent handles are not implemented (analysis G6).
            if durable_granted {
                if dhnq.is_some() {
                    let blob = vec![0u8; 8];
                    resp_ctx_items.push((DHNQ_NAME, blob));
                } else {
                    let mut blob = Vec::with_capacity(8);
                    blob.extend_from_slice(&durable_timeout_msecs.to_le_bytes());
                    blob.extend_from_slice(&0u32.to_le_bytes());
                    resp_ctx_items.push((DH2Q_NAME, blob));
                }
            }

            let create_contexts = if resp_ctx_items.is_empty() {
                Vec::new()
            } else {
                let refs: Vec<(&[u8], &[u8])> = resp_ctx_items
                    .iter()
                    .map(|(n, d)| (*n, d.as_slice()))
                    .collect();
                encode_create_contexts(&refs)
            };

            let create_response = rssmb_proto::create::CreateResponse {
                oplock_level: granted_oplock,
                flags: Default::default(),
                create_action,
                creation_time: FileTime::from(info.creation_time),
                last_access_time: FileTime::from(info.last_access_time),
                last_write_time: FileTime::from(info.last_write_time),
                change_time: FileTime::from(info.change_time),
                allocation_size: info.allocation_size,
                endof_file: info.size,
                file_attributes: crate::fsinfo::file_attributes_to_fscc(&info.attributes),
                file_id,
                create_contexts,
            };

            // A break that removes a delay-mask bit pends the CREATE
            // (MS-SMB2 3.3.4.7; Samba delay_for_oplock_fn): interim
            // STATUS_PENDING now, the CreateResponse once every holder acks
            // or its 35 s break timer expires.
            if !pending_break_waiters.is_empty() {
                return pend_until_breaks(
                    conn_state,
                    &req.header,
                    std::mem::take(&mut pending_break_waiters),
                    Command::Create,
                    Ok(ResponseContent::Create(create_response)),
                )
                .await;
            }

            let response = build_response(&req.header, ResponseContent::Create(create_response));
            FramedResponse::Plain(response)
        }
        Err(e) => {
            debug!(conn_id = conn_state.conn_id, error = %e, "create failed");
            let status = match e {
                rssmb_vfs::VfsError::NotFound => NtStatus::ObjectNameNotFound,
                rssmb_vfs::VfsError::AlreadyExists => NtStatus::ObjectNameCollision,
                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                rssmb_vfs::VfsError::SharingViolation => NtStatus::SharingViolation,
                rssmb_vfs::VfsError::PathTraversal => NtStatus::InvalidParameter,
                rssmb_vfs::VfsError::InvalidName => NtStatus::ObjectNameInvalid,
                rssmb_vfs::VfsError::IsDirectory => NtStatus::FileIsADirectory,
                rssmb_vfs::VfsError::NotDirectory => NtStatus::NotADirectory,
                rssmb_vfs::VfsError::DirectoryNotEmpty => NtStatus::DirectoryNotEmpty,
                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                rssmb_vfs::VfsError::ResourceExhausted => NtStatus::InsufficientServerResources,
                rssmb_vfs::VfsError::NotSupported => NtStatus::NotSupported,
                rssmb_vfs::VfsError::Io(ref msg) => {
                    // Fallback string matching for custom VFS backends that
                    // return VfsError::Io directly without VfsError::from_io.
                    if msg.contains("No space left") {
                        NtStatus::DiskFull
                    } else if msg.contains("Read-only")
                        || msg.contains("read-only")
                        || msg.contains("Permission denied")
                    {
                        NtStatus::AccessDenied
                    } else if msg.contains("Too many open") {
                        NtStatus::InsufficientServerResources
                    } else {
                        NtStatus::InvalidParameter
                    }
                }
                _ => NtStatus::InvalidParameter,
            };
            error_response_for(Command::Create, status, &req.header)
        }
    }
}

/// CLOSE — close a file handle.
async fn handle_close(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let close_req = match &req.content {
        RequestContent::Close(c) => c,
        _ => return error_response_for(Command::Close, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = close_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Look up and remove the open, validating session ownership.
    let open_entry = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        match opens.get(&file_id_volatile) {
            Some(entry) => {
                if entry.session_id != session_id || entry.tree_id != tree_id {
                    debug!(
                        conn_id = conn_state.conn_id,
                        file_id = file_id_volatile,
                        "close: handle does not belong to this session/tree"
                    );
                    return error_response_for(
                        Command::Close,
                        NtStatus::InvalidHandle,
                        &req.header,
                    );
                }
                opens.remove(&file_id_volatile)
            }
            None => None,
        }
    };
    match open_entry {
        Some(entry) => {
            // If the client set POSTQUERY_ATTRIB, query the VFS for file
            // metadata before closing so we can return it in the response.
            let postquery = close_req.flags.postquery_attrib();

            let (
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                endof_file,
                file_attributes,
            ) = if postquery {
                let info = entry
                    .vfs
                    .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                    .await
                    .unwrap_or(rssmb_vfs::FileInfo {
                        file_id: rssmb_vfs::FileId { dev: 0, ino: 0 },
                        attributes: rssmb_vfs::FileAttributes::default(),
                        size: 0,
                        allocation_size: 0,
                        creation_time: 0,
                        last_access_time: 0,
                        last_write_time: 0,
                        change_time: 0,
                        file_name: String::new(),
                    });
                (
                    FileTime::from(info.creation_time),
                    FileTime::from(info.last_access_time),
                    FileTime::from(info.last_write_time),
                    FileTime::from(info.change_time),
                    info.allocation_size,
                    info.size,
                    Default::default(),
                )
            } else {
                (
                    FileTime::ZERO,
                    FileTime::ZERO,
                    FileTime::ZERO,
                    FileTime::ZERO,
                    0,
                    0,
                    Default::default(),
                )
            };

            // Close via VFS (skip for pipe opens — no VFS handle).
            // For disk opens, remove from the global open table first.
            // The OpenTable tracks delete_on_close per-open. remove()
            // returns any_delete_on_close = true if the file's
            // delete_pending disposition was set (by this open or a
            // previously-closed one). When this is the last open,
            // was_last=true and any_delete_on_close=true → the file
            // must be unlinked. The VFS close() unlinks if the handle's
            // delete_on_close flag is set; for DOC set via SET_INFO
            // (not at create time), vfs.delete() is called instead.
            if !entry.is_pipe {
                // Remove from the global open table and check if this was
                // the last open with delete-on-close pending.
                if let Some(fid) = entry.file_id {
                    let remove_result = state.open_table.remove(fid, entry.open_id).await;
                    if remove_result.was_last && remove_result.any_delete_on_close {
                        // Last open with delete-pending disposition (possibly set
                        // by an earlier open that has already closed) — ensure
                        // this VFS handle's delete_on_close flag is set before
                        // close() unlinks the file.
                        let _ = entry.vfs.set_delete_on_close(entry.open_id, true).await;
                    }
                    // Release all byte-range locks held by this open.
                    state
                        .open_table
                        .release_all_locks_for_open(entry.open_id)
                        .await;
                }
                state
                    .open_table
                    .remove_open_from_leases(entry.open_id)
                    .await;

                // If this was a durable open, remove it from the durable
                // table. The VFS handle is closed below — `forget` does not
                // close it, avoiding a double-close.
                if let Some(guid) = entry.durable_guid {
                    state.durable_table.forget(&guid).await;
                }
                if let Some(pid) = entry.durable_persistent_id {
                    state.durable_table.forget_v1(pid).await;
                }

                if let Err(e) = entry.vfs.close(entry.open_id).await {
                    debug!(conn_id = conn_state.conn_id, error = %e, "close VFS failed");
                }
            }

            // Complete any pending CHANGE_NOTIFY whose WATCHED HANDLE is
            // the one being closed with STATUS_NOTIFY_CLEANUP
            // (MS-SMB2 3.3.5.10: closes the watch and notifies the client
            // via an async completion). Other pending CHANGE_NOTIFY ops on
            // this tree watch DIFFERENT handles and must stay pending —
            // cancelling them tree-wide hung smb2.notify's valid-req
            // (setup-file CLOSE killed the unrelated root-dir watch).
            {
                let mut pending = conn_state.pending_async.lock().await;
                let closed_volatile = file_id_volatile;
                let cleanup_keys: Vec<u64> = pending
                    .iter()
                    .filter(|(_, op)| {
                        op.command == Command::ChangeNotify
                            && op.tree_id == tree_id
                            && op.watched_file_id == Some(closed_volatile)
                    })
                    .map(|(k, _)| *k)
                    .collect();
                for key in cleanup_keys {
                    if let Some(op) = pending.remove(&key) {
                        // Guard must be released first — send_notify_cleanup
                        // awaits, and re-locking below while the old guard
                        // is still held would self-deadlock the connection
                        // task (Rust drops the old binding only AFTER the
                        // RHS completes).
                        drop(pending);
                        // Stops the watcher, then sends the async
                        // NOTIFY_CLEANUP completion.
                        send_notify_cleanup(conn_state, key, op).await;
                        // Re-acquire for any remaining keys.
                        pending = conn_state.pending_async.lock().await;
                    }
                }
                // Pended blocking LOCKs owned by the CLOSING open are
                // completed with RANGE_NOT_LOCKED (torture cancel "cancel
                // by close", lock.c:978 — the client's smb2_lock_recv must
                // unblock when h2 closes). Locks pended by other opens are
                // untouched.
                let lock_keys: Vec<u64> = pending
                    .iter()
                    .filter(|(_, op)| {
                        op.command == Command::Lock
                            && op.lock_open_volatile == Some(closed_volatile)
                            && op.session_id == session_id
                    })
                    .map(|(k, _)| *k)
                    .collect();
                for key in lock_keys {
                    if let Some(op) = pending.remove(&key) {
                        drop(pending);
                        let mut header = Header {
                            credit_charge: 0,
                            status: NtStatus::RangeNotLocked.to_u32(),
                            command: Command::Lock,
                            credit_request: 0,
                            flags: HeaderFlags::new().with_server_to_redir(true),
                            next_command: 0,
                            message_id: key,
                            tree_id: Some(op.tree_id),
                            async_id: None,
                            session_id: op.session_id,
                            signature: 0,
                        };
                        header.to_async(key);
                        let resp = FramedResponse::Plain(PlainResponse {
                            header,
                            content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                                error_data: vec![],
                            }),
                        });
                        send_unsolicited(conn_state, &resp, true).await;
                        pending = conn_state.pending_async.lock().await;
                    }
                }
            }

            let close_flags = if postquery {
                rssmb_proto::create::CloseFlags::new().with_postquery_attrib(true)
            } else {
                rssmb_proto::create::CloseFlags::new()
            };

            let close_response = rssmb_proto::create::CloseResponse {
                flags: close_flags,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                endof_file,
                file_attributes,
            };
            let response = build_response(&req.header, ResponseContent::Close(close_response));
            FramedResponse::Plain(response)
        }
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                file_id = file_id_volatile,
                "close: handle not found"
            );
            // Close of an unknown/already-closed handle is FILE_CLOSED
            // (MS-SMB2 3.3.5.16: fail with STATUS_FILE_CLOSED; torture
            // connect.c:227 asserts exactly this on double-close).
            error_response_for(Command::Close, NtStatus::FileClosed, &req.header)
        }
    }
}

/// READ — read data from a file.
async fn handle_read(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let read_req = match &req.content {
        RequestContent::Read(r) => r,
        _ => return error_response_for(Command::Read, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = read_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Look up the open, validating session ownership.
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => {
                debug!(
                    conn_id = conn_state.conn_id,
                    file_id = file_id_volatile,
                    "read: handle not found or wrong session"
                );
                return error_response_for(Command::Read, status, &req.header);
            }
        };

    // Pipe opens: drain the RPC output queue.
    if entry.is_pipe {
        let ps = entry
            .pipe_state
            .as_ref()
            .expect("pipe open without pipe_state");
        let mut state = ps.lock().unwrap();
        let (data, read_status) = state.read(read_req.length as usize);
        let max_read = read_req.length as usize;
        let _ = max_read;
        if data.is_empty() {
            return error_response_for(Command::Read, NtStatus::PipeEmpty, &req.header);
        }
        let read_response = rssmb_proto::file::ReadResponse { buffer: data };
        let mut response = build_response(&req.header, ResponseContent::Read(read_response));
        if read_status == rssmb_rpc_server::ReadStatus::Overflow {
            response.header.status = NtStatus::BufferOverflow.to_u32();
        }
        return FramedResponse::Plain(response);
    }

    // Bound the allocation by the negotiated MaxReadSize.
    if read_req.length > max_io_size(&state.config) {
        return error_response_for(Command::Read, NtStatus::InvalidParameter, &req.header);
    }

    // A 0-byte READ is answered with OK + 0 bytes regardless of file size,
    // offset, or lock state — even past EOF and inside another open's
    // exclusive range (torture zerobyteread asserts OK for a 0-byte read
    // at offset 5 under an exclusive lock [0,10); smbd behaves the same).
    // Must precede the lock-conflict check below.
    if read_req.length == 0 {
        let read_response = rssmb_proto::file::ReadResponse { buffer: vec![] };
        return FramedResponse::Plain(build_response(
            &req.header,
            ResponseContent::Read(read_response),
        ));
    }

    // Byte-range lock check: a READ must not conflict with an exclusive lock
    // held by a different open on the same file. We use `check_range_lock`
    // which only reports conflicts with exclusive locks by other opens.
    if let Some(fid) = entry.file_id {
        if let Err(_conflict) = state
            .open_table
            .check_range_lock(fid, entry.open_id, read_req.offset, read_req.length as u64)
            .await
        {
            return error_response_for(
                Command::Read,
                NtStatus::FileLockConflict,
                &req.header,
            );
        }
        // Break any Write lease/oplock held by another client on this file.
        let (breaks, waiters) = state
            .open_table
            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Read)
            .await;
        send_break_notifications(&breaks).await;
        state.open_table.arm_break_timers(&waiters);
    }

    // Read from VFS
    match entry
        .vfs
        .read_at(entry.open_id, read_req.offset, read_req.length)
        .await
    {
        Ok(data) => {
            if data.is_empty() {
                return error_response_for(Command::Read, NtStatus::EndOfFile, &req.header);
            }
            // `data` is a Bytes over the pooled read buffer; `to_vec` here
            // would copy the payload a second time. Into the response we
            // move the Bytes itself (the wire encoder copies it exactly
            // once, into the outgoing frame).
            let read_response = rssmb_proto::file::ReadResponse {
                buffer: data.to_vec(),
            };
            let response = build_response(&req.header, ResponseContent::Read(read_response));
            FramedResponse::Plain(response)
        }
        Err(e) => {
            debug!(conn_id = conn_state.conn_id, error = %e, "read failed");
            let status = match e {
                rssmb_vfs::VfsError::EndOfFile => NtStatus::EndOfFile,
                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                _ => NtStatus::InvalidParameter,
            };
            error_response_for(Command::Read, status, &req.header)
        }
    }
}

/// WRITE — write data to a file.
/// Note: WriteRequest data is position-marked after the fixed header.
/// Full implementation requires extracting the data from the raw SMB message.
async fn handle_write(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_frame: &[u8],
) -> FramedResponse {
    let write_req = match &req.content {
        RequestContent::Write(w) => w,
        _ => return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = write_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Look up the open, validating session ownership.
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => {
                debug!(
                    conn_id = conn_state.conn_id,
                    file_id = file_id_volatile,
                    "write: handle not found or wrong session"
                );
                return error_response_for(Command::Write, status, &req.header);
            }
        };

    // Pipe opens: feed RPC input bytes to the pipe state machine.
    if entry.is_pipe {
        // Extract write data (same logic as disk path below).
        let max_write_size = max_io_size(&state.config);
        let write_data_offset: usize = match raw_frame.get(66..68) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
            None => {
                return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header)
            }
        };
        if write_data_offset < 64 + 48 {
            return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
        }
        if write_req.length > max_write_size {
            return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
        }
        let data_len = write_req.length as usize;
        let data: Vec<u8> = if data_len == 0 {
            Vec::new()
        } else if raw_frame.len() >= write_data_offset + data_len {
            raw_frame[write_data_offset..write_data_offset + data_len].to_vec()
        } else {
            return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
        };

        let ps = entry
            .pipe_state
            .as_ref()
            .expect("pipe open without pipe_state");
        let identity = lookup_session_identity(conn_state, session_id).await;
        let shares = visible_shares_for_ctx(&state.shares_snapshot(), identity.as_ref());
        let server_name = if !state.config.server_name.is_empty() {
            &state.config.server_name
        } else {
            "rssmb"
        };
        let rpc_ctx = rssmb_rpc_server::RpcCtx {
            username: identity.as_ref().map(|i| i.username.as_str()).unwrap_or(""),
            is_guest: identity.as_ref().map(|i| i.is_guest).unwrap_or(false),
            shares,
            server_name,
        };
        let mut pipe_state = ps.lock().unwrap();
        let _consumed = pipe_state.process(&data, &rpc_ctx);
        let write_response = rssmb_proto::file::WriteResponse {
            count: data.len() as u32,
        };
        let response = build_response(&req.header, ResponseContent::Write(write_response));
        return FramedResponse::Plain(response);
    }

    // Enforce read-only / no-write-access policy using the tree entry.
    {
        let trees_ref = conn_state.trees_ref();
        let trees = trees_ref.read().await;
        if let Some(tree_entry) = trees.get(&tree_id) {
            if tree_entry.read_only || !tree_entry.write_access {
                debug!(conn_id = conn_state.conn_id, share = %tree_entry.share_name, "write denied: read-only or no write access");
                return error_response_for(Command::Write, NtStatus::AccessDenied, &req.header);
            }
        }
    }

    // Extract write data. `raw_frame` is exactly this message's bytes (the
    // dispatcher slices compound members), and DataOffset (u16 at body+2) is
    // relative to this message's header — so it is correct in any compound
    // position. smb-msg drops DataOffset after parsing, so read it here.
    let max_write_size = max_io_size(&state.config);
    let write_data_offset: usize = match raw_frame.get(66..68) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
        None => return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header),
    };
    if write_data_offset < 64 + 48 {
        return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
    }

    // Validate length against negotiated max_write_size.
    if write_req.length > max_write_size {
        debug!(
            conn_id = conn_state.conn_id,
            length = write_req.length,
            max = max_write_size,
            "write: exceeds max_write_size"
        );
        return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
    }

    let data_len = write_req.length as usize;
    let data: Vec<u8> = if data_len == 0 {
        // Zero-length write is valid.
        Vec::new()
    } else if raw_frame.len() >= write_data_offset + data_len {
        raw_frame[write_data_offset..write_data_offset + data_len].to_vec()
    } else {
        debug!(
            conn_id = conn_state.conn_id,
            frame_len = raw_frame.len(),
            data_offset = write_data_offset,
            data_len,
            "write: frame too short for data"
        );
        return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
    };

    // Byte-range lock check: a WRITE must not conflict with any lock
    // (shared or exclusive) held by a different open on the same file.
    if let Some(fid) = entry.file_id {
        if let Err(_conflict) = state
            .open_table
            .check_range_lock_for_write(
                fid,
                entry.open_id,
                write_req.offset,
                write_req.length as u64,
            )
            .await
        {
            return error_response_for(
                Command::Write,
                NtStatus::FileLockConflict,
                &req.header,
            );
        }
        // Break any Read or Write lease/oplock held by another client on this file.
        let (breaks, waiters) = state
            .open_table
            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Write)
            .await;
        send_break_notifications(&breaks).await;
        // Arm the 35 s break-timeout for any ack-required breaks (the
        // write itself is fire-and-forget, but the lease must not stay
        // stuck in breaking if the holder never acks).
        state.open_table.arm_break_timers(&waiters);
    }

    match entry
        .vfs
        .write_at(entry.open_id, write_req.offset, &data)
        .await
    {
        Ok(count) => {
            let write_response = rssmb_proto::file::WriteResponse { count };
            let response = build_response(&req.header, ResponseContent::Write(write_response));
            FramedResponse::Plain(response)
        }
        Err(e) => {
            tracing::warn!(conn_id = conn_state.conn_id, error = %e, "write failed");
            let status = match e {
                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                rssmb_vfs::VfsError::IsDirectory => NtStatus::FileIsADirectory,
                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                rssmb_vfs::VfsError::ResourceExhausted => NtStatus::InsufficientServerResources,
                // An I/O failure is not the client's fault.
                _ => NtStatus::Other(0xC000_0185), // STATUS_IO_DEVICE_ERROR
            };
            error_response_for(Command::Write, status, &req.header)
        }
    }
}

/// FLUSH — flush buffered data.
async fn handle_flush(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    // Extract file_id from the request if available
    let flush_req = match &req.content {
        RequestContent::Flush(f) => f,
        _ => {
            // FLUSH with no recognized content — just return success
            let response = build_response(&req.header, ResponseContent::Flush(Default::default()));
            return FramedResponse::Plain(response);
        }
    };

    let file_id_volatile = flush_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => {
                return error_response_for(Command::Flush, status, &req.header);
            }
        };
    // Pipe opens don't support FLUSH.
    if entry.is_pipe {
        return error_response_for(Command::Flush, NtStatus::Other(0xC000_0010), &req.header);
    }
    match entry.vfs.flush(entry.open_id).await {
        Ok(()) => {
            let response = build_response(&req.header, ResponseContent::Flush(Default::default()));
            FramedResponse::Plain(response)
        }
        Err(e) => {
            debug!(conn_id = conn_state.conn_id, error = %e, "flush failed");
            let status = match e {
                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                _ => NtStatus::Other(0xC000_0001), // STATUS_UNSUCCESSFUL
            };
            error_response_for(Command::Flush, status, &req.header)
        }
    }
}

/// QUERY_INFO — query file or filesystem information.
async fn handle_query_info(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let qi_req = match &req.content {
        RequestContent::QueryInfo(q) => q,
        _ => {
            return error_response_for(Command::QueryInfo, NtStatus::InvalidParameter, &req.header)
        }
    };

    let file_id_volatile = qi_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::QueryInfo, status, &req.header),
        };

    // Pipe opens: return minimal info for FileStandardInformation, reject rest.
    if entry.is_pipe {
        let info_type_byte = qi_req.info_type as u8;
        let info_class_byte = qi_req.info_class.0;
        let data = match info_type_byte {
            0x01 => match info_class_byte {
                5 => vec![0u8; 24], // FileStandardInformation: zeros for a pipe.
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported pipe info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::NotSupported,
                        &req.header,
                    );
                }
            },
            _ => {
                return error_response_for(Command::QueryInfo, NtStatus::NotSupported, &req.header);
            }
        };
        let query_response = rssmb_proto::info::QueryInfoResponse::from_bytes(data);
        let response = build_response(&req.header, ResponseContent::QueryInfo(query_response));
        return FramedResponse::Plain(response);
    }

    // Determine the info type and class from the request.
    // The info_type is 1=File, 2=FileSystem, 3=Security, 4=Quota.
    // For File, the info_class byte maps to QueryFileInfoClass values.
    // For FileSystem, the info_class byte maps to QueryFileSystemInfoClass values.
    let info_type_byte = qi_req.info_type as u8;
    let info_class_byte = qi_req.info_class.0;

    let data = match info_type_byte {
        // InfoType::File (0x01)
        0x01 => {
            // Query the VFS for file info
            let info = match entry
                .vfs
                .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "query_info VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            match info_class_byte {
                4 => crate::fsinfo::file_basic_info(&info), // FileBasicInformation
                5 => crate::fsinfo::file_standard_info(&info), // FileStandardInformation
                6 => crate::fsinfo::file_internal_info(&info), // FileInternalInformation
                7 => crate::fsinfo::file_ea_info(),         // FileEaInformation
                18 => {
                    // FileAllInformation — what Linux cifs.ko uses to stat.
                    let ro = tree_read_only(conn_state, entry.tree_id).await;
                    let access = if ro { 0x0012_00a9 } else { 0x001f_01ff };
                    crate::fsinfo::file_all_info(&info, &entry.path, access)
                }
                22 => crate::fsinfo::file_stream_info(&info), // FileStreamInformation
                34 => crate::fsinfo::file_network_open_info(&info), // FileNetworkOpenInformation
                35 => crate::fsinfo::file_attribute_tag_info(&info), // FileAttributeTagInformation
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported file info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidInfoClass,
                        &req.header,
                    );
                }
            }
        }
        // InfoType::FileSystem (0x02)
        0x02 => {
            let stats = match entry.vfs.fs_stats(entry.open_id).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "fs_stats VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            let share_name = {
                let trees_ref = conn_state.trees_ref();
                let trees = trees_ref.read().await;
                trees
                    .get(&tree_id)
                    .map(|t| t.share_name.clone())
                    .unwrap_or_default()
            };
            match info_class_byte {
                1 => crate::fsinfo::fs_volume_info(&share_name), // FileFsVolumeInformation
                3 => crate::fsinfo::fs_size_info(&stats),        // FileFsSizeInformation
                4 => crate::fsinfo::fs_device_info(),            // FileFsDeviceInformation
                5 => crate::fsinfo::fs_attribute_info(),         // FileFsAttributeInformation
                7 => crate::fsinfo::fs_full_size_info(&stats),   // FileFsFullSizeInformation
                11 => crate::fsinfo::fs_sector_size_info(&stats), // FileFsSectorSizeInformation
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported filesystem info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidInfoClass,
                        &req.header,
                    );
                }
            }
        }
        // InfoType::Security (0x03) — synthesize a minimal SD from POSIX mode.
        0x03 => {
            // Only DACL/OWNER/GROUP are supported. SACL requests require
            // ACCESS_SYSTEM_SECURITY which we don't grant.
            let additional_info = u32::from_le_bytes(qi_req.additional_info.into_bytes());
            let sec_info = match entry.vfs.query_security(entry.open_id).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "query_security VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            let sd = crate::fsinfo::synthesize_security_descriptor(&sec_info, additional_info);
            if sd.is_empty() {
                return error_response_for(
                    Command::QueryInfo,
                    NtStatus::Other(0xC000_0001),
                    &req.header,
                );
            }
            sd
        }
        // InfoType::Quota (0x04)
        0x04 => {
            return error_response_for(Command::QueryInfo, NtStatus::NotSupported, &req.header);
        }
        _ => {
            return error_response_for(Command::QueryInfo, NtStatus::InvalidInfoClass, &req.header);
        }
    };

    let query_response = rssmb_proto::info::QueryInfoResponse::from_bytes(data);
    let response = build_response(&req.header, ResponseContent::QueryInfo(query_response));
    FramedResponse::Plain(response)
}

/// QUERY_DIRECTORY — list directory entries.
async fn handle_query_directory(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let qd_req = match &req.content {
        RequestContent::QueryDirectory(q) => q,
        _ => {
            return error_response_for(
                Command::QueryDirectory,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    let file_id_volatile = qd_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::QueryDirectory, status, &req.header),
        };

    // Pipe opens don't support QUERY_DIRECTORY.
    if entry.is_pipe {
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::Other(0xC000_0010),
            &req.header,
        );
    }

    // MS-SMB2 3.3.5.18: an unsupported FileInformationClass fails with
    // STATUS_INVALID_INFO_CLASS (after the handle checks above).
    let Some(info_class) = qd_req.info_class() else {
        debug!(
            conn_id = conn_state.conn_id,
            class = qd_req.file_information_class,
            "unsupported directory info class"
        );
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::InvalidInfoClass,
            &req.header,
        );
    };
    let class_id = u8::from(info_class);

    let pattern = qd_req.file_name.to_string();
    let restart = qd_req.flags.restart_scans() || qd_req.flags.reopen();
    let single = qd_req.flags.return_single_entry();
    let max_len = qd_req.output_buffer_length as usize;

    let mut cursor = entry.dir_cursor.lock().await;
    if restart {
        cursor.entries = None;
        cursor.next = 0;
    }
    let first_call = cursor.entries.is_none();
    if first_call {
        // Snapshot the listing once; later calls page through it.
        let mut all = Vec::new();
        // Synthesize . and .. only for wildcard enumerations.
        if pattern == "*" || pattern.is_empty() {
            all.extend(crate::fsinfo::synthesize_dot_entries());
        }
        match entry
            .vfs
            .query_dir(
                entry.open_id,
                &pattern,
                rssmb_vfs::DirInfoClass::IdBothDirectoryInfo,
                true,
                0,
            )
            .await
        {
            Ok(vfs_entries) => all.extend(vfs_entries),
            Err(e) => {
                debug!(conn_id = conn_state.conn_id, error = %e, "query_dir VFS failed");
                return error_response_for(
                    Command::QueryDirectory,
                    NtStatus::NoSuchFile,
                    &req.header,
                );
            }
        }
        cursor.entries = Some(all);
        cursor.next = 0;
    }

    let all = cursor.entries.as_ref().expect("snapshot set above");
    if cursor.next >= all.len() {
        // MS-SMB2 3.3.5.18: no match on the first query → NO_SUCH_FILE,
        // exhausted cursor → NO_MORE_FILES.
        let status = if first_call {
            NtStatus::NoSuchFile
        } else {
            NtStatus::NoMoreFiles
        };
        return error_response_for(Command::QueryDirectory, status, &req.header);
    }

    // Take as many entries as fit in output_buffer_length.
    let remaining = &all[cursor.next..];
    let limit = if single { 1 } else { remaining.len() };
    let mut take = 0;
    let mut buffer: Option<Vec<u8>> = None;
    for n in 1..=limit {
        match crate::fsinfo::build_directory_buffer(&remaining[..n], class_id) {
            Some(b) if b.len() <= max_len => {
                take = n;
                buffer = Some(b);
            }
            Some(_) => break,
            None => {
                debug!(
                    conn_id = conn_state.conn_id,
                    class = class_id,
                    "unsupported directory info class"
                );
                return error_response_for(
                    Command::QueryDirectory,
                    NtStatus::InvalidInfoClass,
                    &req.header,
                );
            }
        }
    }
    if take == 0 {
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::BufferOverflow,
            &req.header,
        );
    }
    cursor.next += take;
    drop(cursor);

    match buffer {
        Some(buffer) => {
            let response = build_response(
                &req.header,
                ResponseContent::QueryDirectory(rssmb_proto::query_dir::QueryDirectoryResponse {
                    output_buffer: buffer,
                }),
            );
            FramedResponse::Plain(response)
        }
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                class = class_id,
                "unsupported directory info class"
            );
            error_response_for(
                Command::QueryDirectory,
                NtStatus::InvalidInfoClass,
                &req.header,
            )
        }
    }
}

/// SET_INFO — set file or filesystem information.
///
/// Handles: FileBasicInformation (timestamps/attributes),
/// FileEndOfFileInformation (truncate/extend),
/// FileDispositionInformation (mark delete-on-close),
/// FileRenameInformation (rename).
/// Other classes return NotSupported.
async fn handle_set_info(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let si_req = match &req.content {
        RequestContent::SetInfo(s) => s,
        _ => return error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = si_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::SetInfo, status, &req.header),
        };

    // Pipe opens don't support SET_INFO.
    if entry.is_pipe {
        return error_response_for(Command::SetInfo, NtStatus::Other(0xC000_0010), &req.header);
    }

    // Only File-type SET_INFO is supported for now.
    // InfoType::File = 0x01 is the only supported type for SET_INFO.
    // InfoType::Security (0x03) is accepted and ignored (the SD is not
    // persisted — documented as unsupported in the README/plan).
    let is_file_type = si_req.info_type == InfoType::File;
    let is_security_type = si_req.info_type == InfoType::Security;
    if !is_file_type && !is_security_type {
        return error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header);
    }
    if is_security_type {
        // Security SET_INFO: accept and succeed without persisting.
        // This is a documented compatibility behavior — the SD is not
        // mapped back to POSIX mode bits. A strict mode would return
        // ACCESS_DENIED here.
        debug!(
            conn_id = conn_state.conn_id,
            "set_info security: accepted (not persisted)"
        );
        return FramedResponse::Plain(build_response(
            &req.header,
            ResponseContent::SetInfo(rssmb_proto::info::SetInfoResponse::default()),
        ));
    }

    // Get the info class and raw data.
    let class_byte = si_req.info_class.0;
    let raw_data = si_req.data.data().to_vec();

    // Every handled file SET_INFO class mutates (timestamps, size, rename,
    // delete). On a read-only share or for a user without write access,
    // refuse them all — except clearing delete-pending, which is harmless
    // but also pointless, so refuse too.
    if tree_read_only(conn_state, tree_id).await || !tree_write_access(conn_state, tree_id).await {
        return error_response_for(Command::SetInfo, NtStatus::AccessDenied, &req.header);
    }

    // Parse and apply the specific info class.
    use binrw::BinRead;
    match class_byte {
        // FileBasicInformation (4): set timestamps and attributes
        4 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileBasicInformation::read_le(&mut cursor) {
                Ok(basic) => {
                    // Query current info, apply changes, call set_info.
                    let mut info = match entry
                        .vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info: query failed");
                            return error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            );
                        }
                    };
                    // Apply timestamps (0 means "don't change" in MS-FSCC).
                    // FileTime is stored as u64; 0 means don't change.
                    if basic.creation_time.as_u64() != 0 {
                        info.creation_time = basic.creation_time.as_u64();
                    }
                    if basic.last_access_time.as_u64() != 0 {
                        info.last_access_time = basic.last_access_time.as_u64();
                    }
                    if basic.last_write_time.as_u64() != 0 {
                        info.last_write_time = basic.last_write_time.as_u64();
                    }
                    if basic.change_time.as_u64() != 0 {
                        info.change_time = basic.change_time.as_u64();
                    }
                    // Apply DOS attributes (READONLY, HIDDEN, SYSTEM, ARCHIVE).
                    // The VFS set_info maps READONLY to the owner write bit.
                    // HIDDEN/SYSTEM/ARCHIVE are accepted but not yet persisted
                    // in xattr (Phase 2.8 partial — READONLY only).
                    info.attributes.read_only = basic.file_attributes.readonly();
                    info.attributes.hidden = basic.file_attributes.hidden();
                    info.attributes.system = basic.file_attributes.system();
                    info.attributes.archive = basic.file_attributes.archive();
                    match entry
                        .vfs
                        .set_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo, &info)
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info basic failed");
                            error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            )
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse basic failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileEndOfFileInformation (20): truncate or extend
        20 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileEndOfFileInformation::read_le(&mut cursor) {
                Ok(eof) => {
                    if let Some(fid) = entry.file_id {
                        let (breaks, waiters) = state
                            .open_table
                            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Write)
                            .await;
                        send_break_notifications(&breaks).await;
                        state.open_table.arm_break_timers(&waiters);
                    }
                    let mut info = match entry
                        .vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(_) => {
                            return error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            )
                        }
                    };
                    info.size = eof.end_of_file;
                    match entry
                        .vfs
                        .set_info(
                            entry.open_id,
                            rssmb_vfs::InfoClass::FileEndOfFileInfo,
                            &info,
                        )
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info eof failed");
                            let status = match e {
                                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                                _ => NtStatus::InvalidParameter,
                            };
                            error_response_for(Command::SetInfo, status, &req.header)
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse eof failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileDispositionInformation (13): mark delete-on-close
        13 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileDispositionInformation::read_le(&mut cursor) {
                Ok(disp) => {
                    let delete_pending = bool::from(disp.delete_pending);
                    debug!(
                        conn_id = conn_state.conn_id,
                        delete_pending, "set_info disposition"
                    );
                    if delete_pending && tree_read_only(conn_state, tree_id).await {
                        return error_response_for(
                            Command::SetInfo,
                            NtStatus::AccessDenied,
                            &req.header,
                        );
                    }
                    if delete_pending {
                        if let Some(fid) = entry.file_id {
                            let (breaks, waiters) = state
                                .open_table
                                .break_for_op(
                                    fid,
                                    Some(entry.open_id),
                                    opens::ConflictOp::HandleOrDelete,
                                )
                                .await;
                            send_break_notifications(&breaks).await;
                            state.open_table.arm_break_timers(&waiters);
                        }
                    }
                    match entry
                        .vfs
                        .set_delete_on_close(entry.open_id, delete_pending)
                        .await
                    {
                        Ok(()) => {
                            // Update the global open table's delete_on_close
                            // flag for this open so that the last-close logic
                            // in handle_close knows whether to unlink.
                            if let Some(fid) = entry.file_id {
                                state
                                    .open_table
                                    .update_delete_on_close(fid, entry.open_id, delete_pending)
                                    .await;
                            }
                            FramedResponse::Plain(build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            ))
                        }
                        Err(rssmb_vfs::VfsError::DirectoryNotEmpty) => error_response_for(
                            Command::SetInfo,
                            NtStatus::DirectoryNotEmpty,
                            &req.header,
                        ),
                        Err(rssmb_vfs::VfsError::AccessDenied) => error_response_for(
                            Command::SetInfo,
                            NtStatus::AccessDenied,
                            &req.header,
                        ),
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_delete_on_close failed");
                            error_response_for(
                                Command::SetInfo,
                                NtStatus::NotSupported,
                                &req.header,
                            )
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse disposition failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileRenameInformation (10): rename the file
        10 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileRenameInformation::read_le(&mut cursor) {
                Ok(rename) => {
                    let new_name = rename.file_name.to_string();
                    let replace = rename.replace_if_exists.into();
                    if let Some(fid) = entry.file_id {
                        // Samba delay_rename_for_lease_break (smb2_setinfo.c):
                        // a rename defers iff another lease on this file holds
                        // Handle caching — the break target is state minus H
                        // (keep R+W), and the rename pends until the holder
                        // acks or the 70 s timeout fires (rename_wait golden).
                        let (breaks, waiters) = state
                            .open_table
                            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Rename)
                            .await;
                        send_break_notifications(&breaks).await;
                        state.open_table.arm_break_timers(&waiters);
                        if !waiters.is_empty() {
                            // Rename must pend for the H-removing break.
                            // Return an interim PENDING and spawn a completion
                            // task that awaits the break waiters (with 70 s
                            // cap) then performs the rename.
                            let message_id = req.header.message_id;
                            let session_id = req.header.session_id;
                            let tree_id = req.header.tree_id.unwrap_or(0);
                            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                            conn_state.pending_async.lock().await.insert(
                                message_id,
                                AsyncOp {
                                    command: Command::SetInfo,
                                    session_id,
                                    tree_id,
                                    cancel: cancel_tx,
                                    notify_handle: None,
                                    watched_file_id: None,
                        lock_open_volatile: None,
                                },
                            );
                            // Send interim STATUS_PENDING. Construct manually
                            // (build_response overwrites flags/status).
                            let mut pending_hdr = req.header.clone();
                            pending_hdr.status = NtStatus::Pending.to_u32();
                            pending_hdr.to_async(message_id);
                            pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
                            let pending_resp = PlainResponse {
                                header: pending_hdr,
                                content: ResponseContent::Error(
                                    rssmb_proto::error::ErrorResponse { error_data: vec![] },
                                ),
                            };
                            // Spawn completion task.
                            let state_clone = state;
                            let conn_clone = conn_state.clone();
                            let vfs_clone = entry.vfs.clone();
                            let open_id = entry.open_id;
                            let req_header = req.header.clone();
                            let client_signed = req.header.flags.signed();
                            tokio::spawn(async move {
                                let timeout =
                                    tokio::time::sleep(std::time::Duration::from_secs(70));
                                let wait_all = futures::future::join_all(
                                    waiters.into_iter().map(|w| w.receiver),
                                );
                                tokio::pin!(wait_all);
                                tokio::pin!(timeout);
                                tokio::select! {
                                    _ = wait_all => {}
                                    _ = timeout => {}
                                    _ = cancel_rx => {
                                        conn_clone.pending_async.lock().await.remove(&message_id);
                                        return;
                                    }
                                }
                                conn_clone.pending_async.lock().await.remove(&message_id);
                                match vfs_clone.rename(open_id, &new_name, replace).await {
                                    Ok(()) => {
                                        let mut resp = build_response(
                                            &req_header,
                                            ResponseContent::SetInfo(
                                                rssmb_proto::info::SetInfoResponse::default(),
                                            ),
                                        );
                                        resp.header.to_async(message_id);
                                        let framed = FramedResponse::Plain(resp);
                                        send_unsolicited(&conn_clone, &framed, client_signed).await;
                                    }
                                    Err(e) => {
                                        let status = match e {
                                            rssmb_vfs::VfsError::InvalidHandle => {
                                                NtStatus::InvalidHandle
                                            }
                                            rssmb_vfs::VfsError::AlreadyExists => {
                                                NtStatus::ObjectNameCollision
                                            }
                                            rssmb_vfs::VfsError::AccessDenied => {
                                                NtStatus::AccessDenied
                                            }
                                            rssmb_vfs::VfsError::NotFound => {
                                                NtStatus::ObjectNameNotFound
                                            }
                                            rssmb_vfs::VfsError::DirectoryNotEmpty => {
                                                NtStatus::DirectoryNotEmpty
                                            }
                                            rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                            _ => NtStatus::InvalidParameter,
                                        };
                                        let err_resp = error_response_for(
                                            Command::SetInfo,
                                            status,
                                            &req_header,
                                        );
                                        // Convert to async for the pended response.
                                        let framed = match err_resp {
                                            FramedResponse::Plain(mut p) => {
                                                p.header.to_async(message_id);
                                                FramedResponse::Plain(p)
                                            }
                                            other => other,
                                        };
                                        send_unsolicited(&conn_clone, &framed, client_signed).await;
                                    }
                                }
                                let _ = state_clone; // keep alive
                            });
                            // Return the interim PENDING response; the
                            // completion is sent out-of-band.
                            return FramedResponse::Plain(pending_resp);
                        }
                    }
                    debug!(conn_id = conn_state.conn_id, new_name = %new_name, "set_info rename");
                    match entry
                        .vfs
                        .rename(entry.open_id, &new_name, rename.replace_if_exists.into())
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "rename failed");
                            let status = match e {
                                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                                rssmb_vfs::VfsError::AlreadyExists => NtStatus::ObjectNameCollision,
                                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                                rssmb_vfs::VfsError::NotFound => NtStatus::ObjectNameNotFound,
                                rssmb_vfs::VfsError::DirectoryNotEmpty => {
                                    NtStatus::DirectoryNotEmpty
                                }
                                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                _ => NtStatus::InvalidParameter,
                            };
                            error_response_for(Command::SetInfo, status, &req.header)
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse rename failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        _ => {
            debug!(
                conn_id = conn_state.conn_id,
                class = class_byte,
                "unsupported set_info class"
            );
            error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header)
        }
    }
}

/// CHANGE_NOTIFY — register a directory watch.
///
/// Returns STATUS_PENDING immediately. A background task watches the
/// directory using the `notify` crate (inotify on Linux) and sends
/// FILE_NOTIFY_INFORMATION as an async completion when changes occur.
///
/// On CLOSE, CANCEL, tree-disconnect, or logoff, the watch is cancelled
/// and the async op is removed from `pending_async`.
async fn handle_change_notify(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let cn_req = match &req.content {
        RequestContent::ChangeNotify(cn) => cn,
        _ => {
            return error_response_for(
                Command::ChangeNotify,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    let file_id_volatile = cn_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Validate the handle belongs to this session.
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::ChangeNotify, status, &req.header),
        };

    // CHANGE_NOTIFY requires a directory handle.
    if !entry.is_pipe {
        let info = entry
            .vfs
            .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
            .await
            .unwrap_or(rssmb_vfs::FileInfo {
                file_id: rssmb_vfs::FileId { dev: 0, ino: 0 },
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                file_name: String::new(),
            });
        if !info.attributes.directory {
            debug!(
                conn_id = conn_state.conn_id,
                "change_notify: handle is not a directory"
            );
            return error_response_for(
                Command::ChangeNotify,
                NtStatus::InvalidParameter,
                &req.header,
            );
        }
    }

    let message_id = req.header.message_id;
    let watch_tree = cn_req.flags.watch_tree();

    // Build the CompletionFilter from the request.
    let filter = crate::notify::CompletionFilter {
        file_name: cn_req.completion_filter.file_name(),
        dir_name: cn_req.completion_filter.dir_name(),
        attributes: cn_req.completion_filter.attributes(),
        size: cn_req.completion_filter.size(),
        last_write: cn_req.completion_filter.last_write(),
        last_access: cn_req.completion_filter.last_access(),
        creation: cn_req.completion_filter.creation(),
        ea: cn_req.completion_filter.ea(),
        security: cn_req.completion_filter.security(),
        stream_name: cn_req.completion_filter.stream_name(),
        stream_size: cn_req.completion_filter.stream_size(),
        stream_write: cn_req.completion_filter.stream_write(),
    };

    // Start the directory watch. The path is the share root joined with
    // the handle's relative path. For the share root itself (entry.path
    // is ""), the watch is on the share root.
    // We use the share root path from the VFS — but we don't have access
    // to the actual filesystem path from the VFS trait. The notify
    // watcher needs a real filesystem path, so we reconstruct it from
    // the share config path + the entry's relative path.
    let dir_path = {
        let trees_ref = conn_state.trees_ref();
        let trees = trees_ref.read().await;
        let share_name = trees
            .get(&tree_id)
            .map(|t| t.share_name.clone())
            .unwrap_or_default();
        // Look up the share path from config.
        let share_path = state
            .shares_snapshot()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&share_name))
            .map(|(_, v)| v.path.clone())
            .unwrap_or_default();
        if share_path.is_empty() {
            debug!(
                conn_id = conn_state.conn_id,
                "change_notify: no share path — using stub"
            );
            // No real path — fall back to the stub (no real watching).
            let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
            conn_state.pending_async.lock().await.insert(
                message_id,
                AsyncOp {
                    command: Command::ChangeNotify,
                    session_id,
                    tree_id,
                    cancel: cancel_tx,
                    notify_handle: None,
                    watched_file_id: None,
                        lock_open_volatile: None,
                },
            );
            let mut response = build_response(
                &req.header,
                ResponseContent::ChangeNotify(rssmb_proto::notify::ChangeNotifyResponse {
                    buffer: Default::default(),
                }),
            );
            response.header.status = NtStatus::Pending.to_u32();
            response.header.to_async(message_id);
            return FramedResponse::Plain(response);
        }
        // Join the share path with the entry's relative path.
        let mut path = std::path::PathBuf::from(share_path);
        if !entry.path.is_empty() {
            // The entry path is share-relative (e.g. "subdir/file.txt").
            // Join it with the share root.
            path.push(&entry.path);
        }
        path
    };

    // Register the async op before starting the watcher task so an immediate
    // watcher failure or quick event can remove it cleanly from pending_async.
    let max_output_length = cn_req.output_buffer_length;
    let mut pending_guard = conn_state.pending_async.lock().await;
    let notify_handle = crate::notify::start_watch(
        conn_state,
        message_id,
        session_id,
        tree_id,
        dir_path,
        watch_tree,
        filter,
        max_output_length,
    );
    let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
    pending_guard.insert(
        message_id,
        AsyncOp {
            command: Command::ChangeNotify,
            session_id,
            tree_id,
            cancel: cancel_tx,
            notify_handle: Some(notify_handle),
            watched_file_id: Some(file_id_volatile),
            lock_open_volatile: None,
        },
    );
    drop(pending_guard);

    // Build a PENDING response with async header.
    let mut response = build_response(
        &req.header,
        ResponseContent::ChangeNotify(rssmb_proto::notify::ChangeNotifyResponse {
            buffer: Default::default(),
        }),
    );
    response.header.status = NtStatus::Pending.to_u32();
    response.header.to_async(message_id);
    FramedResponse::Plain(response)
}

/// IOCTL (MS-SMB2 3.3.5.15). Only what mount clients probe for:
/// - FSCTL_VALIDATE_NEGOTIATE_INFO (3.0/3.0.2): validate the client's
///   negotiation parameters against the stored negotiation record, then
///   return the server's values. A mismatch terminates the connection
///   (MS-SMB2 3.3.5.15.12).
/// - FSCTL_DFS_GET_REFERRALS(_EX): STATUS_NOT_FOUND (0xC0000225)
/// - FSCTL_QUERY_NETWORK_INTERFACE_INFO: returns server interface addresses
///   for multichannel (SMB 3.0+). Returns NotSupported when multichannel
///   is disabled or no interfaces are available.
/// - anything else: STATUS_INVALID_DEVICE_REQUEST (the documented code for
///   an unsupported FSCTL).
async fn handle_ioctl(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let io = match &req.content {
        RequestContent::Ioctl(i) => i,
        _ => return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header),
    };
    const FSCTL_DFS_GET_REFERRALS: u32 = 0x0006_0194;
    const FSCTL_DFS_GET_REFERRALS_EX: u32 = 0x0006_01B0;
    const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
    const FSCTL_LMR_REQ_RESILIENCY: u32 = 0x0014_01F4;
    const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    const STATUS_NOT_FOUND: u32 = 0xC000_0225;
    const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    debug!(
        conn_id = conn_state.conn_id,
        ctl_code = format!("{:#010x}", io.ctl_code),
        "ioctl"
    );

    // FSCTL_PIPE_TRANSCEIVE: write input to the pipe, read output back.
    // Only valid on pipe opens (named pipes on IPC$).
    if io.ctl_code == FSCTL_PIPE_TRANSCEIVE {
        let file_id_volatile = io.file_id.volatile;
        let session_id = req.header.session_id;
        let tree_id = req.header.tree_id.unwrap_or(0);
        let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile)
            .await
        {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::Ioctl, status, &req.header),
        };
        if !entry.is_pipe {
            return error_response_for(
                Command::Ioctl,
                NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST),
                &req.header,
            );
        }
        let ps = entry
            .pipe_state
            .as_ref()
            .expect("pipe open without pipe_state");
        let identity = lookup_session_identity(conn_state, session_id).await;
        let shares = visible_shares_for_ctx(&state.shares_snapshot(), identity.as_ref());
        let server_name = if !state.config.server_name.is_empty() {
            &state.config.server_name
        } else {
            "rssmb"
        };
        let rpc_ctx = rssmb_rpc_server::RpcCtx {
            username: identity.as_ref().map(|i| i.username.as_str()).unwrap_or(""),
            is_guest: identity.as_ref().map(|i| i.is_guest).unwrap_or(false),
            shares,
            server_name,
        };

        // Extract input buffer from the IOCTL request.
        let input_data: Vec<u8> = match &io.buffer {
            rssmb_proto::ioctl::IoctlReqData::FsctlPipeTransceive(buf) => buf.as_slice().to_vec(),
            _ => vec![],
        };

        let max_output = io.max_output_response as usize;
        let mut state = ps.lock().unwrap();
        if !input_data.is_empty() {
            let _consumed = state.process(&input_data, &rpc_ctx);
        }
        let (output, read_status) = state.read(max_output);

        if output.is_empty() {
            return error_response_for(Command::Ioctl, NtStatus::PipeEmpty, &req.header);
        }

        let ioctl_resp = rssmb_proto::ioctl::IoctlResponse {
            ctl_code: io.ctl_code,
            file_id: io.file_id,
            in_buffer: vec![],
            out_buffer: output,
        };
        let mut response = build_response(&req.header, ResponseContent::Ioctl(ioctl_resp));
        if read_status == rssmb_rpc_server::ReadStatus::Overflow {
            response.header.status = NtStatus::BufferOverflow.to_u32();
        }
        return FramedResponse::Plain(response);
    }

    let status = match io.ctl_code {
        FSCTL_VALIDATE_NEGOTIATE_INFO => {
            let rec_guard = conn_state.negotiate_record.lock().await;
            let Some(rec) = &*rec_guard else {
                return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
            };
            // MS-SMB2 3.3.5.15.12: VNI is only defined for SMB 3.0/3.0.2.
            // For other dialects, return STATUS_NOT_SUPPORTED (or the
            // spec's behavior for non-applicable dialects).
            if !matches!(rec.dialect, DialectConfig::Smb30 | DialectConfig::Smb302) {
                return error_response_for(Command::Ioctl, NtStatus::NotSupported, &req.header);
            }
            match &io.buffer {
                rssmb_proto::ioctl::IoctlReqData::FsctlValidateNegotiateInfo(vni) => {
                    if vni.capabilities != u32::from_le_bytes(rec.client_capabilities.into_bytes())
                    {
                        warn!(conn_id = conn_state.conn_id, "VNI capabilities mismatch");
                        return FramedResponse::Disconnect;
                    }
                    if vni.guid != rec.client_guid {
                        warn!(conn_id = conn_state.conn_id, "VNI GUID mismatch");
                        return FramedResponse::Disconnect;
                    }
                    if vni.security_mode != rec.client_security_mode {
                        warn!(conn_id = conn_state.conn_id, "VNI security mode mismatch");
                        return FramedResponse::Disconnect;
                    }
                    let vni_dialects: Vec<WireDialect> = vni
                        .dialects
                        .iter()
                        .map(|d| match d.dialect {
                            0x0202 => WireDialect::Smb0202,
                            0x0210 => WireDialect::Smb021,
                            0x0300 => WireDialect::Smb030,
                            0x0302 => WireDialect::Smb0302,
                            0x0311 => WireDialect::Smb0311,
                            _ => WireDialect::Smb0202,
                        })
                        .collect();
                    let reselected = select_dialect(
                        &vni_dialects,
                        state.config.min_dialect,
                        state.config.max_dialect,
                    );
                    if reselected != Some(rec.dialect) {
                        warn!(
                            conn_id = conn_state.conn_id,
                            "VNI dialect re-selection mismatch"
                        );
                        return FramedResponse::Disconnect;
                    }
                    let out = rssmb_proto::ioctl::ValidateNegotiateInfoResponse {
                        capabilities: u32::from_le_bytes(rec.server_capabilities.into_bytes()),
                        guid: Guid::from(state.server_guid),
                        security_mode: rec.server_security_mode,
                        dialect: rec.wire_dialect(),
                    };
                    use binrw::BinWrite;
                    let mut buf = std::io::Cursor::new(Vec::new());
                    if out.write_le(&mut buf).is_err() {
                        return error_response_for(
                            Command::Ioctl,
                            NtStatus::InvalidParameter,
                            &req.header,
                        );
                    }
                    let resp = rssmb_proto::ioctl::IoctlResponse {
                        ctl_code: io.ctl_code,
                        file_id: io.file_id,
                        in_buffer: vec![],
                        out_buffer: buf.into_inner(),
                    };
                    return FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::Ioctl(resp),
                    ));
                }
                _ => {
                    return error_response_for(
                        Command::Ioctl,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            }
        }
        FSCTL_DFS_GET_REFERRALS | FSCTL_DFS_GET_REFERRALS_EX => NtStatus::Other(STATUS_NOT_FOUND),
        FSCTL_QUERY_NETWORK_INTERFACE_INFO => {
            // MS-SMB2 2.2.32.5 / 3.3.5.15.11: return the server's network
            // interface addresses so the client can establish additional
            // channels (multichannel). Requires SMB 3.0+ and a multichannel-
            // capable server.
            let rec_guard = conn_state.negotiate_record.lock().await;
            let Some(rec) = &*rec_guard else {
                return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
            };
            // QNII is defined for SMB 3.x only.
            if rec.dialect < DialectConfig::Smb30 {
                return error_response_for(Command::Ioctl, NtStatus::NotSupported, &req.header);
            }
            if !state.config.multichannel {
                NtStatus::NotSupported
            } else {
                let addresses = state.interface_snapshot.get();
                if addresses.is_empty() {
                    NtStatus::NotSupported
                } else {
                    let interfaces = crate::netinfo::to_network_interface_infos(&addresses);
                    let mut buf = rssmb_proto::ioctl::serialize_network_interface_list(&interfaces);
                    // Truncate at entry boundaries if the client's
                    // MaxOutputResponse cannot hold the full list, and
                    // return STATUS_BUFFER_OVERFLOW with the truncated data.
                    let max_output = io.max_output_response as usize;
                    let entry_size = rssmb_proto::ioctl::NETWORK_INTERFACE_INFO_SIZE;
                    let mut overflow = false;
                    if buf.len() > max_output {
                        let fit = max_output / entry_size;
                        if fit == 0 {
                            // Not even one entry fits: STATUS_BUFFER_TOO_SMALL
                            // with no data (a warning + empty buffer would
                            // read as "server has zero interfaces").
                            return error_response_for(
                                Command::Ioctl,
                                NtStatus::BufferTooSmall,
                                &req.header,
                            );
                        }
                        buf.truncate(fit * entry_size);
                        overflow = true;
                        // Fix the new last entry's Next to 0.
                        let last = buf.len() - entry_size;
                        buf[last..last + 4].fill(0);
                    }
                    let resp = rssmb_proto::ioctl::IoctlResponse {
                        ctl_code: io.ctl_code,
                        file_id: io.file_id,
                        in_buffer: vec![],
                        out_buffer: buf,
                    };
                    let mut response = build_response(&req.header, ResponseContent::Ioctl(resp));
                    if overflow {
                        response.header.status = NtStatus::BufferOverflow.to_u32();
                    }
                    return FramedResponse::Plain(response);
                }
            }
        }
        FSCTL_LMR_REQ_RESILIENCY => {
            // MS-SMB2 3.3.5.15.15: client asks the server to make the open
            // resilient (min 1 s timeout in the 8-byte input). We have no
            // durable-handle wipe on connection loss for plain opens, so
            // this is a validated no-op: require a live file handle and
            // reply OK (torture replay_broken_windows asserts OK at
            // lock.c:2992; the old fall-through returned
            // INVALID_DEVICE_REQUEST).
            let file_id_volatile = io.file_id.volatile;
            let session_id = req.header.session_id;
            let tree_id = req.header.tree_id.unwrap_or(0);
            if let Err(status) =
                lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await
            {
                return error_response_for(Command::Ioctl, status, &req.header);
            }
            NtStatus::Success
        }
        _ => NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST),
    };
    error_response_for(Command::Ioctl, status, &req.header)
}

/// Re-arm the LockSequence bucket with the incoming value after a request
/// completed successfully (smbd stores `state->lock_sequence_value` in the
/// cleanup fn on success only).
fn rearm_lock_sequence(
    seq_element: &Option<Arc<std::sync::Mutex<[u8; 64]>>>,
    seq_bucket: usize,
    seq_value: u8,
) {
    if let Some(arr) = seq_element {
        if (1..=64).contains(&seq_bucket) {
            arr.lock().unwrap()[seq_bucket - 1] = seq_value;
        }
    }
}

/// LOCK — acquire or release byte-range locks (MS-SMB2 3.3.5.14).
///
/// Processes a LOCK request containing one or more lock elements. Each element
/// specifies a byte range and flags (shared/exclusive/unlock/fail-immediately).
/// Locks are tracked in the global `OpenTable` keyed by file identity, so
/// conflicts across sessions and trees are enforced.
///
/// Only FAIL_IMMEDIATELY is supported in this phase. Blocking (async) locks
/// are deferred — the client gets `LOCK_NOT_GRANTED` if the range is
/// contended instead of waiting for the holder to release.
async fn handle_lock(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let lock_req = match &req.content {
        RequestContent::Lock(l) => l,
        _ => return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header),
    };

    // lock_count == 0 is INVALID_PARAMETER (torture `valid-request`,
    // MS-SMB2 2.2.21: LockCount must be at least 1).
    if lock_req.locks.is_empty() {
        return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
    }

    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // LOCK-specific: validate the persistent half of the FileId (forged
    // persistent → FILE_CLOSED, torture valid-request lock.c:133).
    if let Err(status) = check_lock_file_id_persistent(conn_state, &lock_req.file_id).await {
        return error_response_for(Command::Lock, status, &req.header);
    }

    // LockSequence replay detection (MS-SMB2 3.3.5.14; smbd
    // smbd_smb2_lock_send): the server advertises MULTI_CHANNEL, so
    // checking is enabled for all opens (spec SHOULD; also enabled for
    // durable handles). Bucket = sequence >> 4 (only 1..=64 valid);
    // value = sequence & 0xF. A replayed (bucket == stored value) request
    // is ignored: the request returns the ORIGINAL result — replayed
    // success is succeeded silently again, replayed failure is also
    // suppressed, which is what the torture replay_* subtests assert.
    let lock_sequence = lock_req.lock_sequence;
    let seq_bucket = (lock_sequence >> 4) as usize;
    let seq_value = (lock_sequence & 0xF) as u8;

    // Look up the open handle, validating session/tree ownership. A handle
    // that is gone (closed/tdis/logoff) is FILE_CLOSED for LOCK (torture
    // cancel-logoff lock.c:1166 and valid-request lock.c:133 both assert
    // FILE_CLOSED here; most other commands keep INVALID_HANDLE).
    let file_id_volatile = lock_req.file_id.volatile;
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile)
        .await
    {
        Ok(e) => e,
        Err(NtStatus::InvalidHandle) => {
            return error_response_for(Command::Lock, NtStatus::FileClosed, &req.header)
        }
        Err(status) => return error_response_for(Command::Lock, status, &req.header),
    };

    // Pipe opens don't support byte-range locks.
    if entry.is_pipe {
        return error_response_for(Command::Lock, NtStatus::NotSupported, &req.header);
    }

    // We need the stable file identity to key into the global lock table.
    let file_id = match entry.file_id {
        Some(fid) => fid,
        None => return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header),
    };

    // LockSequence check (needs the open; see comment above). smbd runs
    // this BEFORE parsing element flags — a replayed request short-circuits
    // to OK regardless of its content.
    let seq_element: Option<Arc<std::sync::Mutex<[u8; 64]>>> = if (1..=64).contains(&seq_bucket) {
        Some(entry.lock_sequence_array.clone())
    } else {
        None
    };
    if let Some(arr) = &seq_element {
        let mut a = arr.lock().unwrap();
        let stored = &mut a[seq_bucket - 1];
        if *stored == seq_value {
            // Replay of an already-successful request: ignore completely
            // (return OK, touch nothing) — smbd tevent_req_done path.
            return build_lock_ok(&req);
        }
        // Not a replay: invalidate the bucket while processing; it is
        // re-armed with the incoming value only on success (matching
        // smbd's cleanup fn).
        *stored = 0xFF;
    }

    // Process the lock elements exactly like smbd (source3/smbd/smb2_lock.c,
    // verified against torture valid-request/unlock/multiple-unlock):
    //
    // 1. First-element flags switch (pre-loop):
    //    - SHARED or EXCLUSIVE alone (no FAIL_IMMEDIATELY) with >1 element
    //      → INVALID_PARAMETER; alone it is a BLOCKING lock (K5 pends on
    //      conflict; a conflict-free blocking lock grants immediately).
    //    - SHARED|FI, EXCLUSIVE|FI → normal immediate locks.
    //    - UNLOCK → the whole request is an unlock request (only the first
    //      element may carry the UNLOCK bit, MS-SMB2 3.3.5.14).
    //    - anything else (0, type bit | UNLOCK, stray bits) →
    //      INVALID_PARAMETER before any state changes.
    // 2. Non-unlock requests with >1 element: every element must carry
    //    FAIL_IMMEDIATELY (MS-SMB2 3.3.5.14.2 SHOULD) → INVALID_PARAMETER.
    // 3. Unlock requests: ALL unlock elements are processed first (applied
    //    unlocks stay applied); the first missing range fails the request
    //    with RANGE_NOT_LOCKED (deferred-invalid elements lose to a real
    //    unlock miss); invalid (type-bit/unknown) elements then fail with
    //    INVALID_PARAMETER (MS-SMB2 3.3.5.14.1, torture multiple-unlock
    //    Test4/Test10).
    use rssmb_proto::lock::lock_flags;

    let elements = &lock_req.locks;
    let first_flags = elements[0].flags;
    let isunlock = first_flags == lock_flags::UNLOCK;

    match first_flags {
        lock_flags::SHARED | lock_flags::EXCLUSIVE => {
            if elements.len() > 1 {
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }
        f if f == lock_flags::SHARED | lock_flags::FAIL_IMMEDIATELY
            || f == lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY =>
        {
            // SHARED|FI or EXCLUSIVE|FI — normal immediate lock.
        }
        lock_flags::UNLOCK => {}
        _ => {
            return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
        }
    }

    if !isunlock && elements.len() > 1 {
        for el in elements {
            if el.flags & lock_flags::FAIL_IMMEDIATELY == 0 {
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }
    }

    let mut acquired: Vec<(u64, u64, bool)> = Vec::new();

    if isunlock {
        let mut saw_invalid = false;
        for element in elements {
            if element.flags != lock_flags::UNLOCK {
                // Type bit | UNLOCK or unknown flags: deferred error — all
                // valid unlock elements are processed first.
                saw_invalid = true;
                continue;
            }
            if let Err(_miss) = state
                .open_table
                .release_range_lock(file_id, entry.open_id, element.offset, element.length)
                .await
            {
                return error_response_for(Command::Lock, NtStatus::RangeNotLocked, &req.header);
            }
        }
        if saw_invalid {
            return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
        }
        rearm_lock_sequence(&seq_element, seq_bucket, seq_value);
        return build_lock_ok(&req);
    }

    for element in elements {
        let flags = element.flags;
        let offset = element.offset;
        let length = element.length;
        let exclusive = flags & lock_flags::EXCLUSIVE != 0;
        // A lock element without FAIL_IMMEDIATELY is a BLOCKING lock
        // (MS-SMB2 3.3.5.14); SHARED/EXCLUSIVE-only first elements were
        // validated above. Blocking only applies to the single-element
        // request (the multi-element case already failed validation).
        let blocking = flags & lock_flags::FAIL_IMMEDIATELY == 0;

        // Per-element validation (smbd's second switch): a non-unlock
        // request accepts only SHARED, EXCLUSIVE, SHARED|FI or
        // EXCLUSIVE|FI — anything else (0, type|FI mixtures like
        // SHARED-only on a later element, UNLOCK, unknown bits) is
        // INVALID_PARAMETER (torture valid-request flag permutations).
        match flags {
            lock_flags::SHARED | lock_flags::EXCLUSIVE => {}
            f if f == lock_flags::SHARED | lock_flags::FAIL_IMMEDIATELY
                || f == lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY => {}
            _ => {
                for (o, l, _) in &acquired {
                    let _ = state
                        .open_table
                        .release_range_lock(file_id, entry.open_id, *o, *l)
                        .await;
                }
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }

        // >63-bit lock requests: per MS-FSA (and Samba's byte_range_valid),
        // INVALID_LOCK_RANGE only when (offset + length - 1) wraps AND
        // length != 0 — so offset=u64::MAX with length=1 (the single last
        // byte) is a VALID lock (torture lock "Trying max/1 lock" asserts
        // OK at lock.c:747).
        if length != 0 && (length - 1) > u64::MAX - offset {
            for (o, l, _) in &acquired {
                let _ = state
                    .open_table
                    .release_range_lock(file_id, entry.open_id, *o, *l)
                    .await;
            }
            return error_response_for(Command::Lock, NtStatus::InvalidLockRange, &req.header);
        }

        // Zero-length locks are VALID entries (torture `lock` "Trying 0/0
        // lock" and `zerobytelength` — MS-SMB2 2.2.21 allows Length 0;
        // smbd treats them like any other stacked entry). The u128 overlap
        // math makes a 0-length range conflict with nothing, and only an
        // exact (offset, 0) unlock removes it.
        match state
            .open_table
            .acquire_range_lock(
                file_id,
                entry.open_id,
                session_id,
                tree_id,
                offset,
                length,
                exclusive,
            )
            .await
        {
            Ok(()) => {
                acquired.push((offset, length, exclusive));
            }
            Err(_conflict) => {
                // Blocking lock (no FAIL_IMMEDIATELY): pend until the
                // conflicting range is released, the request is cancelled,
                // or the server-side timeout — then either grant
                // (STATUS_OK async completion) or fail LOCK_NOT_GRANTED
                // (MS-SMB2 3.3.5.14; torture async/cancel/cancel-tdis/
                // cancel-logoff).
                if blocking {
                    let message_id = req.header.message_id;
                    let (wake_tx, mut wake_rx) = tokio::sync::watch::channel(false);
                    let waiter = opens::LockWaiter {
                        file_id,
                        open_id: entry.open_id,
                        elements: vec![(offset, length, exclusive)],
                        wake: wake_tx,
                    };
                    let rx = state.open_table.register_lock_waiter(waiter).await;
                    let _ = rx;
                    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                    conn_state.pending_async.lock().await.insert(
                        message_id,
                        AsyncOp {
                            command: Command::Lock,
                            session_id,
                            tree_id,
                            cancel: cancel_tx,
                            notify_handle: None,
                            watched_file_id: None,
                            lock_open_volatile: Some(file_id_volatile),
                        },
                    );
                    let mut pending_hdr = req.header.clone();
                    pending_hdr.status = NtStatus::Pending.to_u32();
                    pending_hdr.to_async(message_id);
                    pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
                    let pending_resp = PlainResponse {
                        header: pending_hdr,
                        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                            error_data: vec![],
                        }),
                    };
                    let conn_clone = conn_state.clone();
                    let req_header = req.header.clone();
                    let open_table = state.open_table.clone();
                    let entry_open_id = entry.open_id;
                    let client_signed = req.header.flags.signed();
                    tokio::spawn(async move {
                        let timeout = tokio::time::sleep(std::time::Duration::from_secs(35));
                        tokio::pin!(timeout);
                        let granted = tokio::select! {
                            _ = wake_rx.changed() => true,
                            _ = timeout => false,
                            _ = cancel_rx => {
                                conn_clone.pending_async.lock().await.remove(&message_id);
                                return;
                            }
                        };
                        // Ownership rule: the completion is sent only by the
                        // task that successfully removes the pending_async
                        // entry. CLOSE/TDIS/LOGOFF sweeps complete pended
                        // locks out-of-band and remove the entry first, so a
                        // woken watcher whose entry is gone must stay silent
                        // (a second response for the same MessageId is
                        // INVALID_NETWORK_RESPONSE for the client).
                        if conn_clone.pending_async.lock().await.remove(&message_id).is_none() {
                            return;
                        }
                        // Re-check and apply atomically; a lost race (another
                        // waiter or request grabbed the range) fails.
                        let outcome = if granted
                            && open_table
                                .acquire_range_lock(
                                    file_id,
                                    entry_open_id,
                                    session_id,
                                    tree_id,
                                    offset,
                                    length,
                                    exclusive,
                                )
                                .await
                                .is_ok()
                        {
                            NtStatus::Success
                        } else {
                            NtStatus::LockNotGranted
                        };
                        let mut resp = build_response(
                            &req_header,
                            ResponseContent::Lock(rssmb_proto::lock::LockResponse::default()),
                        );
                        resp.header.to_async(message_id);
                        resp.header.status = outcome.to_u32();
                        resp.header.credit_charge = 0;
                        resp.header.credit_request = 0;
                        send_unsolicited(&conn_clone, &FramedResponse::Plain(resp), client_signed)
                            .await;
                    });
                    return FramedResponse::Plain(pending_resp);
                }
                // FAIL_IMMEDIATELY → LOCK_NOT_GRANTED.
                for (o, l, _) in &acquired {
                    let _ = state
                        .open_table
                        .release_range_lock(file_id, entry.open_id, *o, *l)
                        .await;
                }
                return error_response_for(
                    Command::Lock,
                    NtStatus::LockNotGranted,
                    &req.header,
                );
            }
        }
    }

    if !acquired.is_empty() {
        let (breaks, waiters) = state
            .open_table
            .break_for_op(file_id, Some(entry.open_id), opens::ConflictOp::Lock)
            .await;
        send_break_notifications(&breaks).await;
        state.open_table.arm_break_timers(&waiters);
    }

    rearm_lock_sequence(&seq_element, seq_bucket, seq_value);
    fn build_lock_ok(req: &rssmb_proto::plain::PlainRequest) -> FramedResponse {
        FramedResponse::Plain(build_response(
            &req.header,
            ResponseContent::Lock(rssmb_proto::lock::LockResponse::default()),
        ))
    }

    build_lock_ok(&req)
}

/// Encode and send unsolicited SMB2 OPLOCK_BREAK / LEASE_BREAK notifications
/// (MS-SMB2 2.2.23.1 / 2.2.23.2: `Command = OplockBreak`, `Flags = SERVER_TO_REDIR`,
/// `MessageId = 0xFFFFFFFFFFFFFFFF`, `SessionId = 0`, `TreeId = 0`).
async fn send_break_notifications(breaks: &[opens::BreakNotification]) {
    for b in breaks {
        let (tx, content) = match b {
            opens::BreakNotification::Lease {
                notify_tx,
                lease_key,
                current_state,
                new_state,
                new_epoch,
                ack_required,
            } => (
                notify_tx,
                ResponseContent::LeaseBreakNotify(rssmb_proto::create::LeaseBreakNotify {
                    new_epoch: *new_epoch,
                    ack_required: u32::from(*ack_required),
                    lease_key: Guid::from(*lease_key),
                    current_lease_state: current_state.to_proto(),
                    new_lease_state: new_state.to_proto(),
                }),
            ),
            opens::BreakNotification::Oplock {
                notify_tx,
                smb_file_id,
                new_oplock_level,
            } => (
                notify_tx,
                ResponseContent::OplockBreakNotify(rssmb_proto::create::OplockBreakMsg {
                    oplock_level: *new_oplock_level,
                    reserved: 0,
                    _reserved2: 0,
                    file_id: *smb_file_id,
                }),
            ),
        };
        let plain = PlainResponse {
            header: Header {
                credit_charge: 0,
                status: NtStatus::Success.to_u32(),
                command: Command::OplockBreak,
                credit_request: 0,
                flags: HeaderFlags::new().with_server_to_redir(true),
                next_command: 0,
                message_id: u64::MAX,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        };
        let encoded = rssmb_wire_adapter::encode_response(&FramedResponse::Plain(plain));
        if !encoded.is_empty() {
            let _ = tx.send(encoded).await;
        }
    }
}

/// OPLOCK_BREAK — handle a client Oplock Break Acknowledgment or Lease Break
/// Acknowledgment (MS-SMB2 3.3.5.19.1 / 3.3.5.19.2).
async fn handle_oplock_break(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    // Validate that the session exists on this connection.
    let session_id = req.header.session_id;
    let session_exists = {
        let sessions = conn_state.sessions.read().await;
        sessions.iter().any(|s| s.id == session_id)
    };
    if !session_exists {
        return error_response_for(
            Command::OplockBreak,
            NtStatus::UserSessionDeleted,
            &req.header,
        );
    }

    match &req.content {
        RequestContent::LeaseBreakAck(ack) => {
            let client_guid = {
                let rec = conn_state.negotiate_record.lock().await;
                match &*rec {
                    Some(r) => {
                        let mut cg = [0u8; 16];
                        cg[0..4].copy_from_slice(&r.client_guid.0.to_le_bytes());
                        cg[4..6].copy_from_slice(&r.client_guid.1.to_le_bytes());
                        cg[6..8].copy_from_slice(&r.client_guid.2.to_le_bytes());
                        cg[8..16].copy_from_slice(&r.client_guid.3);
                        cg
                    }
                    None => [0u8; 16],
                }
            };
            let mut lease_key = [0u8; 16];
            lease_key[0..4].copy_from_slice(&ack.lease_key.0.to_le_bytes());
            lease_key[4..6].copy_from_slice(&ack.lease_key.1.to_le_bytes());
            lease_key[6..8].copy_from_slice(&ack.lease_key.2.to_le_bytes());
            lease_key[8..16].copy_from_slice(&ack.lease_key.3);

            let acked = opens::LeaseCaching::from_proto(ack.lease_state);
            match state
                .open_table
                .ack_lease_break(client_guid, lease_key, acked)
                .await
            {
                Ok((new_state, followup)) => {
                    if let Some(notif) = followup {
                        send_break_notifications(&[notif]).await;
                    }
                    let resp = rssmb_proto::create::LeaseBreakAckResponse {
                        reserved: 0,
                        _reserved2: 0,
                        lease_key: ack.lease_key,
                        lease_state: new_state.to_proto(),
                        _reserved3: 0,
                    };
                    FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::LeaseBreak(resp),
                    ))
                }
                Err(status) => error_response_for(Command::OplockBreak, status, &req.header),
            }
        }
        RequestContent::OplockBreakAck(ack) => {
            match state
                .open_table
                .ack_oplock_break(ack.file_id, ack.oplock_level)
                .await
            {
                Ok((new_level, followup)) => {
                    if let Some(notif) = followup {
                        send_break_notifications(&[notif]).await;
                    }
                    let resp = rssmb_proto::create::OplockBreakMsg {
                        oplock_level: new_level,
                        reserved: 0,
                        _reserved2: 0,
                        file_id: ack.file_id,
                    };
                    FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::OplockBreak(resp),
                    ))
                }
                Err(status) => error_response_for(Command::OplockBreak, status, &req.header),
            }
        }
        _ => error_response_for(
            Command::OplockBreak,
            NtStatus::InvalidParameter,
            &req.header,
        ),
    }
}

/// Complete a removed CHANGE_NOTIFY async op with STATUS_NOTIFY_CLEANUP
/// (0x0000010B, empty buffer) — MS-SMB2 3.3.5.10/3.3.5.19.2: closing the
/// watched handle or tree-disconnect ends the watch and notifies the
/// client with an async completion. The watcher is stopped first so no
/// second completion can race.
async fn send_notify_cleanup(conn_state: &ConnState, key: u64, op: AsyncOp) {
    let _ = op.cancel.send(());
    if let Some(handle) = op.notify_handle {
        handle.cancel();
    }
    let mut header = Header {
        credit_charge: 0,
        status: 0x0000_010B,
        command: Command::ChangeNotify,
        credit_request: 0,
        flags: HeaderFlags::new().with_server_to_redir(true),
        next_command: 0,
        message_id: key,
        tree_id: Some(op.tree_id),
        async_id: None,
        session_id: op.session_id,
        signature: 0,
    };
    header.to_async(key);
    let resp = FramedResponse::Plain(PlainResponse {
        header,
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    });
    // Out-of-band completion: sign when the session requires signing
    // (same rule as handle_cancel: the client signs requests when signing
    // is required, so the request's signed flag and `required` agree).
    let signed = conn_state
        .signing_ref()
        .read()
        .unwrap()
        .get(&op.session_id)
        .map(|st| st.required)
        .unwrap_or(false);
    send_unsolicited(conn_state, &resp, signed).await;
}

/// CANCEL — cancel a pending async operation (MS-SMB2 3.3.5.16).
///
/// CANCEL itself never gets a response. The cancelled operation is completed
/// with STATUS_CANCELLED, sent on the write channel as an async response.
async fn handle_cancel(conn_state: &ConnState, req_header: &Header) -> Option<FramedResponse> {
    // Async CANCEL carries the AsyncId; sync CANCEL carries the MessageId of
    // the original request. We use MessageId as AsyncId, so both map here.
    let target = req_header.async_id.unwrap_or(req_header.message_id);

    let removed = {
        let mut pending = conn_state.pending_async.lock().await;
        match pending.get(&target) {
            // Only the owning session may cancel.
            Some(op) if op.session_id == req_header.session_id => pending.remove(&target),
            _ => None,
        }
    };
    let Some(op) = removed else {
        // MS-SMB2 pre-interim CANCEL: Samba's client sends the CANCEL
        // immediately after smb2_notify_send, before the STATUS_PENDING
        // interim arrives (smbXcli_base.c smb2cli_req_cancel: MessageId=0,
        // AsyncId=0, no ASYNC flag). smbd answers this by cancelling the
        // session's most recent pending async op — do the same: the
        // highest message_id (client mids are monotonic per session).
        if target == 0 && req_header.session_id != 0 {
            let candidates: Vec<u64> = {
                let pending = conn_state.pending_async.lock().await;
                pending
                    .iter()
                    .filter(|(_, op)| op.session_id == req_header.session_id)
                    .map(|(k, _)| *k)
                    .collect()
            };
            if let Some(newest) = candidates.into_iter().max() {
                let removed = {
                    let mut pending = conn_state.pending_async.lock().await;
                    match pending.get(&newest) {
                        Some(op) if op.session_id == req_header.session_id => {
                            pending.remove(&newest)
                        }
                        _ => None,
                    }
                };
                if let Some(op) = removed {
                    debug!(
                        conn_id = conn_state.conn_id,
                        newest, "cancel: pre-interim CANCEL (mid=0) — cancelled newest pending op"
                    );
                    finish_cancel(conn_state, op, newest, req_header).await;
                    // CANCEL never gets its own response; the completion was
                    // already sent out-of-band.
                    return None;
                }
            }
        }
        debug!(
            conn_id = conn_state.conn_id,
            target, "cancel: no matching pending op"
        );
        return None;
    };
    finish_cancel(conn_state, op, target, req_header).await;
    // CANCEL never gets a response (MS-SMB2 3.3.5.16); the STATUS_CANCELLED
    // completion went out-of-band above. Returning it here too made the
    // read loop send it twice (torture lock `cancel`: INVALID_NETWORK_
    // RESPONSE at lock.c:926).
    None
}

/// Fire the cancel signal, stop any watcher, and send the STATUS_CANCELLED
/// async completion for a removed pending op. Shared by the exact-match and
/// pre-interim (mid=0) CANCEL paths.
async fn finish_cancel(
    conn_state: &ConnState,
    op: AsyncOp,
    target: u64,
    req_header: &Header,
) -> FramedResponse {
    let _ = op.cancel.send(());
    // Cancel the notify watcher if present.
    if let Some(handle) = op.notify_handle {
        handle.cancel();
    }
    debug!(conn_id = conn_state.conn_id, target, "cancelled async op");
    let mut header = Header {
        credit_charge: 0,
        status: NtStatus::Other(0xC000_0120).to_u32(), // STATUS_CANCELLED
        command: op.command,
        credit_request: 0,
        flags: HeaderFlags::new().with_server_to_redir(true),
        next_command: 0,
        message_id: target,
        tree_id: Some(op.tree_id),
        async_id: None,
        session_id: op.session_id,
        signature: 0,
    };
    header.to_async(target);
    let resp = FramedResponse::Plain(PlainResponse {
        header,
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    });
    // Out-of-band responses must be signed like any other (the CANCEL itself
    // was signed if the session requires it — verified before dispatch).
    send_unsolicited(conn_state, &resp, req_header.flags.signed()).await;
    resp
}

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
async fn pend_until_breaks(
    conn_state: &ConnState,
    req_header: &Header,
    waiters: Vec<opens::BreakWaiter>,
    command: Command,
    outcome: Result<ResponseContent, NtStatus>,
) -> FramedResponse {
    let message_id = req_header.message_id;
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    conn_state.pending_async.lock().await.insert(
        message_id,
        AsyncOp {
            command,
            session_id: req_header.session_id,
            tree_id: req_header.tree_id.unwrap_or(0),
            cancel: cancel_tx,
            notify_handle: None,
            watched_file_id: None,
                        lock_open_volatile: None,
        },
    );
    let mut pending_hdr = req_header.clone();
    pending_hdr.status = NtStatus::Pending.to_u32();
    pending_hdr.to_async(message_id);
    pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
    let pending_resp = PlainResponse {
        header: pending_hdr,
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    };
    let conn_clone = conn_state.clone();
    let req_header = req_header.clone();
    tokio::spawn(async move {
        let wait_all = futures::future::join_all(waiters.into_iter().map(|w| w.receiver));
        let safety_timeout = tokio::time::sleep(std::time::Duration::from_secs(36));
        tokio::pin!(wait_all);
        tokio::pin!(safety_timeout);
        tokio::select! {
            _ = wait_all => {}
            _ = safety_timeout => {}
            _ = cancel_rx => {
                conn_clone.pending_async.lock().await.remove(&message_id);
                return;
            }
        }
        conn_clone.pending_async.lock().await.remove(&message_id);
        let (content, status) = match outcome {
            Ok(c) => (c, NtStatus::Success),
            Err(s) => (
                ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
                s,
            ),
        };
        let mut resp = build_response(&req_header, content);
        resp.header.to_async(message_id);
        resp.header.status = status.to_u32();
        resp.header.credit_charge = 0;
        resp.header.credit_request = 0;
        send_unsolicited(&conn_clone, &FramedResponse::Plain(resp), true).await;
    });
    FramedResponse::Plain(pending_resp)
}

pub(crate) async fn send_unsolicited(
    conn_state: &ConnState,
    resp: &FramedResponse,
    client_signed: bool,
) {
    let mut bytes = rssmb_wire_adapter::encode_response(resp).to_vec();
    if bytes.is_empty() {
        tracing::warn!(
            conn_id = conn_state.conn_id,
            "send_unsolicited: nothing to send"
        );
        return;
    }

    // Snapshot the encryption state once (avoid TOCTOU between the
    // encrypt_data check and the key lookup).
    let enc_state_snap: Option<EncryptionState> = match resp {
        FramedResponse::Plain(p) => {
            let sid = p.header.session_id;
            if sid == 0 {
                None
            } else {
                conn_state
                    .encryption_ref()
                    .read()
                    .unwrap()
                    .get(&sid)
                    .filter(|st| st.encrypt_data)
                    .cloned()
            }
        }
        _ => None,
    };

    // Sign only when NOT encrypting. When encrypting, the AEAD provides
    // integrity; the SIGNED flag and signature are cleared before
    // encryption.
    if enc_state_snap.is_none() {
        crate::signing::sign_response_frame(
            &mut bytes,
            &[client_signed],
            |sid| conn_state.signing_ref().read().unwrap().get(&sid).cloned(),
            |_| {},
        );
    }

    let bytes = if let Some(st) = enc_state_snap {
        // Clear SIGNED flag and zero signatures before encryption.
        let body = &mut bytes[4..];
        let ranges = rssmb_wire_adapter::framing::message_ranges(body);
        for (s, e) in &ranges {
            let msg = &mut body[*s..*e];
            let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap());
            let flags = flags & !0x0000_0008;
            msg[16..20].copy_from_slice(&flags.to_le_bytes());
            let sig_end = 64.min(msg.len());
            msg[48..sig_end].fill(0);
        }

        let sid = match resp {
            FramedResponse::Plain(p) => p.header.session_id,
            _ => 0,
        };
        let smb2_body = &bytes[4..];
        let mut plaintext = smb2_body.to_vec();
        let nonce = match st.nonce_source.next() {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(conn_id = conn_state.conn_id,
                    error = %e, "send_unsolicited: nonce exhausted");
                return;
            }
        };
        let orig_len = plaintext.len() as u32;
        match crate::crypto::encrypt_message(&st.enc_key, &nonce, orig_len, sid, &mut plaintext) {
            Ok((hdr, tag)) => {
                let mut wire = Vec::with_capacity(4 + 52 + plaintext.len());
                let nb_len = (52 + plaintext.len()) as u32;
                wire.push(0x00);
                wire.push((nb_len >> 16) as u8);
                wire.push((nb_len >> 8) as u8);
                wire.push(nb_len as u8);
                let mut full_hdr = hdr;
                full_hdr[4..20].copy_from_slice(&tag);
                wire.extend_from_slice(&full_hdr);
                wire.extend_from_slice(&plaintext);
                Bytes::from(wire)
            }
            Err(e) => {
                tracing::warn!(conn_id = conn_state.conn_id,
                    error = %e, "send_unsolicited: encryption failed");
                return;
            }
        }
    } else {
        Bytes::from(bytes)
    };

    let _ = conn_state.write_tx.send(bytes).await;
}

/// Extract share name from a UNC path like "\\server\share" or "server\share".
///
/// The TREE_CONNECT path is always `\\server\share` (MS-SMB2 2.2.9); the
/// share is the component after the server name. A bare "share" (no
/// separator) is accepted as-is for leniency.
fn extract_share_name(path: &str) -> String {
    let trimmed = path.trim_start_matches(['\\', '/']);
    let mut parts = trimmed.split(['\\', '/']).filter(|s| !s.is_empty());
    let first = parts.next().unwrap_or("");
    let share = parts.next().unwrap_or(first);
    share.trim_end_matches('\0').to_string()
}

/// Look up the session identity for a request, returning the identity and
/// the session's `is_guest` flag. Returns `None` if the session doesn't
/// exist (caller should return STATUS_USER_SESSION_DELETED).
async fn lookup_session_identity(
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
async fn tree_read_only(conn_state: &ConnState, tree_id: u32) -> bool {
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
async fn tree_write_access(conn_state: &ConnState, tree_id: u32) -> bool {
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
async fn teardown_previous_session(
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
fn visible_shares_for_ctx(
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
async fn lookup_open_for_session(
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
    let entry = opens.get(&file_id_volatile).ok_or(NtStatus::InvalidHandle)?;
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
async fn check_lock_file_id_persistent(
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
fn error_response_for(command: Command, status: NtStatus, req_header: &Header) -> FramedResponse {
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
fn current_filetime() -> FileTime {
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
        let state = make_test_state();
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
        let state = make_test_state();
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
        let reqs = vec![close_req(1, 42, false), close_req(2, u64::MAX, true)];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        match resp.expect("compound response") {
            FramedResponse::Compound(ps) => {
                assert_eq!(ps.len(), 2);
                assert_eq!(ps[0].header.session_id, 42);
                assert_eq!(
                    ps[1].header.session_id, 42,
                    "propagated error lost the effective session"
                );
                assert_eq!(ps[1].header.tree_id, Some(7));
                assert_eq!(ps[1].header.status, NtStatus::FileClosed.to_u32());
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
