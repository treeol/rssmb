//! Message dispatcher — receives [`FramedMessage`] from the wire and produces
//! [`FramedResponse`].
//!
//! Phase 1: NEGOTIATE and ECHO are implemented.
//! Phase 2: SESSION_SETUP with multi-round NTLM auth is implemented.
//! Other commands return STATUS_NOT_SUPPORTED.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use rssmb_wire_adapter::{FramedMessage, FramedResponse, NtStatus};
use rssmb_proto::header::{Command, Header, HeaderFlags};
use rssmb_proto::negotiate::{
    Dialect as WireDialect, EncryptionCipher, GlobalCapabilities, NegotiateDialect,
    NegotiateResponse, NegotiateSecurityMode,
};
use rssmb_proto::plain::{PlainResponse, RequestContent, ResponseContent};

use rssmb_proto::FileTime;
use rssmb_proto::Guid;
use rssmb_proto::info::InfoType;

use crate::session::Session;
use crate::ServerState;
use crate::config::DialectConfig;
use crate::opens;

/// Negotiated MaxTransact/MaxRead/MaxWriteSize. Kept at 64 KiB: larger sizes
/// need multi-credit accounting (CreditCharge = ceil(len/64K) validated
/// against the payload size) and a MessageId window, neither of which exists
/// yet. The credit balance itself is enforced in `handle_plain`.
const MAX_IO_SIZE: u32 = 65536;

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

/// Per-connection state handed to the dispatcher.
#[derive(Clone)]
pub struct ConnState {
    // NOTE: PreauthTarget is defined above this struct.
    /// Unique connection identifier assigned by the connection engine.
    pub conn_id: u64,
    /// Remote peer IP address — used for auth throttling and audit logging.
    pub remote_addr: std::net::IpAddr,
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
    /// Tree connections on this connection: tree_id → (share_name, VFS, session_id).
    pub trees: std::sync::Arc<tokio::sync::RwLock<HashMap<u32, TreeEntry>>>,
    /// Open file handles: FileId volatile → OpenEntry.
    pub opens: std::sync::Arc<tokio::sync::RwLock<HashMap<u64, OpenEntry>>>,
    /// Pending authentication SessionIds — only these may be used as
    /// continuation IDs in subsequent SESSION_SETUP rounds.
    pub pending_sessions: std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<u64>>>,
    /// Per-connection credit flow-control manager.
    pub credits: std::sync::Arc<rssmb_wire_adapter::credits::CreditManager>,
    /// Pending async operations keyed by MessageId — for CHANGE_NOTIFY, LOCK, etc.
    /// When a CANCEL arrives, the op is looked up here and completed.
    pub pending_async: std::sync::Arc<tokio::sync::Mutex<HashMap<u64, AsyncOp>>>,
    /// Signing state per SessionId. Only sessions with a non-empty session
    /// key appear here (guest/anonymous sessions are never signed).
    pub signing: std::sync::Arc<std::sync::RwLock<HashMap<u64, SigningState>>>,
    /// Encryption state per SessionId. Only 3.x sessions with a negotiated
    /// cipher and non-empty session key appear here.
    pub encryption: std::sync::Arc<std::sync::RwLock<HashMap<u64, EncryptionState>>>,
    /// Preauth integrity hash for the connection (SMB 3.1.1 only).
    /// H0 = 64 zero bytes; updated with NEGOTIATE request+response.
    /// Forked per-session at SESSION_SETUP SessionId==0.
    pub preauth_conn: std::sync::Arc<std::sync::Mutex<Option<crate::crypto::PreauthHashValue>>>,
    /// Per-session preauth integrity hashes (3.1.1 only).
    /// Session.H starts as a fork of Conn.H; updated with each
    /// SESSION_SETUP request and each MORE_PROCESSING response.
    pub preauth_sessions: std::sync::Arc<std::sync::Mutex<HashMap<u64, crate::crypto::PreauthHashValue>>>,
    /// Directive from a handler: "hash the next encoded response into the
    /// preauth hash" (set by NEGOTIATE and SESSION_SETUP MORE_PROCESSING).
    /// `Conn` → hash into preauth_conn; `Session(sid)` → hash into preauth_sessions[sid].
    /// Consumed exactly once by the connection loop after encode+sign.
    pub preauth_hash_response: std::sync::Arc<std::sync::Mutex<Option<PreauthTarget>>>,
    /// Per-connection next TreeId counter (MS-SMB2 3.3.1.5: per-session, starts at 1).
    pub next_tree_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Per-connection next volatile FileId counter (MS-SMB2 3.3.1.6).
    pub next_volatile_id: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Per-connection random persistent FileId base (MS-SMB2 3.3.1.6).
    pub persistent_base: u64,
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
            continue; // Not implemented (e.g. 3.1.1 until Step 7c).
        }
        if dc < effective_min || dc > effective_max {
            continue; // Outside configured range.
        }
        if best.map_or(true, |b| dc > b) {
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
}

/// A tree connection entry tracking the owning session and VFS backend.
#[derive(Clone)]
pub struct TreeEntry {
    pub share_name: String,
    pub vfs: Arc<dyn rssmb_vfs::Vfs>,
    pub session_id: u64,
    /// Whether this share is read-only (enforced at WRITE/SET_INFO).
    pub read_only: bool,
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
        FramedMessage::Plain(req) => handle_plain(state, conn_state, req, raw_frame, was_encrypted).await,
        FramedMessage::Compound(requests) => {
            handle_compound(state, conn_state, requests, raw_frame, was_encrypted).await
        }
        FramedMessage::Smb1Negotiate(_) => {
            // SMB2-only server: do not respond to SMB1 negotiate.
            // The client (impacket, smbclient, cifs.ko) will close and retry
            // with SMB2. Returning an SMB2 error response here would be
            // misinterpreted by some clients as a truncated SMB2 negotiate
            // response, causing a parse failure instead of a clean fallback.
            debug!(conn_id = conn_state.conn_id, "SMB1 negotiate — dropping (SMB2-only server)");
            None
        }
        FramedMessage::Encrypted(_) => {
            // Encryption is handled in the connection read loop (decrypt
            // before parse). Reaching here means the frame was not decrypted
            // — disconnect.
            debug!(conn_id = conn_state.conn_id, "encrypted frame reached dispatch — should not happen");
            Some(FramedResponse::Disconnect)
        }
        FramedMessage::Compressed(_) => {
            debug!(conn_id = conn_state.conn_id, "compressed frame — not supported yet");
            Some(FramedResponse::Error {
                command: Command::Negotiate,
                status: NtStatus::NotSupported,
                message_id: u64::MAX,
                session_id: 0,
                tree_id: Some(0),
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

    for (i, mut req) in requests.into_iter().enumerate() {
        let is_related = req.header.flags.related_operations();

        // MS-SMB2: NEGOTIATE and SESSION_SETUP MUST NOT be compounded.
        // A compound containing either is rejected with STATUS_INVALID_PARAMETER.
        // This also prevents the preauth-hash response-before-encode race
        // for 3.1.1 (Mashūra plan review §1): in a compound, the response
        // bytes of the first member are not available for hashing before the
        // second member is dispatched.
        if req.header.command == Command::Negotiate
            || req.header.command == Command::SessionSetup
        {
            if let Err(FramedResponse::Disconnect) = charge_credits(conn_state, &req.header) {
                return Some(FramedResponse::Disconnect);
            }
            return Some(FramedResponse::Plain(error_plain_response(
                &req.header,
                NtStatus::InvalidParameter.to_u32(),
            )));
        }

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
            if let Err(FramedResponse::Disconnect) = charge_credits(conn_state, &saved_header) {
                return Some(FramedResponse::Disconnect);
            }
        }

        if is_related && i == 0 {
            // MS-SMB2: first request in a chain MUST NOT have RELATED set.
            // Fail this one and propagate to all remaining members.
            propagated_status = Some(NtStatus::InvalidParameter.to_u32());
            responses.push((false, error_plain_response(&saved_header, NtStatus::InvalidParameter.to_u32())));
            continue;
        }

        // The effective SessionId/TreeId for this member: for related
        // members these are inherited from the previous response; for
        // unrelated members they come from the member's own header.
        // We must carry these into error responses so the signing layer
        // can resolve the correct session key — using the saved_header's
        // SessionId would give the original (possibly placeholder) value.
        let effective_session_id = if is_related { inherited_session_id } else { saved_header.session_id };
        let effective_tree_id = if is_related { inherited_tree_id } else { saved_header.tree_id };

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
                responses.push((true, error_plain_response_with_ids(
                    &saved_header, status, effective_session_id, effective_tree_id,
                )));
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
                responses.push((is_related, error_plain_response_with_ids(
                    &saved_header, status.to_u32(), effective_session_id, effective_tree_id,
                )));
            }
            Some(_) => {
                tracing::warn!(conn_id = conn_state.conn_id, "unexpected response type in compound");
                inherited_session_id = effective_session_id;
                inherited_tree_id = effective_tree_id;
                propagated_status = Some(NtStatus::InvalidParameter.to_u32());
                responses.push((is_related, error_plain_response_with_ids(
                    &saved_header, NtStatus::InvalidParameter.to_u32(), effective_session_id, effective_tree_id,
                )));
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
        Some(FramedResponse::Plain(plain_responses.into_iter().next().unwrap()))
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
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
            error_data: vec![],
        }),
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
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
            error_data: vec![],
        }),
    }
}

/// Replace FileId 0xFFFF...FFFF with the given FileId in a request's content.
fn substitute_file_id(req: &mut rssmb_proto::plain::PlainRequest, fid: rssmb_proto::create::FileId) {
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
fn charge_credits(conn_state: &ConnState, header: &Header) -> Result<(), FramedResponse> {
    use rssmb_wire_adapter::credits::CreditError;
    match conn_state.credits.check_and_deduct(header.message_id, header.credit_charge.max(1) as u32) {
        Ok(()) => Ok(()),
        Err(CreditError::InsufficientCredits { available, requested }) => {
            tracing::warn!(conn_id = conn_state.conn_id, available, requested,
                message_id = header.message_id, "request outside credit window — terminating connection");
            Err(FramedResponse::Disconnect)
        }
        Err(CreditError::ExcessiveCharge(charge)) => {
            debug!(conn_id = conn_state.conn_id, charge, "credit charge above local cap — rejecting");
            Err(error_response_for(header.command, NtStatus::InvalidParameter, header))
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
            warn!(conn_id = conn_state.conn_id,
                "repeat NEGOTIATE — terminating connection");
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
    if was_encrypted.is_none()
        && command != Command::Negotiate
        && command != Command::SessionSetup
    {
        let sid = req.header.session_id;
        if sid != 0 {
            let session_encrypt = {
                let enc_map = conn_state.encryption.read().unwrap();
                enc_map.get(&sid).map(|st| st.encrypt_data).unwrap_or(false)
            };
            if session_encrypt {
                // Session-level encrypt_data: reject.
                debug!(conn_id = conn_state.conn_id, session_id = sid,
                    command = %command, "unencrypted request on encrypt_data session — denying");
                return Some(error_response_for(command, NtStatus::AccessDenied, &req.header));
            }
            // Tree-level encrypt_data: check if the tree requires encryption.
            if let Some(tid) = req.header.tree_id {
                let tree_encrypt = {
                    let trees = conn_state.trees.read().await;
                    trees.get(&tid).map(|t| t.encrypt_data).unwrap_or(false)
                };
                if tree_encrypt {
                    debug!(conn_id = conn_state.conn_id, session_id = sid,
                        tree_id = tid, command = %command,
                        "unencrypted request on encrypt_data tree — denying");
                    return Some(error_response_for(command, NtStatus::AccessDenied, &req.header));
                }
            }
        }
    }

    // CANCEL never consumes credits (MS-SMB2 3.3.5.14). Handle it before
    // the credit check to avoid leaking a credit.
    if command == Command::Cancel {
        return handle_cancel(conn_state, &req.header).await;
    }

    if let Err(resp) = charge_credits(conn_state, &req.header) {
        return Some(resp);
    }

    match command {
        Command::Negotiate => Some(handle_negotiate(state, conn_state, req, raw_frame).await),
        Command::SessionSetup => Some(handle_session_setup(state, conn_state, req, raw_frame).await),
        Command::Echo => Some(handle_echo(&req.header)),
        Command::Logoff => Some(handle_logoff(conn_state, &req.header).await),
        Command::TreeConnect => Some(handle_tree_connect(state, conn_state, req).await),
        Command::TreeDisconnect => Some(handle_tree_disconnect(state, conn_state, &req.header).await),
        Command::Create => Some(handle_create(state, conn_state, req).await),
        Command::Close => Some(handle_close(state, conn_state, req).await),
        Command::Read => Some(handle_read(state, conn_state, req).await),
        Command::Write => Some(handle_write(state, conn_state, req, raw_frame).await),
        Command::Flush => Some(handle_flush(state, conn_state, req).await),
        Command::QueryInfo => Some(handle_query_info(state, conn_state, req).await),
        Command::QueryDirectory => Some(handle_query_directory(state, conn_state, req).await),
        Command::SetInfo => Some(handle_set_info(state, conn_state, req).await),
        Command::ChangeNotify => Some(handle_change_notify(state, conn_state, req).await),
        Command::Ioctl => Some(handle_ioctl(state, conn_state, req).await),
        Command::ServerToClientNotification => None,
        other => {
            debug!(conn_id = conn_state.conn_id, command = %other, "unsupported command");
            Some(error_response_for(other, NtStatus::NotSupported, &req.header))
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
    let selected = match select_dialect(
        &neg_req.dialects,
        state.config.min_dialect,
        state.config.max_dialect,
    ) {
        Some(d) => d,
        None => {
            warn!(conn_id = conn_state.conn_id,
                dialects = ?neg_req.dialects,
                min = ?state.config.min_dialect,
                max = ?state.config.max_dialect,
                "no common dialect — rejecting NEGOTIATE");
            return error_response_for(Command::Negotiate, NtStatus::NotSupported, req_header);
        }
    };
    debug!(conn_id = conn_state.conn_id, dialect = ?selected, "negotiated dialect");

    let server_guid = Guid::from(state.server_guid);

    // Server capabilities: large_mtu only for 3.0+ (MS-SMB2 3.3.5.4:
    // capabilities MUST be 0 for 2.0.2). Encryption is not advertised
    // until Step 7d (encrypt/decrypt is not implemented).
    let server_capabilities = if selected > DialectConfig::Smb2002 {
        GlobalCapabilities::new().with_large_mtu(true)
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
    let (neg311, response_contexts) = if selected == DialectConfig::Smb311 {
        match crate::negotiate_ctx::process_request_contexts(neg_req, state.config.encryption) {
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
            0x60, 0x1c,                                    // APPLICATION 0, length 28
            0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // OID SPNEGO (1.3.6.1.5.5.2)
            0xa0, 0x12,                                    // [0] negTokenInit, length 18
            0x30, 0x10,                                    // SEQUENCE, length 16
            0xa0, 0x0e,                                    // [0] mechTypeList, length 14
            0x30, 0x0c,                                    // SEQUENCE OF, length 12
            0x06, 0x0a,                                    // OID, length 10
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, // NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
        ]
    };

    let negotiate_response = NegotiateResponse {
        security_mode: server_security_mode,
        dialect_revision: dialect_config_to_negotiate(selected),
        server_guid,
        capabilities: server_capabilities,
        max_transact_size: MAX_IO_SIZE,
        max_read_size: MAX_IO_SIZE,
        max_write_size: MAX_IO_SIZE,
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
        _ => return error_response_for(Command::SessionSetup, NtStatus::InvalidParameter, &req.header),
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
                let conn_fails = conn_state.auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                tracing::warn!(
                    conn_id = conn_state.conn_id,
                    ip = %conn_state.remote_addr,
                    conn_failures = conn_fails,
                    "SESSION_SETUP refused — auth cooldown active",
                );
                if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                    warn!(conn_id = conn_state.conn_id, conn_failures = conn_fails,
                        "per-connection auth failure cap exceeded — disconnecting");
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
    let auth_state = auth_guard.get_or_insert_with(|| rssmb_auth::AuthState::new());

    // Create the NTLM auth provider with server-side credentials from
    // ServerState. The identity store is built once at startup with
    // pre-computed NT hashes — no plaintext passwords are rebuilt per
    // SESSION_SETUP. Guest fallback is gated on config.guest_access.
    // Guest/anonymous sessions have no key and can never be signed, so
    // `signing = "required"` disables them (as Windows does).
    let guest_allowed = state.config.guest_access
        && state.config.signing != crate::config::SigningPolicy::Required;
    let provider: Box<dyn rssmb_auth::AuthProvider> =
        Box::new(rssmb_auth::NtlmAuthProvider::with_identity_store_and_flags(
            state.identities.clone(),
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
        let new_id = next_session_id(conn_state);
        let mut pending = conn_state.pending_sessions.write().await;
        pending.clear();
        pending.insert(new_id);
        // Clear stale preauth session entries from abandoned auth attempts.
        conn_state.preauth_sessions.lock().unwrap().clear();
        // SMB 3.1.1: fork the connection preauth hash into a per-session hash.
        let is_311 = conn_state.negotiate_record.lock().await
            .as_ref().map(|r| r.dialect == DialectConfig::Smb311).unwrap_or(false);
        if is_311 {
            let conn_hash = conn_state.preauth_conn.lock().unwrap().clone();
            if let Some(ch) = conn_hash {
                conn_state.preauth_sessions.lock().unwrap().insert(new_id, ch);
            }
        }
        new_id
    } else if conn_state.pending_sessions.read().await.contains(&req.header.session_id) {
        req.header.session_id
    } else {
        // Re-authentication of an established session and multichannel
        // binding are not supported — refuse instead of pretending success.
        let established = conn_state.sessions.read().await.iter().any(|s| s.id == req.header.session_id);
        debug!(conn_id = conn_state.conn_id, session_id = req.header.session_id, established,
            "session_setup: not a pending SessionId");
        let status = if established { NtStatus::NotSupported } else { NtStatus::UserSessionDeleted };
        return error_response_for(Command::SessionSetup, status, &req.header);
    };

    // SMB 3.1.1: hash the SESSION_SETUP request into the session's preauth hash.
    {
        let is_311 = conn_state.negotiate_record.lock().await
            .as_ref().map(|r| r.dialect == DialectConfig::Smb311).unwrap_or(false);
        if is_311 {
            if let Some(h) = conn_state.preauth_sessions.lock().unwrap().get_mut(&session_id) {
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
                let is_311 = conn_state.negotiate_record.lock().await
                    .as_ref().map(|r| r.dialect == DialectConfig::Smb311).unwrap_or(false);
                if is_311 {
                    *conn_state.preauth_hash_response.lock().unwrap() = Some(PreauthTarget::Session(session_id));
                }
            }
            FramedResponse::Plain(response)
        }
        Ok(rssmb_auth::AuthStep::Complete { output_token, session_key, identity }) => {
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
                tracing::debug!(conn_id = conn_state.conn_id, session_id,
                    "session_setup: SPNEGO mic-exchange round — session already established");
                // Clear auth state now — the conversation is truly over.
                *auth_guard = None;
                conn_state.pending_sessions.write().await.remove(&session_id);

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
                            warn!(conn_id = conn_state.conn_id,
                                "SESSION_SETUP without negotiation — disconnecting");
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
                    conn_state.preauth_sessions.lock().unwrap()
                        .get(&session_id).copied()
                } else {
                    None
                };
                let (ctx, force_sign_once) = match preauth_hash {
                    Some(ref h) => (crate::crypto::KdfContext::Preauth(h), true),
                    None => {
                        if dialect == DialectConfig::Smb311 {
                            warn!(conn_id = conn_state.conn_id,
                                "3.1.1 session without preauth hash — aborting session");
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
                let cipher: Option<crate::crypto::Cipher> = if signable && dialect >= DialectConfig::Smb30 {
                    let neg_cipher = conn_state.negotiate_record.lock().await
                        .as_ref().and_then(|r| r.neg311.as_ref())
                        .and_then(|n| n.cipher);
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
                // 2.x dialect, no common cipher), deny session establishment.
                // This check runs OUTSIDE `signable` so guest/anon are denied.
                if state.config.encryption == crate::config::EncryptionPolicy::Required
                    && cipher.is_none()
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
                    let enc_key = match crate::crypto::compute_encryption_key(&session_key, dialect, ctx) {
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
                    let dec_key = match crate::crypto::compute_decryption_key(&session_key, dialect, ctx) {
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
                            warn!(conn_id = conn_state.conn_id,
                                "encryption key not 16 bytes (got {}) — aborting session",
                                enc_key.len());
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
                            warn!(conn_id = conn_state.conn_id,
                                "decryption key not 16 bytes (got {}) — aborting session",
                                dec_key.len());
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let encrypt_data = state.config.encryption == crate::config::EncryptionPolicy::Required;
                    Some(EncryptionState {
                        enc_key: enc_key_arr,
                        dec_key: dec_key_arr,
                        nonce_source: std::sync::Arc::new(
                            crate::crypto::NonceSource::new(cipher),
                        ),
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
                    conn_state.signing.write().unwrap().insert(
                        session_id,
                        SigningState { key, required, dialect, retiring: false, force_sign_once },
                    );
                }
                if let Some(ref st) = enc_state_derived {
                    conn_state.encryption.write().unwrap().insert(session_id, st.clone());
                    debug!(conn_id = conn_state.conn_id, session_id, cipher = ?st.cipher,
                        "encryption keys derived for session");
                }
                tracing::debug!(conn_id = conn_state.conn_id, username = %identity.username,
                    is_guest = identity.is_guest, signing = session.signing_required, "session authenticated");
                conn_state.sessions.write().await.push(Arc::new(session));
                // SMB 3.1.1: remove the preauth session entry (keys derived).
                conn_state.preauth_sessions.lock().unwrap().remove(&session_id);
                // Stash the encrypt_data flag so the response builder can set
                // SESSION_FLAG_ENCRYPT_DATA (the session is now in the list).
                session_encrypt_data = enc_state_derived
                    .as_ref().map(|st| st.encrypt_data).unwrap_or(false);
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
            conn_state.pending_sessions.write().await.remove(&session_id);
            conn_state.preauth_sessions.lock().unwrap().remove(&session_id);
            // Throttle: record failure, apply delay, check per-connection cap.
            // The delay is applied after dropping auth_guard (the lock is no
            // longer needed). The failure is recorded BEFORE the delay so
            // disconnecting during the wait cannot evade accounting.
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                reason = %reason,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth failure",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(conn_id = conn_state.conn_id, conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting");
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
            conn_state.pending_sessions.write().await.remove(&session_id);
            conn_state.preauth_sessions.lock().unwrap().remove(&session_id);
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                error = %e,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth error (throttled)",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(conn_id = conn_state.conn_id, conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting");
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
async fn handle_logoff(conn_state: &ConnState, req_header: &Header) -> FramedResponse {
    let session_id = req_header.session_id;

    // Remove all opens belonging to this session, closing them via VFS.
    let removed = {
        let mut opens = conn_state.opens.write().await;
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
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "logoff: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(conn_id = conn_state.conn_id, session_id, removed, "logoff: closed handles");
    }

    // Remove all trees belonging to this session.
    {
        let mut trees = conn_state.trees.write().await;
        let tree_ids: Vec<u32> = trees
            .iter()
            .filter(|(_, e)| e.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for tid in &tree_ids {
            trees.remove(tid);
        }
    }

    // Remove the session.
    conn_state.sessions.write().await.retain(|s| s.id != session_id);
    // The signing state is kept until the LOGOFF response has been signed;
    // the read loop removes it then (see `connection.rs`).
    if let Some(st) = conn_state.signing.write().unwrap().get_mut(&session_id) {
        st.retiring = true;
    }

    // Cancel any pending async ops for this session.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                let _ = op.cancel.send(());
            }
        }
    }

    let response = build_response(req_header, ResponseContent::Logoff(rssmb_proto::session_setup::LogoffResponse::default()));
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

/// Allocate a fresh, non-zero SMB2 SessionId (random with collision check).
fn next_session_id(conn_state: &ConnState) -> u64 {
    use rand::Rng;
    loop {
        let id: u64 = rand::thread_rng().gen_range(1..u64::MAX);
        // Check against active sessions and pending sessions.
        let sessions = conn_state.sessions.try_read();
        let pending = conn_state.pending_sessions.try_read();
        let in_sessions = sessions.as_ref()
            .map(|s| s.iter().any(|sess| sess.id == id))
            .unwrap_or(false);
        let in_pending = pending.as_ref()
            .map(|p| p.contains(&id))
            .unwrap_or(false);
        if !in_sessions && !in_pending {
            return id;
        }
    }
}

/// Allocate a per-connection TreeId (starts at 1, never 0 or 0xFFFFFFFF).
fn next_tree_id(conn_state: &ConnState) -> u32 {
    conn_state.next_tree_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Allocate a per-connection FileId: volatile from a counter, persistent random.
fn next_file_id(conn_state: &ConnState) -> rssmb_proto::create::FileId {
    let volatile = conn_state.next_volatile_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Skip the sentinel value (0xFFFFFFFFFFFFFFFF) used by substitute_file_id.
    let volatile = if volatile == u64::MAX { 0 } else { volatile };
    let persistent = conn_state.persistent_base.wrapping_add(volatile);
    rssmb_proto::create::FileId { persistent, volatile }
}

/// TREE_CONNECT — look up a share and create a tree connection.
async fn handle_tree_connect(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let tc_req = match &req.content {
        RequestContent::TreeConnect(tc) => tc,
        _ => return error_response_for(Command::TreeConnect, NtStatus::InvalidParameter, &req.header),
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
            debug!(conn_id = conn_state.conn_id, session_id, "tree_connect: no authenticated session");
            return error_response_for(Command::TreeConnect, NtStatus::UserSessionDeleted, &req.header);
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
        conn_state.trees.write().await.insert(
            tree_id,
            TreeEntry {
                share_name: "IPC$".to_string(),
                vfs: Arc::new(rssmb_vfs::memoryfs::MemoryFs::new()) as Arc<dyn rssmb_vfs::Vfs>,
                session_id,
                read_only: false,
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

    // Look up share in config (share names are case-insensitive)
    let share_config = match state
        .config
        .shares
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&share_name))
        .map(|(_, v)| v)
    {
        Some(c) => c.clone(),
        None => {
            debug!(conn_id = conn_state.conn_id, share = %share_name, "share not found");
            return error_response_for(Command::TreeConnect, NtStatus::ObjectNameNotFound, &req.header);
        }
    };

    // ── Share access policy ─────────────────────────────────────────────
    // 1. Guest users can only connect if the share allows guest access.
    // 2. If valid_users is non-empty, the user must be in the list
    //    (guests are also subject to this check if valid_users is set).
    // 3. MaximalAccess reflects read_only policy.
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

    // Derive MaximalAccess from share read_only policy.
    // Read-only: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE = 0x001200a9
    // Read-write: FILE_ALL_ACCESS = 0x001f01ff
    let maximal_access = if share_config.read_only {
        0x0012_00a9
    } else {
        0x001f_01ff
    };

    // Create VFS backend: LocalFs for real shares, MemoryFs for unnamed/test
    let vfs: Arc<dyn rssmb_vfs::Vfs> = if share_config.path.is_empty() {
        Arc::new(rssmb_vfs::memoryfs::MemoryFs::new())
    } else {
        match rssmb_vfs::localfs::LocalFs::new(&share_config.path, share_config.follow_symlinks, share_config.case_sensitive) {
            Ok(fs) => Arc::new(fs),
            Err(e) => {
                tracing::warn!(share = %share_name, path = %share_config.path, error = %e, "failed to create LocalFs");
                return error_response_for(Command::TreeConnect, NtStatus::InvalidParameter, &req.header);
            }
        }
    };

    // Assign tree ID
    let tree_id = next_tree_id(conn_state);

    // Store tree in connection tree table with owning session and policy
    let tree_encrypt_data = share_config.encrypt_data;
    conn_state.trees.write().await.insert(tree_id, TreeEntry {
        share_name: share_name.clone(),
        vfs: vfs.clone(),
        session_id,
        read_only: share_config.read_only,
        encrypt_data: tree_encrypt_data,
        is_ipc: false,
    });

    let tree_connect_response = rssmb_proto::tree_connect::TreeConnectResponse {
        share_type: rssmb_proto::tree_connect::ShareType::Disk,
        share_flags: rssmb_proto::tree_connect::ShareFlags::new()
            .with_encrypt_data(tree_encrypt_data),
        maximal_access,
        ..Default::default()
    };

    let mut response = build_response(&req.header, ResponseContent::TreeConnect(tree_connect_response));
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
        let trees = conn_state.trees.read().await;
        trees.get(&tree_id).map(|e| e.session_id == session_id).unwrap_or(false)
    };
    if !tree_owned {
        return error_response_for(Command::TreeDisconnect, NtStatus::AccessDenied, req_header);
    }

    // Remove all opens belonging to this tree, closing them via VFS.
    let removed = {
        let mut opens = conn_state.opens.write().await;
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
            if let Some(fid) = entry.file_id {
                state.open_table.remove(fid, entry.open_id).await;
            }
            // Close the VFS handle — fire and forget, log on error.
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "tree_disconnect: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(conn_id = conn_state.conn_id, tree_id, removed, "tree_disconnect: closed handles");
    }

    // Remove the tree from the connection tree table.
    conn_state.trees.write().await.remove(&tree_id);

    // Cancel any pending async ops for this tree.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.tree_id == tree_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                let _ = op.cancel.send(());
            }
        }
    }

    let response = build_response(
        req_header,
        ResponseContent::TreeDisconnect(Default::default()),
    );
    FramedResponse::Plain(response)
}

/// CREATE — open or create a file.
async fn handle_create(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let create_req = match &req.content {
        RequestContent::Create(c) => c,
        _ => return error_response_for(Command::Create, NtStatus::InvalidParameter, &req.header),
    };

    // Look up tree by tree_id from the request header, validating
    // that it belongs to this session.
    let tree_id = req.header.tree_id.unwrap_or(0);
    let session_id = req.header.session_id;
    let trees = conn_state.trees.read().await;
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
        debug!(conn_id = conn_state.conn_id, tree_id, session_id, "create: tree does not belong to this session");
        return error_response_for(Command::Create, NtStatus::AccessDenied, &req.header);
    }
    let vfs = tree_entry.vfs.clone();

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
        conn_state.opens.write().await.insert(
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
        };
        let response = build_response(&req.header, ResponseContent::Create(create_response));
        return FramedResponse::Plain(response);
    }

    // Read-only share: refuse any open that could mutate. This covers
    // requested rights (write/append/EA/attrs/delete/DACL/owner, generic
    // write/all, MAXIMUM_ALLOWED is narrowed by the advertised MaximalAccess),
    // delete-on-close, and dispositions that create, overwrite or supersede.
    if tree_entry.read_only {
        let a = &create_req.desired_access;
        let wants_write = a.file_write_data() || a.file_append_data() || a.file_write_ea()
            || a.file_write_attributes() || a.file_delete_child() || a.delete()
            || a.write_dacl() || a.write_owner() || a.generic_write() || a.generic_all();
        let mutating_disposition = !matches!(
            create_req.create_disposition,
            rssmb_proto::create::CreateDisposition::Open
        );
        if wants_write || mutating_disposition || create_req.create_options.delete_on_close() {
            debug!(conn_id = conn_state.conn_id, tree_id, "create denied: read-only share");
            return error_response_for(Command::Create, NtStatus::AccessDenied, &req.header);
        }
    }

    // Map SMB create disposition to VFS
    let disposition = match create_req.create_disposition {
        rssmb_proto::create::CreateDisposition::Superseded => rssmb_vfs::CreateDisposition::Supersede,
        rssmb_proto::create::CreateDisposition::Open => rssmb_vfs::CreateDisposition::Open,
        rssmb_proto::create::CreateDisposition::Create => rssmb_vfs::CreateDisposition::Create,
        rssmb_proto::create::CreateDisposition::OpenIf => rssmb_vfs::CreateDisposition::OpenIf,
        rssmb_proto::create::CreateDisposition::Overwrite => rssmb_vfs::CreateDisposition::Overwrite,
        rssmb_proto::create::CreateDisposition::OverwriteIf => rssmb_vfs::CreateDisposition::OverwriteIf,
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
        Ok(open_id) => {
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
                            tree_id,
                            "create: sharing violation — closing VFS handle"
                        );
                        // Undo the VFS open.
                        let _ = vfs.close(open_id).await;
                        return error_response_for(
                            Command::Create,
                            NtStatus::SharingViolation,
                            &req.header,
                        );
                    }
                }
            }

            let file_id = next_file_id(conn_state);

            // Store the open in the per-connection open table
            conn_state.opens.write().await.insert(
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
                },
            );

            // Query file info for the response
            let info = vfs.query_info(open_id, rssmb_vfs::InfoClass::FileStandardInfo).await
                .unwrap_or(rssmb_vfs::FileInfo {
                    file_id: rssmb_vfs::FileId(0),
                    attributes: rssmb_vfs::FileAttributes::default(),
                    size: 0,
                    allocation_size: 0,
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    file_name: file_path.clone(),
                });

            let create_response = rssmb_proto::create::CreateResponse {
                oplock_level: rssmb_proto::oplock::OplockLevel::None,
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
            };

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
        let mut opens = conn_state.opens.write().await;
        match opens.get(&file_id_volatile) {
            Some(entry) => {
                if entry.session_id != session_id || entry.tree_id != tree_id {
                    debug!(conn_id = conn_state.conn_id, file_id = file_id_volatile, "close: handle does not belong to this session/tree");
                    return error_response_for(Command::Close, NtStatus::InvalidHandle, &req.header);
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

            let (creation_time, last_access_time, last_write_time, change_time,
                 allocation_size, endof_file, file_attributes) = if postquery {
                let info = entry.vfs
                    .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                    .await
                    .unwrap_or(rssmb_vfs::FileInfo {
                        file_id: rssmb_vfs::FileId(0),
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
                    FileTime::ZERO, FileTime::ZERO, FileTime::ZERO, FileTime::ZERO,
                    0, 0, Default::default(),
                )
            };

            // Close via VFS (skip for pipe opens — no VFS handle).
            // For disk opens, remove from the global open table first.
            // If this was the last open and any open had delete_on_close,
            // the VFS close will unlink the file (LocalFs.close honors
            // delete_on_close on the handle). For multi-open files, the
            // delete is deferred to the last close — but LocalFs currently
            // only has per-handle delete_on_close. The open table tracks
            // delete_on_close per-open, and the last close triggers the
            // actual unlink.
            if !entry.is_pipe {
                // Remove from the global open table and check if this was
                // the last open with delete-on-close pending.
                if let Some(fid) = entry.file_id {
                    let remove_result = state.open_table.remove(fid, entry.open_id).await;
                    if remove_result.was_last && remove_result.any_delete_on_close {
                        // Last open — perform the actual delete via VFS.
                        // The VFS close will handle unlinking because the
                        // handle's delete_on_close flag was set at create time.
                        // For handles where delete_on_close was set later via
                        // SET_INFO, we call vfs.delete() here.
                        //
                        // LocalFs.close() checks handle.delete_on_close and
                        // unlinks. But if delete_on_close was set via
                        // set_delete_on_close (not at create time), the
                        // handle's flag is already updated. So close() will
                        // unlink correctly.
                    }
                }

                if let Err(e) = entry.vfs.close(entry.open_id).await {
                    debug!(conn_id = conn_state.conn_id, error = %e, "close VFS failed");
                }
            }

            // Complete any pending CHANGE_NOTIFY for this handle with
            // STATUS_NOTIFY_CLEANUP (MS-SMB2 3.3.5.10). Since our dispatch
            // is serial, the pending op was already returned as PENDING —
            // we just remove it from tracking so CANCEL can't target it.
            // In a truly async model we'd send a NotifyCleanup response.
            {
                let mut pending = conn_state.pending_async.lock().await;
                let to_remove: Vec<u64> = pending
                    .iter()
                    .filter(|(_, op)| op.tree_id == tree_id)
                    .map(|(k, _)| *k)
                    .collect();
                for key in to_remove {
                    if let Some(op) = pending.remove(&key) {
                        let _ = op.cancel.send(());
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
            debug!(conn_id = conn_state.conn_id, file_id = file_id_volatile, "close: handle not found");
            error_response_for(Command::Close, NtStatus::InvalidHandle, &req.header)
        }
    }
}

/// READ — read data from a file.
async fn handle_read(
    _state: &ServerState,
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
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(e) => e,
        Err(status) => {
            debug!(conn_id = conn_state.conn_id, file_id = file_id_volatile, "read: handle not found or wrong session");
            return error_response_for(Command::Read, status, &req.header);
        }
    };

    // Pipe opens: drain the RPC output queue.
    if entry.is_pipe {
        let ps = entry.pipe_state.as_ref().expect("pipe open without pipe_state");
        let mut state = ps.lock().unwrap();
        let (data, read_status) = state.read(read_req.length as usize);
        let max_read = read_req.length as usize;
        let _ = max_read;
        if data.is_empty() {
            return error_response_for(Command::Read, NtStatus::Other(0xC000_0050), &req.header);
            // STATUS_PIPE_EMPTY = 0xC0000050
        }
        let read_response = rssmb_proto::file::ReadResponse {
            buffer: data,
            ..Default::default()
        };
        let mut response = build_response(&req.header, ResponseContent::Read(read_response));
        if read_status == rssmb_rpc_server::ReadStatus::Overflow {
            response.header.status = NtStatus::BufferOverflow.to_u32();
        }
        return FramedResponse::Plain(response);
    }

    // Bound the allocation by the negotiated MaxReadSize.
    if read_req.length > MAX_IO_SIZE {
        return error_response_for(Command::Read, NtStatus::InvalidParameter, &req.header);
    }

    // Read from VFS
    match entry.vfs.read_at(entry.open_id, read_req.offset, read_req.length).await {
        Ok(data) => {
            if data.is_empty() {
                return error_response_for(Command::Read, NtStatus::EndOfFile, &req.header);
            }
            let read_response = rssmb_proto::file::ReadResponse {
                buffer: data.to_vec(),
                ..Default::default()
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
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(e) => e,
        Err(status) => {
            debug!(conn_id = conn_state.conn_id, file_id = file_id_volatile, "write: handle not found or wrong session");
            return error_response_for(Command::Write, status, &req.header);
        }
    };

    // Pipe opens: feed RPC input bytes to the pipe state machine.
    if entry.is_pipe {
        // Extract write data (same logic as disk path below).
        const MAX_WRITE_SIZE: u32 = MAX_IO_SIZE;
        let write_data_offset: usize = match raw_frame.get(66..68) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
            None => return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header),
        };
        if write_data_offset < 64 + 48 {
            return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
        }
        if write_req.length > MAX_WRITE_SIZE {
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

        let ps = entry.pipe_state.as_ref().expect("pipe open without pipe_state");
        let identity = lookup_session_identity(conn_state, session_id).await;
        let shares = visible_shares_for_ctx(&state.config, identity.as_ref());
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
            ..Default::default()
        };
        let response = build_response(&req.header, ResponseContent::Write(write_response));
        return FramedResponse::Plain(response);
    }

    // Enforce read-only share policy using the tree entry's stored policy.
    {
        let trees = conn_state.trees.read().await;
        if let Some(tree_entry) = trees.get(&tree_id) {
            if tree_entry.read_only {
                debug!(conn_id = conn_state.conn_id, share = %tree_entry.share_name, "write denied: share is read-only");
                return error_response_for(Command::Write, NtStatus::AccessDenied, &req.header);
            }
        }
    }

    // Extract write data. `raw_frame` is exactly this message's bytes (the
    // dispatcher slices compound members), and DataOffset (u16 at body+2) is
    // relative to this message's header — so it is correct in any compound
    // position. smb-msg drops DataOffset after parsing, so read it here.
    const MAX_WRITE_SIZE: u32 = MAX_IO_SIZE;
    let write_data_offset: usize = match raw_frame.get(66..68) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
        None => return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header),
    };
    if write_data_offset < 64 + 48 {
        return error_response_for(Command::Write, NtStatus::InvalidParameter, &req.header);
    }

    // Validate length against negotiated max_write_size.
    if write_req.length > MAX_WRITE_SIZE {
        debug!(
            conn_id = conn_state.conn_id,
            length = write_req.length,
            max = MAX_WRITE_SIZE,
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

    match entry.vfs.write_at(entry.open_id, write_req.offset, &data).await {
        Ok(count) => {
            let write_response = rssmb_proto::file::WriteResponse {
                count,
                ..Default::default()
            };
            let response = build_response(&req.header, ResponseContent::Write(write_response));
            FramedResponse::Plain(response)
        }
        Err(e) => {
            tracing::warn!(conn_id = conn_state.conn_id, error = %e, "write failed");
            let status = match e {
                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                rssmb_vfs::VfsError::IsDirectory => NtStatus::FileIsADirectory,
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

    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(e) => e,
        Err(status) => {
            return error_response_for(Command::Flush, status, &req.header);
        }
    }
    ;
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
        _ => return error_response_for(Command::QueryInfo, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = qi_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
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
                    debug!(conn_id = conn_state.conn_id, class = info_class_byte, "unsupported pipe info class");
                    return error_response_for(Command::QueryInfo, NtStatus::NotSupported, &req.header);
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
            let info = match entry.vfs
                .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "query_info VFS failed");
                    return error_response_for(Command::QueryInfo, NtStatus::InvalidParameter, &req.header);
                }
            };
            match info_class_byte {
                4 => crate::fsinfo::file_basic_info(&info),      // FileBasicInformation
                5 => crate::fsinfo::file_standard_info(&info),    // FileStandardInformation
                6 => crate::fsinfo::file_internal_info(&info),    // FileInternalInformation
                7 => crate::fsinfo::file_ea_info(),               // FileEaInformation
                18 => {
                    // FileAllInformation — what Linux cifs.ko uses to stat.
                    let ro = tree_read_only(conn_state, entry.tree_id).await;
                    let access = if ro { 0x0012_00a9 } else { 0x001f_01ff };
                    crate::fsinfo::file_all_info(&info, &entry.path, access)
                }
                34 => crate::fsinfo::file_network_open_info(&info), // FileNetworkOpenInformation
                35 => crate::fsinfo::file_attribute_tag_info(&info), // FileAttributeTagInformation
                _ => {
                    debug!(conn_id = conn_state.conn_id, class = info_class_byte, "unsupported file info class");
                    return error_response_for(Command::QueryInfo, NtStatus::InvalidInfoClass, &req.header);
                }
            }
        }
        // InfoType::FileSystem (0x02)
        0x02 => {
            match info_class_byte {
                1 => crate::fsinfo::fs_volume_info(),       // FileFsVolumeInformation
                3 => crate::fsinfo::fs_size_info(),         // FileFsSizeInformation
                4 => crate::fsinfo::fs_device_info(),       // FileFsDeviceInformation
                5 => crate::fsinfo::fs_attribute_info(),    // FileFsAttributeInformation
                7 => crate::fsinfo::fs_full_size_info(),    // FileFsFullSizeInformation
                11 => crate::fsinfo::fs_sector_size_info(), // FileFsSectorSizeInformation
                _ => {
                    debug!(conn_id = conn_state.conn_id, class = info_class_byte, "unsupported filesystem info class");
                    return error_response_for(Command::QueryInfo, NtStatus::InvalidInfoClass, &req.header);
                }
            }
        }
        // InfoType::Security (0x03) — return a minimal SD or ACCESS_DENIED
        0x03 => {
            return error_response_for(Command::QueryInfo, NtStatus::AccessDenied, &req.header);
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
        _ => return error_response_for(Command::QueryDirectory, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = qd_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(e) => e,
        Err(status) => return error_response_for(Command::QueryDirectory, status, &req.header),
    };

    // Pipe opens don't support QUERY_DIRECTORY.
    if entry.is_pipe {
        return error_response_for(Command::QueryDirectory, NtStatus::Other(0xC000_0010), &req.header);
    }

    let pattern = qd_req.file_name.to_string();
    let class_id = qd_req.file_information_class as u8;
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
        match entry.vfs.query_dir(
            entry.open_id,
            &pattern,
            rssmb_vfs::DirInfoClass::IdBothDirectoryInfo,
            true,
            0,
        ).await {
            Ok(vfs_entries) => all.extend(vfs_entries),
            Err(e) => {
                debug!(conn_id = conn_state.conn_id, error = %e, "query_dir VFS failed");
                return error_response_for(Command::QueryDirectory, NtStatus::NoSuchFile, &req.header);
            }
        }
        cursor.entries = Some(all);
        cursor.next = 0;
    }

    let all = cursor.entries.as_ref().expect("snapshot set above");
    if cursor.next >= all.len() {
        // MS-SMB2 3.3.5.18: no match on the first query → NO_SUCH_FILE,
        // exhausted cursor → NO_MORE_FILES.
        let status = if first_call { NtStatus::NoSuchFile } else { NtStatus::NoMoreFiles };
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
                debug!(conn_id = conn_state.conn_id, class = class_id, "unsupported directory info class");
                return error_response_for(Command::QueryDirectory, NtStatus::InvalidInfoClass, &req.header);
            }
        }
    }
    if take == 0 {
        return error_response_for(Command::QueryDirectory, NtStatus::BufferOverflow, &req.header);
    }
    cursor.next += take;
    drop(cursor);

    match buffer {
        Some(buffer) => {
            let response = build_response(
                &req.header,
                ResponseContent::QueryDirectory(
                    rssmb_proto::query_dir::QueryDirectoryResponse { output_buffer: buffer },
                ),
            );
            FramedResponse::Plain(response)
        }
        None => {
            debug!(conn_id = conn_state.conn_id, class = class_id, "unsupported directory info class");
            error_response_for(Command::QueryDirectory, NtStatus::InvalidInfoClass, &req.header)
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
    let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(e) => e,
        Err(status) => return error_response_for(Command::SetInfo, status, &req.header),
    };

    // Pipe opens don't support SET_INFO.
    if entry.is_pipe {
        return error_response_for(Command::SetInfo, NtStatus::Other(0xC000_0010), &req.header);
    }

    // Only File-type SET_INFO is supported for now.
    // InfoType::File = 0x01 is the only supported type for SET_INFO.
    let is_file_type = si_req.info_type == InfoType::File;
    if !is_file_type {
        return error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header);
    }

    // Get the info class and raw data.
    let class_byte = si_req.info_class.0;
    let raw_data = si_req.data.data().to_vec();

    // Every handled file SET_INFO class mutates (timestamps, size, rename,
    // delete). On a read-only share, refuse them all — except clearing
    // delete-pending, which is harmless but also pointless, so refuse too.
    if tree_read_only(conn_state, tree_id).await {
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
                    let mut info = match entry.vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info: query failed");
                            return error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header);
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
                    match entry.vfs.set_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo, &info).await {
                        Ok(()) => {
                            let response = build_response(&req.header, ResponseContent::SetInfo(
                                rssmb_proto::info::SetInfoResponse::default(),
                            ));
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info basic failed");
                            error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
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
                    let mut info = match entry.vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(_) => return error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header),
                    };
                    info.size = eof.end_of_file;
                    match entry.vfs.set_info(entry.open_id, rssmb_vfs::InfoClass::FileEndOfFileInfo, &info).await {
                        Ok(()) => {
                            let response = build_response(&req.header, ResponseContent::SetInfo(
                                rssmb_proto::info::SetInfoResponse::default(),
                            ));
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info eof failed");
                            error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
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
                    debug!(conn_id = conn_state.conn_id, delete_pending, "set_info disposition");
                    if delete_pending && tree_read_only(conn_state, tree_id).await {
                        return error_response_for(Command::SetInfo, NtStatus::AccessDenied, &req.header);
                    }
                    match entry.vfs.set_delete_on_close(entry.open_id, delete_pending).await {
                        Ok(()) => {
                            // Update the global open table's delete_on_close
                            // flag for this open so that the last-close logic
                            // in handle_close knows whether to unlink.
                            if let Some(fid) = entry.file_id {
                                state.open_table
                                    .update_delete_on_close(fid, entry.open_id, delete_pending)
                                    .await;
                            }
                            FramedResponse::Plain(build_response(&req.header, ResponseContent::SetInfo(
                                rssmb_proto::info::SetInfoResponse::default(),
                            )))
                        }
                        Err(rssmb_vfs::VfsError::DirectoryNotEmpty) => {
                            error_response_for(Command::SetInfo, NtStatus::Other(0xC000_0101), &req.header)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_delete_on_close failed");
                            error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header)
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
                    debug!(conn_id = conn_state.conn_id, new_name = %new_name, "set_info rename");
                    match entry.vfs.rename(entry.open_id, &new_name, rename.replace_if_exists.into()).await {
                        Ok(()) => {
                            let response = build_response(&req.header, ResponseContent::SetInfo(
                                rssmb_proto::info::SetInfoResponse::default(),
                            ));
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "rename failed");
                            let status = match e {
                                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                                rssmb_vfs::VfsError::AlreadyExists => NtStatus::ObjectNameCollision,
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
            debug!(conn_id = conn_state.conn_id, class = class_byte, "unsupported set_info class");
            error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header)
        }
    }
}

/// CHANGE_NOTIFY — register a directory watch. For MVP, immediately return
/// STATUS_PENDING so the client doesn't block. On CLOSE of the handle or
/// TREE_DISCONNECT, complete with STATUS_NOTIFY_CLEANUP.
async fn handle_change_notify(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let cn_req = match &req.content {
        RequestContent::ChangeNotify(cn) => cn,
        _ => return error_response_for(Command::ChangeNotify, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = cn_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Validate the handle belongs to this session.
    match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
        Ok(_) => {},
        Err(status) => return error_response_for(Command::ChangeNotify, status, &req.header),
    };

    // For MVP: return STATUS_PENDING with the output buffer empty.
    // The client will keep this request outstanding and wait for a response.
    // We don't actually monitor for changes — we just don't complete the
    // response until CLOSE/CANCEL/TREE_DISCONNECT.
    //
    // Since our dispatch model is serial (we must return a FramedResponse
    // from the handler), we can't truly hold this request open. Instead we
    // return PENDING immediately and track it in pending_async so that
    // CANCEL or CLOSE can complete it.
    let message_id = req.header.message_id;
    let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
    conn_state.pending_async.lock().await.insert(message_id, AsyncOp {
        command: Command::ChangeNotify,
        session_id,
        tree_id,
        cancel: cancel_tx,
    });

    // Build a PENDING response with async header.
    let mut response = build_response(&req.header, ResponseContent::ChangeNotify(
        rssmb_proto::notify::ChangeNotifyResponse {
            buffer: Default::default(),
        },
    ));
    response.header.status = NtStatus::Pending.to_u32();
    // Convert to async header — sets async_command flag, clears tree_id,
    // sets async_id.
    response.header.to_async(message_id);
    FramedResponse::Plain(response)
}

/// IOCTL (MS-SMB2 3.3.5.15). Only what mount clients probe for:
/// - FSCTL_VALIDATE_NEGOTIATE_INFO (3.0/3.0.2): validate the client's
///   negotiation parameters against the stored negotiation record, then
///   return the server's values. A mismatch terminates the connection
///   (MS-SMB2 3.3.5.15.12).
/// - FSCTL_DFS_GET_REFERRALS(_EX): STATUS_NOT_FOUND (0xC0000225)
/// - FSCTL_QUERY_NETWORK_INTERFACE_INFO: STATUS_NOT_SUPPORTED (no multichannel).
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
    const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    const STATUS_NOT_FOUND: u32 = 0xC000_0225;
    const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    debug!(conn_id = conn_state.conn_id, ctl_code = format!("{:#010x}", io.ctl_code), "ioctl");

    // FSCTL_PIPE_TRANSCEIVE: write input to the pipe, read output back.
    // Only valid on pipe opens (named pipes on IPC$).
    if io.ctl_code == FSCTL_PIPE_TRANSCEIVE {
        let file_id_volatile = io.file_id.volatile;
        let session_id = req.header.session_id;
        let tree_id = req.header.tree_id.unwrap_or(0);
        let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::Ioctl, status, &req.header),
        };
        if !entry.is_pipe {
            return error_response_for(Command::Ioctl, NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST), &req.header);
        }
        let ps = entry.pipe_state.as_ref().expect("pipe open without pipe_state");
        let identity = lookup_session_identity(conn_state, session_id).await;
        let shares = visible_shares_for_ctx(&state.config, identity.as_ref());
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
            return error_response_for(Command::Ioctl, NtStatus::Other(0xC000_0050), &req.header);
            // STATUS_PIPE_EMPTY
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
                    if vni.capabilities != u32::from_le_bytes(rec.client_capabilities.into_bytes()) {
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
                    let vni_dialects: Vec<WireDialect> = vni.dialects.iter().map(|d| {
                        match d.dialect {
                            0x0202 => WireDialect::Smb0202,
                            0x0210 => WireDialect::Smb021,
                            0x0300 => WireDialect::Smb030,
                            0x0302 => WireDialect::Smb0302,
                            0x0311 => WireDialect::Smb0311,
                            _ => WireDialect::Smb0202,
                        }
                    }).collect();
                    let reselected = select_dialect(&vni_dialects, state.config.min_dialect, state.config.max_dialect);
                    if reselected != Some(rec.dialect) {
                        warn!(conn_id = conn_state.conn_id, "VNI dialect re-selection mismatch");
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
                        return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
                    }
                    let resp = rssmb_proto::ioctl::IoctlResponse {
                        ctl_code: io.ctl_code,
                        file_id: io.file_id,
                        in_buffer: vec![],
                        out_buffer: buf.into_inner(),
                    };
                    return FramedResponse::Plain(build_response(&req.header, ResponseContent::Ioctl(resp)));
                }
                _ => {
                    return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
                }
            }
        }
        FSCTL_DFS_GET_REFERRALS | FSCTL_DFS_GET_REFERRALS_EX => NtStatus::Other(STATUS_NOT_FOUND),
        FSCTL_QUERY_NETWORK_INTERFACE_INFO => NtStatus::NotSupported,
        _ => NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST),
    };
    error_response_for(Command::Ioctl, status, &req.header)
}

/// CANCEL — cancel a pending async operation (MS-SMB2 3.3.5.16).
///
/// CANCEL itself never gets a response. The cancelled operation is completed
/// with STATUS_CANCELLED, sent on the write channel as an async response.
async fn handle_cancel(
    conn_state: &ConnState,
    req_header: &Header,
) -> Option<FramedResponse> {
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
        debug!(conn_id = conn_state.conn_id, target, "cancel: no matching pending op");
        return None;
    };
    let _ = op.cancel.send(());
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
    None
}

/// Encode, sign (per session signing state) and enqueue a response that is
/// not returned through the read loop — async completions, cancellations.
///
/// If the response's session has `encrypt_data` set, the response is
/// encrypted with that session's encryption key. Never falls back to
/// plaintext once encryption is selected — if the encryption state is
/// missing after the decision, the response is dropped (not sent
/// unencrypted).
pub(crate) async fn send_unsolicited(conn_state: &ConnState, resp: &FramedResponse, client_signed: bool) {
    let mut bytes = rssmb_wire_adapter::encode_response(resp).to_vec();
    if bytes.is_empty() {
        tracing::warn!(conn_id = conn_state.conn_id, "send_unsolicited: nothing to send");
        return;
    }

    // Snapshot the encryption state once (avoid TOCTOU between the
    // encrypt_data check and the key lookup).
    let enc_state_snap: Option<EncryptionState> = match resp {
        FramedResponse::Plain(p) => {
            let sid = p.header.session_id;
            if sid == 0 { None } else {
                conn_state.encryption.read().unwrap()
                    .get(&sid).filter(|st| st.encrypt_data).cloned()
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
            |sid| conn_state.signing.read().unwrap().get(&sid).cloned(),
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
        match crate::crypto::encrypt_message(
            &st.enc_key, &nonce, orig_len, sid, &mut plaintext,
        ) {
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
        .trees
        .read()
        .await
        .get(&tree_id)
        .map(|t| t.read_only)
        .unwrap_or(true)
}

/// Build a share snapshot for the RPC context (Step 8.3 simplified — full
/// visibility filtering comes in Step 8.5). Returns all configured shares
/// that the session can see, sorted by name, plus a synthetic IPC$ entry.
fn visible_shares_for_ctx(
    config: &crate::config::ServerConfig,
    identity: Option<&rssmb_auth::Identity>,
) -> Vec<rssmb_rpc_server::ShareInfo> {
    let is_guest = identity.map(|i| i.is_guest).unwrap_or(true);
    let username = identity.map(|i| i.username.as_str()).unwrap_or("");

    let mut shares: Vec<rssmb_rpc_server::ShareInfo> = config
        .shares
        .iter()
        .filter(|(_, sc)| {
            // Browseable + access policy (same as TREE_CONNECT).
            if !sc.browseable {
                return false;
            }
            if is_guest && !sc.guest_ok {
                return false;
            }
            if !sc.valid_users.is_empty() {
                return sc.valid_users.iter().any(|u| u.eq_ignore_ascii_case(username));
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
    shares.sort_by(|a, b| a.name.cmp(&b.name));
    // Append synthetic IPC$.
    shares.push(rssmb_rpc_server::ShareInfo {
        name: "IPC$".to_string(),
        comment: String::new(),
        share_type: 0x80000003, // STYPE_IPC | STYPE_SPECIAL
        encrypt_data: false,
    });
    shares
}

/// Look up an open handle, validating that it belongs to the request's
/// session and tree. Returns the `OpenEntry` or an error response.
async fn lookup_open_for_session(
    conn_state: &ConnState,
    session_id: u64,
    tree_id: u32,
    file_id_volatile: u64,
) -> Result<OpenEntry, NtStatus> {
    let opens = conn_state.opens.read().await;
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

/// Build an error response carrying the request's header fields so the
/// client can match it to the original request.
fn error_response_for(command: Command, status: NtStatus, req_header: &Header) -> FramedResponse {
    FramedResponse::Error {
        command,
        status,
        message_id: req_header.message_id,
        session_id: req_header.session_id,
        tree_id: req_header.tree_id,
    }
}

/// Construct a PlainResponse mirroring the request header.
fn build_response(req_header: &Header, content: ResponseContent) -> PlainResponse {
    let command = content.associated_cmd();
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

    fn make_test_state() -> Arc<ServerState> {
        Arc::new(ServerState::new(crate::config::ServerConfig::for_testing()))
    }

    fn make_conn_state() -> ConnState {
        let (tx, _rx) = mpsc::channel::<Bytes>(16);
        ConnState {
            conn_id: 1,
            remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            write_tx: tx,
            auth_state: Arc::new(tokio::sync::Mutex::new(None)),
            auth_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            negotiate_record: Arc::new(tokio::sync::Mutex::new(None)),
            trees: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            opens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            pending_sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            credits: Arc::new(rssmb_wire_adapter::credits::CreditManager::new(1024)),
            pending_async: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            signing: Arc::new(std::sync::RwLock::new(HashMap::new())),
            encryption: Arc::new(std::sync::RwLock::new(HashMap::new())),
            preauth_conn: Arc::new(std::sync::Mutex::new(None)),
            preauth_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            preauth_hash_response: Arc::new(std::sync::Mutex::new(None)),
            next_tree_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_volatile_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            persistent_base: 0,
        }
    }

    /// Establish negotiation on a conn_state so subsequent commands
    /// pass the negotiate gate. Also grants credits to simulate what
    /// the real connection read loop does after each response.
    async fn establish_negotiation(state: &Arc<ServerState>, conn: &ConnState) {
        let req = make_negotiate_request();
        let resp = handle_message(state, conn, FramedMessage::Plain(req), &[], None).await;
        assert!(resp.is_some(), "negotiate should produce a response");
        assert!(!matches!(resp, Some(FramedResponse::Disconnect)));
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

    fn make_negotiate_request_with_dialects(dialects: Vec<WireDialect>) -> rssmb_proto::plain::PlainRequest {
        use rssmb_proto::negotiate::{NegotiateRequest, PreauthIntegrityCapabilities, HashAlgorithm};
        // If 3.1.1 is in the offer, include preauth context (required for 3.1.1).
        let negotiate_context_list = if dialects.contains(&WireDialect::Smb0311) {
            Some(vec![
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![HashAlgorithm::Sha512],
                    salt: vec![0xab; 32],
                }
                .into(),
            ])
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

    fn make_request_with_command(command: Command, message_id: u64) -> rssmb_proto::plain::PlainRequest {
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
                        assert_eq!(neg.max_transact_size, 65536);
                        assert!(neg.capabilities.large_mtu());
                        assert!(!neg.capabilities.leasing());
                        assert!(!neg.capabilities.encryption());
                        assert!(*neg.system_time != 0);
                    }
                    other => panic!("expected Negotiate content, got {:?}", other),
                }
            }
            other => panic!("expected Plain response, got {:?}", other),
        }
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

        assert_eq!(guid1, guid2, "server GUID must be stable across negotiate responses");
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
        assert!(resp.is_none(), "SMB1 negotiate should produce no response (SMB2-only server)");
    }

    #[tokio::test]
    async fn test_unsupported_command_rejected() {
        let state = make_test_state();
        let conn = make_conn_state();
        establish_negotiation(&state, &conn).await;
        // Use Lock — not implemented in Phase 3
        let req = make_request_with_command(Command::Lock, 3);
        let framed = FramedMessage::Plain(req);
        let resp = handle_message(&state, &conn, framed, &[], None).await;

        let resp = resp.expect("unsupported command should produce a response");
        match resp {
            FramedResponse::Error { command, status, .. } => {
                assert_eq!(command, Command::Lock);
                assert_eq!(status, NtStatus::NotSupported);
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
        assert!(resp.is_none(), "ServerToClientNotification should not produce a response");
    }

    #[tokio::test]
    async fn test_close_with_zero_flags_succeeds() {
        // GVFS sends CLOSE with flags=0 (no POSTQUERY_ATTRIB).
        // Before the fix, smb-msg asserted flags==POSTQUERY and the request
        // was rejected, causing the client to hang. This test verifies that
        // a CLOSE with flags=0 on a non-existent handle returns InvalidHandle
        // (i.e. the request parsed successfully; the failure is just no handle).
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
            // No handle → InvalidHandle is correct; the important thing is
            // that we got here at all (the request parsed).
            FramedResponse::Error { command, status, .. } => {
                assert_eq!(command, Command::Close);
                assert_eq!(status, NtStatus::InvalidHandle);
            }
            other => panic!("expected Error(InvalidHandle), got {:?}", other),
        }
    }

    fn close_req(message_id: u64, session_id: u64, related: bool) -> rssmb_proto::plain::PlainRequest {
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
                file_id: rssmb_proto::create::FileId { persistent: u64::MAX, volatile: u64::MAX },
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
                assert_eq!(ps[1].header.session_id, 42, "propagated error lost the effective session");
                assert_eq!(ps[1].header.tree_id, Some(7));
                assert_eq!(ps[1].header.status, NtStatus::InvalidHandle.to_u32());
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
            let r = handle_message(&state, &conn, FramedMessage::Plain(make_echo_request_with_id(i + 1)), &[], None).await;
            assert!(r.is_some(), "echo should produce a response");
        }
        // Now exactly 1 credit remains (message_id 16). The next echo uses it.
        let r1 = handle_message(&state, &conn, FramedMessage::Plain(make_echo_request_with_id(16)), &[], None).await;
        assert!(matches!(r1, Some(FramedResponse::Plain(_))), "echo should succeed with the last credit");
        // Now 0 credits — next request must disconnect.
        let r2 = handle_message(&state, &conn, FramedMessage::Plain(make_echo_request_with_id(17)), &[], None).await;
        assert!(matches!(r2, Some(FramedResponse::Disconnect)), "expected disconnect, got {:?}", r2);
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
        assert!(matches!(resp, Some(FramedResponse::Disconnect)), "expected disconnect, got {:?}", resp);
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
        let reqs = vec![close_req(0, 42, false), close_req(1, u64::MAX, true), close_req(2, u64::MAX, true)];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        assert!(matches!(resp, Some(FramedResponse::Compound(ref ps)) if ps.len() == 3), "got {:?}", resp);
        assert_eq!(conn.credits.available_credits(), 0);
    }

    #[tokio::test]
    async fn unaffordable_propagated_member_disconnects() {
        // Only 2 credits for 3 members: the third (a propagated failure,
        // never executed) is still outside the window → disconnect.
        let state = make_test_state();
        let conn = make_conn_state();
        conn.credits.grant(1);
        let reqs = vec![close_req(0, 42, false), close_req(1, u64::MAX, true), close_req(2, u64::MAX, true)];
        let resp = handle_message(&state, &conn, FramedMessage::Compound(reqs), &[], None).await;
        assert!(matches!(resp, Some(FramedResponse::Disconnect)), "got {:?}", resp);
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
            Some(FramedResponse::Error { status, .. }) => assert_eq!(status, NtStatus::InvalidParameter),
            other => panic!("expected InvalidParameter, got {:?}", other),
        }
    }

    // --- Dialect selection tests ---

    #[test]
    fn select_highest_common_dialect() {
        let client = vec![WireDialect::Smb0202, WireDialect::Smb021, WireDialect::Smb030, WireDialect::Smb0302];
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
        let client = vec![WireDialect::Smb030, WireDialect::Smb0302, WireDialect::Smb0311];
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
        let client = vec![WireDialect::Smb021, WireDialect::Smb030, WireDialect::Smb0302];
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
        let client = vec![WireDialect::Smb0302, WireDialect::Smb0202, WireDialect::Smb030, WireDialect::Smb021];
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
        assert!(matches!(resp2, Some(FramedResponse::Disconnect)),
            "repeat NEGOTIATE should disconnect, got {:?}", resp2);
    }

    #[tokio::test]
    async fn command_before_negotiate_disconnects() {
        let state = make_test_state();
        let conn = make_conn_state();
        // ECHO before NEGOTIATE should disconnect.
        let req = make_echo_request();
        let resp = handle_message(&state, &conn, FramedMessage::Plain(req), &[], None).await;
        assert!(matches!(resp, Some(FramedResponse::Disconnect)),
            "command before NEGOTIATE should disconnect, got {:?}", resp);
    }

    #[tokio::test]
    async fn negotiate_selects_311_for_modern_client() {
        let state = make_test_state();
        let conn = make_conn_state();
        // Client offers all dialects including 3.1.1.
        let req = make_negotiate_request_with_dialects(vec![
            WireDialect::Smb0202, WireDialect::Smb021,
            WireDialect::Smb030, WireDialect::Smb0302, WireDialect::Smb0311,
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
            Some(FramedResponse::Error { status, .. }) => assert_eq!(status, NtStatus::NotSupported),
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
        conn.next_volatile_id.store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);
        let fid1 = next_file_id(&conn);
        let fid2 = next_file_id(&conn);
        assert_ne!(fid1.volatile, u64::MAX, "volatile must never be 0xFFFF...FFFF");
        assert_ne!(fid2.volatile, u64::MAX, "volatile must never be 0xFFFF...FFFF");
    }

    #[tokio::test]
    async fn file_ids_persistent_differs_from_volatile() {
        let mut conn = make_conn_state();
        conn.persistent_base = 0x1234_5678_9ABC_DEF0;
        let fid = next_file_id(&conn);
        // persistent = base + volatile; with base != 0 they should differ.
        assert_ne!(fid.persistent, fid.volatile, "persistent should differ from volatile when base != 0");
    }

    #[tokio::test]
    async fn session_ids_are_random_and_nonzero() {
        let conn = make_conn_state();
        let id1 = next_session_id(&conn);
        let id2 = next_session_id(&conn);
        assert_ne!(0, id1, "SessionId must be non-zero");
        assert_ne!(0, id2, "SessionId must be non-zero");
        // Random — extremely unlikely to collide.
        assert_ne!(id1, id2, "SessionId should be random (collision is astronomically unlikely)");
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
