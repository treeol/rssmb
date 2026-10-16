//! TCP connection engine.
//!
//! The connection engine owns the accept loop and the per-connection read/write
//! task pair:
//!
//! - [`listen`] binds a [`tokio::net::TcpListener`] and spawns a task per
//!   accepted connection, assigning monotonically increasing connection IDs.
//! - [`Connection::handle`] is the per-connection entry point. It splits the
//!   stream into read/write halves, spawns a **write task** that drains the
//!   mpsc write channel onto the socket, and runs a **read loop** that frames
//!   NetBIOS-delimited SMB messages, dispatches them to
//!   [`crate::dispatch::handle_message`], and enqueues the encoded response.
//! - Graceful shutdown is driven by [`crate::ServerState::shutdown`] (a
//!   `tokio::sync::Notify`); the read loop `select!`s against it so a shutdown
//!   request aborts the connection promptly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use binrw::BinRead;
use rssmb_proto::header::Command;
use rssmb_wire_adapter::build_error_response;
use rssmb_wire_adapter::credits::CreditManager;
use rssmb_wire_adapter::framing::parse_payload;
use rssmb_wire_adapter::{encode_response, FramedMessage, FramedResponse, NtStatus};

use crate::config::ServerConfig;
use crate::dispatch::{handle_message, ConnState};
use crate::signing;
use crate::ServerState;

/// Buffer capacity for the write channel (number of outbound frames).
const WRITE_CHANNEL_CAPACITY: usize = 64;

/// Connection limiter — tracks active connections globally and per IP.
///
/// Enforces `max_connections` and `max_connections_per_ip` from the config.
/// A connection count of 0 means unlimited. The limiter uses a plain `RwLock`
/// (not tokio) because the critical sections are tiny and never await.
pub struct ConnectionLimiter {
    max_total: u32,
    max_per_ip: u32,
    counts: StdRwLock<HashMap<std::net::IpAddr, u32>>,
    total: AtomicU64,
}

impl ConnectionLimiter {
    pub fn new(max_total: u32, max_per_ip: u32) -> Self {
        Self {
            max_total,
            max_per_ip,
            counts: StdRwLock::new(HashMap::new()),
            total: AtomicU64::new(0),
        }
    }

    /// Try to admit a connection from `addr`. Returns a guard that
    /// decrements the count when dropped. Returns `None` if a limit
    /// is exceeded.
    pub fn try_admit(self: &Arc<Self>, addr: std::net::IpAddr) -> Option<ConnectionGuard> {
        let mut counts = self.counts.write().unwrap();
        let per_ip = counts.entry(addr).or_insert(0);
        if self.max_per_ip > 0 && *per_ip >= self.max_per_ip {
            warn!(ip = %addr, "connection rejected: per-IP limit reached");
            // Remove the entry we just inserted if its count is still 0,
            // so rejected IPs don't accumulate in the map (finding 7).
            if *per_ip == 0 {
                counts.remove(&addr);
            }
            return None;
        }
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_total > 0 && total > self.max_total as u64 {
            self.total.fetch_sub(1, Ordering::Relaxed);
            warn!(ip = %addr, total, "connection rejected: global limit reached");
            // Remove the per-IP entry if we haven't incremented it yet —
            // prevents unbounded map growth from rejected connections (finding 7).
            if *per_ip == 0 {
                counts.remove(&addr);
            }
            return None;
        }
        *per_ip += 1;
        drop(counts);
        Some(ConnectionGuard {
            limiter: self.clone(),
            addr,
        })
    }
}

/// RAII guard that decrements the connection count when dropped.
pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    addr: std::net::IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.total.fetch_sub(1, Ordering::Relaxed);
        let mut counts = self.limiter.counts.write().unwrap();
        if let Some(c) = counts.get_mut(&self.addr) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&self.addr);
            }
        }
    }
}

/// Reads the next complete NetBIOS-framed payload from `stream`.
///
/// NetBIOS session service framing uses a 4-byte header (1 byte type, 3 bytes
/// big-endian length). This helper reads the header then the body into a
/// `Vec<u8>` and returns the payload bytes, returning `Err` on EOF or I/O
/// error.
async fn read_netbios_payload<R>(
    stream: &mut R,
    max_frame_size: usize,
) -> std::io::Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    loop {
        // Read the 4-byte NetBIOS header. Distinguish clean EOF (0 bytes read
        // — peer closed the connection) from a truncated header (1–3 bytes —
        // connection was cut mid-frame). Read the first byte separately so
        // EOF on byte 0 means "clean close" and EOF on bytes 1–3 means
        // "truncated header".
        let mut hdr = [0u8; 4];
        match stream.read_exact(&mut hdr[..1]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        // Read the remaining 3 bytes — EOF here means truncated header.
        match stream.read_exact(&mut hdr[1..]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated NetBIOS header — connection closed mid-frame",
                ));
            }
            Err(e) => return Err(e),
        }

        let msg_type = hdr[0];
        let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);

        // NetBIOS session request (0x81): read and discard the body, then loop.
        if msg_type == 0x81 {
            if len > max_frame_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("oversized NetBIOS session request: {len} bytes"),
                ));
            }
            let mut discard = vec![0u8; len];
            stream.read_exact(&mut discard).await?;
            continue; // loop to read the next frame
        }

        // Keep-alive (0x85): no payload per spec, but a non-zero length must
        // still be consumed to stay aligned in the stream.
        if msg_type == 0x85 {
            if len > 0 {
                if len > max_frame_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("oversized NetBIOS keep-alive: {len} bytes"),
                    ));
                }
                let mut discard = vec![0u8; len];
                stream.read_exact(&mut discard).await?;
            }
            continue;
        }

        if msg_type != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown NetBIOS message type: 0x{msg_type:02X}"),
            ));
        }

        if len > max_frame_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("oversized NetBIOS frame: {len} bytes"),
            ));
        }

        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        return Ok(Some(body));
    }
}

/// A single client connection.
///
/// Owns the socket and the per-connection credit manager. The write channel
/// (`write_tx`) is shared with the dispatch layer via [`ConnState`] so that
/// handlers can enqueue async/unsolicited responses.
pub struct Connection {
    /// Unique connection identifier assigned by the accept loop.
    pub conn_id: u64,
    /// The underlying TCP stream (split into read/write halves in `handle`).
    pub stream: TcpStream,
    /// Remote peer address.
    pub remote_addr: std::net::SocketAddr,
    /// Shared server state.
    pub state: Arc<ServerState>,
    /// Sender half of the write channel — handlers push serialized responses
    /// here and the write task drains them onto the socket.
    pub write_tx: mpsc::Sender<Bytes>,
}

impl Connection {
    /// Per-connection entry point.
    ///
    /// Splits the stream, spawns the write task, and runs the read loop until
    /// the peer disconnects, an I/O error occurs, or the server is shut down.
    /// On exit any sessions belonging to this connection are removed from the
    /// shared [`ServerState`].
    pub async fn handle(state: Arc<ServerState>, stream: TcpStream, conn_id: u64) {
        let remote_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(conn_id, error = %e, "could not determine peer address; closing");
                return;
            }
        };

        info!(conn_id, %remote_addr, "connection accepted");

        let max_frame_size = state.config.max_frame_size;
        let max_credits = state.config.max_credits;

        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);

        let credits = Arc::new(CreditManager::new(max_credits));

        // Split the stream into read and write halves.
        let (mut read_half, mut write_half) = stream.into_split();

        // Spawn the write task: drain the channel and write to the socket.
        let write_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(frame) = write_rx.recv().await {
                if let Err(e) = write_half.write_all(&frame).await {
                    warn!(error = %e, "write task: failed to write frame");
                    break;
                }
            }
            // Best-effort flush on exit.
            let _ = write_half.flush().await;
        });

        // Build the per-connection dispatch state. The session is attached
        // later (after SESSION_SETUP); for Phase 1 it stays `None`.
        let conn_state = ConnState {
            conn_id,
            remote_addr: remote_addr.ip(),
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            write_tx: write_tx.clone(),
            auth_state: Arc::new(tokio::sync::Mutex::new(None)),
            auth_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            negotiate_record: Arc::new(tokio::sync::Mutex::new(None)),
            trees: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            opens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            pending_sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            credits: credits.clone(),
            pending_async: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            signing: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            encryption: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            preauth_conn: Arc::new(std::sync::Mutex::new(None)),
            preauth_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            preauth_hash_response: Arc::new(std::sync::Mutex::new(None)),
            next_tree_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_volatile_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            persistent_base: rand::random::<u64>(),
        };

        // Read loop.
        let read_result =
            Self::read_loop(&mut read_half, &state, &conn_state, max_frame_size).await;

        match read_result {
            Ok(()) => debug!(conn_id, "read loop completed cleanly"),
            Err(e) => warn!(conn_id, error = %e, "read loop terminated with error"),
        }

        // Clean up: remove sessions owned by this connection, close all
        // remaining VFS handles, and cancel pending async ops. Bound the
        // entire post-read-loop phase (cleanup + write drain) so a stuck
        // VFS close or a blocked write task can't keep the connection
        // half-open forever (finding 5: shutdown timeout was after cleanup,
        // not around it).
        let cleanup_grace = std::time::Duration::from_secs(state.config.shutdown_grace_secs.max(5));
        let _ =
            tokio::time::timeout(cleanup_grace, Self::cleanup(&state, conn_id, &conn_state)).await;

        // Close the write channel so the write task drains and exits. Every
        // sender must go: `conn_state` holds a clone, and while it lived the
        // channel stayed open and the writer only ended at the timeout
        // below — a fixed 5 s stall on every disconnect.
        drop(conn_state);
        drop(write_tx);

        // Wait for the write task to finish (bounded wait to avoid hanging).
        // A timed-out JoinHandle would merely detach the task, keeping the
        // socket half open — abort it explicitly and await to observe
        // termination (finding 6).
        let mut write_task = write_task;
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut write_task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(conn_id, error = %e, "write task failed"),
            Err(_) => {
                warn!(
                    conn_id,
                    "write task did not finish within 5 s — aborting it"
                );
                write_task.abort();
                let _ = write_task.await;
            }
        }

        // Decrement active connection count.
        state
            .metrics
            .connections_active
            .fetch_sub(1, Ordering::Relaxed);
        info!(conn_id, %remote_addr, "connection closed");
    }

    /// The read loop: frame NetBIOS messages, dispatch, enqueue responses.
    ///
    /// Selects against the server shutdown signal so a shutdown request
    /// aborts the loop promptly.
    async fn read_loop(
        read_half: &mut tokio::net::tcp::OwnedReadHalf,
        state: &Arc<ServerState>,
        conn_state: &ConnState,
        max_frame_size: usize,
    ) -> std::io::Result<()> {
        let idle_timeout = std::time::Duration::from_secs(state.config.idle_timeout_secs);
        loop {
            let payload = tokio::select! {
                biased;

                _ = state.shutdown.notified() => {
                    debug!(conn_id = conn_state.conn_id, "shutdown signaled; ending read loop");
                    return Ok(());
                }

                res = tokio::time::timeout(idle_timeout, read_netbios_payload(read_half, max_frame_size)) => {
                    match res {
                        Ok(Ok(None)) => {
                            debug!(conn_id = conn_state.conn_id, "peer closed connection");
                            return Ok(());
                        }
                        Ok(Ok(Some(body))) => {
                            debug!(conn_id = conn_state.conn_id, len = body.len(), "received NetBIOS payload");
                            body
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            warn!(conn_id = conn_state.conn_id, "idle timeout ({}s) — closing connection", idle_timeout.as_secs());
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "idle timeout",
                            ));
                        }
                    }
                }
            };

            // Empty payloads (e.g. keep-alives) produce no dispatchable message.
            if payload.is_empty() {
                continue;
            }

            // --- SMB 3.x encryption: decrypt transform frames before parsing ---

            // Tracks the SessionId of an encrypted request, so the response
            // is encrypted back under the same session.
            let was_encrypted: Option<u64>;

            let payload = if payload.len() >= 4 && payload[..4] == *b"\xfdSMB" {
                // TRANSFORM_HEADER (MS-SMB2 2.2.41): 52-byte header + ciphertext.
                if payload.len() < 52 {
                    warn!(
                        conn_id = conn_state.conn_id,
                        "truncated transform header — disconnecting"
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "truncated transform header",
                    ));
                }
                let transform_session_id = u64::from_le_bytes(payload[44..52].try_into().unwrap());
                was_encrypted = Some(transform_session_id);
                let enc_state = conn_state
                    .encryption
                    .read()
                    .unwrap()
                    .get(&transform_session_id)
                    .cloned();
                match enc_state {
                    Some(st) => {
                        match crate::crypto::decrypt_message(&st.dec_key, &payload) {
                            Ok(plaintext) => {
                                // The plaintext must be a plain SMB2 message
                                // (0xFE 'SMB'). No nested transform/compress.
                                if plaintext.len() < 4 || plaintext[..4] != *b"\xfeSMB" {
                                    warn!(
                                        conn_id = conn_state.conn_id,
                                        "decrypted frame is not SMB2 — disconnecting"
                                    );
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "decrypted frame is not plain SMB2",
                                    ));
                                }
                                debug!(
                                    conn_id = conn_state.conn_id,
                                    session_id = transform_session_id,
                                    plaintext_len = plaintext.len(),
                                    "decrypted transform frame"
                                );
                                plaintext
                            }
                            Err(e) => {
                                // MS-SMB2 3.3.5.2.1.1: decryption failure →
                                // disconnect without a response.
                                warn!(conn_id = conn_state.conn_id,
                                    error = %e, session_id = transform_session_id,
                                    "transform decryption failed — disconnecting");
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "transform decryption failed",
                                ));
                            }
                        }
                    }
                    None => {
                        // Unknown SessionId — disconnect (3.3.5.2.1.1).
                        warn!(
                            conn_id = conn_state.conn_id,
                            session_id = transform_session_id,
                            "encrypted frame for unknown session — disconnecting"
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "encrypted frame for unknown session",
                        ));
                    }
                }
            } else {
                was_encrypted = None;
                payload
            };

            // Parse the framed payload into a FramedMessage.
            // The decoder is third-party (smb-msg/binrw) and has panicked on
            // malformed input before (unchecked offset arithmetic). A panic
            // there must not take down the connection task; treat it as a
            // decode error. Parsing is pure, so unwinding is safe.
            let parsed =
                std::panic::catch_unwind(|| parse_payload(&payload)).unwrap_or_else(|_| {
                    warn!(
                        conn_id = conn_state.conn_id,
                        "decoder panicked — treating as malformed"
                    );
                    Err(rssmb_wire_adapter::WireError::DecodeError(
                        "decoder panic".into(),
                    ))
                });
            let framed = match parsed {
                Ok(msg) => msg,
                Err(e) => {
                    // Try to at least parse the 64-byte header so we can send
                    // an error response with the correct message_id/session_id.
                    // Otherwise the client waits forever for a reply.
                    warn!(conn_id = conn_state.conn_id, error = %e, "failed to parse payload");
                    // Hex preview at trace for diagnostics — never at debug
                    // (filenames and payloads should not appear in debug logs).
                    let preview_len = payload.len().min(128);
                    trace!(conn_id = conn_state.conn_id, hex_preview = ?&payload[..preview_len],
                        "payload hex preview");
                    if let Some(transform_sid) = was_encrypted {
                        // Decrypted frame: the AEAD authenticated the content,
                        // but we still need to validate compound structure and
                        // effective SessionId binding before sending a reply.
                        let valid = match signing::walk_compound(&payload) {
                            Ok(members) => {
                                let mut ok = true;
                                for m in &members {
                                    if m.effective_sid != transform_sid {
                                        ok = false;
                                        break;
                                    }
                                    let st = conn_state
                                        .encryption
                                        .read()
                                        .unwrap()
                                        .get(&m.effective_sid)
                                        .cloned();
                                    match st {
                                        Some(st) if !st.retiring => {}
                                        _ => {
                                            ok = false;
                                            break;
                                        }
                                    }
                                }
                                ok
                            }
                            Err(_) => false,
                        };
                        if valid && payload.len() >= 64 {
                            match rssmb_proto::header::Header::read_le(&mut std::io::Cursor::new(
                                &payload,
                            )) {
                                Ok(hdr) => {
                                    if conn_state.credits.check_and_deduct(hdr.message_id, hdr.credit_charge.max(1) as u32)
                                        .is_err_and(|e| matches!(e, rssmb_wire_adapter::credits::CreditError::InsufficientCredits { .. }))
                                    {
                                        warn!(conn_id = conn_state.conn_id, "malformed decrypted request without credits — terminating");
                                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request outside the credit window"));
                                    }
                                    let granted =
                                        conn_state.credits.grant(hdr.credit_request.max(1) as u32)
                                            as u16;
                                    let mut body = build_error_response(
                                        hdr.command,
                                        NtStatus::InvalidParameter,
                                        hdr.message_id,
                                        hdr.session_id,
                                        hdr.tree_id,
                                    );
                                    if body.len() >= 16 {
                                        body[14..16].copy_from_slice(&granted.to_le_bytes());
                                    }
                                    // The error reply must be encrypted under
                                    // the transform session. send_unsolicited
                                    // can't encrypt Raw responses (it can't
                                    // resolve the session from raw bytes), so
                                    // encrypt directly here.
                                    let enc_st = conn_state
                                        .encryption
                                        .read()
                                        .unwrap()
                                        .get(&transform_sid)
                                        .cloned();
                                    match enc_st {
                                        Some(st) => {
                                            let mut plaintext = body.clone();
                                            let nonce = match st.nonce_source.next() {
                                                Ok(n) => n,
                                                Err(e) => {
                                                    warn!(conn_id = conn_state.conn_id,
                                                        error = %e, "nonce exhausted sending error reply");
                                                    return Err(std::io::Error::new(
                                                        std::io::ErrorKind::InvalidData,
                                                        "nonce space exhausted",
                                                    ));
                                                }
                                            };
                                            match crate::crypto::encrypt_message(
                                                &st.enc_key,
                                                &nonce,
                                                plaintext.len() as u32,
                                                transform_sid,
                                                &mut plaintext,
                                            ) {
                                                Ok((hdr, tag)) => {
                                                    let mut wire = Vec::with_capacity(
                                                        4 + 52 + plaintext.len(),
                                                    );
                                                    let nb_len = (52 + plaintext.len()) as u32;
                                                    wire.push(0x00);
                                                    wire.push((nb_len >> 16) as u8);
                                                    wire.push((nb_len >> 8) as u8);
                                                    wire.push(nb_len as u8);
                                                    let mut full_hdr = hdr;
                                                    full_hdr[4..20].copy_from_slice(&tag);
                                                    wire.extend_from_slice(&full_hdr);
                                                    wire.extend_from_slice(&plaintext);
                                                    let _ = conn_state
                                                        .write_tx
                                                        .send(Bytes::from(wire))
                                                        .await;
                                                }
                                                Err(e) => {
                                                    warn!(conn_id = conn_state.conn_id,
                                                        error = %e, "encryption of error reply failed — disconnecting");
                                                    return Err(std::io::Error::new(
                                                        std::io::ErrorKind::InvalidData,
                                                        "encryption failed",
                                                    ));
                                                }
                                            }
                                        }
                                        None => {
                                            // The session should have encryption state
                                            // (it was set at admission). If not, don't
                                            // send plaintext — disconnect.
                                            warn!(conn_id = conn_state.conn_id,
                                                session_id = transform_sid,
                                                "no encryption state for error reply — disconnecting");
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                "missing encryption state",
                                            ));
                                        }
                                    }
                                }
                                Err(e2) => {
                                    warn!(conn_id = conn_state.conn_id, error = %e2, "failed to parse even the header — dropping");
                                }
                            }
                        } else if !valid {
                            warn!(conn_id = conn_state.conn_id,
                                "decrypted frame with malformed compound or SID mismatch — disconnecting");
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "decrypted frame compound/SID validation failed",
                            ));
                        }
                    } else {
                        // Plaintext frame: authenticate the raw bytes first.
                        let verdict = signing::verify_frame(&payload, |sid| {
                            conn_state.signing.read().unwrap().get(&sid).cloned()
                        });
                        if payload.len() >= 64 && verdict == signing::Verdict::Ok {
                            match rssmb_proto::header::Header::read_le(&mut std::io::Cursor::new(
                                &payload,
                            )) {
                                Ok(hdr) => {
                                    if conn_state.credits.check_and_deduct(hdr.message_id, hdr.credit_charge.max(1) as u32)
                                        .is_err_and(|e| matches!(e, rssmb_wire_adapter::credits::CreditError::InsufficientCredits { .. }))
                                    {
                                        warn!(conn_id = conn_state.conn_id, "malformed request without credits — terminating connection");
                                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request outside the credit window"));
                                    }
                                    let granted =
                                        conn_state.credits.grant(hdr.credit_request.max(1) as u32)
                                            as u16;
                                    let status = NtStatus::InvalidParameter;
                                    let mut body = build_error_response(
                                        hdr.command,
                                        status,
                                        hdr.message_id,
                                        hdr.session_id,
                                        hdr.tree_id,
                                    );
                                    if body.len() >= 16 {
                                        body[14..16].copy_from_slice(&granted.to_le_bytes());
                                    }
                                    let signed = hdr.flags.signed();
                                    crate::dispatch::send_unsolicited(
                                        conn_state,
                                        &FramedResponse::Raw(body),
                                        signed,
                                    )
                                    .await;
                                }
                                Err(e2) => {
                                    warn!(conn_id = conn_state.conn_id, error = %e2, "failed to parse even the header — dropping");
                                }
                            }
                        }
                    }
                    continue;
                }
            };

            debug!(
                conn_id = conn_state.conn_id,
                frame_kind = framed_kind(&framed),
                "dispatching framed message"
            );

            // Signature verification (MS-SMB2 3.3.5.2.4), per message, before
            // anything is acted on. A bad signature on a signed session means
            // the message is discarded without a response.
            //
            // Encrypted frames are authenticated by the AEAD — skip SMB
            // signature verification for them (MS-SMB2 3.3.5.2.4: messages
            // that are encrypted are not also signed). But validate the
            // compound structure and that every member's effective SessionId
            // matches the transform SessionId.
            let client_signed = if was_encrypted.is_none() {
                signing::request_signed_flags(&payload)
            } else {
                vec![false] // encrypted frames carry no SMB2 signature
            };
            if let Some(&transform_sid) = was_encrypted.as_ref() {
                // Decrypted frame: validate compound structure and that every
                // member's effective SessionId matches the transform SessionId.
                match signing::walk_compound(&payload) {
                    Ok(members) => {
                        for m in &members {
                            if m.effective_sid != transform_sid {
                                warn!(
                                    conn_id = conn_state.conn_id,
                                    transform_sid,
                                    effective_sid = m.effective_sid,
                                    "decrypted frame session id mismatch — disconnecting"
                                );
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "transform session id mismatch",
                                ));
                            }
                            // The session must have encryption state and not be
                            // retiring.
                            let st = conn_state
                                .encryption
                                .read()
                                .unwrap()
                                .get(&m.effective_sid)
                                .cloned();
                            match st {
                                Some(st) if !st.retiring => {}
                                _ => {
                                    warn!(conn_id = conn_state.conn_id,
                                        session_id = m.effective_sid,
                                        "decrypted frame for session without encryption state or retiring — disconnecting");
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "no encryption state for transform session",
                                    ));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        warn!(
                            conn_id = conn_state.conn_id,
                            "malformed decrypted compound — disconnecting"
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "malformed decrypted compound",
                        ));
                    }
                }
            } else if matches!(framed, FramedMessage::Plain(_) | FramedMessage::Compound(_)) {
                let verdict = signing::verify_frame(&payload, |sid| {
                    conn_state.signing.read().unwrap().get(&sid).cloned()
                });
                if verdict == signing::Verdict::Reject {
                    warn!(
                        conn_id = conn_state.conn_id,
                        "signature check failed — discarding request"
                    );
                    continue;
                }
            }

            // Dispatch to the handler.
            // Only plain/compound SMB2 requests are charged credits (in
            // dispatch); replies to anything else (SMB1 negotiate, encrypted,
            // compressed) must not grant any, or the ledgers diverge.
            let ledgered = matches!(framed, FramedMessage::Plain(_) | FramedMessage::Compound(_));
            let response = handle_message(state, conn_state, framed, &payload, was_encrypted).await;

            // A fatal protocol violation: no reply, no credit grant, end the
            // connection (Connection::handle then runs the normal cleanup).
            if matches!(response, Some(FramedResponse::Disconnect)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "protocol violation: request outside the credit window",
                ));
            }

            if let Some(mut resp) = response {
                // Grant credits and write the actual grant into the response
                // header's credit_request field. The client uses this to track
                // its available credits; if we don't write it, the client and
                // server disagree on the credit balance.
                let requested = match &resp {
                    FramedResponse::Plain(p) => p.header.credit_request,
                    FramedResponse::Compound(ps) => {
                        ps.last().map(|p| p.header.credit_request).unwrap_or(1)
                    }
                    _ => 1,
                };
                let granted = if ledgered {
                    conn_state.credits.grant(requested.max(1) as u32)
                } else {
                    0
                };

                // Write the granted amount into every response header.
                match &mut resp {
                    FramedResponse::Plain(p) => {
                        p.header.credit_request = granted as u16;
                    }
                    FramedResponse::Compound(ps) => {
                        // Grant credits only on the last response in the chain;
                        // intermediate responses get 0 (MS-SMB2 3.2.4.1.3).
                        if let Some(last) = ps.last_mut() {
                            last.header.credit_request = granted as u16;
                        }
                        for p in ps.iter_mut().rev().skip(1) {
                            p.header.credit_request = 0;
                        }
                    }
                    _ => {}
                }

                let mut encoded = encode_response(&resp).to_vec();
                if encoded.is_empty() {
                    // Nothing can be sent, and the grant above would then
                    // exist only on our side. End the connection instead of
                    // letting the ledgers diverge.
                    warn!(
                        conn_id = conn_state.conn_id,
                        "encode_response returned empty — terminating connection"
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response encoding failed",
                    ));
                }
                // Error replies are pre-built with CreditResponse = 1. Write
                // the amount actually granted into the last message of the
                // frame (earlier compound members already carry 0), so the
                // client never counts a credit the server did not grant.
                if let FramedResponse::Error { .. } = resp {
                    set_last_credit_response(&mut encoded, granted as u16);
                }
                signing::sign_response_frame(
                    &mut encoded,
                    &client_signed,
                    |sid| conn_state.signing.read().unwrap().get(&sid).cloned(),
                    |sid| {
                        if let Some(st) = conn_state.signing.write().unwrap().get_mut(&sid) {
                            st.force_sign_once = false;
                        }
                    },
                );
                // SMB 3.1.1 preauth hash: hash the encoded+signed response
                // into the connection or session hash. The handler set
                // preauth_hash_response to indicate which target.
                // The response bytes are encoded[4..] (no NetBIOS header).
                if let Some(target) = conn_state.preauth_hash_response.lock().unwrap().take() {
                    if encoded.len() > 4 {
                        let msg_bytes = &encoded[4..];
                        use crate::dispatch::PreauthTarget;
                        match target {
                            PreauthTarget::Conn => {
                                if let Some(h) = conn_state.preauth_conn.lock().unwrap().as_mut() {
                                    *h = crate::crypto::preauth_update(h, msg_bytes);
                                }
                            }
                            PreauthTarget::Session(sid) => {
                                if let Some(h) =
                                    conn_state.preauth_sessions.lock().unwrap().get_mut(&sid)
                                {
                                    *h = crate::crypto::preauth_update(h, msg_bytes);
                                }
                            }
                        }
                    }
                }
                // LOGOFF'd sessions keep their key only long enough to sign
                // the LOGOFF response itself. But don't retire encryption
                // state yet — it's needed to encrypt the response below.
                conn_state
                    .signing
                    .write()
                    .unwrap()
                    .retain(|_, st| !st.retiring);

                // --- SMB 3.x encryption: encrypt the response if required ---
                //
                // Encrypt when:
                // 1. The request arrived encrypted (encrypt with the same
                //    SessionId — MS-SMB2 3.3.4.1.4).
                // 2. The session has encrypt_data set.
                // Never encrypt: NEGOTIATE, SESSION_SETUP responses, or
                // responses with SessionId 0 (no encryption state).
                // When encrypting, the SIGNED flag and signature are
                // meaningless (the AEAD provides integrity) — clear the flag
                // and zero the signature before encryption.
                let response_command = match &resp {
                    FramedResponse::Plain(p) => Some(p.header.command),
                    FramedResponse::Compound(ps) => ps.first().map(|p| p.header.command),
                    _ => None,
                };
                let is_handshake = matches!(
                    response_command,
                    Some(Command::Negotiate) | Some(Command::SessionSetup)
                );

                let encrypt_sid = if is_handshake {
                    None // Never encrypt handshake responses
                } else {
                    was_encrypted.or_else(|| {
                        let sid = match &resp {
                            FramedResponse::Plain(p) => p.header.session_id,
                            FramedResponse::Compound(ps) => {
                                ps.first().map(|p| p.header.session_id).unwrap_or(0)
                            }
                            _ => return None,
                        };
                        if sid == 0 {
                            return None;
                        }
                        let enc_map = conn_state.encryption.read().unwrap();
                        enc_map
                            .get(&sid)
                            .map(|st| st.encrypt_data)
                            .unwrap_or(false)
                            .then_some(sid)
                    })
                };

                let encoded = if let Some(sid) = encrypt_sid {
                    // Clear the SIGNED flag and zero the signature on every
                    // message in the encoded frame before encryption.
                    let body = &mut encoded[4..];
                    let ranges = rssmb_wire_adapter::framing::message_ranges(body);
                    for (s, e) in &ranges {
                        let msg = &mut body[*s..*e];
                        // Clear SIGNED flag (bit 3 of Flags at offset 16).
                        let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap());
                        let flags = flags & !0x0000_0008;
                        msg[16..20].copy_from_slice(&flags.to_le_bytes());
                        // Zero the signature (offset 48..64).
                        let sig_end = 64.min(msg.len());
                        msg[48..sig_end].fill(0);
                    }

                    let enc_state = conn_state.encryption.read().unwrap().get(&sid).cloned();
                    match enc_state {
                        Some(st) => {
                            // Strip the 4-byte NetBIOS header, encrypt the
                            // SMB2 body, and re-frame with a new NetBIOS
                            // length.
                            let smb2_body = &encoded[4..];
                            let mut plaintext = smb2_body.to_vec();
                            let nonce = match st.nonce_source.next() {
                                Ok(n) => n,
                                Err(e) => {
                                    warn!(conn_id = conn_state.conn_id,
                                        error = %e, "nonce exhausted — disconnecting");
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "nonce space exhausted",
                                    ));
                                }
                            };
                            let orig_len = plaintext.len() as u32;
                            match crate::crypto::encrypt_message(
                                &st.enc_key,
                                &nonce,
                                orig_len,
                                sid,
                                &mut plaintext,
                            ) {
                                Ok((hdr, tag)) => {
                                    let mut wire = Vec::with_capacity(4 + 52 + plaintext.len());
                                    // NetBIOS header: 52 (transform header) + ciphertext.
                                    let nb_len = (52 + plaintext.len()) as u32;
                                    wire.push(0x00);
                                    wire.push((nb_len >> 16) as u8);
                                    wire.push((nb_len >> 8) as u8);
                                    wire.push(nb_len as u8);
                                    // Transform header with signature filled in.
                                    let mut full_hdr = hdr;
                                    full_hdr[4..20].copy_from_slice(&tag);
                                    wire.extend_from_slice(&full_hdr);
                                    // Ciphertext.
                                    wire.extend_from_slice(&plaintext);
                                    debug!(
                                        conn_id = conn_state.conn_id,
                                        session_id = sid,
                                        resp_len = wire.len(),
                                        "encrypted response"
                                    );
                                    Bytes::from(wire)
                                }
                                Err(e) => {
                                    warn!(conn_id = conn_state.conn_id,
                                        error = %e, "encryption failed — disconnecting");
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "encryption failed",
                                    ));
                                }
                            }
                        }
                        None => {
                            // encrypt_data was set but the session has no
                            // encryption state — never downgrade to plaintext.
                            warn!(
                                conn_id = conn_state.conn_id,
                                session_id = sid,
                                "encrypt_data set but no encryption state — disconnecting"
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "missing encryption state for encrypt_data session",
                            ));
                        }
                    }
                } else {
                    Bytes::from(encoded)
                };

                // Now retire encryption state (after the response has been
                // encrypted or sent as plaintext).
                conn_state
                    .encryption
                    .write()
                    .unwrap()
                    .retain(|_, st| !st.retiring);

                debug!(
                    conn_id = conn_state.conn_id,
                    resp_len = encoded.len(),
                    credits_granted = granted,
                    "encoded response"
                );
                // If the write channel is closed (peer gone / write task
                // exited) or shutdown is signaled, end the loop. Use a
                // timeout race so a full channel can't block indefinitely
                // and prevent shutdown from aborting the loop (finding 6).
                let send_result = tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        debug!(
                            conn_id = conn_state.conn_id,
                            "shutdown signaled during response enqueue; ending read loop"
                        );
                        return Ok(());
                    }
                    res = conn_state.write_tx.send(encoded) => res,
                };
                if send_result.is_err() {
                    warn!(
                        conn_id = conn_state.conn_id,
                        "write channel closed; ending read loop"
                    );
                    return Ok(());
                }
            }
        }
    }

    /// Remove all sessions owned by this connection from the shared state,
    /// close any remaining VFS handles on the per-connection open table, and
    /// cancel pending async operations.
    ///
    /// On an abrupt disconnect (peer dropped, I/O error), LOGOFF and
    /// TREE_DISCONNECT never ran. Without this, VFS handles (OS file
    /// descriptors) would leak until the process exits.
    async fn cleanup(state: &Arc<ServerState>, conn_id: u64, conn_state: &ConnState) {
        // Close all per-connection VFS handles. Fire-and-forget like
        // TREE_DISCONNECT/LOGOFF — the peer is gone, so there is nobody
        // to wait for a response.
        let removed_opens: Vec<(u64, crate::dispatch::OpenEntry)> = {
            let mut opens = conn_state.opens.write().await;
            let entries: Vec<(u64, crate::dispatch::OpenEntry)> =
                opens.iter().map(|(k, v)| (*k, v.clone())).collect();
            for (key, _) in &entries {
                opens.remove(key);
            }
            entries
        };
        for (_, entry) in &removed_opens {
            if entry.is_pipe {
                continue;
            }
            // Remove from the global open table and release any byte-range
            // locks held by this open. On abrupt disconnect (TCP RST, idle
            // timeout), the normal CLOSE/LOGOFF/TREE_DISCONNECT path doesn't
            // run, so locks would otherwise survive as stale entries.
            if let Some(fid) = entry.file_id {
                state.open_table.remove(fid, entry.open_id).await;
            }
            let released = state
                .open_table
                .release_all_locks_for_open(entry.open_id)
                .await;
            if released > 0 {
                debug!(conn_id, open_id = ?entry.open_id, released, "cleanup: released stale locks");
            }
            // Durable opens: leave the VFS handle alive in the durable
            // table for reconnect. The OpenTable entry was removed above so
            // new opens during the durable window don't conflict with the
            // disconnected client.
            if entry.durable_guid.is_some() {
                debug!(
                    conn_id,
                    open_id = ?entry.open_id,
                    "cleanup: skipping VFS close for durable open (left in durable table)"
                );
                continue;
            }
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "connection cleanup: VFS close failed");
                }
            });
        }
        if !removed_opens.is_empty() {
            debug!(
                conn_id,
                open_count = removed_opens.len(),
                "cleanup: scheduled VFS closes"
            );
        }

        // Cancel all pending async operations on this connection.
        let cancelled: Vec<u64> = {
            let mut pending = conn_state.pending_async.lock().await;
            let keys: Vec<u64> = pending.keys().copied().collect();
            let mut cancelled = Vec::with_capacity(keys.len());
            for key in keys {
                if let Some(op) = pending.remove(&key) {
                    let _ = op.cancel.send(());
                    if let Some(handle) = op.notify_handle {
                        handle.cancel();
                    }
                    cancelled.push(key);
                }
            }
            cancelled
        };
        if !cancelled.is_empty() {
            debug!(
                conn_id,
                async_count = cancelled.len(),
                "cleanup: cancelled async ops"
            );
        }

        // Remove all sessions owned by this connection from the shared state.
        let to_remove: Vec<u64> = {
            let sessions = state.sessions.read().await;
            sessions
                .iter()
                .filter(|s| s.connection_id == conn_id)
                .map(|s| s.id)
                .collect()
        };
        for session_id in to_remove {
            state.remove_session(session_id).await;
            debug!(conn_id, session_id, "removed session on connection cleanup");
        }
    }
}

/// Overwrite CreditResponse (header offset 14) of the last SMB2 message in a
/// NetBIOS-framed response. Must run before signing.
fn set_last_credit_response(frame: &mut [u8], credits: u16) {
    if frame.len() < 4 + 64 {
        return;
    }
    let body = &mut frame[4..];
    if let Some(&(s, _)) = rssmb_wire_adapter::framing::message_ranges(body).last() {
        body[s + 14..s + 16].copy_from_slice(&credits.to_le_bytes());
    }
}

/// Human-readable kind label for a [`FramedMessage`], for logging.
fn framed_kind(msg: &FramedMessage) -> &'static str {
    match msg {
        FramedMessage::Plain(_) => "plain",
        FramedMessage::Compound(_) => "compound",
        FramedMessage::Encrypted(_) => "encrypted",
        FramedMessage::Compressed(_) => "compressed",
        FramedMessage::Smb1Negotiate(_) => "smb1_negotiate",
    }
}

/// Bind a TCP listener and spawn a task per accepted connection.
///
/// Connection IDs are assigned from a monotonically increasing counter.
/// Returns once the listener fails to accept (e.g. on shutdown) — callers
/// should typically `spawn` this function.
pub async fn listen(config: ServerConfig) -> std::io::Result<()> {
    listen_with_state(config, |cfg| Arc::new(ServerState::new(cfg))).await
}

/// Listen on an already-bound [`TcpListener`] using an externally
/// constructed [`ServerState`].
///
/// This variant lets the caller bind the listener (e.g. on port 0 for an
/// ephemeral port) and read `local_addr()` before the accept loop starts.
/// The returned `SocketAddr` is the bound address.
pub async fn listen_on(
    listener: TcpListener,
    state: Arc<ServerState>,
) -> std::io::Result<std::net::SocketAddr> {
    let addr = listener.local_addr()?;
    info!(addr = %addr, "SMB listener bound (pre-bound)");

    let next_conn_id = Arc::new(AtomicU64::new(1));
    let mut connections = tokio::task::JoinSet::<()>::new();

    loop {
        let (stream, remote_addr) = tokio::select! {
            biased;

            _ = state.shutdown.notified() => {
                info!("shutdown signaled; listener stopping");
                break;
            }

            res = listener.accept() => match res {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    warn!(error = %e, "accept error; listener stopping");
                    return Err(e);
                }
            },
        };

        let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);

        // Enforce connection limits (global + per-IP).
        let ip = remote_addr.ip();
        let guard = match state.conn_limiter.try_admit(ip) {
            Some(g) => g,
            None => {
                // Limit exceeded — drop the connection without a response.
                debug!(conn_id, %remote_addr, "connection limit exceeded — dropping");
                state
                    .metrics
                    .connections_rejected_limit_total
                    .fetch_add(1, Ordering::Relaxed);
                // The stream is dropped here, closing the TCP connection.
                continue;
            }
        };

        debug!(conn_id, %remote_addr, "spawning connection task");
        state
            .metrics
            .connections_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .connections_active
            .fetch_add(1, Ordering::Relaxed);

        let state = state.clone();
        connections.spawn(async move {
            // The guard lives for the duration of the connection task.
            let _guard = guard;
            Connection::handle(state, stream, conn_id).await;
        });

        // Reap completed connection tasks non-blockingly.
        while connections.try_join_next().is_some() {}
    }

    // Graceful drain: wait up to shutdown_grace_secs for active connections
    // to finish, then abort any that remain.
    drain_connections(&mut connections, state.config.shutdown_grace_secs).await;

    // Close all durable VFS handles so they don't leak.
    let durable_closed = state.durable_table.close_all().await;
    if durable_closed > 0 {
        info!(durable_closed, "closed durable handles during shutdown");
    }

    Ok(addr)
}

/// Drain active connections up to a grace period, then abort any that remain.
///
/// Each connection task runs `Connection::cleanup` on exit, which closes
/// all VFS handles for that connection. After the grace period expires,
/// remaining tasks are aborted (their cleanup may not run, but the OS
/// closes the sockets).
async fn drain_connections(connections: &mut tokio::task::JoinSet<()>, grace_secs: u64) {
    let grace = std::time::Duration::from_secs(grace_secs);
    let deadline = tokio::time::Instant::now() + grace;

    while !connections.is_empty() {
        let remaining = connections.len();
        match tokio::time::timeout_at(deadline, connections.join_next()).await {
            Ok(Some(result)) => {
                if let Err(e) = result {
                    // Task panicked or was cancelled — log but continue draining.
                    if !e.is_cancelled() {
                        warn!(error = %e, "connection task panicked during drain");
                    }
                }
            }
            Ok(None) => break, // all done
            Err(_) => {
                // Grace period expired — abort remaining tasks.
                let stuck = connections.len();
                warn!(
                    stuck,
                    remaining, "grace period expired — aborting {} connection(s)", stuck
                );
                connections.abort_all();
                // Wait briefly for aborts to complete.
                while connections.join_next().await.is_some() {}
                break;
            }
        }
    }
    debug!("connection drain complete");
}

/// Bind a TCP listener using an externally constructed [`ServerState`] and
/// spawn a task per accepted connection.
///
/// This variant lets the caller hold a handle to the shared state (for
/// triggering shutdown). The `state_fn` closure is invoked once with the
/// config to produce the shared state; the returned `Arc<ServerState>` is
/// cloned into every connection task.
pub async fn listen_with_state<F>(config: ServerConfig, state_fn: F) -> std::io::Result<()>
where
    F: FnOnce(ServerConfig) -> Arc<ServerState>,
{
    let bind_addr = format!("{}:{}", config.listen_addr, config.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "SMB listener bound");

    let state = state_fn(config);

    // Connection ID counter — starts at 1.
    let next_conn_id = Arc::new(AtomicU64::new(1));
    let mut connections = tokio::task::JoinSet::<()>::new();

    loop {
        // Accept loop races shutdown against the next incoming connection.
        let (stream, remote_addr) = tokio::select! {
            biased;

            _ = state.shutdown.notified() => {
                info!("shutdown signaled; listener stopping");
                break;
            }

            res = listener.accept() => match res {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    warn!(error = %e, "accept error; listener stopping");
                    return Err(e);
                }
            },
        };

        let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);

        // Enforce connection limits (global + per-IP).
        let ip = remote_addr.ip();
        let guard = match state.conn_limiter.try_admit(ip) {
            Some(g) => g,
            None => {
                debug!(conn_id, %remote_addr, "connection limit exceeded — dropping");
                state
                    .metrics
                    .connections_rejected_limit_total
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        debug!(conn_id, %remote_addr, "spawning connection task");
        state
            .metrics
            .connections_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .connections_active
            .fetch_add(1, Ordering::Relaxed);

        let state = state.clone();
        connections.spawn(async move {
            let _guard = guard;
            Connection::handle(state, stream, conn_id).await;
        });

        // Reap completed connection tasks non-blockingly.
        while connections.try_join_next().is_some() {}
    }

    // Graceful drain: wait up to shutdown_grace_secs for active connections
    // to finish, then abort any that remain.
    drain_connections(&mut connections, state.config.shutdown_grace_secs).await;

    // Close all durable VFS handles so they don't leak.
    let durable_closed = state.durable_table.close_all().await;
    if durable_closed > 0 {
        info!(durable_closed, "closed durable handles during shutdown");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn test_connection_id_generation() {
        // Connection IDs are assigned by an AtomicU64 counter. Verify the
        // sequence is monotonic and unique.
        let counter = AtomicU64::new(1);
        let mut ids = Vec::new();
        for _ in 0..1000 {
            ids.push(counter.fetch_add(1, Ordering::Relaxed));
        }
        // First ID is 1, last is 1000.
        assert_eq!(ids[0], 1);
        assert_eq!(ids[999], 1000);
        // All unique.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn test_credit_manager_default() {
        // The CreditManager used by Connection starts with 1 available credit
        // and the configured max_grant cap.
        let credits = CreditManager::new(1024);
        assert_eq!(credits.available_credits(), 1);
        credits.grant(10);
        assert_eq!(credits.available_credits(), 11);
    }

    #[tokio::test]
    async fn test_connection_struct_fields() {
        // Exercise the struct construction path with a real (unbound) state and
        // a channel, without touching the network.
        let config = ServerConfig::for_testing();
        let state = Arc::new(ServerState::new(config));
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);

        // Push a dummy frame through the channel.
        write_tx.send(Bytes::from_static(b"ping")).await.unwrap();
        let received = write_rx
            .recv()
            .await
            .expect("channel should yield the frame");
        assert_eq!(&received[..], b"ping");

        // The state's shutdown Notify is usable.
        state.shutdown().await;
        // Subsequent waits should complete immediately — the signal is
        // stateful: once triggered, all future notified() calls return
        // instantly without re-triggering.
        let notified = state.shutdown.notified();
        drop(notified);
    }

    #[tokio::test]
    async fn test_read_netbios_payload_eof() {
        // A closed socket yields Ok(None).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        // Close the server side read half by dropping the client — give it a
        // moment.
        // The client is dropped here; read should return EOF.
        drop(_client);
        // Read should eventually yield None.
        let result = read_netbios_payload(&mut server, 1_048_576).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn test_listen_shutdown() {
        // listen_with_state returns promptly once shutdown is signaled, even
        // with no incoming connections.
        let config = ServerConfig::for_testing();
        // Use an ephemeral port.
        let mut config = config;
        config.port = 0;
        config.listen_addr = "127.0.0.1".to_string();

        let state = Arc::new(ServerState::new(config));
        let shutdown_state = state.clone();

        let listener = tokio::spawn(async move {
            let cfg = ServerConfig::for_testing();
            // We can't bind the same testing port twice reliably; use a fresh
            // ephemeral config by zeroing the port and letting the OS assign.
            let mut cfg = cfg;
            cfg.port = 0;
            cfg.listen_addr = "127.0.0.1".to_string();
            // Reuse listen_with_state's internal bind via a custom state fn.
            listen_with_state(cfg, |_| state.clone()).await
        });

        // Give the listener a moment to bind and enter the accept loop.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Trigger shutdown.
        shutdown_state.shutdown().await;

        // The listener task should complete (Ok or Err depending on race).
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), listener).await;
        assert!(result.is_ok(), "listener should exit on shutdown");
    }

    #[test]
    fn error_reply_credit_response_is_patched_to_real_grant() {
        // A pre-built error reply says CreditResponse = 1; at the credit cap
        // the real grant is 0 and that is what must go on the wire.
        let resp = FramedResponse::Error {
            command: rssmb_proto::header::Command::Create,
            status: NtStatus::AccessDenied,
            message_id: 5,
            session_id: 9,
            tree_id: Some(1),
        };
        let mut frame = encode_response(&resp).to_vec();
        assert_eq!(u16::from_le_bytes([frame[4 + 14], frame[4 + 15]]), 1);
        set_last_credit_response(&mut frame, 0);
        assert_eq!(u16::from_le_bytes([frame[4 + 14], frame[4 + 15]]), 0);
    }

    #[tokio::test]
    async fn cleanup_drains_opens_and_async_ops_on_disconnect() {
        use rssmb_vfs::Vfs;
        let state = Arc::new(ServerState::new(ServerConfig::for_testing()));
        let (tx, _rx) = mpsc::channel::<Bytes>(4);
        let conn_state = ConnState {
            conn_id: 77,
            remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            write_tx: tx,
            auth_state: Arc::new(tokio::sync::Mutex::new(None)),
            auth_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            negotiate_record: Arc::new(tokio::sync::Mutex::new(None)),
            trees: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            opens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            pending_sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            credits: Arc::new(CreditManager::new(16)),
            pending_async: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            signing: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            encryption: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            preauth_conn: Arc::new(std::sync::Mutex::new(None)),
            preauth_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            preauth_hash_response: Arc::new(std::sync::Mutex::new(None)),
            next_tree_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_volatile_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            persistent_base: 0,
        };

        let vfs: Arc<dyn Vfs> = Arc::new(rssmb_vfs::memoryfs::MemoryFs::new());
        let args = rssmb_vfs::CreateArgs {
            disposition: rssmb_vfs::CreateDisposition::Create,
            share_access: rssmb_vfs::ShareAccess::all(),
            desired_access: Default::default(),
            create_options: Default::default(),
        };
        let open_id = vfs.create("", "f.txt", &args).await.expect("create");
        conn_state.opens.write().await.insert(
            1,
            crate::dispatch::OpenEntry {
                session_id: 5,
                tree_id: 3,
                open_id,
                vfs: vfs.clone(),
                file_id: None,
                dir_cursor: Default::default(),
                path: "f.txt".into(),
                is_pipe: false,
                pipe_state: None,
                durable_guid: None,
            },
        );
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        conn_state.pending_async.lock().await.insert(
            9,
            crate::dispatch::AsyncOp {
                command: rssmb_proto::header::Command::ChangeNotify,
                session_id: 5,
                tree_id: 3,
                cancel: cancel_tx,
                notify_handle: None,
            },
        );

        Connection::cleanup(&state, 77, &conn_state).await;

        assert!(
            conn_state.opens.read().await.is_empty(),
            "opens not drained"
        );
        assert!(
            conn_state.pending_async.lock().await.is_empty(),
            "async ops not drained"
        );
        assert!(cancel_rx.await.is_ok(), "async op was not signalled");
    }

    #[test]
    fn test_framed_kind_labels() {
        use rssmb_proto::echo::EchoRequest;
        use rssmb_proto::header::{Command, Header};
        use rssmb_proto::plain::{PlainRequest, RequestContent};
        use rssmb_wire_adapter::FramedMessage;

        let req = PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Echo,
                credit_request: 1,
                flags: rssmb_proto::header::HeaderFlags::new(),
                next_command: 0,
                message_id: 1,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Echo(EchoRequest::default()),
        };

        assert_eq!(framed_kind(&FramedMessage::Plain(req)), "plain");
        assert_eq!(framed_kind(&FramedMessage::Encrypted(vec![])), "encrypted");
        assert_eq!(
            framed_kind(&FramedMessage::Compressed(vec![])),
            "compressed"
        );
        assert_eq!(
            framed_kind(&FramedMessage::Smb1Negotiate(vec![])),
            "smb1_negotiate"
        );
    }
}
