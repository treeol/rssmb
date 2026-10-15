//! RSSMB wire adapter — server-side framing and codec over rssmb-proto.
//!
//! This crate wraps the `rssmb-proto` crate to provide:
//! - Frame-level parsing: recognize `\xfeSMB` (plain), `\xfdSMB` (transform/encrypt),
//!   `\xfcSMB` (compress) at the framing layer.
//! - Bounds checking: cap frame lengths to prevent DoS.
//! - Compound/related request chaining.
//! - Credit tracking.
//! - Error response construction.
//! - Original byte preservation for preauth integrity.

use bytes::{BufMut, Bytes, BytesMut};

pub mod credits;
pub mod error;
pub mod framing;

pub use error::{NtStatus, WireError};

/// SMB2 protocol magic bytes.
pub const SMB2_MAGIC: [u8; 4] = [0xfe, 0x53, 0x4d, 0x42];

/// Transform header magic (encrypted).
pub const TRANSFORM_MAGIC: [u8; 4] = [0xfd, 0x53, 0x4d, 0x42];

/// Compression header magic.
pub const COMPRESS_MAGIC: [u8; 4] = [0xfc, 0x53, 0x4d, 0x42];

/// SMB1 protocol magic (for multi-protocol negotiate detection).
pub const SMB1_MAGIC: [u8; 4] = [0xff, 0x53, 0x4d, 0x42];

/// Maximum frame size we'll accept (1 MB). The NetBIOS length field is 24 bits
/// (max ~16MB), but we cap well below that to prevent memory exhaustion attacks.
pub const MAX_FRAME_SIZE: usize = 1_048_576;

/// Default port for SMB over TCP.
pub const SMB_PORT: u16 = 445;

/// Default port for SMB over NetBIOS (legacy).
pub const NETBIOS_PORT: u16 = 139;

/// Re-export key types from rssmb-proto for convenience.
pub use rssmb_proto::{
    header::{Command, Header},
    negotiate::{NegotiateRequest, NegotiateResponse},
    plain::{PlainRequest, PlainResponse, RequestContent, ResponseContent},
};

/// A framed message received from the wire.
#[derive(Debug)]
pub enum FramedMessage {
    /// Plain SMB2 message (`\xfeSMB`).
    /// The raw bytes preserve the original frame for WRITE data extraction
    /// and future signing/preauth-integrity support.
    Plain(PlainRequest),
    /// Compound SMB2 message — multiple chained requests in one frame.
    /// The raw bytes and per-message offsets preserve the original frame
    /// for WRITE data extraction and signing.
    Compound(Vec<PlainRequest>),
    /// Encrypted transform header (`\xfdSMB`).
    Encrypted(Vec<u8>),
    /// Compressed message (`\xfcSMB`).
    Compressed(Vec<u8>),
    /// SMB1 multi-protocol negotiate (`\xffSMB`) — respond with 0x02FF or close.
    Smb1Negotiate(Vec<u8>),
}

/// A response to send on the wire.
#[derive(Debug)]
pub enum FramedResponse {
    /// Plain SMB2 response.
    Plain(PlainResponse),
    /// Compound SMB2 response — multiple chained responses in one frame.
    Compound(Vec<PlainResponse>),
    /// Encrypted response.
    Encrypted(Vec<u8>),
    /// Error response with NTSTATUS carrying the request header fields
    /// so the client can match it (message_id, session_id, tree_id).
    Error {
        command: Command,
        status: NtStatus,
        message_id: u64,
        session_id: u64,
        tree_id: Option<u32>,
    },
    /// Pre-encoded raw bytes (used for decode-failure fallback).
    Raw(Vec<u8>),
    /// No reply: the request violated the protocol in a way that requires
    /// the connection to be terminated (e.g. MS-SMB2 3.3.5.2.3, a request
    /// the client had no credits for). Never encoded.
    Disconnect,
}

/// Encode a single PlainResponse body (header + content) into a Vec<u8>,
/// without NetBIOS transport framing. Used for compound response assembly.
fn encode_plain_body(plain: &PlainResponse) -> Option<Vec<u8>> {
    use binrw::BinWrite;
    let mut temp: Vec<u8> = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut temp);
    if let Err(e) = plain.write_le(&mut cursor) {
        tracing::error!("Failed to encode PlainResponse: {e:?}");
        return None;
    }
    Some(temp)
}

/// Encode a FramedResponse into NetBIOS-framed bytes for the wire.
pub fn encode_response(resp: &FramedResponse) -> Bytes {
    let mut buf = BytesMut::new();
    match resp {
        FramedResponse::Plain(plain) => {
            let temp = match encode_plain_body(plain) {
                Some(b) => b,
                None => return Bytes::new(),
            };
            let len = temp.len();
            tracing::debug!("Encoded PlainResponse: {} bytes", len);
            buf.put_u8(0x00);
            buf.put_u8((len >> 16) as u8);
            buf.put_u8((len >> 8) as u8);
            buf.put_u8(len as u8);
            buf.extend_from_slice(&temp);
        }
        FramedResponse::Compound(responses) => {
            // Encode each response body, then patch next_command offsets
            // and concatenate into one frame.
            let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(responses.len());
            for resp in responses {
                match encode_plain_body(resp) {
                    Some(b) => bodies.push(b),
                    None => {
                        tracing::error!("Failed to encode compound response member");
                        return Bytes::new();
                    }
                }
            }

            // Patch next_command and pad each non-last body to 8 bytes.
            let n = bodies.len();
            let mut frame = Vec::new();
            for (i, body) in bodies.iter_mut().enumerate() {
                let is_last = i == n - 1;
                if !is_last {
                    let len = body.len();
                    let aligned = (len + 7) & !7;
                    let pad = aligned - len;
                    body.extend(std::iter::repeat_n(0u8, pad));
                    let aligned_u32 = aligned as u32;
                    body[20..24].copy_from_slice(&aligned_u32.to_le_bytes());
                } else {
                    let zero = 0u32;
                    body[20..24].copy_from_slice(&zero.to_le_bytes());
                }
                frame.extend_from_slice(&body[..]);
            }

            let len = frame.len();
            tracing::debug!(
                "Encoded CompoundResponse: {} bytes ({} members)",
                len,
                bodies.len()
            );
            buf.put_u8(0x00);
            buf.put_u8((len >> 16) as u8);
            buf.put_u8((len >> 8) as u8);
            buf.put_u8(len as u8);
            buf.extend_from_slice(&frame);
        }
        FramedResponse::Encrypted(data) => {
            let len = data.len();
            buf.put_u8(0x00);
            buf.put_u8((len >> 16) as u8);
            buf.put_u8((len >> 8) as u8);
            buf.put_u8(len as u8);
            buf.extend_from_slice(data);
        }
        FramedResponse::Disconnect => return Bytes::new(),
        FramedResponse::Raw(data) => {
            let len = data.len();
            buf.put_u8(0x00);
            buf.put_u8((len >> 16) as u8);
            buf.put_u8((len >> 8) as u8);
            buf.put_u8(len as u8);
            buf.extend_from_slice(data);
        }
        FramedResponse::Error {
            command,
            status,
            message_id,
            session_id,
            tree_id,
        } => {
            let body = build_error_response(*command, *status, *message_id, *session_id, *tree_id);
            if body.is_empty() {
                tracing::error!("build_error_response returned empty for {:?}", *command);
                return Bytes::new();
            }
            let len = body.len();
            buf.put_u8(0x00);
            buf.put_u8((len >> 16) as u8);
            buf.put_u8((len >> 8) as u8);
            buf.put_u8(len as u8);
            buf.extend_from_slice(&body);
        }
    }
    buf.freeze()
}

/// Build a raw error response (header + 9-byte error body) carrying the
/// request's message_id, session_id, and tree_id so the client can match it.
pub fn build_error_response(
    command: Command,
    status: NtStatus,
    message_id: u64,
    session_id: u64,
    tree_id: Option<u32>,
) -> Vec<u8> {
    let header = Header {
        credit_charge: 0,
        status: status.to_u32(),
        command,
        credit_request: 1,
        flags: rssmb_proto::header::HeaderFlags::new().with_server_to_redir(true),
        next_command: 0,
        message_id,
        tree_id,
        async_id: None,
        session_id,
        signature: 0,
    };
    use binrw::BinWrite;
    let mut temp: Vec<u8> = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut temp);
    if let Err(e) = header.write_le(&mut cursor) {
        tracing::error!("Failed to encode error header: {e:?}");
        return Vec::new();
    }
    // 9-byte ErrorResponse body
    temp.extend_from_slice(&9u16.to_le_bytes());
    temp.push(0); // error_context_count
    temp.push(0); // reserved
    temp.extend_from_slice(&0u32.to_le_bytes()); // byte_count
    temp
}
