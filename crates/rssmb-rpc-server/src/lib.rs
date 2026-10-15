//! RSSMB RPC server — DCE/RPC server-side dispatch.
//!
//! Handles IPC$ named pipe operations: SrvSvc share enumeration,
//! RPC bind/alter/await, fragmentation/reassembly.

pub mod ndr;
pub mod pdu;

use std::collections::{HashMap, VecDeque};

use thiserror::Error;
use tracing::{debug, warn};

pub use pdu::*;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("not supported")]
    NotSupported,
    #[error("invalid pipe name: {0}")]
    InvalidPipeName(String),
    #[error("bind error: {0}")]
    BindError(String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

/// Known named pipe UUIDs.
pub mod uuids {
    /// SrvSvc: 4B324FC8-1670-01D3-1278-5A47BF6EE188
    pub const SRVSVC: &str = "4B324FC8-1670-01D3-1278-5A47BF6EE188";

    /// SvcCtl: 367ABB81-9844-35F1-AD32-98F038001003
    pub const SVCCTL: &str = "367ABB81-9844-35F1-AD32-98F038001003";

    /// WinReg: 338CD001-2244-31F1-AAAA-900038001003
    pub const WINREG: &str = "338CD001-2244-31F1-AAAA-900038001003";

    /// LsaSrv: 12345778-1234-ABCD-EF00-0123456789AB
    pub const LSASRV: &str = "12345778-1234-ABCD-EF00-0123456789AB";
}

/// Check if a pipe name is a known RPC pipe.
///
/// **Note:** this matches several pipe names for completeness, but Step 8
/// only *serves* `srvsvc`. Use [`serves_pipe`] as the CREATE allowlist — it
/// matches only `srvsvc` and requires a `\` separator after `PIPE`.
pub fn is_rpc_pipe(name: &str) -> bool {
    matches!(
        name.to_uppercase()
            .trim_start_matches('\\')
            .trim_start_matches("PIPE")
            .trim_start_matches('\\'),
        "SRVSVC" | "SVCCTL" | "WINREG" | "LSARPC" | "SAMR" | "NETLOGON"
    )
}

/// Whether this server actively serves the named pipe (Step 8: only srvsvc).
/// Strips a leading `\` and an optional `PIPE\` prefix (with separator)
/// before matching case-insensitively.
pub fn serves_pipe(name: &str) -> bool {
    let trimmed = name.trim_start_matches('\\');
    // Strip "PIPE\" prefix (case-insensitive, with separator).
    let after_pipe = if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case("PIPE\\") {
        &trimmed[5..]
    } else {
        trimmed
    };
    after_pipe.eq_ignore_ascii_case("srvsvc")
}

/// Maximum reassembled request size (1 MiB).
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Per-pipe RPC state. Manages PDU parsing, fragment reassembly, and
/// response queuing.
pub struct PipeState {
    /// Bound presentation contexts: p_cont_id → (interface, transfer_syntax).
    bound: HashMap<u16, ContextBinding>,
    /// Negotiated max transmit fragment size (our max to the client).
    max_xmit_frag: u16,
    /// Negotiated max receive fragment size (client's max from us).
    max_recv_frag: u16,
    /// Association group ID.
    assoc_group_id: u32,
    /// Transport reassembly buffer: incomplete PDUs waiting for more data.
    transport_buf: Vec<u8>,
    /// Per-call stub reassembly buffer: accumulated stub data from REQUEST fragments.
    stub_buf: Vec<u8>,
    /// The call_id of the in-progress reassembly (if any).
    in_call_id: Option<u32>,
    /// The p_cont_id of the in-progress reassembly (if any).
    in_p_cont_id: Option<u16>,
    /// The opnum of the in-progress reassembly (if any).
    in_opnum: Option<u16>,
    /// Output queue: complete response PDU byte vectors waiting to be read.
    out_queue: VecDeque<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
struct ContextBinding {
    /// Whether this context was accepted (SRVSVC/NDR20).
    _accepted: bool,
}

impl Default for PipeState {
    fn default() -> Self {
        Self {
            bound: HashMap::new(),
            max_xmit_frag: MAX_XMIT_FRAG,
            max_recv_frag: MAX_RECV_FRAG,
            assoc_group_id: 0,
            transport_buf: Vec::new(),
            stub_buf: Vec::new(),
            in_call_id: None,
            in_p_cont_id: None,
            in_opnum: Option::None,
            out_queue: VecDeque::new(),
        }
    }
}

impl PipeState {
    /// Create a new, empty pipe state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process incoming transport bytes. Parses complete PDUs, handles BIND
    /// and REQUEST, and enqueues response PDUs into the output queue.
    ///
    /// Returns the number of bytes consumed from `input`. Unconsumed bytes
    /// are buffered internally for the next call.
    pub fn process(&mut self, input: &[u8], ctx: &RpcCtx) -> usize {
        // Append to the transport reassembly buffer.
        self.transport_buf.extend_from_slice(input);
        let total_input = input.len();

        // Process as many complete PDUs as are available.
        loop {
            if self.transport_buf.len() < PduHeader::SIZE {
                break;
            }
            // Peek at frag_length without consuming.
            let frag_length =
                u16::from_le_bytes([self.transport_buf[8], self.transport_buf[9]]) as usize;
            if frag_length < PduHeader::SIZE {
                // Invalid frag_length — drop the buffer.
                warn!(frag_length, "invalid DCE/RPC frag_length — dropping buffer");
                self.transport_buf.clear();
                break;
            }
            if self.transport_buf.len() < frag_length {
                // Not enough data yet — wait for more.
                break;
            }

            // We have a complete PDU. Extract it.
            let pdu_bytes = self.transport_buf[..frag_length].to_vec();
            self.transport_buf.drain(..frag_length);

            // Parse and handle the PDU.
            self.handle_pdu(&pdu_bytes, ctx);
        }

        // All input bytes are accepted (buffered or processed).
        total_input
    }

    /// Handle a single complete PDU.
    fn handle_pdu(&mut self, pdu: &[u8], ctx: &RpcCtx) {
        let Some((header, body)) = PduHeader::parse(pdu) else {
            warn!("failed to parse DCE/RPC PDU header");
            return;
        };

        // Reject auth trailers (auth_length != 0) — not supported.
        if header.auth_length != 0 {
            warn!(
                auth_length = header.auth_length,
                "auth trailer in RPC PDU — not supported"
            );
            if header.ptype == PTYPE_BIND {
                self.enqueue(build_bind_nak(
                    header.call_id,
                    pdu::NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
                ));
            } else {
                self.enqueue(build_fault(
                    header.call_id,
                    0,
                    FAULT_ACCESS_DENIED,
                    PFC_FIRST_FRAG | PFC_LAST_FRAG,
                ));
            }
            return;
        }

        // Reject non-ASCII / big-endian drep.
        if header.drep[0] & 0xF0 != 0x10 {
            warn!(drep = ?header.drep, "non-ASCII/big-endian drep — not supported");
            if header.ptype == PTYPE_BIND {
                self.enqueue(build_bind_nak(
                    header.call_id,
                    pdu::NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
                ));
            } else {
                self.enqueue(build_fault(
                    header.call_id,
                    0,
                    FAULT_NCA_S_PROTO_ERROR,
                    PFC_FIRST_FRAG | PFC_LAST_FRAG,
                ));
            }
            return;
        }

        match header.ptype {
            PTYPE_BIND => self.handle_bind(&header, body, ctx),
            PTYPE_ALTER_CONTEXT => self.handle_alter_context(&header, body, ctx),
            PTYPE_REQUEST => self.handle_request(&header, body, ctx),
            other => {
                debug!(
                    ptype = other,
                    "unexpected PDU type — sending protocol error fault"
                );
                self.enqueue(build_fault(
                    header.call_id,
                    0,
                    FAULT_NCA_S_PROTO_ERROR,
                    PFC_FIRST_FRAG | PFC_LAST_FRAG,
                ));
            }
        }
    }

    /// Handle a BIND PDU — negotiate contexts and respond with BIND_ACK.
    fn handle_bind(&mut self, _header: &PduHeader, body: &[u8], _ctx: &RpcCtx) {
        let Some((client_max_xmit, client_max_recv, assoc_group, ctx_items)) = parse_bind(body)
        else {
            warn!("failed to parse BIND body");
            self.enqueue(build_bind_nak(
                _header.call_id,
                pdu::NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
            ));
            return;
        };

        // Evaluate each context element.
        let _results: Vec<BindAckResult> = ctx_items
            .iter()
            .map(|ctx| {
                let result = evaluate_bind_context(ctx);
                if result.result == RESULT_ACCEPTANCE {
                    self.bound
                        .insert(ctx.context_id, ContextBinding { _accepted: true });
                }
                result
            })
            .collect();

        // Negotiate fragment sizes (directional: our transmit ≤ client's recv,
        // our recv ≤ client's transmit).
        self.max_xmit_frag = std::cmp::min(client_max_recv, MAX_XMIT_FRAG).max(256);
        self.max_recv_frag = std::cmp::min(client_max_xmit, MAX_RECV_FRAG).max(256);
        self.assoc_group_id = if assoc_group != 0 {
            assoc_group
        } else {
            _header.call_id.wrapping_mul(0x4910) | 1
        };

        let ack = build_bind_ack(
            _header.call_id,
            client_max_xmit,
            client_max_recv,
            assoc_group,
            &ctx_items,
        );
        self.enqueue(ack);
    }

    /// Handle an ALTER_CONTEXT PDU — same logic as BIND but responds with
    /// ALTER_CONTEXT_RESP (same format as BIND_ACK).
    fn handle_alter_context(&mut self, header: &PduHeader, body: &[u8], ctx: &RpcCtx) {
        // ALTER_CONTEXT has the same format as BIND; respond with BIND_ACK
        // (ALTER_CONTEXT_RESP has the same wire format).
        self.handle_bind(header, body, ctx);
    }

    /// Handle a REQUEST PDU — reassemble fragments, then dispatch.
    fn handle_request(&mut self, header: &PduHeader, body: &[u8], ctx: &RpcCtx) {
        // Check if bound.
        if self.bound.is_empty() {
            warn!("REQUEST before BIND — faulting unk_if");
            self.enqueue(build_fault(
                header.call_id,
                0,
                FAULT_NCA_S_UNK_IF,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ));
            return;
        }

        let Some((alloc_hint, p_cont_id, opnum, stub_data)) = parse_request(body) else {
            warn!("failed to parse REQUEST body");
            self.enqueue(build_fault(
                header.call_id,
                0,
                FAULT_NCA_S_PROTO_ERROR,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ));
            return;
        };

        // Validate the context was bound.
        if !self.bound.contains_key(&p_cont_id) {
            warn!(p_cont_id, "REQUEST on unbound context — faulting unk_if");
            self.enqueue(build_fault(
                header.call_id,
                p_cont_id,
                FAULT_NCA_S_UNK_IF,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ));
            return;
        }

        // Fragment reassembly: if FIRST, start a new reassembly. If not FIRST,
        // append to existing. If not LAST, just accumulate.
        if header.is_first() {
            // New call — reset reassembly state.
            self.in_call_id = Some(header.call_id);
            self.in_p_cont_id = Some(p_cont_id);
            self.in_opnum = Some(opnum);
            self.stub_buf_clear();
        } else if self.in_call_id != Some(header.call_id) {
            // Continuation of a different call — reject.
            warn!("REQUEST fragment with mismatched call_id — faulting proto_error");
            self.enqueue(build_fault(
                header.call_id,
                p_cont_id,
                FAULT_NCA_S_PROTO_ERROR,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ));
            return;
        }

        // Accumulate stub data.
        self.stub_buf_accumulate(stub_data);

        // Check reassembly limit.
        if self.stub_buf_len() > MAX_REQUEST_SIZE {
            warn!("reassembled request exceeds limit — faulting");
            self.enqueue(build_fault(
                header.call_id,
                p_cont_id,
                FAULT_NCA_S_PROTO_ERROR,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ));
            self.stub_buf_clear();
            self.in_call_id = None;
            return;
        }

        let _ = alloc_hint; // advisory only

        if !header.is_last() {
            // Wait for more fragments.
            return;
        }

        // Last fragment — dispatch the reassembled stub.
        let full_stub = self.take_stub_buf();
        let call_id = header.call_id;
        let opnum = self.in_opnum.unwrap_or(opnum);
        self.in_call_id = None;

        // Dispatch to the SrvSvc handler (Step 8.4).
        let response_stub = dispatch_srvsvc(opnum, &full_stub, ctx);

        match response_stub {
            Ok(stub) => {
                // Fragment and enqueue response PDUs.
                let pdus = fragment_response(call_id, p_cont_id, &stub, self.max_xmit_frag);
                for pdu in pdus {
                    self.enqueue(pdu);
                }
            }
            Err(fault_status) => {
                self.enqueue(build_fault(
                    call_id,
                    p_cont_id,
                    fault_status,
                    PFC_FIRST_FRAG | PFC_LAST_FRAG,
                ));
            }
        }
    }

    /// Read up to `max` bytes from the output queue.
    ///
    /// Returns the data and whether more data remains in the current message.
    pub fn read(&mut self, max: usize) -> (Vec<u8>, ReadStatus) {
        if self.out_queue.is_empty() {
            return (Vec::new(), ReadStatus::Empty);
        }
        // The output queue holds complete PDU byte vectors.
        // Each read returns complete PDUs up to `max` bytes.
        let mut result = Vec::new();
        while let Some(front) = self.out_queue.front() {
            if result.len() + front.len() <= max {
                result.extend_from_slice(front);
                self.out_queue.pop_front();
            } else {
                // Can't fit the next complete PDU — stop.
                break;
            }
        }
        let status = if result.is_empty() {
            // Data is available but doesn't fit in `max` — return Overflow
            // so the caller knows to retry with a larger buffer.
            ReadStatus::Overflow
        } else if !self.out_queue.is_empty() {
            ReadStatus::Overflow
        } else {
            ReadStatus::Complete
        };
        (result, status)
    }

    /// Whether there is data waiting to be read.
    pub fn has_output(&self) -> bool {
        !self.out_queue.is_empty()
    }

    fn enqueue(&mut self, pdu: Vec<u8>) {
        self.out_queue.push_back(pdu);
    }

    fn stub_buf_clear(&mut self) {
        self.stub_buf.clear();
    }

    fn stub_buf_accumulate(&mut self, data: &[u8]) {
        self.stub_buf.extend_from_slice(data);
    }

    fn stub_buf_len(&self) -> usize {
        self.stub_buf.len()
    }

    fn take_stub_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stub_buf)
    }
}

/// Read status from `PipeState::read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadStatus {
    /// All requested data returned, no more pending.
    Complete,
    /// Data returned but more PDUs remain in the queue.
    Overflow,
    /// No data available.
    Empty,
}

/// Context provided to the RPC dispatcher for each call.
#[derive(Clone)]
pub struct RpcCtx<'a> {
    /// The authenticated session's username.
    pub username: &'a str,
    /// Whether the session is a guest/anonymous session.
    pub is_guest: bool,
    /// Snapshot of visible shares (for enumeration).
    pub shares: Vec<ShareInfo>,
    /// Server name (for NetrServerGetInfo).
    pub server_name: &'a str,
}

/// A share entry visible to the session (for SrvSvc enumeration).
#[derive(Clone, Debug)]
pub struct ShareInfo {
    pub name: String,
    pub comment: String,
    pub share_type: u32,
    pub encrypt_data: bool,
}

/// Dispatch a SrvSvc call.
fn dispatch_srvsvc(opnum: u16, stub: &[u8], ctx: &RpcCtx) -> Result<Vec<u8>, u32> {
    debug!(opnum, stub_len = stub.len(), "SrvSvc dispatch");
    match opnum {
        15 => dispatch_netr_share_enum(stub, ctx),
        16 => dispatch_netr_share_get_info(stub, ctx),
        21 => dispatch_netr_server_get_info(stub, ctx),
        _ => {
            debug!(opnum, "unknown SrvSvc opnum — faulting op_rng_error");
            Err(FAULT_NCA_S_OP_RNG_ERROR)
        }
    }
}

fn hexdump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// NetrShareEnum (opnum 15).
fn dispatch_netr_share_enum(stub: &[u8], ctx: &RpcCtx) -> Result<Vec<u8>, u32> {
    let (level, _pref_max_len) = ndr::parse_netr_share_enum_request(stub).unwrap_or((0, 0));
    debug!(level, share_count = ctx.shares.len(), shares = ?ctx.shares.iter().map(|s| &s.name).collect::<Vec<_>>(), "NetrShareEnum");
    match level {
        1 => {
            let data = ndr::encode_netr_share_enum_response(&ctx.shares, level);
            debug!(data_hex = %hexdump(&data), "NetrShareEnum response");
            Ok(data)
        }
        _ => {
            // Unsupported level — return WERR_INVALID_LEVEL in the response.
            let data = ndr::encode_netr_share_enum_response(&[], level);
            // Override the WERROR to INVALID_LEVEL by patching the last u32.
            let mut data = data;
            let len = data.len();
            if len >= 4 {
                data[len - 4..len].copy_from_slice(&ndr::WERR_INVALID_LEVEL.to_le_bytes());
            }
            Ok(data)
        }
    }
}

/// NetrShareGetInfo (opnum 16).
fn dispatch_netr_share_get_info(stub: &[u8], ctx: &RpcCtx) -> Result<Vec<u8>, u32> {
    let (level, share_name) =
        ndr::parse_netr_share_get_info_request(stub).unwrap_or((0, String::new()));
    let share = ctx
        .shares
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(&share_name));
    match level {
        1 => {
            let data = ndr::encode_netr_share_get_info_response(share, level);
            Ok(data)
        }
        _ => {
            // Unsupported level — return WERR_INVALID_LEVEL.
            let data = ndr::encode_netr_share_get_info_response(None, level);
            let mut data = data;
            let len = data.len();
            if len >= 4 {
                data[len - 4..len].copy_from_slice(&ndr::WERR_INVALID_LEVEL.to_le_bytes());
            }
            Ok(data)
        }
    }
}

/// NetrServerGetInfo (opnum 21).
fn dispatch_netr_server_get_info(stub: &[u8], ctx: &RpcCtx) -> Result<Vec<u8>, u32> {
    let level = ndr::parse_netr_server_get_info_request(stub).unwrap_or(0);
    let data = ndr::encode_netr_server_get_info_response(ctx.server_name, level);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> RpcCtx<'static> {
        RpcCtx {
            username: "test",
            is_guest: false,
            shares: vec![],
            server_name: "localhost",
        }
    }

    #[test]
    fn test_is_rpc_pipe() {
        assert!(is_rpc_pipe("\\PIPE\\SRVSVC"));
        assert!(is_rpc_pipe("\\PIPE\\srvsvc"));
        assert!(!is_rpc_pipe("\\PIPE\\UNKNOWN"));
        assert!(!is_rpc_pipe("test.txt"));
    }

    #[test]
    fn test_serves_pipe() {
        assert!(serves_pipe("srvsvc"));
        assert!(serves_pipe("SRVSVC"));
        assert!(serves_pipe("\\srvsvc"));
        assert!(serves_pipe("\\PIPE\\srvsvc"));
        assert!(serves_pipe("\\PiPe\\srvsvc"));
        assert!(!serves_pipe("lsarpc"));
        assert!(!serves_pipe("\\PIPE\\lsarpc"));
        assert!(!serves_pipe("PIPESRVSVC"));
        assert!(!serves_pipe("test.txt"));
    }

    #[test]
    fn pipe_state_new_is_empty() {
        let ps = PipeState::new();
        assert!(!ps.has_output());
    }

    #[test]
    fn process_bind_returns_ack() {
        let ctx = test_ctx();
        let mut ps = PipeState::new();

        // Build a BIND PDU with SRVSVC/NDR20.
        let mut bind_body = Vec::new();
        bind_body.extend_from_slice(&4280u16.to_le_bytes());
        bind_body.extend_from_slice(&4280u16.to_le_bytes());
        bind_body.extend_from_slice(&0u32.to_le_bytes());
        bind_body.push(1); // num_ctx_items
        bind_body.push(0);
        bind_body.extend_from_slice(&0u16.to_le_bytes());
        // ctx element
        bind_body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        bind_body.push(1); // num_transfer_syntaxes
        bind_body.push(0); // reserved
        write_syntax_id(&mut bind_body, &SRVSVC_SYNTAX);
        write_syntax_id(&mut bind_body, &NDR20_SYNTAX);

        let mut pdu = Vec::new();
        let hdr = PduHeader {
            ptype: PTYPE_BIND,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            drep: [0x10, 0, 0, 0],
            frag_length: (PduHeader::SIZE + bind_body.len()) as u16,
            auth_length: 0,
            call_id: 42,
        };
        hdr.encode(&mut pdu);
        pdu.extend_from_slice(&bind_body);

        let consumed = ps.process(&pdu, &ctx);
        assert_eq!(consumed, pdu.len());
        assert!(ps.has_output());

        let (data, status) = ps.read(65536);
        assert_ne!(data.len(), 0);
        assert_eq!(status, ReadStatus::Complete);

        // Verify it's a BIND_ACK.
        let (ack_hdr, _) = PduHeader::parse(&data).expect("parse ack");
        assert_eq!(ack_hdr.ptype, PTYPE_BIND_ACK);
        assert_eq!(ack_hdr.call_id, 42);
    }

    #[test]
    fn request_before_bind_faults() {
        let ctx = test_ctx();
        let mut ps = PipeState::new();

        let mut req_body = Vec::new();
        req_body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        req_body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        req_body.extend_from_slice(&15u16.to_le_bytes()); // opnum
        req_body.push(0); // stub

        let mut pdu = Vec::new();
        let hdr = PduHeader {
            ptype: PTYPE_REQUEST,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            drep: [0x10, 0, 0, 0],
            frag_length: (PduHeader::SIZE + req_body.len()) as u16,
            auth_length: 0,
            call_id: 1,
        };
        hdr.encode(&mut pdu);
        pdu.extend_from_slice(&req_body);

        ps.process(&pdu, &ctx);
        let (data, _) = ps.read(65536);
        let (fault_hdr, body) = PduHeader::parse(&data).expect("parse fault");
        assert_eq!(fault_hdr.ptype, PTYPE_FAULT);
        let status = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        assert_eq!(status, FAULT_NCA_S_UNK_IF);
    }

    fn write_syntax_id(buf: &mut Vec<u8>, sid: &SyntaxId) {
        let bytes: [u8; 16] = sid.uuid.into();
        buf.extend_from_slice(&bytes);
        buf.extend_from_slice(&sid.version.to_le_bytes());
    }

    #[test]
    fn partial_pdu_waits_for_more() {
        let ctx = test_ctx();
        let mut ps = PipeState::new();

        // Build a complete BIND, then send only the first half.
        let mut bind_body = Vec::new();
        bind_body.extend_from_slice(&4280u16.to_le_bytes());
        bind_body.extend_from_slice(&4280u16.to_le_bytes());
        bind_body.extend_from_slice(&0u32.to_le_bytes());
        bind_body.push(1);
        bind_body.push(0);
        bind_body.extend_from_slice(&0u16.to_le_bytes());
        bind_body.extend_from_slice(&0u16.to_le_bytes());
        bind_body.push(1);
        bind_body.push(0);
        write_syntax_id(&mut bind_body, &SRVSVC_SYNTAX);
        write_syntax_id(&mut bind_body, &NDR20_SYNTAX);

        let mut pdu = Vec::new();
        let hdr = PduHeader {
            ptype: PTYPE_BIND,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            drep: [0x10, 0, 0, 0],
            frag_length: (PduHeader::SIZE + bind_body.len()) as u16,
            auth_length: 0,
            call_id: 1,
        };
        hdr.encode(&mut pdu);
        pdu.extend_from_slice(&bind_body);

        // Send first half.
        let half = pdu.len() / 2;
        let consumed = ps.process(&pdu[..half], &ctx);
        assert_eq!(consumed, half);
        assert!(!ps.has_output());

        // Send the rest.
        let consumed2 = ps.process(&pdu[half..], &ctx);
        assert_eq!(consumed2, pdu.len() - half);
        assert!(ps.has_output());
    }
}
