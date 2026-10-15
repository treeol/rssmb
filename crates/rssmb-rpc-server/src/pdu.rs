//! DCE/RPC connection-oriented PDU codec (MS-RPCE).
//!
//! Hand-written server-side codec for the PDU types needed by Step 8:
//! BIND, BIND_ACK, BIND_NAK, REQUEST, RESPONSE, FAULT.
//! Only NDR20 (little-endian/ASCII) is supported.

use rssmb_proto::Guid;
use tracing::debug;

// --- PDU types (PTYPE) ---
pub const PTYPE_REQUEST: u8 = 0;
pub const PTYPE_RESPONSE: u8 = 2;
pub const PTYPE_FAULT: u8 = 3;
pub const PTYPE_BIND: u8 = 11;
pub const PTYPE_BIND_ACK: u8 = 12;
pub const PTYPE_BIND_NAK: u8 = 13;
pub const PTYPE_ALTER_CONTEXT: u8 = 14;
pub const PTYPE_ALTER_CONTEXT_RESP: u8 = 15;

// --- PFC flags ---
pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
pub const PFC_CONC_MPX: u8 = 0x10;
pub const PFC_OBJECT_UUID: u8 = 0x80;

// --- Bind ACK result codes ---
pub const RESULT_ACCEPTANCE: u16 = 0;
pub const RESULT_PROVIDER_REJECTION: u16 = 2;
pub const RESULT_NEGOTIATE_ACK: u16 = 3;

// --- Bind ACK rejection reasons ---
pub const REASON_NOT_SPECIFIED: u16 = 0;
pub const REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;
pub const REASON_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;

// --- Bind NAK reject reasons ---
pub const NAK_PROTOCOL_VERSION_NOT_SUPPORTED: u16 = 4;

// --- Fault status codes (NTSTATUS) ---
pub const FAULT_NCA_S_PROTO_ERROR: u32 = 0x1C010003;
pub const FAULT_NCA_S_OP_RNG_ERROR: u32 = 0x1C010002;
pub const FAULT_NCA_S_UNK_IF: u32 = 0x1C000001;
pub const FAULT_ACCESS_DENIED: u32 = 0xC0000022;
pub const FAULT_NCA_S_INVALID_TAG: u32 = 0x1C000006;

/// SRVSVC interface UUID: 4B324FC8-1670-01D3-1278-5A47BF6EE188 v3.0
pub const SRVSVC_SYNTAX: SyntaxId = SyntaxId {
    uuid: rssmb_proto::make_guid!("4b324fc8-1670-01d3-1278-5a47bf6ee188"),
    version: 3,
};

/// NDR20 transfer syntax: 8A885D04-1CEB-11C9-9FE8-08002B104860 v2.0
pub const NDR20_SYNTAX: SyntaxId = SyntaxId {
    uuid: rssmb_proto::make_guid!("8a885d04-1ceb-11c9-9fe8-08002b104860"),
    version: 0x00000002,
};

/// Bind-time feature negotiation UUID: 6CB71C2C-9812-4540-0300-000000000000 v1.0
pub const BTN_SYNTAX: SyntaxId = SyntaxId {
    uuid: rssmb_proto::make_guid!("6cb71c2c-9812-4540-0300-000000000000"),
    version: 0x00000001,
};

/// A syntax identifier (UUID + version).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxId {
    pub uuid: Guid,
    pub version: u32,
}

impl SyntaxId {
    pub const ZERO: Self = Self {
        uuid: Guid::ZERO,
        version: 0,
    };
}

/// Common 16-byte PDU header.
#[derive(Clone, Copy, Debug)]
pub struct PduHeader {
    pub ptype: u8,
    pub pfc_flags: u8,
    pub drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl PduHeader {
    pub const SIZE: usize = 16;

    pub fn is_first(&self) -> bool {
        self.pfc_flags & PFC_FIRST_FRAG != 0
    }

    pub fn is_last(&self) -> bool {
        self.pfc_flags & PFC_LAST_FRAG != 0
    }

    /// Parse the common header from a byte slice.
    pub fn parse(data: &[u8]) -> Option<(PduHeader, &[u8])> {
        if data.len() < Self::SIZE {
            return None;
        }
        // rpc_vers=5, minor=0 — reject otherwise.
        if data[0] != 5 || data[1] != 0 {
            return None;
        }
        let ptype = data[2];
        let pfc_flags = data[3];
        let drep = [data[4], data[5], data[6], data[7]];
        let frag_length = u16::from_le_bytes([data[8], data[9]]);
        let auth_length = u16::from_le_bytes([data[10], data[11]]);
        let call_id = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        // Reject if the buffer doesn't contain the full PDU.
        if data.len() < frag_length as usize {
            return None;
        }
        // Reject invalid frag_length — must be at least the header size.
        if (frag_length as usize) < Self::SIZE {
            return None;
        }
        let body = &data[Self::SIZE..frag_length as usize];
        Some((
            PduHeader {
                ptype,
                pfc_flags,
                drep,
                frag_length,
                auth_length,
                call_id,
            },
            body,
        ))
    }

    /// Encode the common header into a byte vector.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(5); // rpc_vers
        buf.push(0); // rpc_vers_minor
        buf.push(self.ptype);
        buf.push(self.pfc_flags);
        buf.extend_from_slice(&self.drep);
        // frag_length and auth_length are patched by the caller.
        buf.extend_from_slice(&self.frag_length.to_le_bytes());
        buf.extend_from_slice(&self.auth_length.to_le_bytes());
        buf.extend_from_slice(&self.call_id.to_le_bytes());
    }
}

/// A presentation context element from a BIND PDU.
#[derive(Clone, Debug)]
pub struct BindContextElement {
    pub context_id: u16,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

/// A BIND_ACK result entry.
#[derive(Clone, Debug)]
pub struct BindAckResult {
    pub result: u16,
    pub reason: u16,
    pub syntax: SyntaxId,
}

/// Maximum fragment sizes we negotiate.
pub const MAX_XMIT_FRAG: u16 = 4280;
pub const MAX_RECV_FRAG: u16 = 4280;

/// Parse a BIND PDU body (after the 16-byte common header).
pub fn parse_bind(body: &[u8]) -> Option<(u16, u16, u32, Vec<BindContextElement>)> {
    // Fixed part: max_xmit(2) + max_recv(2) + assoc(4) + num_ctx(1) + reserved(1) + reserved2(2) = 12
    if body.len() < 12 {
        return None;
    }
    let max_xmit_frag = u16::from_le_bytes([body[0], body[1]]);
    let max_recv_frag = u16::from_le_bytes([body[2], body[3]]);
    let assoc_group_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let num_ctx_items = body[8] as usize;
    // body[9] = reserved, body[10..12] = reserved2
    let mut pos = 12;
    let mut ctx_items = Vec::with_capacity(num_ctx_items);
    for _ in 0..num_ctx_items {
        if pos + 4 > body.len() {
            return None;
        }
        let context_id = u16::from_le_bytes([body[pos], body[pos + 1]]);
        let num_trans = body[pos + 2] as usize;
        // body[pos+3] = reserved
        pos += 4;
        // Abstract syntax: 16-byte UUID + 4-byte version
        if pos + 20 > body.len() {
            return None;
        }
        let abstract_syntax = read_syntax_id(&body[pos..]);
        pos += 20;
        let mut transfer_syntaxes = Vec::with_capacity(num_trans);
        for _ in 0..num_trans {
            if pos + 20 > body.len() {
                return None;
            }
            transfer_syntaxes.push(read_syntax_id(&body[pos..]));
            pos += 20;
        }
        ctx_items.push(BindContextElement {
            context_id,
            abstract_syntax,
            transfer_syntaxes,
        });
    }
    Some((max_xmit_frag, max_recv_frag, assoc_group_id, ctx_items))
}

/// Parse a REQUEST PDU body (after the 16-byte common header).
pub fn parse_request(body: &[u8]) -> Option<(u32, u16, u16, &[u8])> {
    if body.len() < 8 {
        return None;
    }
    let alloc_hint = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let p_cont_id = u16::from_le_bytes([body[4], body[5]]);
    let opnum = u16::from_le_bytes([body[6], body[7]]);
    let stub_data = &body[8..];
    Some((alloc_hint, p_cont_id, opnum, stub_data))
}

/// Read a 20-byte syntax ID (16-byte UUID + 4-byte LE version).
fn read_syntax_id(data: &[u8]) -> SyntaxId {
    let mut guid_bytes = [0u8; 16];
    guid_bytes.copy_from_slice(&data[0..16]);
    let uuid: Guid = guid_bytes.into();
    let version = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    SyntaxId { uuid, version }
}

/// Write a 20-byte syntax ID.
fn write_syntax_id(buf: &mut Vec<u8>, sid: &SyntaxId) {
    let bytes: [u8; 16] = sid.uuid.into();
    buf.extend_from_slice(&bytes);
    buf.extend_from_slice(&sid.version.to_le_bytes());
}

/// Build a BIND_ACK PDU for the given contexts.
///
/// For each context element:
/// - If abstract == SRVSVC and a transfer syntax == NDR20 → accept.
/// - If transfer syntax is BTN (feature negotiation) → negotiate_ack with zero.
/// - Otherwise → provider_rejection.
///
/// `assoc_group_id` is the client's value, or a fresh nonzero if zero.
pub fn build_bind_ack(
    call_id: u32,
    client_max_xmit: u16,
    client_max_recv: u16,
    assoc_group_id: u32,
    ctx_items: &[BindContextElement],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
    // Encode common header (frag_length patched later).
    let header_start = buf.len();
    let header = PduHeader {
        ptype: PTYPE_BIND_ACK,
        pfc_flags,
        drep: [0x10, 0, 0, 0], // little-endian, ASCII
        frag_length: 0,        // patched
        auth_length: 0,
        call_id,
    };
    header.encode(&mut buf);

    // max_xmit_frag, max_recv_frag
    let max_xmit = std::cmp::min(client_max_xmit, MAX_XMIT_FRAG).max(256);
    let max_recv = std::cmp::min(client_max_recv, MAX_RECV_FRAG).max(256);
    buf.extend_from_slice(&max_xmit.to_le_bytes());
    buf.extend_from_slice(&max_recv.to_le_bytes());

    // assoc_group_id — echo client's or assign fresh
    let assoc = if assoc_group_id != 0 {
        assoc_group_id
    } else {
        // Use a deterministic-ish nonzero value based on call_id.
        call_id.wrapping_mul(0x4910) | 1
    };
    buf.extend_from_slice(&assoc.to_le_bytes());

    // Secondary address: "\PIPE\srvsvc\0", padded to 4-byte boundary.
    let sec_addr = b"\\PIPE\\srvsvc\0";
    let sec_addr_len = sec_addr.len() as u16;
    buf.extend_from_slice(&sec_addr_len.to_le_bytes());
    buf.extend_from_slice(sec_addr);
    // Pad to 4-byte boundary from PDU start (header is 16 bytes, already 4-aligned).
    let offset_from_pdu_start = buf.len() - header_start;
    let pad = (4 - (offset_from_pdu_start % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, pad));

    // Results: num_results, reserved, reserved2
    let results: Vec<BindAckResult> = ctx_items.iter().map(evaluate_bind_context).collect();
    buf.push(results.len() as u8);
    buf.push(0); // reserved
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    for r in &results {
        buf.extend_from_slice(&r.result.to_le_bytes());
        buf.extend_from_slice(&r.reason.to_le_bytes());
        write_syntax_id(&mut buf, &r.syntax);
    }

    // Patch frag_length.
    let frag_length = buf.len() as u16;
    let fl_pos = header_start + 8;
    buf[fl_pos..fl_pos + 2].copy_from_slice(&frag_length.to_le_bytes());

    buf
}

/// Evaluate a single BIND context element: accept, reject, or negotiate_ack.
pub fn evaluate_bind_context(ctx: &BindContextElement) -> BindAckResult {
    // Check if abstract syntax is SRVSVC.
    let is_srvsvc = ctx.abstract_syntax == SRVSVC_SYNTAX;
    debug!(
        is_srvsvc,
        received_uuid = %ctx.abstract_syntax.uuid,
        received_version = ctx.abstract_syntax.version,
        expected_uuid = %SRVSVC_SYNTAX.uuid,
        expected_version = SRVSVC_SYNTAX.version,
        "evaluate_bind_context"
    );

    // Check for NDR20 in the transfer syntaxes.
    let has_ndr20 = ctx.transfer_syntaxes.contains(&NDR20_SYNTAX);

    if is_srvsvc && has_ndr20 {
        return BindAckResult {
            result: RESULT_ACCEPTANCE,
            reason: REASON_NOT_SPECIFIED,
            syntax: NDR20_SYNTAX,
        };
    }

    // Check for bind-time feature negotiation.
    let has_btn = ctx.transfer_syntaxes.contains(&BTN_SYNTAX);
    if has_btn {
        return BindAckResult {
            result: RESULT_NEGOTIATE_ACK,
            reason: 0, // feature bitmask (0 = no features)
            syntax: SyntaxId::ZERO,
        };
    }

    // Reject.
    let reason = if !is_srvsvc {
        REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED
    } else {
        REASON_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED
    };
    BindAckResult {
        result: RESULT_PROVIDER_REJECTION,
        reason,
        syntax: SyntaxId::ZERO,
    }
}

/// Build a BIND_NAK PDU.
pub fn build_bind_nak(call_id: u32, reason: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    let header = PduHeader {
        ptype: PTYPE_BIND_NAK,
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        drep: [0x10, 0, 0, 0],
        frag_length: 0,
        auth_length: 0,
        call_id,
    };
    let header_start = buf.len();
    header.encode(&mut buf);
    // reason (u16) + num_protocols (u8) + [protocol versions]
    buf.extend_from_slice(&reason.to_le_bytes());
    buf.push(1); // num_protocols
    buf.push(5); // version major
    buf.push(0); // version minor
                 // Pad to frag_length
    let frag_length = buf.len() as u16;
    let fl_pos = header_start + 8;
    buf[fl_pos..fl_pos + 2].copy_from_slice(&frag_length.to_le_bytes());
    buf
}

/// Build a RESPONSE PDU (single fragment).
pub fn build_response(
    call_id: u32,
    p_cont_id: u16,
    stub_data: &[u8],
    pfc_flags: u8,
    max_frag: u16,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let header_start = buf.len();
    let header = PduHeader {
        ptype: PTYPE_RESPONSE,
        pfc_flags,
        drep: [0x10, 0, 0, 0],
        frag_length: 0,
        auth_length: 0,
        call_id,
    };
    header.encode(&mut buf);
    // alloc_hint (total remaining stub), p_cont_id, cancel_count, reserved
    buf.extend_from_slice(&(stub_data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&p_cont_id.to_le_bytes());
    buf.push(0); // cancel_count
    buf.push(0); // reserved
    buf.extend_from_slice(stub_data);
    let frag_length = buf.len() as u16;
    let fl_pos = header_start + 8;
    buf[fl_pos..fl_pos + 2].copy_from_slice(&frag_length.to_le_bytes());
    let _ = max_frag; // used by fragment_response
    buf
}

/// Fragment a stub into multiple RESPONSE PDUs, each at most `max_frag` bytes.
/// Returns a Vec of complete PDU byte vectors.
pub fn fragment_response(
    call_id: u32,
    p_cont_id: u16,
    stub_data: &[u8],
    max_frag: u16,
) -> Vec<Vec<u8>> {
    // Each fragment has a 24-byte overhead (16 header + 8 response header).
    let max_stub = (max_frag as usize).saturating_sub(24);
    if max_stub == 0 || stub_data.is_empty() {
        // Single fragment (even if empty).
        let flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
        return vec![build_response(
            call_id, p_cont_id, stub_data, flags, max_frag,
        )];
    }
    let mut pdus = Vec::new();
    let mut offset = 0;
    while offset < stub_data.len() {
        let end = std::cmp::min(offset + max_stub, stub_data.len());
        let chunk = &stub_data[offset..end];
        let is_first = offset == 0;
        let is_last = end == stub_data.len();
        let mut flags = 0u8;
        if is_first {
            flags |= PFC_FIRST_FRAG;
        }
        if is_last {
            flags |= PFC_LAST_FRAG;
        }
        pdus.push(build_response(call_id, p_cont_id, chunk, flags, max_frag));
        offset = end;
    }
    pdus
}

/// Build a FAULT PDU.
pub fn build_fault(call_id: u32, p_cont_id: u16, status: u32, pfc_flags: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    let header_start = buf.len();
    let header = PduHeader {
        ptype: PTYPE_FAULT,
        pfc_flags,
        drep: [0x10, 0, 0, 0],
        frag_length: 0,
        auth_length: 0,
        call_id,
    };
    header.encode(&mut buf);
    // alloc_hint, p_cont_id, cancel_count, reserved, status, reserved2
    buf.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
    buf.extend_from_slice(&p_cont_id.to_le_bytes());
    buf.push(0); // cancel_count
    buf.push(0); // reserved
    buf.extend_from_slice(&status.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    let frag_length = buf.len() as u16;
    let fl_pos = header_start + 8;
    buf[fl_pos..fl_pos + 2].copy_from_slice(&frag_length.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_rejects_short_data() {
        assert!(PduHeader::parse(&[0u8; 15]).is_none());
    }

    #[test]
    fn parse_header_rejects_wrong_version() {
        let mut data = vec![0u8; 20];
        data[0] = 4; // wrong major
        assert!(PduHeader::parse(&data).is_none());
    }

    #[test]
    fn parse_header_rejects_incomplete_frag() {
        let mut data = vec![0u8; 20];
        data[0] = 5;
        data[1] = 0;
        data[8] = 0xff;
        data[9] = 0xff; // frag_length=0xffff > 20
        assert!(PduHeader::parse(&data).is_none());
    }

    #[test]
    fn bind_ack_roundtrip() {
        // A minimal BIND with one context: SRVSVC/NDR20.
        let mut bind_body = Vec::new();
        bind_body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        bind_body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        bind_body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
        bind_body.push(1); // num_ctx_items
        bind_body.push(0); // reserved
        bind_body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
                                                          // Context element: p_cont_id=0, num_trans=1, abstract=SRVSVC, trans=NDR20
        bind_body.extend_from_slice(&0u16.to_le_bytes()); // context_id
        bind_body.push(1); // num_transfer_syntaxes
        bind_body.push(0); // reserved
        write_syntax_id(&mut bind_body, &SRVSVC_SYNTAX);
        write_syntax_id(&mut bind_body, &NDR20_SYNTAX);

        // Wrap in a PDU header.
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

        // Parse it.
        let (parsed_hdr, body) = PduHeader::parse(&pdu).expect("parse");
        assert_eq!(parsed_hdr.ptype, PTYPE_BIND);
        assert_eq!(parsed_hdr.call_id, 42);
        let (_, _, _, ctx_items) = parse_bind(body).expect("parse_bind");
        assert_eq!(ctx_items.len(), 1);
        assert_eq!(ctx_items[0].abstract_syntax, SRVSVC_SYNTAX);
        assert_eq!(ctx_items[0].transfer_syntaxes.len(), 1);
        assert_eq!(ctx_items[0].transfer_syntaxes[0], NDR20_SYNTAX);

        // Build BIND_ACK.
        let ack = build_bind_ack(42, 4280, 4280, 0, &ctx_items);
        let (ack_hdr, ack_body) = PduHeader::parse(&ack).expect("parse ack");
        assert_eq!(ack_hdr.ptype, PTYPE_BIND_ACK);
        assert_eq!(ack_hdr.call_id, 42);
        assert!(ack_hdr.is_first());
        assert!(ack_hdr.is_last());

        // Verify the results: 1 context → acceptance.
        // Parse the ack body: max_xmit(2) + max_recv(2) + assoc(4) + sec_addr...
        let max_xmit = u16::from_le_bytes([ack_body[0], ack_body[1]]);
        assert_eq!(max_xmit, 4280);
    }

    #[test]
    fn bind_rejects_wrong_interface() {
        let wrong_syntax = SyntaxId {
            uuid: rssmb_proto::make_guid!("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            version: 1,
        };
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
        write_syntax_id(&mut bind_body, &wrong_syntax);
        write_syntax_id(&mut bind_body, &NDR20_SYNTAX);

        let p = {
            let mut p = Vec::new();
            let h = PduHeader {
                ptype: PTYPE_BIND,
                pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
                drep: [0x10, 0, 0, 0],
                frag_length: (PduHeader::SIZE + bind_body.len()) as u16,
                auth_length: 0,
                call_id: 1,
            };
            h.encode(&mut p);
            p.extend_from_slice(&bind_body);
            p
        };
        let (_, body) = PduHeader::parse(&p).expect("parse");
        let (_, _, _, ctx_items) = parse_bind(body).expect("parse_bind");
        let result = evaluate_bind_context(&ctx_items[0]);
        assert_eq!(result.result, RESULT_PROVIDER_REJECTION);
        assert_eq!(result.reason, REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED);
    }

    #[test]
    fn bind_feature_negotiation_ack() {
        let btn_ctx = BindContextElement {
            context_id: 1,
            abstract_syntax: SRVSVC_SYNTAX,
            transfer_syntaxes: vec![BTN_SYNTAX],
        };
        let result = evaluate_bind_context(&btn_ctx);
        assert_eq!(result.result, RESULT_NEGOTIATE_ACK);
        assert_eq!(result.reason, 0);
    }

    #[test]
    fn response_single_fragment() {
        let stub = vec![0x01, 0x02, 0x03];
        let pdu = build_response(7, 0, &stub, PFC_FIRST_FRAG | PFC_LAST_FRAG, 4280);
        let (hdr, body) = PduHeader::parse(&pdu).expect("parse");
        assert_eq!(hdr.ptype, PTYPE_RESPONSE);
        assert_eq!(hdr.call_id, 7);
        assert!(hdr.is_first());
        assert!(hdr.is_last());
        // alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1) = 8
        assert_eq!(body.len(), 8 + 3);
        let p_cont = u16::from_le_bytes([body[4], body[5]]);
        assert_eq!(p_cont, 0);
    }

    #[test]
    fn response_multi_fragment() {
        // 100 bytes of stub, max_frag=40 → each fragment has at most 16 bytes of stub.
        let stub = vec![0xab; 100];
        let pdus = fragment_response(3, 0, &stub, 40);
        assert!(pdus.len() > 1);
        let (first_hdr, _) = PduHeader::parse(&pdus[0]).expect("parse first");
        assert!(first_hdr.is_first());
        assert!(!first_hdr.is_last());
        let (last_hdr, _) = PduHeader::parse(pdus.last().unwrap()).expect("parse last");
        assert!(!last_hdr.is_first());
        assert!(last_hdr.is_last());
        // All PDUs should be ≤ max_frag bytes.
        for p in &pdus {
            assert!(p.len() <= 40);
        }
    }

    #[test]
    fn fault_pdu_structure() {
        let pdu = build_fault(
            9,
            0,
            FAULT_NCA_S_OP_RNG_ERROR,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
        );
        let (hdr, body) = PduHeader::parse(&pdu).expect("parse");
        assert_eq!(hdr.ptype, PTYPE_FAULT);
        assert_eq!(hdr.call_id, 9);
        // alloc(4) + p_cont(2) + cancel(1) + reserved(1) + status(4) + reserved2(4) = 16
        assert_eq!(body.len(), 16);
        let status = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        assert_eq!(status, FAULT_NCA_S_OP_RNG_ERROR);
    }
}
