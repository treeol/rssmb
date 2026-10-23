use super::*;

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
pub(crate) async fn handle_negotiate(
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
