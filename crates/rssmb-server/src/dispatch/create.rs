use super::*;

// ── Durable handle & Lease create contexts (MS-SMB2 2.2.13.2.8–2.2.13.2.12) ──

/// DHnQ create context name (durable handle v1 request, MS-SMB2 2.2.13.2.8).
pub(crate) const DHNQ_NAME: &[u8; 4] = b"DHnQ";
/// DHnC create context name (durable handle v1 reconnect, MS-SMB2 2.2.13.2.7).
pub(crate) const DHNC_NAME: &[u8; 4] = b"DHnC";
/// DH2Q create context name (durable handle v2 request).
pub(crate) const DH2Q_NAME: &[u8; 4] = b"DH2Q";
/// DH2C create context name (durable handle v2 reconnect).
pub(crate) const DH2C_NAME: &[u8; 4] = b"DH2C";
/// RqLs create context name (lease v1 / v2 request & response).
pub(crate) const RQLS_NAME: &[u8; 4] = b"RqLs";

/// Parsed DH2Q create context data (32 bytes).
#[derive(Debug)]
pub(crate) struct Dh2qContext {
    /// Timeout in milliseconds the server should keep the handle alive.
    timeout: u32,
    /// Flags (bit 1 = persistent handle).
    _flags: u32,
    /// The client-supplied GUID identifying this durable open.
    create_guid: [u8; 16],
}

/// Parsed DH2C create context data (36 bytes).
#[derive(Debug)]
pub(crate) struct Dh2cContext {
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
pub(crate) struct DhncContext {
    file_id: rssmb_proto::create::FileId,
}

/// Parsed DHnQ create context data (16 bytes, zeroed — the v1 request
/// context body is all reserved).
#[derive(Debug)]
pub(crate) struct DhnqContext;

/// Parsed RqLs create context data (32 bytes for v1, 52 bytes for v2).
#[derive(Debug, Clone)]
pub(crate) struct RqLsContext {
    pub(crate) lease_key: [u8; 16],
    pub(crate) lease_state: opens::LeaseCaching,
    #[allow(dead_code)]
    pub(crate) lease_flags: u32,
    pub(crate) parent_lease_key: Option<[u8; 16]>,
    pub(crate) epoch: u16,
    pub(crate) is_v2: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ParsedCreateContexts {
    pub(crate) dh2q: Option<Dh2qContext>,
    pub(crate) dh2c: Option<Dh2cContext>,
    /// v1 durable request (DHnQ), present-flag.
    pub(crate) dhnq: Option<DhnqContext>,
    /// v1 durable reconnect (DHnC) — file id only.
    pub(crate) dhnc: Option<DhncContext>,
    pub(crate) rqls: Option<RqLsContext>,
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
pub(crate) struct ReconnectContext<'a> {
    persistent_id: u64,
    create_guid: Option<&'a [u8; 16]>,
}

/// Serialize a list of `(name, data)` create contexts into an 8-byte aligned
/// SMB2_CREATE_CONTEXT chain (MS-SMB2 2.2.13.2).
pub(crate) fn encode_create_contexts(contexts: &[(&[u8], &[u8])]) -> Vec<u8> {
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
pub(crate) fn build_rqls_response_data(grant: &opens::LeaseGrant) -> Vec<u8> {
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
pub(crate) fn parse_create_contexts(
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
pub(crate) async fn handle_create(
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
