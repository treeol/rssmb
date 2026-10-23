use super::*;

pub(crate) async fn handle_write(
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
            return error_response_for(Command::Write, NtStatus::FileLockConflict, &req.header);
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
