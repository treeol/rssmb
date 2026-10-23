use super::*;

pub(crate) async fn handle_read(
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
            return error_response_for(Command::Read, NtStatus::FileLockConflict, &req.header);
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
