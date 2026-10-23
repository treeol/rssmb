use super::*;

pub(crate) async fn handle_flush(
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
