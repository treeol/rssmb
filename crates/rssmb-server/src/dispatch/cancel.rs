use super::*;

pub(crate) async fn send_notify_cleanup(conn_state: &ConnState, key: u64, op: AsyncOp) {
    let _ = op.cancel.send(());
    if let Some(handle) = op.notify_handle {
        handle.cancel();
    }
    let mut header = Header {
        credit_charge: 0,
        status: 0x0000_010B,
        command: Command::ChangeNotify,
        credit_request: 0,
        flags: HeaderFlags::new().with_server_to_redir(true),
        next_command: 0,
        message_id: key,
        tree_id: Some(op.tree_id),
        async_id: None,
        session_id: op.session_id,
        signature: 0,
    };
    header.to_async(key);
    let resp = FramedResponse::Plain(PlainResponse {
        header,
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    });
    // Out-of-band completion: sign when the session requires signing
    // (same rule as handle_cancel: the client signs requests when signing
    // is required, so the request's signed flag and `required` agree).
    let signed = conn_state
        .signing_ref()
        .read()
        .unwrap()
        .get(&op.session_id)
        .map(|st| st.required)
        .unwrap_or(false);
    send_unsolicited(conn_state, &resp, signed).await;
}

/// CANCEL — cancel a pending async operation (MS-SMB2 3.3.5.16).
///
/// CANCEL itself never gets a response. The cancelled operation is completed
/// with STATUS_CANCELLED, sent on the write channel as an async response.
pub(crate) async fn handle_cancel(
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
        // MS-SMB2 pre-interim CANCEL: Samba's client sends the CANCEL
        // immediately after smb2_notify_send, before the STATUS_PENDING
        // interim arrives (smbXcli_base.c smb2cli_req_cancel: MessageId=0,
        // AsyncId=0, no ASYNC flag). smbd answers this by cancelling the
        // session's most recent pending async op — do the same: the
        // highest message_id (client mids are monotonic per session).
        if target == 0 && req_header.session_id != 0 {
            let candidates: Vec<u64> = {
                let pending = conn_state.pending_async.lock().await;
                pending
                    .iter()
                    .filter(|(_, op)| op.session_id == req_header.session_id)
                    .map(|(k, _)| *k)
                    .collect()
            };
            if let Some(newest) = candidates.into_iter().max() {
                let removed = {
                    let mut pending = conn_state.pending_async.lock().await;
                    match pending.get(&newest) {
                        Some(op) if op.session_id == req_header.session_id => {
                            pending.remove(&newest)
                        }
                        _ => None,
                    }
                };
                if let Some(op) = removed {
                    debug!(
                        conn_id = conn_state.conn_id,
                        newest, "cancel: pre-interim CANCEL (mid=0) — cancelled newest pending op"
                    );
                    finish_cancel(conn_state, op, newest, req_header).await;
                    // CANCEL never gets its own response; the completion was
                    // already sent out-of-band.
                    return None;
                }
            }
        }
        debug!(
            conn_id = conn_state.conn_id,
            target, "cancel: no matching pending op"
        );
        return None;
    };
    finish_cancel(conn_state, op, target, req_header).await;
    // CANCEL never gets a response (MS-SMB2 3.3.5.16); the STATUS_CANCELLED
    // completion went out-of-band above. Returning it here too made the
    // read loop send it twice (torture lock `cancel`: INVALID_NETWORK_
    // RESPONSE at lock.c:926).
    None
}

pub(crate) async fn finish_cancel(
    conn_state: &ConnState,
    op: AsyncOp,
    target: u64,
    req_header: &Header,
) -> FramedResponse {
    let _ = op.cancel.send(());
    // Cancel the notify watcher if present.
    if let Some(handle) = op.notify_handle {
        handle.cancel();
    }
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
    resp
}
