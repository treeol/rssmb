use super::*;

pub(crate) async fn handle_logoff(
    state: &ServerState,
    conn_state: &ConnState,
    req_header: &Header,
) -> FramedResponse {
    let session_id = req_header.session_id;

    // LOGOFF of an unknown/already-logged-off session fails with
    // USER_SESSION_DELETED (MS-SMB2 3.3.5.6; torture connect.c:248 logs
    // off twice and asserts the second logoff fails with this). Checked
    // BEFORE teardown so the first (valid) logoff succeeds.
    if !conn_state
        .sessions
        .read()
        .await
        .iter()
        .any(|s| s.id == session_id)
    {
        return error_response_for(Command::Logoff, NtStatus::UserSessionDeleted, req_header);
    }

    // Remove all opens belonging to this session, closing them via VFS.
    let removed = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        let to_close: Vec<(u64, OpenEntry)> = opens
            .iter()
            .filter(|(_, e)| e.session_id == session_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (key, entry) in &to_close {
            opens.remove(key);
            if entry.is_pipe {
                // Pipe opens have no VFS handle to close; just drop the Arc.
                continue;
            }
            let mut should_delete_on_close = false;
            if let Some(fid) = entry.file_id {
                let remove_result = state.open_table.remove(fid, entry.open_id).await;
                should_delete_on_close =
                    remove_result.was_last && remove_result.any_delete_on_close;
            }
            state
                .open_table
                .remove_open_from_leases(entry.open_id)
                .await;
            if let Some(guid) = entry.durable_guid {
                state.durable_table.forget(&guid).await;
            }
            if let Some(pid) = entry.durable_persistent_id {
                state.durable_table.forget_v1(pid).await;
            }
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if should_delete_on_close {
                    let _ = vfs.set_delete_on_close(open_id, true).await;
                }
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "logoff: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(
            conn_id = conn_state.conn_id,
            session_id, removed, "logoff: closed handles"
        );
    }

    // Release all byte-range locks held by this session.
    state
        .open_table
        .release_all_locks_for_session(session_id)
        .await;

    // Remove all trees belonging to this session.
    {
        let trees_ref = conn_state.trees_ref();
        let mut trees = trees_ref.write().await;
        let tree_ids: Vec<u32> = trees
            .iter()
            .filter(|(_, e)| e.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for tid in &tree_ids {
            trees.remove(tid);
        }
    }

    // Remove the session from the connection's list and the global registry.
    // LOGOFF tears down the entire session across all channels (MS-SMB2 3.3.5.6).
    conn_state
        .sessions
        .write()
        .await
        .retain(|s| s.id != session_id);
    state.session_registry.write().unwrap().remove(&session_id);
    state.remove_session(session_id).await;
    // The signing state is kept until the LOGOFF response has been signed;
    // the read loop removes it then (see `connection.rs`).
    if let Some(st) = conn_state
        .signing_ref()
        .write()
        .unwrap()
        .get_mut(&session_id)
    {
        st.retiring = true;
    }

    // Cancel any pending async ops for this session. CHANGE_NOTIFY ops
    // get the async STATUS_NOTIFY_CLEANUP completion (MS-SMB2: logoff
    // ends the watches and notifies the client) — silently dropping them
    // left smb2.notify logoff waiting forever.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.session_id == session_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                if op.command == Command::ChangeNotify {
                    drop(pending);
                    send_notify_cleanup(conn_state, key, op).await;
                    pending = conn_state.pending_async.lock().await;
                } else if op.command == Command::Lock {
                    // Pended blocking LOCK: complete out-of-band (torture
                    // cancel-logoff accepts RANGE_NOT_LOCKED or OK).
                    drop(pending);
                    let mut header = Header {
                        credit_charge: 0,
                        status: NtStatus::RangeNotLocked.to_u32(),
                        command: Command::Lock,
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
                        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                            error_data: vec![],
                        }),
                    });
                    send_unsolicited(conn_state, &resp, true).await;
                    pending = conn_state.pending_async.lock().await;
                } else {
                    let _ = op.cancel.send(());
                    if let Some(handle) = op.notify_handle {
                        handle.cancel();
                    }
                }
            }
        }
    }

    let resp = build_response(
        req_header,
        ResponseContent::Logoff(rssmb_proto::session_setup::LogoffResponse::default()),
    );
    FramedResponse::Plain(resp)
}
