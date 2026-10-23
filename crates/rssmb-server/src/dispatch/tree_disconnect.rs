use super::*;

pub(crate) async fn handle_tree_disconnect(
    state: &ServerState,
    conn_state: &ConnState,
    req_header: &Header,
) -> FramedResponse {
    let tree_id = req_header.tree_id.unwrap_or(0);
    let session_id = req_header.session_id;

    // Validate that the tree belongs to this session before removing.
    let tree_owned = {
        let trees_ref = conn_state.trees_ref();
        let trees = trees_ref.read().await;
        trees
            .get(&tree_id)
            .map(|e| e.session_id == session_id)
            .unwrap_or(false)
    };
    if !tree_owned {
        // Second TDIS on an already-disconnected tree: the tree id is
        // simply unknown. MS-SMB2 3.3.5.9 has no success path here —
        // torture connect.c:234 double-tdis asserts
        // NT_STATUS_NETWORK_NAME_DELETED (Windows/Samba behavior), not
        // ACCESS_DENIED.
        return error_response_for(
            Command::TreeDisconnect,
            NtStatus::NetworkNameDeleted,
            req_header,
        );
    }

    // Remove all opens belonging to this tree, closing them via VFS.
    let removed = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        let to_close: Vec<(u64, OpenEntry)> = opens
            .iter()
            .filter(|(_, e)| e.tree_id == tree_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (key, entry) in &to_close {
            opens.remove(key);
            if entry.is_pipe {
                // Pipe opens have no VFS handle to close; just drop the Arc.
                continue;
            }
            // Remove from the global open table.
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
            // Close the VFS handle — fire and forget, log on error.
            let vfs = entry.vfs.clone();
            let open_id = entry.open_id;
            tokio::spawn(async move {
                if should_delete_on_close {
                    let _ = vfs.set_delete_on_close(open_id, true).await;
                }
                if let Err(e) = vfs.close(open_id).await {
                    tracing::warn!(error = %e, "tree_disconnect: VFS close failed");
                }
            });
        }
        to_close.len()
    };
    if removed > 0 {
        debug!(
            conn_id = conn_state.conn_id,
            tree_id, removed, "tree_disconnect: closed handles"
        );
    }

    // Remove the tree from the connection tree table.
    conn_state.trees_ref().write().await.remove(&tree_id);

    // Cancel any pending async ops for this tree. CHANGE_NOTIFY ops get
    // the async STATUS_NOTIFY_CLEANUP completion (MS-SMB2 3.3.5.10: tree
    // disconnect ends the watch and notifies the client) — silently
    // dropping them left smb2.notify tdis/tdis1 waiting forever.
    {
        let mut pending = conn_state.pending_async.lock().await;
        let to_remove: Vec<u64> = pending
            .iter()
            .filter(|(_, op)| op.tree_id == tree_id)
            .map(|(k, _)| *k)
            .collect();
        for key in to_remove {
            if let Some(op) = pending.remove(&key) {
                if op.command == Command::ChangeNotify {
                    drop(pending);
                    send_notify_cleanup(conn_state, key, op).await;
                    pending = conn_state.pending_async.lock().await;
                } else if op.command == Command::Lock {
                    // Pended blocking LOCK: complete it out-of-band so the
                    // client's smb2_lock_recv unblocks (torture cancel-tdis
                    // accepts RANGE_NOT_LOCKED or OK; a silent drop made the
                    // client wait for its 35 s timeout → IO_TIMEOUT at
                    // lock.c:1064).
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

    // Release all byte-range locks held by this tree.
    state.open_table.release_all_locks_for_tree(tree_id).await;

    let response = build_response(
        req_header,
        ResponseContent::TreeDisconnect(Default::default()),
    );
    FramedResponse::Plain(response)
}
